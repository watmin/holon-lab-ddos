//! Veth Lab XDP Filter
//!
//! XDP program with dynamic rules loaded from BPF maps.
//! Rules are managed by the userspace sidecar based on Holon detection.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::XdpContext,
};

// =============================================================================
// Rule Types
// =============================================================================

/// Rule type discriminator
#[repr(u8)]
pub enum RuleType {
    SrcIp = 0,
    DstIp = 1,
    SrcPort = 2,
    DstPort = 3,
    Protocol = 4,
}

/// Rule action
#[repr(u8)]
pub enum RuleAction {
    Pass = 0,
    Drop = 1,
    RateLimit = 2,
}

/// Rule key - what to match
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleKey {
    pub rule_type: u8,
    pub _pad: [u8; 3],
    pub value: u32,
}

/// Rule value - what to do
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleValue {
    pub action: u8,
    pub _pad: [u8; 3],
    pub rate_pps: u32,
    pub match_count: u64,
}

// =============================================================================
// BPF Maps
// =============================================================================

/// Dynamic rules map
#[map]
static RULES: HashMap<RuleKey, RuleValue> = HashMap::with_max_entries(1024, 0);

/// Stats counters (per-CPU)
/// 0: total, 1: passed, 2: dropped, 3: matched, 4: sampled
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(8, 0);

/// Configuration
/// 0: sample_rate, 1: enforce_mode
#[map]
static CONFIG: PerCpuArray<u32> = PerCpuArray::with_max_entries(4, 0);

/// Perf event array for packet samples (like the working xdp-filter)
#[map]
static SAMPLES: PerfEventArray<PacketSample> = PerfEventArray::new(0);

// =============================================================================
// Packet Sample Structure
// =============================================================================

const SAMPLE_DATA_SIZE: usize = 128;

#[repr(C)]
pub struct PacketSample {
    pub pkt_len: u32,
    pub cap_len: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub matched_rule: u8,
    pub action_taken: u8,
    pub _pad: u8,
    pub data: [u8; SAMPLE_DATA_SIZE],
}

// =============================================================================
// Constants
// =============================================================================

const ETH_HDR_LEN: usize = 14;
const IP_HDR_MIN_LEN: usize = 20;
const ETH_P_IP: u16 = 0x0800;

// =============================================================================
// XDP Program
// =============================================================================

#[xdp]
pub fn veth_filter(ctx: XdpContext) -> u32 {
    match try_veth_filter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_veth_filter(ctx: XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = (data_end - data) as u32;

    // Increment total counter
    if let Some(total) = STATS.get_ptr_mut(0) {
        unsafe { *total += 1; }
    }

    // Bounds check for Ethernet header
    if data + ETH_HDR_LEN > data_end {
        return pass_packet();
    }

    // Check EtherType
    let ethertype = unsafe { u16::from_be(*((data + 12) as *const u16)) };
    if ethertype != ETH_P_IP {
        return pass_packet();
    }

    // Bounds check for IP header
    if data + ETH_HDR_LEN + IP_HDR_MIN_LEN > data_end {
        return pass_packet();
    }

    // Parse IP header
    let ip_hdr = data + ETH_HDR_LEN;
    let version_ihl = unsafe { *(ip_hdr as *const u8) };
    let ihl = ((version_ihl & 0x0F) as usize) * 4;
    
    if ihl < IP_HDR_MIN_LEN {
        return pass_packet();
    }

    // Verify we can read the full IP header
    if data + ETH_HDR_LEN + ihl > data_end {
        return pass_packet();
    }

    let protocol = unsafe { *((ip_hdr + 9) as *const u8) };
    let src_ip = unsafe { *((ip_hdr + 12) as *const u32) };
    let dst_ip = unsafe { *((ip_hdr + 16) as *const u32) };

    // Parse transport layer for ports
    let (src_port, dst_port) = parse_ports(data_end, ip_hdr, ihl, protocol);

    // Check rules and decide action
    let (matched, action) = check_rules(src_ip, dst_ip, src_port, dst_port, protocol);

    // Update matched counter
    if matched {
        if let Some(matched_cnt) = STATS.get_ptr_mut(3) {
            unsafe { *matched_cnt += 1; }
        }
    }

    // Sample the packet (at configured rate regardless of match status)
    // Matched packets are still sampled so we can track ongoing attacks
    let sample_rate = CONFIG.get(0).copied().unwrap_or(0);
    let total_count = STATS.get(0).copied().unwrap_or(0);
    
    let should_sample = sample_rate > 0 && (total_count % sample_rate as u64 == 0);
    
    if should_sample {
        sample_packet(&ctx, pkt_len, src_ip, dst_ip, src_port, dst_port, 
                      protocol, matched, action, data, data_end);
    }

    // Apply action
    let enforce = CONFIG.get(1).copied().unwrap_or(0) == 1;
    
    if matched && action == RuleAction::Drop as u8 && enforce {
        if let Some(dropped) = STATS.get_ptr_mut(2) {
            unsafe { *dropped += 1; }
        }
        return Ok(xdp_action::XDP_DROP);
    }

    pass_packet()
}

#[inline(always)]
fn pass_packet() -> Result<u32, ()> {
    if let Some(passed) = STATS.get_ptr_mut(1) {
        unsafe { *passed += 1; }
    }
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn parse_ports(
    data_end: usize,
    ip_hdr: usize,
    ihl: usize,
    protocol: u8,
) -> (u16, u16) {
    let transport = ip_hdr + ihl;
    
    // TCP (6) and UDP (17) have ports at same offsets
    if (protocol == 6 || protocol == 17) && transport + 4 <= data_end {
        let src_port = unsafe { u16::from_be(*((transport) as *const u16)) };
        let dst_port = unsafe { u16::from_be(*((transport + 2) as *const u16)) };
        (src_port, dst_port)
    } else {
        (0, 0)
    }
}

#[inline(always)]
fn check_rules(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
) -> (bool, u8) {
    // Check source IP rule
    let key = RuleKey {
        rule_type: RuleType::SrcIp as u8,
        _pad: [0; 3],
        value: src_ip,
    };
    if let Some(rule) = unsafe { RULES.get(&key) } {
        return (true, rule.action);
    }

    // Check destination IP rule
    let key = RuleKey {
        rule_type: RuleType::DstIp as u8,
        _pad: [0; 3],
        value: dst_ip,
    };
    if let Some(rule) = unsafe { RULES.get(&key) } {
        return (true, rule.action);
    }

    // Check source port rule
    if src_port != 0 {
        let key = RuleKey {
            rule_type: RuleType::SrcPort as u8,
            _pad: [0; 3],
            value: src_port as u32,
        };
        if let Some(rule) = unsafe { RULES.get(&key) } {
            return (true, rule.action);
        }
    }

    // Check destination port rule
    if dst_port != 0 {
        let key = RuleKey {
            rule_type: RuleType::DstPort as u8,
            _pad: [0; 3],
            value: dst_port as u32,
        };
        if let Some(rule) = unsafe { RULES.get(&key) } {
            return (true, rule.action);
        }
    }

    // Check protocol rule
    let key = RuleKey {
        rule_type: RuleType::Protocol as u8,
        _pad: [0; 3],
        value: protocol as u32,
    };
    if let Some(rule) = unsafe { RULES.get(&key) } {
        return (true, rule.action);
    }

    (false, RuleAction::Pass as u8)
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn sample_packet(
    ctx: &XdpContext,
    pkt_len: u32,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    matched: bool,
    action: u8,
    data: usize,
    data_end: usize,
) {
    let cap_len = if pkt_len as usize > SAMPLE_DATA_SIZE { 
        SAMPLE_DATA_SIZE 
    } else { 
        pkt_len as usize 
    };

    let mut sample = PacketSample {
        pkt_len,
        cap_len: cap_len as u32,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        matched_rule: if matched { 1 } else { 0 },
        action_taken: action,
        _pad: 0,
        data: [0u8; SAMPLE_DATA_SIZE],
    };

    // Copy packet data byte-by-byte (BPF verifier requires bounded loop)
    let src = data as *const u8;
    for i in 0..SAMPLE_DATA_SIZE {
        if data + i < data_end {
            sample.data[i] = unsafe { *src.add(i) };
        } else {
            break;
        }
    }

    // Send to userspace via perf buffer
    let _ = SAMPLES.output(ctx, &sample, 0);

    // Track sampled count
    if let Some(sampled) = STATS.get_ptr_mut(4) {
        unsafe { *sampled += 1; }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
