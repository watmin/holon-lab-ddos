//! Veth Lab XDP Filter
//!
//! XDP program with dynamic rules loaded from BPF maps.
//! Rules are managed by the userspace sidecar based on Holon detection.
//!
//! Features:
//! - DROP rules for binary blocking
//! - RATE_LIMIT rules with token bucket algorithm
//! - Packet sampling to userspace for Holon analysis

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
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
#[derive(Clone, Copy, PartialEq)]
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

/// Rule value - what to do (with token bucket state for rate limiting)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleValue {
    pub action: u8,
    pub _pad: [u8; 3],
    /// Packets per second limit (for RateLimit action)
    pub rate_pps: u32,
    /// Current token count (for rate limiting)
    pub tokens: u32,
    /// Last update timestamp in nanoseconds (for token refill)
    pub last_update_ns: u64,
    /// Match count for statistics
    pub match_count: u64,
}

// =============================================================================
// BPF Maps
// =============================================================================

/// Dynamic rules map
#[map]
static RULES: HashMap<RuleKey, RuleValue> = HashMap::with_max_entries(1024, 0);

/// Stats counters (per-CPU)
/// 0: total, 1: passed, 2: dropped, 3: matched, 4: sampled, 5: rate_limited
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(8, 0);

/// Configuration
/// 0: sample_rate, 1: enforce_mode
#[map]
static CONFIG: PerCpuArray<u32> = PerCpuArray::with_max_entries(4, 0);

/// Perf event array for packet samples
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

/// Milliseconds per second (for token bucket math without 128-bit ops)
const MS_PER_SEC: u64 = 1000;
/// Nanoseconds per millisecond
const NS_PER_MS: u64 = 1_000_000;

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

    // Check rules and decide action (with rate limiting)
    let (matched, action, should_drop) = check_rules_with_rate_limit(
        src_ip, dst_ip, src_port, dst_port, protocol
    );

    // Update matched counter
    if matched {
        if let Some(matched_cnt) = STATS.get_ptr_mut(3) {
            unsafe { *matched_cnt += 1; }
        }
    }

    // Sample the packet
    let sample_rate = CONFIG.get(0).copied().unwrap_or(0);
    let total_count = STATS.get(0).copied().unwrap_or(0);

    let should_sample = sample_rate > 0 && (total_count % sample_rate as u64 == 0);

    if should_sample {
        sample_packet(
            &ctx, pkt_len, src_ip, dst_ip, src_port, dst_port,
            protocol, matched, action, data, data_end
        );
    }

    // Apply action
    let enforce = CONFIG.get(1).copied().unwrap_or(0) == 1;

    if matched && should_drop && enforce {
        if action == RuleAction::Drop as u8 {
            if let Some(dropped) = STATS.get_ptr_mut(2) {
                unsafe { *dropped += 1; }
            }
        } else if action == RuleAction::RateLimit as u8 {
            // Track rate-limited drops separately
            if let Some(rate_limited) = STATS.get_ptr_mut(5) {
                unsafe { *rate_limited += 1; }
            }
            // Also count in total drops
            if let Some(dropped) = STATS.get_ptr_mut(2) {
                unsafe { *dropped += 1; }
            }
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

/// Check rules with token bucket rate limiting support.
/// Returns (matched, action, should_drop).
#[inline(always)]
fn check_rules_with_rate_limit(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
) -> (bool, u8, bool) {
    // Check source IP rule
    let key = RuleKey {
        rule_type: RuleType::SrcIp as u8,
        _pad: [0; 3],
        value: src_ip,
    };
    if let Some(should_drop) = check_single_rule(&key) {
        let action = unsafe { RULES.get(&key).map(|r| r.action).unwrap_or(0) };
        return (true, action, should_drop);
    }

    // Check destination IP rule
    let key = RuleKey {
        rule_type: RuleType::DstIp as u8,
        _pad: [0; 3],
        value: dst_ip,
    };
    if let Some(should_drop) = check_single_rule(&key) {
        let action = unsafe { RULES.get(&key).map(|r| r.action).unwrap_or(0) };
        return (true, action, should_drop);
    }

    // Check source port rule
    if src_port != 0 {
        let key = RuleKey {
            rule_type: RuleType::SrcPort as u8,
            _pad: [0; 3],
            value: src_port as u32,
        };
        if let Some(should_drop) = check_single_rule(&key) {
            let action = unsafe { RULES.get(&key).map(|r| r.action).unwrap_or(0) };
            return (true, action, should_drop);
        }
    }

    // Check destination port rule
    if dst_port != 0 {
        let key = RuleKey {
            rule_type: RuleType::DstPort as u8,
            _pad: [0; 3],
            value: dst_port as u32,
        };
        if let Some(should_drop) = check_single_rule(&key) {
            let action = unsafe { RULES.get(&key).map(|r| r.action).unwrap_or(0) };
            return (true, action, should_drop);
        }
    }

    // Check protocol rule
    let key = RuleKey {
        rule_type: RuleType::Protocol as u8,
        _pad: [0; 3],
        value: protocol as u32,
    };
    if let Some(should_drop) = check_single_rule(&key) {
        let action = unsafe { RULES.get(&key).map(|r| r.action).unwrap_or(0) };
        return (true, action, should_drop);
    }

    (false, RuleAction::Pass as u8, false)
}

/// Check a single rule and apply rate limiting if needed.
/// Returns Some(should_drop) if rule matched, None if not matched.
#[inline(always)]
fn check_single_rule(key: &RuleKey) -> Option<bool> {
    // Try to get mutable pointer to the rule
    let rule_ptr = RULES.get_ptr_mut(key);

    match rule_ptr {
        Some(ptr) => {
            let rule = unsafe { &mut *ptr };

            // Increment match count
            rule.match_count = rule.match_count.wrapping_add(1);

            match rule.action {
                a if a == RuleAction::Pass as u8 => Some(false),
                a if a == RuleAction::Drop as u8 => Some(true),
                a if a == RuleAction::RateLimit as u8 => {
                    // Token bucket rate limiting
                    Some(apply_token_bucket(rule))
                }
                _ => Some(false),
            }
        }
        None => None,
    }
}

/// Apply token bucket algorithm for rate limiting.
/// Returns true if packet should be dropped (no tokens available).
/// 
/// Uses only 32/64-bit math to be BPF-compatible (no __multi3/__udivti3).
#[inline(always)]
fn apply_token_bucket(rule: &mut RuleValue) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    let rate_pps = rule.rate_pps;

    // Handle uninitialized rule (first packet)
    if rule.last_update_ns == 0 {
        rule.last_update_ns = now;
        rule.tokens = rate_pps; // Start with full bucket
    }

    // Calculate elapsed time since last update (in milliseconds to avoid overflow)
    let elapsed_ns = now.saturating_sub(rule.last_update_ns);
    let elapsed_ms = elapsed_ns / NS_PER_MS;

    // Refill tokens based on elapsed time
    // tokens_to_add = elapsed_seconds * rate_pps
    //               = (elapsed_ms / 1000) * rate_pps
    //               = (elapsed_ms * rate_pps) / 1000
    // 
    // Max values: elapsed_ms ~= 1000 (1 sec), rate_pps ~= 100000
    // Product: 100_000_000 - fits in u64 easily
    if elapsed_ms > 0 && rate_pps > 0 {
        let tokens_to_add = ((elapsed_ms * rate_pps as u64) / MS_PER_SEC) as u32;

        if tokens_to_add > 0 {
            // Add tokens, capped at bucket size (rate_pps)
            let new_tokens = rule.tokens.saturating_add(tokens_to_add);
            rule.tokens = if new_tokens > rate_pps { rate_pps } else { new_tokens };
            rule.last_update_ns = now;
        }
    }

    // Try to consume a token
    if rule.tokens > 0 {
        rule.tokens -= 1;
        false // Packet allowed
    } else {
        true // Packet dropped (rate limited)
    }
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
