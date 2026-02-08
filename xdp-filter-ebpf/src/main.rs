#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::XdpContext,
};

/// Stats counters (per-CPU for lock-free updates)
/// Index 0: total packets
/// Index 1: passed packets  
/// Index 2: dropped packets
/// Index 3: detected attacks
/// Index 4: sampled packets
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(8, 0);

/// Per-source-IP packet counts (for rate limiting / analysis)
#[map]
static IP_COUNTS: HashMap<u32, u64> = HashMap::with_max_entries(65536, 0);

/// Configuration map
/// Index 0: mode (0 = detect only, 1 = enforce/drop)
/// Index 1: sample rate (1 = every packet, 100 = 1 in 100, 0 = disabled)
#[map]
static CONFIG: PerCpuArray<u32> = PerCpuArray::with_max_entries(4, 0);

/// Perf event array for sending packet samples to userspace
/// We capture a fixed-size sample (first 256 bytes) to avoid needing u64 flags
#[map]
static SAMPLES: PerfEventArray<PacketSample> = PerfEventArray::new(0);

/// Maximum bytes to capture from each packet
const SAMPLE_SIZE: usize = 256;

/// Packet sample structure - includes first N bytes of packet data
#[repr(C)]
pub struct PacketSample {
    /// Actual packet length (may be larger than captured)
    pub pkt_len: u32,
    /// How many bytes we actually captured
    pub cap_len: u32,
    /// Is this an attack packet?
    pub is_attack: u32,
    /// Padding for alignment
    pub _pad: u32,
    /// First SAMPLE_SIZE bytes of the packet (Ethernet + IP + TCP/UDP headers + some payload)
    pub data: [u8; SAMPLE_SIZE],
}

const ETH_HDR_LEN: usize = 14;
const IP_HDR_MIN_LEN: usize = 20;

#[xdp]
pub fn xdp_filter(ctx: XdpContext) -> u32 {
    match try_xdp_filter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_xdp_filter(ctx: XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = (data_end - data) as u32;
    
    // Bounds check for Ethernet header
    if data + ETH_HDR_LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // Check EtherType (offset 12-13), expect IPv4 (0x0800)
    let ethertype = unsafe { 
        u16::from_be(*((data + 12) as *const u16))
    };
    
    if ethertype != 0x0800 {
        // Not IPv4, pass through
        return Ok(xdp_action::XDP_PASS);
    }

    // Bounds check for IP header
    if data + ETH_HDR_LEN + IP_HDR_MIN_LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // Extract source IP (offset 12 in IP header)
    let ip_hdr = data + ETH_HDR_LEN;
    let src_ip = unsafe { *((ip_hdr + 12) as *const u32) }; // Network order
    let src_ip_host = u32::from_be(src_ip); // Host order for comparison

    // Increment total packet counter
    if let Some(total) = STATS.get_ptr_mut(0) {
        unsafe { *total += 1; }
    }

    // Track per-IP counts
    if let Some(count) = IP_COUNTS.get_ptr_mut(&src_ip_host) {
        unsafe { *count += 1; }
    } else {
        let _ = IP_COUNTS.insert(&src_ip_host, &1, 0);
    }

    // Check if source IP is in 10.0.0.0/8 (DDoS simulation range)
    let is_attack = (src_ip_host & 0xFF000000) == 0x0A000000;

    // Sampling logic
    let sample_rate = CONFIG.get(1).copied().unwrap_or(0);
    let total_count = STATS.get(0).copied().unwrap_or(0);
    
    // Sample if: sample_rate > 0 AND (attack packet OR total % sample_rate == 0)
    let should_sample = sample_rate > 0 && (is_attack || total_count % sample_rate as u64 == 0);
    
    if should_sample {
        // Calculate how many bytes to capture
        let cap_len = if pkt_len as usize > SAMPLE_SIZE { SAMPLE_SIZE } else { pkt_len as usize };
        
        // Build the sample with packet data
        let mut sample = PacketSample {
            pkt_len,
            cap_len: cap_len as u32,
            is_attack: if is_attack { 1 } else { 0 },
            _pad: 0,
            data: [0u8; SAMPLE_SIZE],
        };
        
        // Copy packet data byte-by-byte (BPF verifier requires bounded loop)
        // We copy up to SAMPLE_SIZE bytes
        let src = data as *const u8;
        for i in 0..SAMPLE_SIZE {
            if data + i < data_end {
                sample.data[i] = unsafe { *src.add(i) };
            } else {
                break;
            }
        }
        
        // Send to userspace via perf buffer (just the struct, no extra data)
        let _ = SAMPLES.output(&ctx, &sample, 0);
        
        // Track sampled count
        if let Some(sampled) = STATS.get_ptr_mut(4) {
            unsafe { *sampled += 1; }
        }
    }

    // Action based on attack status and mode
    if is_attack {
        let mode = CONFIG.get(0).copied().unwrap_or(0);
        
        if mode == 1 {
            // Enforce mode: drop the packet
            if let Some(dropped) = STATS.get_ptr_mut(2) {
                unsafe { *dropped += 1; }
            }
            return Ok(xdp_action::XDP_DROP);
        } else {
            // Detect mode: count but pass
            if let Some(detected) = STATS.get_ptr_mut(3) {
                unsafe { *detected += 1; }
            }
        }
    }

    // Pass the packet
    if let Some(passed) = STATS.get_ptr_mut(1) {
        unsafe { *passed += 1; }
    }
    
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
