#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, PerCpuArray},
    programs::XdpContext,
};
use aya_log_ebpf::info;

/// Stats counters (per-CPU for lock-free updates)
/// Index 0: total packets
/// Index 1: passed packets  
/// Index 2: dropped packets
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(8, 0);

/// Per-source-IP packet counts (for rate limiting / analysis)
#[map]
static IP_COUNTS: HashMap<u32, u64> = HashMap::with_max_entries(65536, 0);

/// Configuration map
/// Index 0: mode (0 = detect only, 1 = enforce/drop)
#[map]
static CONFIG: PerCpuArray<u32> = PerCpuArray::with_max_entries(4, 0);

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

    // Extract source IP (offset 12 in IP header, after 14-byte Ethernet header)
    let src_ip = unsafe {
        u32::from_be(*((data + ETH_HDR_LEN + 12) as *const u32))
    };

    // Increment total packet counter
    if let Some(total) = STATS.get_ptr_mut(0) {
        unsafe { *total += 1; }
    }

    // Track per-IP counts
    if let Some(count) = IP_COUNTS.get_ptr_mut(&src_ip) {
        unsafe { *count += 1; }
    } else {
        let _ = IP_COUNTS.insert(&src_ip, &1, 0);
    }

    // Check if source IP is in 10.0.0.0/8 (DDoS simulation range)
    // 10.x.x.x = 0x0A000000 to 0x0AFFFFFF
    let is_attack = (src_ip & 0xFF000000) == 0x0A000000;

    if is_attack {
        // Get mode: 0 = detect only (pass), 1 = enforce (drop)
        let mode = CONFIG.get(0).copied().unwrap_or(0);
        
        if mode == 1 {
            // Enforce mode: drop the packet
            if let Some(dropped) = STATS.get_ptr_mut(2) {
                unsafe { *dropped += 1; }
            }
            return Ok(xdp_action::XDP_DROP);
        } else {
            // Detect mode: log but pass
            // (stats still tracked, but packet not dropped)
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
