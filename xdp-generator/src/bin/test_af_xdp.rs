//! Test binary for AF_XDP packet generation

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use xdp_generator::af_xdp::{AfXdpConfig, AfXdpGenerator};

fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let interface = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "macv1".to_string());
    
    let target_ip: Ipv4Addr = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "192.168.1.200".to_string())
        .parse()?;

    println!("=== AF_XDP Packet Generator Test ===");
    println!("Interface: {}", interface);
    println!("Target: {}:443", target_ip);
    println!();

    // Get destination MAC from ARP cache
    let dst_mac = get_gateway_mac(target_ip)?;
    println!("Destination MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
             dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);

    // Configure AF_XDP
    let config = AfXdpConfig {
        interface: interface.clone(),
        queue_id: 0,
        num_frames: 4096,
        frame_size: 2048,
        tx_ring_size: 2048,
        comp_ring_size: 2048,
        zero_copy: false,  // Use copy mode for macvlan compatibility
        need_wakeup: true,
    };

    println!("\nCreating AF_XDP socket...");
    let mut generator = match AfXdpGenerator::new(&config, dst_mac) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Failed to create AF_XDP generator: {}", e);
            eprintln!("\nThis might be because:");
            eprintln!("  1. No XDP program is attached to the interface");
            eprintln!("  2. The interface doesn't support AF_XDP");
            eprintln!("  3. Running without root/CAP_NET_RAW");
            eprintln!("\nTrying to attach a dummy XDP program first might help.");
            return Err(e);
        }
    };

    println!("AF_XDP socket created successfully!");
    println!("Free frames: {}", generator.free_frames());
    println!();

    // Test sending packets
    let test_duration = Duration::from_secs(10);
    let batch_size = 64;
    let target_pps = 100_000;  // 100k pps target
    
    println!("Starting packet generation test...");
    println!("Duration: {:?}", test_duration);
    println!("Batch size: {}", batch_size);
    println!("Target PPS: {}", target_pps);
    println!();

    let start = Instant::now();
    let mut last_stats = Instant::now();
    let mut last_packets = 0u64;
    let mut total_kicks = 0u64;

    while start.elapsed() < test_duration {
        // Send a batch
        let sent = generator.send_syn_batch(
            target_ip,
            443,
            10,  // Source network: 10.x.x.x
            batch_size,
        );

        if sent > 0 {
            // Kick kernel to process TX ring
            if let Err(e) = generator.kick() {
                eprintln!("Kick failed: {}", e);
            }
            total_kicks += 1;
        }

        // Print stats every second
        if last_stats.elapsed() >= Duration::from_secs(1) {
            let (packets, bytes, kicks) = generator.stats();
            let elapsed = start.elapsed().as_secs_f64();
            let interval_packets = packets - last_packets;
            let pps = interval_packets as f64 / last_stats.elapsed().as_secs_f64();
            
            println!(
                "[{:5.1}s] {} pkts | {:.0} pps | {:.2} MB | {} kicks | {} free frames",
                elapsed,
                packets,
                pps,
                bytes as f64 / 1_000_000.0,
                kicks,
                generator.free_frames(),
            );
            
            last_stats = Instant::now();
            last_packets = packets;
        }

        // Small yield to prevent busy loop from starving other tasks
        std::thread::sleep(Duration::from_micros(10));
    }

    // Final stats
    let (packets, bytes, kicks) = generator.stats();
    let elapsed = start.elapsed().as_secs_f64();
    
    println!();
    println!("=== Final Results ===");
    println!("Total packets: {}", packets);
    println!("Total bytes: {:.2} MB", bytes as f64 / 1_000_000.0);
    println!("Total kicks: {}", kicks);
    println!("Duration: {:.2}s", elapsed);
    println!("Average PPS: {:.0}", packets as f64 / elapsed);
    println!("Packets per kick: {:.1}", packets as f64 / kicks.max(1) as f64);

    Ok(())
}

/// Get gateway MAC from ARP cache
fn get_gateway_mac(target_ip: Ipv4Addr) -> anyhow::Result<[u8; 6]> {
    let arp = std::fs::read_to_string("/proc/net/arp")?;
    let target_str = target_ip.to_string();
    
    for line in arp.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[0] == target_str {
            if parts[3] == "00:00:00:00:00:00" {
                continue;
            }
            let mac_parts: Vec<u8> = parts[3]
                .split(':')
                .filter_map(|s| u8::from_str_radix(s, 16).ok())
                .collect();
            if mac_parts.len() == 6 {
                return Ok([mac_parts[0], mac_parts[1], mac_parts[2],
                          mac_parts[3], mac_parts[4], mac_parts[5]]);
            }
        }
    }
    
    // Try pinging to populate ARP cache
    println!("MAC not in ARP cache, pinging {} to populate...", target_ip);
    std::process::Command::new("ping")
        .args(["-c", "1", "-W", "1", &target_ip.to_string()])
        .output()?;
    std::thread::sleep(Duration::from_millis(500));
    
    // Retry
    let arp = std::fs::read_to_string("/proc/net/arp")?;
    for line in arp.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[0] == target_str && parts[3] != "00:00:00:00:00:00" {
            let mac_parts: Vec<u8> = parts[3]
                .split(':')
                .filter_map(|s| u8::from_str_radix(s, 16).ok())
                .collect();
            if mac_parts.len() == 6 {
                return Ok([mac_parts[0], mac_parts[1], mac_parts[2],
                          mac_parts[3], mac_parts[4], mac_parts[5]]);
            }
        }
    }
    
    anyhow::bail!("Could not find MAC for {}", target_ip)
}
