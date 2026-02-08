//! Test binary for XDP filter
//!
//! Loads the XDP filter, attaches it to an interface, and monitors stats.

use std::time::Duration;
use xdp_filter::{XdpFilter, FilterMode};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string())
        )
        .init();

    let interface = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "macv1".to_string());
    
    let mode = std::env::args()
        .nth(2)
        .map(|s| {
            if s == "enforce" || s == "1" {
                FilterMode::Enforce
            } else {
                FilterMode::Detect
            }
        })
        .unwrap_or(FilterMode::Detect);

    println!("=== XDP Filter Test ===");
    println!("Interface: {}", interface);
    println!("Mode: {:?}", mode);
    println!();

    // Load and attach XDP filter
    println!("Loading XDP filter...");
    let filter = XdpFilter::new(&interface)?;
    println!("XDP filter attached successfully!");
    println!();

    // Set mode
    if mode == FilterMode::Enforce {
        println!("Setting mode to Enforce (will drop 10.x.x.x packets)");
        filter.set_mode(FilterMode::Enforce).await?;
    } else {
        println!("Mode is Detect (will count but not drop 10.x.x.x packets)");
    }
    println!();

    println!("Monitoring stats (Ctrl+C to stop)...");
    println!("You can run the attack generator in another terminal:");
    println!("  sudo ./target/release/test_sendmmsg {} 192.168.1.200 50000", interface);
    println!();

    // Monitor stats
    let mut last_stats = filter.stats().await?;
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;

        let stats = filter.stats().await?;
        let delta_total = stats.total_packets - last_stats.total_packets;
        let delta_passed = stats.passed_packets - last_stats.passed_packets;
        let delta_dropped = stats.dropped_packets - last_stats.dropped_packets;
        let delta_detected = stats.detected_attacks - last_stats.detected_attacks;

        println!(
            "Total: {} (+{}) | Passed: {} (+{}) | Dropped: {} (+{}) | Detected: {} (+{})",
            stats.total_packets, delta_total,
            stats.passed_packets, delta_passed,
            stats.dropped_packets, delta_dropped,
            stats.detected_attacks, delta_detected,
        );

        // Show top IPs if there's traffic
        if delta_total > 0 {
            let top_ips = filter.top_ips(5).await?;
            if !top_ips.is_empty() {
                println!("  Top source IPs:");
                for (ip, count) in top_ips {
                    println!("    {} - {} packets", ip, count);
                }
            }
        }

        last_stats = stats;
    }
}
