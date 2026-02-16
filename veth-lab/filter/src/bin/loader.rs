//! XDP Filter Loader CLI
//!
//! Loads the XDP program and provides monitoring.
//! Rule management is handled by the sidecar via the tree Rete engine.

use anyhow::Result;
use aya::programs::XdpFlags;
use clap::{Parser, Subcommand};
use std::time::Duration;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use veth_filter::{VethFilter, PacketSample};

#[derive(Parser, Debug)]
#[command(name = "veth-loader")]
#[command(about = "Load XDP filter and monitor traffic")]
struct Args {
    /// Interface to attach XDP filter to
    #[arg(short, long, default_value = "veth-filter")]
    interface: String,

    /// Try native XDP mode first (faster, but may not be supported)
    #[arg(long)]
    native: bool,

    /// Sample rate (1 = all packets, 0 = disabled)
    #[arg(short, long, default_value = "100")]
    sample_rate: u32,

    /// Enable enforce mode (actually drop packets)
    #[arg(short, long)]
    enforce: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run in interactive stats mode
    Stats {
        /// Update interval in seconds
        #[arg(short, long, default_value = "1")]
        interval: u64,
    },
    /// Watch packet samples
    Watch {
        /// Maximum samples to show (0 = unlimited)
        #[arg(short, long, default_value = "100")]
        max: usize,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();

    // Determine XDP flags
    let flags = if args.native {
        XdpFlags::DRV_MODE
    } else {
        XdpFlags::default()
    };

    info!("Loading XDP filter on {}", args.interface);
    let filter = VethFilter::with_flags(&args.interface, flags)?;

    // Configure filter
    filter.set_sample_rate(args.sample_rate).await?;
    filter.set_enforce_mode(args.enforce).await?;

    // Handle commands
    match args.command {
        Some(Command::Stats { interval }) => {
            run_stats_loop(&filter, interval).await?;
        }
        Some(Command::Watch { max }) => {
            run_watch_loop(&filter, max).await?;
        }
        None => {
            // Default: show stats
            run_stats_loop(&filter, 1).await?;
        }
    }

    Ok(())
}

async fn run_stats_loop(filter: &VethFilter, interval: u64) -> Result<()> {
    println!("Monitoring {} (Ctrl+C to stop)...", filter.interface());
    println!();

    let mut last_stats = filter.stats().await?;
    let mut iteration = 0;

    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        
        let stats = filter.stats().await?;
        
        // Calculate rates
        let pps = stats.total_packets.saturating_sub(last_stats.total_packets) / interval;
        let drops_ps = (stats.dropped_packets + stats.rate_limited_packets)
            .saturating_sub(last_stats.dropped_packets + last_stats.rate_limited_packets) / interval;

        if iteration % 10 == 0 {
            println!("{:<12} {:<12} {:<12} {:<12} {:<12} {:<12} {:<12}",
                "TOTAL", "PASSED", "DROPPED", "RATE_LIM", "SAMPLED", "PPS", "DROPS/S");
        }
        
        println!("{:<12} {:<12} {:<12} {:<12} {:<12} {:<12} {:<12}",
            stats.total_packets,
            stats.passed_packets,
            stats.dropped_packets,
            stats.rate_limited_packets,
            stats.sampled_packets,
            pps,
            drops_ps,
        );

        last_stats = stats;
        iteration += 1;
    }
}

async fn run_watch_loop(filter: &VethFilter, max: usize) -> Result<()> {
    use tokio::io::unix::AsyncFd;
    use tokio::sync::mpsc;

    println!("Watching packet samples (Ctrl+C to stop)...");
    println!();
    
    let ring_buf = filter.take_ring_buf().await?;
    
    // Channel to receive samples
    let (tx, mut rx) = mpsc::channel::<PacketSample>(1000);

    // Single task to drain the ring buffer using AsyncFd polling
    {
        let tx = tx.clone();
        tokio::spawn(async move {
            // AsyncFd owns the RingBuf; we access it via the guard
            let mut async_fd = match AsyncFd::new(ring_buf) {
                Ok(fd) => fd,
                Err(e) => {
                    eprintln!("Failed to create AsyncFd for ring buffer: {}", e);
                    return;
                }
            };

            loop {
                let mut guard = match async_fd.readable_mut().await {
                    Ok(g) => g,
                    Err(_) => {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        continue;
                    }
                };

                let ring_buf = guard.get_inner_mut();
                while let Some(item) = ring_buf.next() {
                    if item.len() >= std::mem::size_of::<PacketSample>() {
                        let sample = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const PacketSample)
                        };
                        if tx.send(sample).await.is_err() {
                            return;
                        }
                    }
                }

                guard.clear_ready();
            }
        });
    }

    drop(tx);

    let mut count = 0;
    println!("{:<16} {:<16} {:<8} {:<8} {:<8} {:<8}",
        "SRC_IP", "DST_IP", "SPORT", "DPORT", "PROTO", "MATCHED");

    while let Some(sample) = rx.recv().await {
        println!("{:<16} {:<16} {:<8} {:<8} {:<8} {:<8}",
            sample.src_ip_addr(),
            sample.dst_ip_addr(),
            sample.src_port,
            sample.dst_port,
            sample.protocol_name(),
            if sample.matched_rule == 1 { "YES" } else { "no" },
        );

        count += 1;
        if max > 0 && count >= max {
            println!("\nReached {} samples, stopping.", max);
            return Ok(());
        }
    }

    Ok(())
}
