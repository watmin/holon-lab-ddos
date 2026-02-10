//! XDP Filter Loader CLI
//!
//! Loads the XDP program and provides interactive rule management

use anyhow::Result;
use aya::programs::XdpFlags;
use clap::{Parser, Subcommand};
use std::time::Duration;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use veth_filter::{Rule, RuleAction, RuleType, VethFilter, PacketSample};

#[derive(Parser, Debug)]
#[command(name = "veth-loader")]
#[command(about = "Load XDP filter and manage rules")]
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
    /// Add a drop rule
    Drop {
        /// Rule type: src-ip, dst-ip, src-port, dst-port, protocol
        #[arg(short = 't', long)]
        rule_type: String,
        /// Value (IP address or port number)
        #[arg(short, long)]
        value: String,
    },
    /// Remove a rule
    Remove {
        #[arg(short = 't', long)]
        rule_type: String,
        #[arg(short, long)]
        value: String,
    },
    /// List all rules
    List,
    /// Clear all rules
    Clear,
    /// Watch packet samples
    Watch {
        /// Maximum samples to show (0 = unlimited)
        #[arg(short, long, default_value = "100")]
        max: usize,
    },
    /// Demo: add some test rules and watch
    Demo,
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
        Some(Command::Drop { rule_type, value }) => {
            let rule = parse_rule(&rule_type, &value, RuleAction::Drop)?;
            filter.add_rule(&rule).await?;
            println!("Added drop rule: {:?} = {}", rule.rule_type, rule.value);
        }
        Some(Command::Remove { rule_type, value }) => {
            let rule = parse_rule(&rule_type, &value, RuleAction::Pass)?;
            filter.remove_rule(&rule).await?;
            println!("Removed rule: {:?} = {}", rule.rule_type, rule.value);
        }
        Some(Command::List) => {
            let rules = filter.list_rules().await?;
            if rules.is_empty() {
                println!("No rules configured");
            } else {
                println!("{:<12} {:<20} {:<10} {:<10}", "TYPE", "VALUE", "ACTION", "MATCHES");
                for (rule, count) in rules {
                    println!(
                        "{:<12} {:<20} {:<10} {:<10}",
                        format!("{:?}", rule.rule_type),
                        rule.value,
                        format!("{:?}", rule.action),
                        count
                    );
                }
            }
        }
        Some(Command::Clear) => {
            filter.clear_rules().await?;
            println!("All rules cleared");
        }
        Some(Command::Watch { max }) => {
            run_watch_loop(&filter, max).await?;
        }
        Some(Command::Demo) => {
            run_demo(&filter).await?;
        }
        None => {
            // Default: show stats
            run_stats_loop(&filter, 1).await?;
        }
    }

    Ok(())
}

fn parse_rule(rule_type: &str, value: &str, action: RuleAction) -> Result<Rule> {
    let rt = match rule_type.to_lowercase().as_str() {
        "src-ip" | "srcip" | "src_ip" => RuleType::SrcIp,
        "dst-ip" | "dstip" | "dst_ip" => RuleType::DstIp,
        "src-port" | "srcport" | "src_port" => RuleType::SrcPort,
        "dst-port" | "dstport" | "dst_port" => RuleType::DstPort,
        "protocol" | "proto" => RuleType::Protocol,
        _ => anyhow::bail!("Unknown rule type: {}. Use: src-ip, dst-ip, src-port, dst-port, protocol", rule_type),
    };

    Ok(Rule {
        rule_type: rt,
        value: value.to_string(),
        action,
        rate_pps: None,
    })
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
        let drops_ps = stats.dropped_packets.saturating_sub(last_stats.dropped_packets) / interval;

        if iteration % 10 == 0 {
            println!("{:<12} {:<12} {:<12} {:<12} {:<12} {:<12}",
                "TOTAL", "PASSED", "DROPPED", "SAMPLED", "PPS", "DROPS/S");
        }
        
        println!("{:<12} {:<12} {:<12} {:<12} {:<12} {:<12}",
            stats.total_packets,
            stats.passed_packets,
            stats.dropped_packets,
            stats.sampled_packets,
            pps,
            drops_ps,
        );

        last_stats = stats;
        iteration += 1;
    }
}

async fn run_watch_loop(filter: &VethFilter, max: usize) -> Result<()> {
    use aya::util::online_cpus;
    use bytes::BytesMut;
    use tokio::sync::mpsc;

    println!("Watching packet samples (Ctrl+C to stop)...");
    println!();
    
    let mut perf_array = filter.take_perf_array().await?;
    
    // Channel to receive samples from all CPUs
    let (tx, mut rx) = mpsc::channel::<PacketSample>(1000);

    // Spawn a task for each CPU
    let cpus = online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))?;
    
    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;
        let tx = tx.clone();

        tokio::spawn(async move {
            let mut buffers = (0..16)
                .map(|_| BytesMut::with_capacity(4096))
                .collect::<Vec<_>>();

            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(_) => continue,
                };

                for i in 0..events.read {
                    let event_buf = &buffers[i];
                    if event_buf.len() >= std::mem::size_of::<PacketSample>() {
                        let sample = unsafe {
                            std::ptr::read_unaligned(event_buf.as_ptr() as *const PacketSample)
                        };
                        if tx.send(sample).await.is_err() {
                            return;
                        }
                    }
                }
            }
        });
    }

    drop(tx);  // Drop sender so rx knows when all tasks are done

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

async fn run_demo(filter: &VethFilter) -> Result<()> {
    println!("Running demo...");
    println!();

    // Enable enforcement
    filter.set_enforce_mode(true).await?;
    filter.set_sample_rate(1).await?;  // Sample all packets

    // Add some demo rules
    println!("Adding demo rules:");
    
    // Drop traffic from 10.0.0.0/8 (simulated attack range)
    // We'll add a few specific IPs as examples
    let rules = vec![
        Rule::drop_src_ip("10.0.0.1".parse()?),
        Rule::drop_src_ip("10.0.0.2".parse()?),
        Rule::drop_dst_port(9999),  // Block port 9999
    ];

    for rule in &rules {
        filter.add_rule(rule).await?;
        println!("  + {:?} = {} -> {:?}", rule.rule_type, rule.value, rule.action);
    }

    println!();
    println!("Demo rules active. Send traffic to test:");
    println!("  - From 10.0.0.1 or 10.0.0.2 -> DROPPED");
    println!("  - To port 9999 -> DROPPED");
    println!("  - Other traffic -> PASSED");
    println!();
    
    // Show stats until interrupted
    run_stats_loop(filter, 1).await?;

    Ok(())
}
