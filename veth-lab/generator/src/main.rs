//! Veth Lab Traffic Generator
//!
//! Generates test traffic for XDP filter development.
//! Runs inside the veth-lab-gen namespace.
//!
//! Usage:
//!   sudo ip netns exec veth-lab-gen ./target/release/veth-generator
//!
//! Supports:
//! - Normal traffic patterns (baseline)
//! - Attack bursts (high rate from specific sources)
//! - Mixed traffic for detection testing

use anyhow::{Context, Result};
use chrono::Local;
use clap::{Parser, ValueEnum};
use rand::{Rng, SeedableRng};
use serde::Deserialize;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(name = "veth-generator")]
#[command(about = "Generate test traffic for XDP filter")]
struct Args {
    /// Interface to send on (inside namespace)
    #[arg(short, long, default_value = "veth-gen")]
    interface: String,

    /// Target IP address
    #[arg(short, long, default_value = "10.100.0.2")]
    target: String,

    /// Traffic pattern to generate
    #[arg(short, long, default_value = "mixed")]
    pattern: TrafficPattern,

    /// Packets per second (0 = max speed)
    #[arg(short = 'r', long, default_value = "1000")]
    pps: u32,

    /// Duration in seconds (0 = run forever)
    #[arg(short, long, default_value = "30")]
    duration: u64,

    /// Source IP for attack traffic (spoofed)
    #[arg(long, default_value = "10.0.0.100")]
    attack_src: String,

    /// Destination port for normal traffic
    #[arg(long, default_value = "8888")]
    normal_port: u16,

    /// Destination port for attack traffic  
    #[arg(long, default_value = "9999")]
    attack_port: u16,

    /// Attack PPS for scenario mode (separate from baseline --pps)
    #[arg(long, default_value = "10000")]
    attack_pps: u32,

    /// Warmup duration in seconds (scenario mode - ignored if --scenario-file used)
    #[arg(long, default_value = "5")]
    warmup_secs: u64,

    /// Attack phase duration in seconds (scenario mode - ignored if --scenario-file used)
    #[arg(long, default_value = "5")]
    attack_secs: u64,

    /// Calm/recovery phase duration in seconds (scenario mode - ignored if --scenario-file used)
    #[arg(long, default_value = "3")]
    calm_secs: u64,

    /// Path to scenario JSON file (overrides pattern and timing args)
    #[arg(long)]
    scenario_file: Option<PathBuf>,

    /// PPS jitter percentage (0-100, default 5 = ±5%)
    /// Adds random variance to packet rate for more realistic traffic
    #[arg(long, default_value = "5")]
    jitter_pct: u8,

    /// Directory for log files (also writes to stdout)
    #[arg(long, default_value = "logs")]
    log_dir: PathBuf,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TrafficPattern {
    /// Normal traffic only (varied sources, normal ports)
    Normal,
    /// Attack traffic only (single source, attack port)
    Attack,
    /// Mixed: normal baseline with periodic attack bursts
    Mixed,
    /// Ramp: gradually increase attack ratio
    Ramp,
    /// Scenario: warmup -> attack -> calm -> attack (like Batch 013)
    Scenario,
}

/// Scenario configuration loaded from JSON
#[derive(Debug, Deserialize)]
struct ScenarioConfig {
    name: String,
    #[serde(default)]
    description: String,
    baseline_pps: u32,
    attack_pps: u32,
    phases: Vec<Phase>,
}

#[derive(Debug, Clone, Deserialize)]
struct Phase {
    name: String,
    duration_secs: u64,
    #[serde(rename = "type")]
    phase_type: PhaseType,
    #[serde(default)]
    description: String,
    /// Optional per-phase PPS override (if not set, uses baseline_pps or attack_pps)
    #[serde(default)]
    pps: Option<u32>,
    /// Custom destination IP (overrides --target for this phase)
    #[serde(default)]
    dst_ip: Option<String>,
    /// Custom destination port (overrides normal/attack port for this phase)
    #[serde(default)]
    dst_port: Option<u16>,
    /// Custom payload as hex string (e.g. "DEADBEEF01020304...")
    /// The decoded bytes become the L4 payload. For deep-offset testing,
    /// zero-pad the hex string up to the desired offset then append match bytes.
    #[serde(default)]
    payload_hex: Option<String>,
    /// TTL override (default: 64 for custom/normal, 255 for attack, 128 for syn_flood)
    #[serde(default)]
    ttl: Option<u8>,
    /// DF flag override (default: true for custom/normal, false for attack)
    #[serde(default)]
    df: Option<bool>,
    /// Protocol: "udp" (default) or "tcp_syn"
    #[serde(default)]
    proto: Option<String>,
    /// OS fingerprint profile: "windows", "linux", "spoofed"
    /// Sets TTL, IP ID, DF, DSCP defaults. Per-field overrides (ttl, df, ip_id, dscp)
    /// take precedence over the profile.
    #[serde(default)]
    os_profile: Option<String>,
    /// IP Identification field override (u16). If not set, uses os_profile or random.
    #[serde(default)]
    ip_id: Option<u16>,
    /// DSCP value override (0-63). Default: 0 (best effort).
    #[serde(default)]
    dscp: Option<u8>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum PhaseType {
    Normal,
    Attack,
    /// TCP SYN flood: TCP SYN packets with distinctive p0f fingerprint
    SynFlood,
    /// Fully configurable: dst_ip, payload_hex, dst_port, ttl, df, proto
    Custom,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Create log directory
    fs::create_dir_all(&args.log_dir)
        .with_context(|| format!("Failed to create log dir: {:?}", args.log_dir))?;

    // Generate timestamped log filename
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let log_filename = format!("generator_{}.log", timestamp);
    let log_path = args.log_dir.join(&log_filename);

    // Set up file appender
    let file_appender = tracing_appender::rolling::never(&args.log_dir, &log_filename);
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Initialize tracing with both stdout and file
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_ansi(true)
                .with_target(false)
        )
        .with(
            fmt::layer()
                .with_ansi(false)
                .with_target(false)
                .with_writer(non_blocking)
        )
        .with(tracing_subscriber::filter::LevelFilter::INFO)
        .init();
    
    // Check if using scenario file
    let scenario_config = if let Some(ref path) = args.scenario_file {
        let json = fs::read_to_string(path)
            .with_context(|| format!("Failed to read scenario file: {:?}", path))?;
        Some(serde_json::from_str::<ScenarioConfig>(&json)
            .with_context(|| format!("Failed to parse scenario file: {:?}", path))?)
    } else {
        None
    };
    
    info!("Veth Lab Traffic Generator");
    info!("  Interface: {}", args.interface);
    info!("  Target: {}", args.target);
    info!("  Log file: {:?}", log_path);
    
    if let Some(ref config) = scenario_config {
        info!("  Mode: Scenario file");
        info!("  Scenario: {}", config.name);
    } else {
        info!("  Pattern: {:?}", args.pattern);
        info!("  PPS: {}", if args.pps == 0 { "max".to_string() } else { args.pps.to_string() });
        info!("  Duration: {}s", if args.duration == 0 { "infinite".to_string() } else { args.duration.to_string() });
    }
    
    let target_ip: Ipv4Addr = args.target.parse()?;
    let attack_src: Ipv4Addr = args.attack_src.parse()?;

    // Stats
    let running = Arc::new(AtomicBool::new(true));
    let packets_sent = Arc::new(AtomicU64::new(0));
    let bytes_sent = Arc::new(AtomicU64::new(0));

    // Handle Ctrl+C
    let running_clone = running.clone();
    ctrlc_handler(running_clone);

    // Create socket
    let socket = create_packet_socket(&args.interface)?;

    // Get MACs
    let src_mac = get_interface_mac(&args.interface)?;
    let dst_mac = get_interface_mac("veth-gen")?;  // Same interface, we're on the gen side

    info!("Socket ready, starting traffic generation...");
    info!("");

    // If scenario file provided, run scenario-file loop
    if let Some(config) = scenario_config {
        run_scenario_file(
            &config,
            &args,
            socket,
            &src_mac,
            &dst_mac,
            target_ip,
            attack_src,
            running.clone(),
            packets_sent.clone(),
            bytes_sent.clone(),
        )?;
    } else {
        run_pattern_mode(
            &args,
            socket,
            &src_mac,
            &dst_mac,
            target_ip,
            attack_src,
            running.clone(),
            packets_sent.clone(),
            bytes_sent.clone(),
        )?;
    }

    // Final stats
    let _start = Instant::now();  // Duration tracked by scenario/pattern loops
    let total = packets_sent.load(Ordering::Relaxed);
    let total_bytes = bytes_sent.load(Ordering::Relaxed);
    
    info!("");
    info!("=== Final Stats ===");
    info!("  Total packets: {}", total);
    info!("  Total bytes: {:.2} MB", total_bytes as f64 / 1024.0 / 1024.0);

    // Close socket
    unsafe { libc::close(socket); }

    Ok(())
}

fn run_scenario_file(
    config: &ScenarioConfig,
    args: &Args,
    socket: i32,
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    target_ip: Ipv4Addr,
    attack_src: Ipv4Addr,
    running: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
) -> Result<()> {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut linux_ip_id_counter: u16 = rng.gen(); // Sequential IP ID counter for "linux" profile
    
    // Log scenario timeline
    info!("=== SCENARIO: {} ===", config.name);
    if !config.description.is_empty() {
        info!("  {}", config.description);
    }
    info!("  Baseline PPS: {}", config.baseline_pps);
    info!("  Attack PPS: {}", config.attack_pps);
    info!("");
    info!("Timeline:");
    let mut total_secs = 0u64;
    for (i, phase) in config.phases.iter().enumerate() {
        // Use per-phase PPS if specified, otherwise use global baseline/attack
        let pps = phase.pps.unwrap_or(match phase.phase_type {
            PhaseType::Normal | PhaseType::Custom => config.baseline_pps,
            PhaseType::Attack | PhaseType::SynFlood => config.attack_pps,
        });
        let end_time = total_secs + phase.duration_secs;
        info!(
            "  {:2}. {:12} {:>4}s @ {:>5} pps ({}:{:02} - {}:{:02}) {}",
            i + 1,
            phase.name,
            phase.duration_secs,
            pps,
            total_secs / 60,
            total_secs % 60,
            end_time / 60,
            end_time % 60,
            if phase.description.is_empty() { "" } else { &phase.description }
        );
        total_secs = end_time;
    }
    info!("");
    info!("Total duration: {}m {:02}s", total_secs / 60, total_secs % 60);
    info!("");
    
    // Run each phase
    let scenario_start = Instant::now();
    let mut last_report = Instant::now();
    let mut last_count = 0u64;
    
    for (phase_idx, phase) in config.phases.iter().enumerate() {
        if !running.load(Ordering::Relaxed) {
            break;
        }
        
        // Use per-phase PPS if specified, otherwise use global baseline/attack
        let pps = phase.pps.unwrap_or(match phase.phase_type {
            PhaseType::Normal | PhaseType::Custom => config.baseline_pps,
            PhaseType::Attack | PhaseType::SynFlood => config.attack_pps,
        });
        
        info!(
            ">>> [{:>3}s] PHASE {}: {} ({:?}, {} pps, {}s)",
            scenario_start.elapsed().as_secs(),
            phase_idx + 1,
            phase.name,
            phase.phase_type,
            pps,
            phase.duration_secs
        );
        
        // Pre-parse custom phase payload (once per phase, not per packet)
        let custom_payload: Option<Vec<u8>> = if let Some(ref hex) = phase.payload_hex {
            Some(hex_decode(hex).with_context(|| format!(
                "Phase '{}': invalid payload_hex", phase.name
            ))?)
        } else {
            None
        };
        
        // Pre-parse custom destination IP
        let custom_dst_ip: Option<Ipv4Addr> = if let Some(ref ip_str) = phase.dst_ip {
            Some(ip_str.parse().with_context(|| format!(
                "Phase '{}': invalid dst_ip '{}'", phase.name, ip_str
            ))?)
        } else {
            None
        };
        
        let phase_start = Instant::now();
        let phase_duration = Duration::from_secs(phase.duration_secs);
        let phase_start_packets = packets_sent.load(Ordering::Relaxed);
        
        while running.load(Ordering::Relaxed) && phase_start.elapsed() < phase_duration {
            let src_port: u16 = rng.gen_range(10000..60000);

            // Build IP fingerprint from os_profile + per-field overrides
            let fp = build_fingerprint(&mut rng, phase, &mut linux_ip_id_counter);

            let packet = match phase.phase_type {
                PhaseType::Normal => {
                    let src_ip = Ipv4Addr::new(192, 168, rng.gen_range(1..255), rng.gen_range(1..255));
                    let dst_port = phase.dst_port.unwrap_or(args.normal_port);
                    let dst = custom_dst_ip.unwrap_or(target_ip);
                    craft_udp_packet(
                        src_mac, dst_mac, src_ip, dst,
                        src_port, dst_port, b"VETH-LAB-TEST", &fp,
                    )
                }
                PhaseType::Attack => {
                    let dst_port = phase.dst_port.unwrap_or(args.attack_port);
                    let dst = custom_dst_ip.unwrap_or(target_ip);
                    craft_udp_packet(
                        src_mac, dst_mac, attack_src, dst,
                        src_port, dst_port, b"VETH-LAB-TEST", &fp,
                    )
                }
                PhaseType::SynFlood => {
                    let dst_port = phase.dst_port.unwrap_or(args.attack_port);
                    let dst = custom_dst_ip.unwrap_or(target_ip);
                    craft_tcp_syn_packet(
                        src_mac, dst_mac, attack_src, dst,
                        src_port, dst_port, &fp, 65535,
                    )
                }
                PhaseType::Custom => {
                    let dst = custom_dst_ip.unwrap_or(target_ip);
                    let dst_port = phase.dst_port.unwrap_or(args.normal_port);
                    let src_ip = Ipv4Addr::new(192, 168, rng.gen_range(1..255), rng.gen_range(1..255));
                    let payload = custom_payload.as_deref().unwrap_or(b"VETH-LAB-TEST");
                    
                    let is_tcp = phase.proto.as_deref() == Some("tcp_syn");
                    if is_tcp {
                        craft_tcp_syn_packet(
                            src_mac, dst_mac, src_ip, dst,
                            src_port, dst_port, &fp, 65535,
                        )
                    } else {
                        craft_udp_packet(
                            src_mac, dst_mac, src_ip, dst,
                            src_port, dst_port, payload, &fp,
                        )
                    }
                }
            };

            match send_packet(socket, &packet) {
                Ok(n) => {
                    packets_sent.fetch_add(1, Ordering::Relaxed);
                    bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    if running.load(Ordering::Relaxed) {
                        tracing::warn!("Send error: {}", e);
                    }
                }
            }

            // Time-based rate limiting: calculate where we SHOULD be vs where we ARE
            // This naturally accounts for send time and other overhead
            if pps > 0 {
                // Apply jitter to target PPS for this second
                let jittered_pps = apply_jitter(&mut rng, pps, args.jitter_pct);
                
                let packets_this_phase = packets_sent.load(Ordering::Relaxed) - phase_start_packets;
                let elapsed_ns = phase_start.elapsed().as_nanos() as u64;
                let target_ns = packets_this_phase * 1_000_000_000 / jittered_pps as u64;
                
                if target_ns > elapsed_ns {
                    let sleep_ns = target_ns - elapsed_ns;
                    // Only sleep if we're ahead of schedule by more than 1μs
                    if sleep_ns > 1000 {
                        std::thread::sleep(Duration::from_nanos(sleep_ns));
                    }
                }
                // If we're behind schedule, just keep sending (no sleep)
            }

            // Periodic stats report
            if last_report.elapsed() >= Duration::from_secs(5) {
                let current = packets_sent.load(Ordering::Relaxed);
                let elapsed_secs = 5u64;
                let pps_actual = (current - last_count) / elapsed_secs;
                let total_bytes_val = bytes_sent.load(Ordering::Relaxed);
                let scenario_elapsed = scenario_start.elapsed().as_secs();
                
                info!(
                    "    [{:>3}s] {} packets ({} pps), {:.2} MB | phase: {}s remaining",
                    scenario_elapsed,
                    current,
                    pps_actual,
                    total_bytes_val as f64 / 1024.0 / 1024.0,
                    phase.duration_secs.saturating_sub(phase_start.elapsed().as_secs())
                );
                
                last_count = current;
                last_report = Instant::now();
            }
        }
    }
    
    info!(">>> Scenario complete");
    Ok(())
}

fn run_pattern_mode(
    args: &Args,
    socket: i32,
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    target_ip: Ipv4Addr,
    attack_src: Ipv4Addr,
    running: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
) -> Result<()> {
    let start = Instant::now();
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut last_report = Instant::now();
    let mut last_count = 0u64;
    
    // For mixed pattern: track phases
    let phase_duration = Duration::from_secs(5);
    let mut phase_start = Instant::now();
    let mut in_attack_phase = false;

    // For scenario pattern: phase state machine
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum ScenarioPhase {
        Warmup,
        Normal1,
        Attack1,
        Calm1,
        Attack2,
        Calm2,
        Attack3,
        Done,
    }
    let mut scenario_phase = ScenarioPhase::Warmup;
    let mut scenario_phase_start = Instant::now();
    
    // Log scenario timeline
    if matches!(args.pattern, TrafficPattern::Scenario) {
        info!("=== SCENARIO MODE ===");
        info!("  Warmup:  {}s @ {} pps (baseline)", args.warmup_secs, args.pps);
        info!("  Normal:  {}s @ {} pps", args.calm_secs, args.pps);
        info!("  Attack:  {}s @ {} pps", args.attack_secs, args.attack_pps);
        info!("  Calm:    {}s @ {} pps", args.calm_secs, args.pps);
        info!("  Attack:  {}s @ {} pps", args.attack_secs, args.attack_pps);
        info!("  Calm:    {}s @ {} pps", args.calm_secs, args.pps);
        info!("  Attack:  {}s @ {} pps", args.attack_secs, args.attack_pps);
        info!("");
    }

    while running.load(Ordering::Relaxed) {
        // Check duration (for non-scenario patterns)
        if args.duration > 0 && !matches!(args.pattern, TrafficPattern::Scenario) 
            && start.elapsed().as_secs() >= args.duration {
            info!("Duration reached, stopping");
            break;
        }

        // Calculate current PPS for rate limiting
        let current_pps = match args.pattern {
            TrafficPattern::Scenario => {
                // Update scenario phase state machine
                let elapsed = scenario_phase_start.elapsed().as_secs();
                let (phase_done, _phase_duration) = match scenario_phase {
                    ScenarioPhase::Warmup => (elapsed >= args.warmup_secs, args.warmup_secs),
                    ScenarioPhase::Normal1 => (elapsed >= args.calm_secs, args.calm_secs),
                    ScenarioPhase::Attack1 => (elapsed >= args.attack_secs, args.attack_secs),
                    ScenarioPhase::Calm1 => (elapsed >= args.calm_secs, args.calm_secs),
                    ScenarioPhase::Attack2 => (elapsed >= args.attack_secs, args.attack_secs),
                    ScenarioPhase::Calm2 => (elapsed >= args.calm_secs, args.calm_secs),
                    ScenarioPhase::Attack3 => (elapsed >= args.attack_secs, args.attack_secs),
                    ScenarioPhase::Done => (false, 0),
                };
                
                if phase_done && scenario_phase != ScenarioPhase::Done {
                    scenario_phase = match scenario_phase {
                        ScenarioPhase::Warmup => {
                            info!(">>> PHASE: Normal (baseline learned)");
                            ScenarioPhase::Normal1
                        }
                        ScenarioPhase::Normal1 => {
                            info!(">>> PHASE: Attack 1 @ {} pps", args.attack_pps);
                            ScenarioPhase::Attack1
                        }
                        ScenarioPhase::Attack1 => {
                            info!(">>> PHASE: Calm 1 (recovery)");
                            ScenarioPhase::Calm1
                        }
                        ScenarioPhase::Calm1 => {
                            info!(">>> PHASE: Attack 2 @ {} pps", args.attack_pps);
                            ScenarioPhase::Attack2
                        }
                        ScenarioPhase::Attack2 => {
                            info!(">>> PHASE: Calm 2 (recovery)");
                            ScenarioPhase::Calm2
                        }
                        ScenarioPhase::Calm2 => {
                            info!(">>> PHASE: Attack 3 @ {} pps", args.attack_pps);
                            ScenarioPhase::Attack3
                        }
                        ScenarioPhase::Attack3 => {
                            info!(">>> PHASE: Done");
                            ScenarioPhase::Done
                        }
                        ScenarioPhase::Done => ScenarioPhase::Done,
                    };
                    scenario_phase_start = Instant::now();
                }
                
                if scenario_phase == ScenarioPhase::Done {
                    break;
                }
                
                // Return appropriate PPS for this phase
                match scenario_phase {
                    ScenarioPhase::Attack1 | ScenarioPhase::Attack2 | ScenarioPhase::Attack3 => {
                        args.attack_pps
                    }
                    _ => args.pps
                }
            }
            _ => args.pps
        };

        // Determine if this packet is attack or normal based on pattern
        let is_attack = match args.pattern {
            TrafficPattern::Normal => false,
            TrafficPattern::Attack => true,
            TrafficPattern::Scenario => {
                matches!(scenario_phase, ScenarioPhase::Attack1 | ScenarioPhase::Attack2 | ScenarioPhase::Attack3)
            }
            TrafficPattern::Mixed => {
                // 5 seconds normal, 5 seconds attack
                if phase_start.elapsed() >= phase_duration {
                    in_attack_phase = !in_attack_phase;
                    phase_start = Instant::now();
                    if in_attack_phase {
                        info!(">>> Attack phase started");
                    } else {
                        info!("<<< Normal phase started");
                    }
                }
                in_attack_phase
            }
            TrafficPattern::Ramp => {
                // Gradually increase attack ratio: 0% -> 100% over duration
                let progress = if args.duration > 0 {
                    start.elapsed().as_secs_f64() / args.duration as f64
                } else {
                    (start.elapsed().as_secs() % 60) as f64 / 60.0
                };
                rng.gen::<f64>() < progress
            }
        };

        // Generate packet
        let (src_ip, dst_port) = if is_attack {
            (attack_src, args.attack_port)
        } else {
            // Normal traffic: random source in 192.168.x.x range
            let src = Ipv4Addr::new(192, 168, rng.gen_range(1..255), rng.gen_range(1..255));
            (src, args.normal_port)
        };

        let src_port: u16 = rng.gen_range(10000..60000);
        
        // Build and send UDP packet (legacy mode: normal fingerprint for all)
        let fp = IpFingerprint::legacy(&mut rng, 64, true);
        let packet = craft_udp_packet(
            src_mac,
            dst_mac,
            src_ip,
            target_ip,
            src_port,
            dst_port,
            b"VETH-LAB-TEST",
            &fp,
        );

        match send_packet(socket, &packet) {
            Ok(n) => {
                packets_sent.fetch_add(1, Ordering::Relaxed);
                bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) => {
                if running.load(Ordering::Relaxed) {
                    tracing::warn!("Send error: {}", e);
                }
            }
        }

        // Time-based rate limiting (simple version for pattern mode)
        // For accurate high-PPS, use scenario files which have per-phase tracking
        if current_pps > 0 {
            // Apply jitter to create realistic variance
            let jittered_pps = apply_jitter(&mut rng, current_pps, args.jitter_pct);
            let target_interval_ns = 1_000_000_000u64 / jittered_pps as u64;
            
            if target_interval_ns >= 50_000 {
                // Low-medium PPS (< 20k): sleep per packet works
                std::thread::sleep(Duration::from_nanos(target_interval_ns));
            } else {
                // High PPS: simple batching - sleep every 5 packets
                if packets_sent.load(Ordering::Relaxed) % 5 == 0 {
                    std::thread::sleep(Duration::from_nanos(target_interval_ns * 5));
                }
            }
        }

        // Periodic stats report
        if last_report.elapsed() >= Duration::from_secs(2) {
            let current = packets_sent.load(Ordering::Relaxed);
            let pps = (current - last_count) / 2;
            let total_bytes = bytes_sent.load(Ordering::Relaxed);
            
            info!(
                "Stats: {} packets sent ({} pps), {:.2} KB",
                current,
                pps,
                total_bytes as f64 / 1024.0
            );
            
            last_count = current;
            last_report = Instant::now();
        }
    }
    
    Ok(())
}

fn ctrlc_handler(running: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let mut signals = signal_hook::iterator::Signals::new(&[signal_hook::consts::SIGINT])
            .expect("Failed to register signal handler");
        for _ in signals.forever() {
            info!("\nReceived Ctrl+C, stopping...");
            running.store(false, Ordering::Relaxed);
            break;
        }
    });
}

fn create_packet_socket(interface: &str) -> Result<i32> {
    // Create AF_PACKET socket
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    
    if fd < 0 {
        return Err(anyhow::anyhow!(
            "Failed to create packet socket: {}. Need CAP_NET_RAW",
            std::io::Error::last_os_error()
        ));
    }

    // Get interface index
    let ifindex = get_ifindex(interface)?;

    // Bind to interface
    let sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    let ret = unsafe {
        libc::bind(
            fd,
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        unsafe { libc::close(fd); }
        return Err(anyhow::anyhow!(
            "Failed to bind to {}: {}",
            interface,
            std::io::Error::last_os_error()
        ));
    }

    Ok(fd)
}

fn get_ifindex(name: &str) -> Result<i32> {
    let name_cstr = std::ffi::CString::new(name)?;
    let idx = unsafe { libc::if_nametoindex(name_cstr.as_ptr()) };
    if idx == 0 {
        return Err(anyhow::anyhow!("Interface {} not found", name));
    }
    Ok(idx as i32)
}

fn get_interface_mac(name: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{}/address", name);
    let mac_str = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("Failed to read MAC from {}: {}", path, e))?;
    
    let parts: Vec<u8> = mac_str
        .trim()
        .split(':')
        .filter_map(|s| u8::from_str_radix(s, 16).ok())
        .collect();
    
    if parts.len() != 6 {
        return Err(anyhow::anyhow!("Invalid MAC format: {}", mac_str));
    }
    
    Ok([parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]])
}

/// Decode a hex string into bytes. Accepts upper/lowercase, must be even length.
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        anyhow::bail!("hex string must have even length, got {}", s.len());
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .with_context(|| format!("invalid hex at position {}: {:?}", i, &s[i..i + 2]))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Build an IpFingerprint from a Phase's os_profile + per-field overrides.
/// Per-field overrides (ttl, df, ip_id, dscp) take precedence over the profile.
fn build_fingerprint<R: Rng>(rng: &mut R, phase: &Phase, linux_counter: &mut u16) -> IpFingerprint {
    let base = match phase.os_profile.as_deref() {
        Some("windows") => IpFingerprint::windows(rng),
        Some("linux") => {
            let fp = IpFingerprint::linux(*linux_counter);
            *linux_counter = linux_counter.wrapping_add(1);
            fp
        }
        Some("spoofed") => IpFingerprint::spoofed(),
        _ => {
            // No profile: use phase type defaults (backward compat)
            let default_ttl = match phase.phase_type {
                PhaseType::Normal | PhaseType::Custom => 64,
                PhaseType::Attack => 255,
                PhaseType::SynFlood => 128,
            };
            let default_df = !matches!(phase.phase_type, PhaseType::Attack);
            IpFingerprint::legacy(rng, default_ttl, default_df)
        }
    };

    // Apply per-field overrides
    IpFingerprint {
        ttl: phase.ttl.unwrap_or(base.ttl),
        df: phase.df.unwrap_or(base.df),
        ip_id: phase.ip_id.unwrap_or(base.ip_id),
        dscp: phase.dscp.unwrap_or(base.dscp),
        ecn: base.ecn,
    }
}

/// IPv4 header fingerprint parameters for packet crafting.
/// Controls the "early bytes" of the IP header that Holon uses for
/// OS fingerprinting and surgical mitigation.
#[derive(Debug, Clone)]
struct IpFingerprint {
    ttl: u8,
    df: bool,
    ip_id: u16,
    dscp: u8,
    ecn: u8,
}

impl IpFingerprint {
    /// Windows client: TTL=128, random IP ID, DF set, DSCP=0
    fn windows<R: Rng>(rng: &mut R) -> Self {
        Self { ttl: 128, df: true, ip_id: rng.gen(), dscp: 0, ecn: 0 }
    }

    /// Linux client: TTL=64, sequential IP ID (caller provides), DF set, DSCP=0
    fn linux(ip_id: u16) -> Self {
        Self { ttl: 64, df: true, ip_id, dscp: 0, ecn: 0 }
    }

    /// Spoofed/botnet: TTL varies, IP ID=0, DF clear, DSCP=0
    fn spoofed() -> Self {
        Self { ttl: 64, df: false, ip_id: 0, dscp: 0, ecn: 0 }
    }

    /// Legacy default (backward compat): TTL and DF from args, random IP ID
    fn legacy<R: Rng>(rng: &mut R, ttl: u8, df: bool) -> Self {
        Self { ttl, df, ip_id: rng.gen(), dscp: 0, ecn: 0 }
    }
}

fn craft_udp_packet(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    fp: &IpFingerprint,
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let ip_len = 20 + udp_len;
    let total_len = 14 + ip_len;
    
    let mut packet = vec![0u8; total_len];
    
    // Ethernet header (14 bytes)
    packet[0..6].copy_from_slice(dst_mac);
    packet[6..12].copy_from_slice(src_mac);
    packet[12..14].copy_from_slice(&(0x0800u16).to_be_bytes());  // IPv4
    
    // IP header (20 bytes)
    let ip_offset = 14;
    packet[ip_offset] = 0x45;  // Version + IHL
    packet[ip_offset + 1] = (fp.dscp << 2) | (fp.ecn & 0x03);  // DSCP + ECN
    packet[ip_offset + 2..ip_offset + 4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    packet[ip_offset + 4..ip_offset + 6].copy_from_slice(&fp.ip_id.to_be_bytes());
    packet[ip_offset + 6] = if fp.df { 0x40 } else { 0x00 };  // Flags: DF or clear
    packet[ip_offset + 7] = 0x00;  // Fragment offset
    packet[ip_offset + 8] = fp.ttl;
    packet[ip_offset + 9] = 17;  // Protocol: UDP
    // Checksum at 10-11
    packet[ip_offset + 12..ip_offset + 16].copy_from_slice(&src_ip.octets());
    packet[ip_offset + 16..ip_offset + 20].copy_from_slice(&dst_ip.octets());
    
    // IP checksum
    let ip_csum = checksum(&packet[ip_offset..ip_offset + 20]);
    packet[ip_offset + 10..ip_offset + 12].copy_from_slice(&ip_csum.to_be_bytes());
    
    // UDP header (8 bytes)
    let udp_offset = 34;
    packet[udp_offset..udp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[udp_offset + 4..udp_offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // UDP checksum at 6-7 (optional for IPv4, leave as 0)
    
    // Payload
    packet[udp_offset + 8..].copy_from_slice(payload);
    
    packet
}

fn craft_tcp_syn_packet(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    fp: &IpFingerprint,
    window: u16,
) -> Vec<u8> {
    let tcp_hdr_len = 20;
    let ip_len = 20 + tcp_hdr_len;
    let total_len = 14 + ip_len;

    let mut packet = vec![0u8; total_len];

    // Ethernet header
    packet[0..6].copy_from_slice(dst_mac);
    packet[6..12].copy_from_slice(src_mac);
    packet[12..14].copy_from_slice(&(0x0800u16).to_be_bytes());

    // IP header
    let ip_offset = 14;
    packet[ip_offset] = 0x45;  // Version + IHL
    packet[ip_offset + 1] = (fp.dscp << 2) | (fp.ecn & 0x03);  // DSCP + ECN
    packet[ip_offset + 2..ip_offset + 4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    packet[ip_offset + 4..ip_offset + 6].copy_from_slice(&fp.ip_id.to_be_bytes());
    packet[ip_offset + 6] = if fp.df { 0x40 } else { 0x00 };  // DF
    packet[ip_offset + 7] = 0x00;
    packet[ip_offset + 8] = fp.ttl;
    packet[ip_offset + 9] = 6;  // Protocol: TCP
    packet[ip_offset + 12..ip_offset + 16].copy_from_slice(&src_ip.octets());
    packet[ip_offset + 16..ip_offset + 20].copy_from_slice(&dst_ip.octets());

    let ip_csum = checksum(&packet[ip_offset..ip_offset + 20]);
    packet[ip_offset + 10..ip_offset + 12].copy_from_slice(&ip_csum.to_be_bytes());

    // TCP header (20 bytes, no options)
    let tcp_offset = 34;
    packet[tcp_offset..tcp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    // Seq number (random)
    packet[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&rand::random::<u32>().to_be_bytes());
    // Ack number = 0 (SYN, no ACK)
    // Data offset = 5 (20 bytes / 4), flags = SYN (0x02)
    packet[tcp_offset + 12] = 0x50;  // Data offset: 5 << 4
    packet[tcp_offset + 13] = 0x02;  // Flags: SYN
    // Window size
    packet[tcp_offset + 14..tcp_offset + 16].copy_from_slice(&window.to_be_bytes());
    // TCP checksum at 16-17 (leave 0 — XDP doesn't validate TCP checksums for our test)
    // Urgent pointer = 0

    packet
}

fn send_packet(fd: i32, packet: &[u8]) -> Result<usize> {
    let ret = unsafe {
        libc::send(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
        )
    };
    
    if ret < 0 {
        Err(anyhow::anyhow!("send failed: {}", std::io::Error::last_os_error()))
    } else {
        Ok(ret as usize)
    }
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    !(sum as u16)
}

/// Apply jitter to a PPS value
/// jitter_pct: 0-100 (e.g., 5 = ±5%)
fn apply_jitter<R: Rng>(rng: &mut R, pps: u32, jitter_pct: u8) -> u32 {
    if jitter_pct == 0 || pps == 0 {
        return pps;
    }
    
    // Calculate jitter range: ±jitter_pct% of pps
    let jitter_range = (pps as f64 * jitter_pct as f64 / 100.0) as i32;
    if jitter_range == 0 {
        return pps;
    }
    
    // Random value in [-jitter_range, +jitter_range]
    let delta = rng.gen_range(-jitter_range..=jitter_range);
    let jittered = (pps as i32 + delta).max(1) as u32; // At least 1 pps
    
    jittered
}
