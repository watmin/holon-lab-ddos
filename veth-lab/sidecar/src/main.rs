//! Veth Lab Sidecar - Enhanced Holon-based Anomaly Detection
//!
//! Reads packet samples from XDP ring buffer, encodes them with Holon,
//! detects anomalies using extended primitives, and pushes rules back to XDP.
//!
//! Features from Batch 014/015:
//! - Walkable encoding (5x faster than JSON)
//! - similarity_profile() for per-dimension anomaly analysis
//! - segment() for automatic phase detection  
//! - invert() for pattern attribution
//! - analogy() for zero-shot variant detection
//! - Magnitude-aware encoding ($log) for packet sizes

mod detection;
mod detectors;
mod field_tracker;
mod metrics_server;
mod payload_tracker;
mod rule_manager;
mod rules_parser;

use anyhow::{Context, Result};
use chrono::{DateTime, Local, Utc};
use clap::Parser;
use holon::{Holon, Vector};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};
use veth_filter::{
    PacketSample, Predicate, RuleAction, RuleSpec, VethFilter,
};

use crate::detection::{Detection, compile_compound_rule, rule_identity_key};
use crate::field_tracker::FieldTracker;
use crate::payload_tracker::{PayloadTracker, PayloadEngramEvent, NUM_PAYLOAD_WINDOWS, MAX_PAYLOAD_BYTES};
use crate::rule_manager::{
    ActiveRule, validate_byte_match_density, rule_is_redundant,
    upsert_rules, recompile_tree_and_broadcast,
};
use crate::rules_parser::{parse_rules_file, parse_edn_rule};

#[derive(Parser, Debug)]
#[command(name = "veth-sidecar")]
#[command(about = "Enhanced Holon-based packet anomaly detection sidecar")]
struct Args {
    /// Interface with XDP filter attached
    #[arg(short, long, default_value = "veth-filter")]
    interface: String,

    /// (Deprecated) Detection window in seconds. Ignored — decay-based processing is always active.
    #[arg(short, long, default_value = "2")]
    window: u64,

    /// Drift threshold for anomaly detection (0.0 - 1.0)
    /// Lower = more sensitive. Attack traffic typically shows drift 0.7-0.8
    #[arg(short, long, default_value = "0.85")]
    threshold: f64,

    /// Minimum packets before analysis tick runs detection
    #[arg(short, long, default_value = "50")]
    min_packets: usize,

    /// Decay half-life in packets. Controls how fast the accumulator forgets.
    /// At 3000 pps baseline with half-life 1000: ~333ms memory. At 15000 pps attack: ~67ms.
    #[arg(long, default_value = "1000")]
    decay_half_life: usize,

    /// Analysis tick every N packets (hybrid: whichever fires first with --analysis-max-ms)
    #[arg(long, default_value = "200")]
    analysis_interval: usize,

    /// Maximum milliseconds between analysis ticks (hybrid: whichever fires first with --analysis-interval)
    #[arg(long, default_value = "200")]
    analysis_max_ms: u64,

    /// Time-based half-life (ms) for the rate vector accumulator.
    /// Controls how fast the rate vector forgets old traffic volume.
    /// Magnitude of the rate vector is proportional to PPS at steady state.
    #[arg(long, default_value = "2000")]
    rate_half_life_ms: u64,

    /// Concentration threshold for field values (0.0 - 1.0)
    /// Higher = only flag very concentrated values
    #[arg(short, long, default_value = "0.5")]
    concentration: f64,

    /// Enable enforcement (actually add drop rules)
    #[arg(short, long)]
    enforce: bool,

    /// Vector dimensions for Holon encoding
    #[arg(long, default_value = "4096")]
    dimensions: usize,

    /// (Deprecated) Warmup windows — ignored. Use --warmup-packets instead.
    #[arg(long, default_value = "5")]
    warmup_windows: u64,

    /// Minimum packets required during warmup to establish baseline
    #[arg(long, default_value = "500")]
    warmup_packets: usize,

    /// Directory for log files (also writes to stdout)
    #[arg(long, default_value = "logs")]
    log_dir: PathBuf,

    /// Sample rate: 1 in N packets sampled (100 = 1%, 1000 = 0.1%)
    /// Higher = less userspace load, but less granular detection
    #[arg(long, default_value = "100")]
    sample_rate: u32,

    /// Enable rate limiting instead of binary DROP (experimental)
    #[arg(long)]
    rate_limit: bool,

    /// Pre-load rules from a JSON file at startup.
    /// Rules are compiled into the tree before detection begins.
    /// Holon detection adds rules on top of these at runtime.
    /// Format: JSON array of {constraints, action, rate_pps?, priority?}
    #[arg(long)]
    rules_file: Option<PathBuf>,

    /// Maximum number of l4-match (byte match) rules per destination scope.
    /// Limits per-tenant byte match complexity to prevent resource exhaustion.
    /// Set to 0 to disable the limit.
    #[arg(long, default_value = "32")]
    max_byte_matches_per_scope: usize,

    /// Metrics server port (0 to disable)
    #[arg(long, default_value = "9100")]
    metrics_port: u16,

    /// Similarity threshold for payload window anomaly (0.0 - 1.0).
    /// If omitted, auto-calibrated from warmup data (recommended).
    #[arg(long)]
    payload_threshold: Option<f64>,

    /// Minimum anomalous payloads per destination before deriving rules
    #[arg(long, default_value = "5")]
    payload_min_anomalies: usize,

    /// Number of principal components for subspace detectors.
    #[arg(long, default_value = "32")]
    subspace_k: usize,

    /// Path to persist/load engram libraries (directory). If not set, engrams are not persisted.
    #[arg(long)]
    engram_library_path: Option<PathBuf>,
}

/// Detailed detection event for SOC analyst visibility
#[derive(Debug, Clone, Serialize)]
struct DetectionEvent {
    timestamp: DateTime<Utc>,
    window_id: u64,
    drift: f64,
    anomalous_ratio: f64,
    phase: String,
    attributed_pattern: Option<String>,
    attributed_confidence: f64,
    concentrated_fields: Vec<(String, String, f64)>,
    action_taken: Vec<RuleInfo>,
    variant_similarity: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct RuleInfo {
    rule_type: String,
    value: String,
    action: String,
    rate_pps: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Create log directory
    fs::create_dir_all(&args.log_dir)
        .with_context(|| format!("Failed to create log dir: {:?}", args.log_dir))?;

    // Generate timestamped log filename
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let log_filename = format!("sidecar_{}.log", timestamp);
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

    info!("Veth Lab Sidecar - Enhanced Holon Anomaly Detection");
    info!("  Interface: {}", args.interface);
    info!("  Window: {}s", args.window);
    info!("  Drift threshold: {}", args.threshold);
    info!("  Concentration threshold: {}", args.concentration);
    info!("  Enforce mode: {}", args.enforce);
    info!("  Rate limit mode: {}", args.rate_limit);
    info!("  Rules file: {:?}", args.rules_file.as_deref().unwrap_or(std::path::Path::new("(none)")));
    info!("  Dimensions: {}", args.dimensions);
    info!("  Warmup: {} windows / {} packets", args.warmup_windows, args.warmup_packets);
    info!("  Sample rate: 1 in {} packets", args.sample_rate);
    info!("  Sample transport: BPF RingBuf (4MB shared, overflow-drop)");
    info!("  Log file: {:?}", log_path);
    info!("");
    info!("Enhanced features enabled:");
    info!("  - Walkable encoding (5x faster)");
    info!("  - similarity_profile() for per-dimension analysis");
    info!("  - segment() for phase detection");
    info!("  - invert() for pattern attribution");
    info!("  - analogy() for zero-shot variant detection");
    info!("  - Magnitude-aware $log encoding for packet sizes");
    info!("  - Drift rate (similarity-derivative) for attack onset classification");
    info!("");

    // Load XDP filter
    let filter = VethFilter::new(&args.interface)?;
    let filter = Arc::new(filter);

    // Configure filter
    filter.set_sample_rate(args.sample_rate).await?;
    filter.set_enforce_mode(args.enforce).await?;

    // Initialize Holon
    let holon = Arc::new(Holon::new(args.dimensions));
    info!("Holon initialized with {} dimensions", args.dimensions);

    // Create enhanced field tracker with decay
    let tracker = Arc::new(RwLock::new(FieldTracker::new(holon.clone(), args.decay_half_life, args.rate_half_life_ms, args.subspace_k)));
    
    // Create payload tracker
    let payload_tracker = Arc::new(RwLock::new(PayloadTracker::new(
        holon.clone(),
        args.payload_threshold,
        args.payload_min_anomalies,
        args.rate_limit,
        args.subspace_k,
    )));
    info!("PayloadTracker initialized: {} windows ({}B), threshold={}, min_anomalies={}",
        NUM_PAYLOAD_WINDOWS, MAX_PAYLOAD_BYTES,
        args.payload_threshold.map_or("auto".to_string(), |t| format!("{}", t)),
        args.payload_min_anomalies);

    // Load engram libraries if path specified
    if let Some(ref path) = args.engram_library_path {
        let lib_path = path.to_string_lossy();
        tracker.write().await.subspace.load_library(&format!("{}/field_engrams.json", lib_path));
        payload_tracker.write().await.payload_subspace.load_library(&format!("{}/payload_engrams.json", lib_path));
    }
    info!("Subspace detector: k={}, field engrams={}, payload engrams={}",
          args.subspace_k,
          tracker.read().await.subspace.library.len(),
          payload_tracker.read().await.payload_subspace.library.len());

    // Take ring buffer for sample reading (single shared buffer across all CPUs)
    let ring_buf = filter.take_ring_buf().await?;
    info!("Ring buffer opened (single shared buffer, overflow-drop)");

    // Channel for samples
    let (sample_tx, mut sample_rx) = tokio::sync::mpsc::channel::<PacketSample>(1000);

    // Spawn a single task to drain the ring buffer using AsyncFd polling
    {
        use tokio::io::unix::AsyncFd;

        let tx = sample_tx.clone();

        tokio::spawn(async move {
            let mut async_fd = match AsyncFd::new(ring_buf) {
                Ok(fd) => fd,
                Err(e) => {
                    error!("Failed to create AsyncFd for ring buffer: {}", e);
                    return;
                }
            };

            loop {
                let mut guard = match async_fd.readable_mut().await {
                    Ok(g) => g,
                    Err(e) => {
                        error!("AsyncFd readable error: {}", e);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };

                let ring_buf = guard.get_inner_mut();
                while let Some(item) = ring_buf.next() {
                    if item.len() >= std::mem::size_of::<PacketSample>() {
                        let sample = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const PacketSample)
                        };
                        match tx.try_send(sample) {
                            Ok(_) => {},
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            }
                        }
                    }
                }

                guard.clear_ready();
            }
        });
    }
    drop(sample_tx);

    // Tracked rules: key -> (last_seen, spec)
    let active_rules: Arc<RwLock<HashMap<String, ActiveRule>>> = Arc::new(RwLock::new(HashMap::new()));
    let tree_dirty: Arc<std::sync::atomic::AtomicBool> = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let tree_counter_labels: Arc<RwLock<std::collections::HashMap<u32, (String, String)>>> =
        Arc::new(RwLock::new(std::collections::HashMap::new()));

    let rate_limiter_names: Arc<RwLock<std::collections::HashMap<u32, (String, String)>>> = 
        Arc::new(RwLock::new(std::collections::HashMap::new()));

    let bucket_key_to_spec: Arc<RwLock<std::collections::HashMap<u32, RuleSpec>>> = 
        Arc::new(RwLock::new(std::collections::HashMap::new()));

    // ── Pre-load rules from file if specified ──
    if let Some(ref rules_path) = args.rules_file {
        let start = Instant::now();
        let preloaded = parse_rules_file(rules_path)?;
        let parse_time = start.elapsed();
        info!("Parsed {} rules from {:?} in {:?}", preloaded.len(), rules_path, parse_time);

        if args.max_byte_matches_per_scope > 0 {
            validate_byte_match_density(&preloaded, args.max_byte_matches_per_scope)?;
        }

        if !preloaded.is_empty() {
            let mut rules = active_rules.write().await;
            let mut rate_map = rate_limiter_names.write().await;
            let mut bucket_map = bucket_key_to_spec.write().await;
            
            for spec in &preloaded {
                for action in &spec.actions {
                    match action {
                        veth_filter::RuleAction::RateLimit { .. } | veth_filter::RuleAction::Count { .. } => {
                            if let Some(key) = spec.bucket_key() {
                                bucket_map.entry(key).or_insert_with(|| spec.clone());
                            }
                            break;
                        }
                        _ => {}
                    }
                }
                
                if let Some(key) = spec.bucket_key() {
                    for action in &spec.actions {
                        if let veth_filter::RuleAction::RateLimit { name: Some((ns, n)), .. } = action {
                            rate_map.insert(key, (ns.clone(), n.clone()));
                            break;
                        }
                    }
                }
                
                let key = rule_identity_key(spec);
                rules.insert(key, ActiveRule {
                    last_seen: Instant::now(),
                    spec: spec.clone(),
                    preloaded: true,
                });
            }
            
            if !rate_map.is_empty() {
                info!("Configured {} rate limiters:", rate_map.len());
                for (hash, (ns, name)) in rate_map.iter() {
                    info!("  [\"{}\" \"{}\"] → key 0x{:08x}", ns, name, hash);
                }
            }

            if !bucket_map.is_empty() {
                info!("Bucket map contains {} entries:", bucket_map.len());
                for (key, spec) in bucket_map.iter() {
                    info!("  0x{:08x} → {}", key, spec.display_label());
                }
            }

            if args.enforce {
                let all_specs: Vec<RuleSpec> = rules.values().map(|r| r.spec.clone()).collect();
                let start = Instant::now();
                let (nodes, manifest, _retired) = filter.compile_and_flip_tree(&all_specs).await?;
                let compile_time = start.elapsed();
                let capacity_pct = (nodes as f64 / 2_500_000.0) * 100.0;

                {
                    let mut tcl = tree_counter_labels.write().await;
                    for entry in &manifest {
                        tcl.insert(entry.rule_id, (entry.action_kind().to_string(), entry.label.clone()));
                    }
                    if !tcl.is_empty() {
                        info!("Rule manifest: {} entries", tcl.len());
                        for (id, (kind, label)) in tcl.iter() {
                            info!("  [{}] {} → key 0x{:08x}", kind, label, id);
                        }
                    }
                }

                info!("========================================");
                info!("PRE-LOADED TREE COMPILED");
                info!("  Rules:    {}", all_specs.len());
                info!("  Nodes:    {} ({:.1}% of slot capacity)", nodes, capacity_pct);
                info!("  Time:     {:?}", compile_time);
                info!("  Headroom: ~{} nodes for Holon additions", 2_500_000u64.saturating_sub(nodes as u64));
                info!("========================================");
            } else {
                info!("Pre-loaded {} rules (dry-run, not compiled to tree)", rules.len());
            }
        }
    }

    if args.window != 2 {
        warn!("--window is deprecated and ignored; decay-based processing is always active");
    }

    let preloaded_count = active_rules.read().await.values().filter(|r| r.preloaded).count();
    info!("Starting enhanced detection loop (decay-based)...");
    info!("  Pre-loaded rules: {} (permanent)", preloaded_count);
    info!("  Decay half-life: {} packets (factor={:.6})",
          args.decay_half_life, 0.5_f64.powf(1.0 / args.decay_half_life.max(1) as f64));
    info!("  Analysis trigger: every {} packets or {} ms (hybrid)",
          args.analysis_interval, args.analysis_max_ms);
    info!("  Rate vector half-life: {}ms (time-based decay for PPS encoding)",
          args.rate_half_life_ms);
    info!("  Warmup: {} packets", args.warmup_packets);
    info!("");

    // ── Start metrics server if enabled ──
    let metrics_state = if args.metrics_port > 0 {
        info!("");
        info!("========================================");
        info!("METRICS DASHBOARD");
        info!("  URL: http://localhost:{}", args.metrics_port);
        info!("========================================");
        info!("");
        
        let active_rules_clone = active_rules.clone();
        let metrics_active_rules = Arc::new(RwLock::new(HashMap::new()));
        {
            let src = active_rules_clone.read().await;
            let mut dst = metrics_active_rules.write().await;
            for (key, rule) in src.iter() {
                dst.insert(key.clone(), metrics_server::ActiveRuleInfo {
                    spec: rule.spec.clone(),
                    preloaded: rule.preloaded,
                });
            }
        }
        
        let state = metrics_server::MetricsState::new(
            filter.clone(),
            metrics_active_rules.clone(),
            tree_counter_labels.clone(),
            1000,
        );

        let server_state = state.clone();
        let metrics_port = args.metrics_port;
        tokio::spawn(async move {
            if let Err(e) = metrics_server::run_server(server_state, metrics_port).await {
                error!("Metrics server error: {}", e);
            }
        });

        let collector_state = state.clone();
        tokio::spawn(async move {
            metrics_server::metrics_collector_task(
                collector_state,
                Duration::from_millis(500),
            ).await;
        });

        Some(state)
    } else {
        info!("Metrics server disabled (--metrics-port 0)");
        None
    };

    let analysis_max_dur = Duration::from_millis(args.analysis_max_ms);
    let mut _samples_processed = 0u64;
    let mut ticks_processed = 0u64;
    let mut total_warmup_packets = 0usize;
    let mut warmup_complete = false;
    let mut anomaly_active_since: Option<u64> = None;

    let mut warmup_first_sample: Option<Instant> = None;
    let mut baseline_pps: f64 = 0.0;

    let mut packets_since_tick = 0usize;
    let mut last_tick = Instant::now();

    const MAX_SAMPLES_PER_BATCH: usize = 200;

    loop {
        let mut got_sample = false;
        let mut matched_rule_keys: Vec<String> = Vec::new();

        // ── Per-packet processing ──
        {
            let mut tracker_w = tracker.write().await;
            let mut pt = payload_tracker.write().await;

            for _ in 0..MAX_SAMPLES_PER_BATCH {
                match sample_rx.try_recv() {
                    Ok(sample) => {
                        if warmup_first_sample.is_none() {
                            warmup_first_sample = Some(Instant::now());
                        }

                        tracker_w.add_sample(&sample);

                        if warmup_complete {
                            pt.process_single_sample(&sample);
                        } else {
                            let l4 = sample.l4_payload();
                            if !l4.is_empty() { pt.learn(l4); }
                        }

                        _samples_processed += 1;
                        packets_since_tick += 1;
                        got_sample = true;

                        if sample.matched_rule != 0 {
                            matched_rule_keys.push(format!("src_ip:{}", sample.src_ip_addr()));
                            matched_rule_keys.push(format!("dst_port:{}", sample.dst_port));
                        }
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        info!("Sample channel closed");
                        return Ok(());
                    }
                }
            }
        }

        // Refresh TTL for matched rules
        if !matched_rule_keys.is_empty() {
            let mut rules = active_rules.write().await;
            let now = Instant::now();
            for key in matched_rule_keys {
                if let Some(active) = rules.get_mut(&key) {
                    active.last_seen = now;
                }
            }
        }

        // ── Hybrid analysis trigger ──
        let tick_elapsed = last_tick.elapsed();
        let should_tick = packets_since_tick >= args.analysis_interval
            || tick_elapsed >= analysis_max_dur;

        if !should_tick {
            if !got_sample {
                tokio::time::sleep(Duration::from_millis(5)).await;
            } else {
                tokio::task::yield_now().await;
            }
            continue;
        }

        let tick_secs = tick_elapsed.as_secs_f64().max(0.001);
        let estimated_pps = (packets_since_tick as f64 * args.sample_rate as f64) / tick_secs;

        ticks_processed += 1;
        packets_since_tick = 0;
        last_tick = Instant::now();

        let tracker_read = tracker.read().await;
        let current_phase = tracker_read.current_phase.clone();
        drop(tracker_read);

        // ── Warmup path ──
        if !warmup_complete {
            let effective = tracker.read().await.total_effective;
            {
                let mut tracker_w = tracker.write().await;
                total_warmup_packets += tracker_w.total_effective as usize;
                tracker_w.accumulate_warmup();
            }

            let warmup_by_packets = total_warmup_packets >= args.warmup_packets;

            if warmup_by_packets {
                warmup_complete = true;
                tracker.write().await.freeze_baseline();
                payload_tracker.write().await.freeze_baseline();

                let warmup_secs = warmup_first_sample
                    .map(|t| t.elapsed().as_secs_f64())
                    .unwrap_or(1.0)
                    .max(0.1);
                baseline_pps = (total_warmup_packets as f64 * args.sample_rate as f64) / warmup_secs;

                info!("========================================");
                info!("WARMUP COMPLETE - baseline FROZEN");
                info!("  Ticks: {}, Packets: {}", ticks_processed, total_warmup_packets);
                info!("  Baseline PPS: {:.0} (scalar, instant-response)",
                      baseline_pps);
                info!("  Rate vector: PPS encoded as magnitude (time-decay half-life: {}ms)",
                      args.rate_half_life_ms);
                info!("  Decay half-life: {} packets", args.decay_half_life);
                info!("  Detection now active with extended primitives!");
                info!("  Payload tracking: {} windows frozen", NUM_PAYLOAD_WINDOWS);
                info!("========================================");
            } else {
                info!(
                    "Tick {} [WARMUP]: {:.0} eff this tick, {}/{} total packets",
                    ticks_processed, effective,
                    total_warmup_packets, args.warmup_packets
                );
            }
            continue;
        }

        // ── Post-warmup analysis ──
        let has_enough_samples = tracker.read().await.total_effective >= args.min_packets as f64;
        if !has_enough_samples {
            tracker.write().await.snapshot_history();
            continue;
        }

        let ft_rate_factor = if estimated_pps > 0.0 {
            (baseline_pps / estimated_pps).min(1.0)
        } else {
            1.0
        };

        let stats = filter.stats().await.ok();
        let hard_drops = stats.as_ref().map(|s| s.dropped_packets).unwrap_or(0);
        let rate_drops = stats.as_ref().map(|s| s.rate_limited_packets).unwrap_or(0);
        let drops = hard_drops + rate_drops;
        let total = stats.as_ref().map(|s| s.total_packets).unwrap_or(0);
        let dfs_comp = stats.as_ref().map(|s| s.dfs_completions).unwrap_or(0);
        let tc_entries = stats.as_ref().map(|s| s.tail_call_entries).unwrap_or(0);
        let d_eval2 = stats.as_ref().map(|s| s.diag_eval2).unwrap_or(0);
        let d_root = stats.as_ref().map(|s| s.diag_root_ok).unwrap_or(0);
        let d_state = stats.as_ref().map(|s| s.diag_state_ok).unwrap_or(0);
        let d_tc_try = stats.as_ref().map(|s| s.diag_tc_attempt).unwrap_or(0);
        let d_tc_fail = stats.as_ref().map(|s| s.diag_tc_fail).unwrap_or(0);

        // ── Post-warmup analysis ──
        let tracker_read = tracker.read().await;
        let anomaly = tracker_read.compute_anomaly_details();
        let concentrated = tracker_read.find_concentrated_values(args.concentration);
        let attribution = tracker_read.attribute_pattern();
        let rate_factor = ft_rate_factor;
        drop(tracker_read);

        // Record drift value and check for phase changes
        {
            let mut tw = tracker.write().await;
            tw.record_drift(anomaly.drift);
            if let Some(new_phase) = tw.detect_phase_changes() {
                warn!(">>> PHASE CHANGE DETECTED: {}", new_phase);
            }
        }

        let drift_rate_val = tracker.read().await.compute_drift_rate(3);
        match drift_rate_val {
            Some(drift_rate) => {
                if drift_rate < -0.02 {
                    warn!(">>> FLASH FLOOD DETECTED: drift_rate={:.4}/tick (instant attack onset)", drift_rate);
                } else if drift_rate < -0.005 {
                    warn!(">>> RAMP-UP ATTACK: drift_rate={:.4}/tick (accelerating threat)", drift_rate);
                }
                if ticks_processed % 10 == 0 {
                    info!("    Drift rate: {:.4}/tick", drift_rate);
                }
            }
            None => {
                if ticks_processed % 50 == 0 {
                    info!("    Drift rate: N/A (drift_history len={})", tracker.read().await.drift_history.len());
                }
            }
        }

        // ── Early detection via drift_rate ──
        let early_threshold = (args.threshold + 0.10).min(0.98);
        if let Some(dr) = drift_rate_val {
            if dr < -0.005
                && anomaly.drift < early_threshold
                && anomaly.drift >= args.threshold
                && anomaly_active_since.is_none()
            {
                let early_concentrated = tracker.read().await.find_concentrated_values(0.10);
                if early_concentrated.len() >= 2 {
                    warn!(">>> EARLY DETECTION (drift_rate={:.4}/tick, drift={:.3}): {} emerging fields",
                          dr, anomaly.drift, early_concentrated.len());

                    let detections: Vec<Detection> = early_concentrated.iter().map(|(field, value, conc)| {
                        warn!("    Emerging: {}={} ({:.1}%)", field, value, conc * 100.0);
                        Detection {
                            field: field.clone(),
                            value: value.clone(),
                            rate_factor,
                        }
                    }).collect();

                    if let Some(spec) = compile_compound_rule(&detections, args.rate_limit, estimated_pps) {
                        let mut rules = active_rules.write().await;
                        if rule_is_redundant(&spec, &rules).is_none() {
                            let newly_added = upsert_rules(
                                &[spec.clone()], &mut rules, &bucket_key_to_spec,
                                &tree_dirty, &metrics_state, "EARLY-RULE",
                            ).await;
                            if !newly_added.is_empty() {
                                warn!("    EARLY RULE:\n{}", spec.to_edn_pretty());
                                anomaly_active_since = Some(ticks_processed);
                                if tree_dirty.load(std::sync::atomic::Ordering::SeqCst) && args.enforce {
                                    if let Err(e) = recompile_tree_and_broadcast(
                                        &filter, &rules, &tree_counter_labels,
                                        &tree_dirty, &metrics_state, "early detection",
                                    ).await {
                                        warn!("    Failed to compile tree: {}", e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        info!(
            "Tick {}: {:.0} eff, drift={:.3}, anom_ratio={:.1}%, phase={} | XDP total: {}, dropped: {} (hard:{} rate:{}) | DFS tc:{} comp:{} | DIAG eval2:{} root:{} state:{} tc_try:{} tc_fail:{}",
            ticks_processed, tracker.read().await.total_effective, anomaly.drift, anomaly.anomalous_ratio * 100.0,
            current_phase, total, drops, hard_drops, rate_drops, tc_entries, dfs_comp,
            d_eval2, d_root, d_state, d_tc_try, d_tc_fail
        );

        // Print TREE_COUNTERS stats every 10 ticks
        if ticks_processed % 10 == 0 {
            if let Ok(counter_values) = filter.read_counters().await {
                if !counter_values.is_empty() {
                    let tcl = tree_counter_labels.read().await;

                    let mut pass_entries: Vec<(u32, u64, String)> = Vec::new();
                    let mut count_entries: Vec<(u32, u64, String)> = Vec::new();
                    let mut drop_entries: Vec<(u32, u64, String)> = Vec::new();
                    let mut other_entries: Vec<(u32, u64, String, String)> = Vec::new();

                    for &(key, value) in &counter_values {
                        if let Some((kind, label)) = tcl.get(&key) {
                            match kind.as_str() {
                                "pass" => pass_entries.push((key, value, label.clone())),
                                "count" => count_entries.push((key, value, label.clone())),
                                "drop" => drop_entries.push((key, value, label.clone())),
                                other => other_entries.push((key, value, label.clone(), other.to_string())),
                            }
                        } else {
                            other_entries.push((key, value, format!("unknown-0x{:08x}", key), "?".to_string()));
                        }
                    }

                    if !pass_entries.is_empty() {
                        info!("=== Pass Actions (tick {}) ===", ticks_processed);
                        pass_entries.sort_by_key(|(_, v, _)| std::cmp::Reverse(*v));
                        for (_, value, label) in &pass_entries {
                            info!("  {} {} packets passed", label, value);
                        }
                    }

                    if !count_entries.is_empty() {
                        info!("=== Count Actions (tick {}) ===", ticks_processed);
                        count_entries.sort_by_key(|(_, v, _)| std::cmp::Reverse(*v));
                        for (_, value, label) in &count_entries {
                            info!("  {} {} packets", label, value);
                        }
                    }

                    if !drop_entries.is_empty() {
                        info!("=== Drop Actions (tick {}) ===", ticks_processed);
                        drop_entries.sort_by_key(|(_, v, _)| std::cmp::Reverse(*v));
                        for (_, value, label) in &drop_entries {
                            info!("  {} {} packets dropped", label, value);
                        }
                    }

                    if !other_entries.is_empty() {
                        for (key, value, label, kind) in &other_entries {
                            info!("  [{}] {} {} packets (key 0x{:08x})", kind, label, value, key);
                        }
                    }
                }
            }

            // Report rate limiter stats
            if let Ok(rate_stats) = filter.read_rate_limit_stats().await {
                if !rate_stats.is_empty() {
                    info!("=== Rate Limiters (tick {}) ===", ticks_processed);
                    let mut sorted = rate_stats.clone();
                    sorted.sort_by_key(|(_, allowed, dropped)| std::cmp::Reverse(allowed + dropped));

                    let rate_map = rate_limiter_names.read().await;
                    let bucket_map = bucket_key_to_spec.read().await;

                    for (key, allowed, dropped) in sorted {
                        if let Some((ns, name)) = rate_map.get(&key) {
                            info!("  [{} {}] allowed: {}  dropped: {}", ns, name, allowed, dropped);
                        } else {
                            let label = bucket_map.get(&key)
                                .map(|spec| spec.display_label())
                                .unwrap_or_else(|| format!("unknown-0x{:08x}", key));
                            info!("  {} allowed: {}  dropped: {}", label, allowed, dropped);
                        }
                    }
                }
            }
        }

        // Log attribution if available
        if let Some((pattern, confidence)) = &attribution {
            info!("    Attribution: {} ({:.1}% confidence)", pattern, confidence * 100.0);
        }

        // === Engram-based detection ===
        let subspace_residual = anomaly.subspace_residual;
        let subspace_threshold = tracker.read().await.subspace.baseline.threshold();

        if subspace_residual > subspace_threshold {
            let mut tw = tracker.write().await;
            tw.subspace.anomaly_streak += 1;

            if let Some(raw_vec) = tw.take_tick_subspace_vec() {
                if let Some((engram_name, engram_res)) = tw.subspace.check_library(&raw_vec) {
                    if tw.subspace.anomaly_streak == 1 {
                        let stored_rules: Vec<String> = tw.subspace.library.get(&engram_name)
                            .and_then(|e| e.metadata().get("rules").cloned())
                            .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
                            .unwrap_or_default();

                        if stored_rules.is_empty() {
                            warn!(">>> ENGRAM HIT: '{}' (residual={:.2}) — known attack (no stored rules)", engram_name, engram_res);
                        } else {
                            warn!(">>> ENGRAM HIT: '{}' (residual={:.2}) — deploying {} stored rule(s)", engram_name, engram_res, stored_rules.len());
                            drop(tw);

                            let mut deployed = Vec::new();
                            for edn_str in &stored_rules {
                                match edn_rs::Edn::from_str(edn_str) {
                                    Ok(edn) => match parse_edn_rule(&edn) {
                                        Ok(spec) => deployed.push(spec),
                                        Err(e) => warn!("  Failed to parse stored rule: {}", e),
                                    },
                                    Err(e) => warn!("  Failed to parse stored rule EDN: {}", e),
                                }
                            }

                            if !deployed.is_empty() {
                                let mut rules = active_rules.write().await;
                                let newly_added = upsert_rules(
                                    &deployed, &mut rules, &bucket_key_to_spec,
                                    &tree_dirty, &metrics_state, "ENGRAM-RULE",
                                ).await;

                                if !newly_added.is_empty() {
                                    for spec in &deployed {
                                        warn!("    ENGRAM RULE:\n{}", spec.to_edn_pretty());
                                    }
                                }

                                if tree_dirty.load(std::sync::atomic::Ordering::SeqCst) && args.enforce {
                                    if let Err(e) = recompile_tree_and_broadcast(
                                        &filter, &rules, &tree_counter_labels,
                                        &tree_dirty, &metrics_state, "engram hit",
                                    ).await {
                                        warn!("  Failed to compile tree: {}", e);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    tw.subspace.learn_attack(&raw_vec);
                    if tw.subspace.anomaly_streak == 1 {
                        warn!(">>> SUBSPACE ANOMALY (residual={:.2}, threshold={:.2}) — no engram match, learning attack manifold",
                              subspace_residual, subspace_threshold);
                    }
                }
            }
        } else {
            let mut tw = tracker.write().await;
            let had_attack = tw.subspace.has_active_attack();
            let streak = tw.subspace.anomaly_streak;

            if had_attack && streak >= 5 {
                let tick_name = format!("attack_t{}", ticks_processed);

                let fields: Vec<&str> = vec![
                    "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                    "ttl", "df_bit", "pkt_len", "direction", "size_class",
                ];
                let holon_ref = tw.holon.clone();
                let acc_snapshot = tw.recent_acc.clone();
                let fingerprint = tw.subspace.surprise_fingerprint(&acc_snapshot, &holon_ref, &fields);
                let surprise: HashMap<String, f64> = fingerprint.into_iter().collect();

                let rules_snapshot: Vec<String> = active_rules.read().await
                    .values()
                    .filter(|r| !r.preloaded)
                    .map(|r| r.spec.to_edn())
                    .collect();

                let mut metadata = HashMap::new();
                metadata.insert("minted_at_tick".to_string(), serde_json::Value::from(ticks_processed));
                metadata.insert("anomaly_streak".to_string(), serde_json::Value::from(streak));
                if !rules_snapshot.is_empty() {
                    metadata.insert("rules".to_string(), serde_json::json!(rules_snapshot));
                }

                tw.subspace.mint_engram(&tick_name, surprise, metadata);

                warn!(">>> ENGRAM MINTED: '{}' after {} anomalous ticks (library size: {}, stored {} rules)",
                      tick_name, streak, tw.subspace.library.len(), rules_snapshot.len());
            } else if had_attack {
                tw.subspace.cancel_attack();
                info!("Attack subspace cancelled (streak {} < 5 minimum)", streak);
            }
            tw.subspace.anomaly_streak = 0;
        }

        // Check for anomaly
        if anomaly.drift < args.threshold && !concentrated.is_empty() {
            let is_new_anomaly = anomaly_active_since.is_none();
            let ticks_in_anomaly = anomaly_active_since
                .map(|start| ticks_processed - start)
                .unwrap_or(0);
            if is_new_anomaly {
                anomaly_active_since = Some(ticks_processed);
            }

            if is_new_anomaly || ticks_in_anomaly % 20 == 0 {
                warn!(">>> ANOMALY DETECTED: drift={:.3}, anomalous_ratio={:.1}%{}",
                      anomaly.drift, anomaly.anomalous_ratio * 100.0,
                      if !is_new_anomaly { format!(" (ongoing, tick {})", ticks_in_anomaly) } else { String::new() });
                for (field, value, conc) in &concentrated {
                    warn!("    Concentrated: {}={} ({:.1}%)", field, value, conc * 100.0);
                }
            }

            let mut actions_taken = Vec::new();

            let detections: Vec<Detection> = concentrated.iter().map(|(field, value, _conc)| {
                Detection {
                    field: field.clone(),
                    value: value.clone(),
                    rate_factor,
                }
            }).collect();

            if let Some(spec) =
                compile_compound_rule(&detections, args.rate_limit, estimated_pps)
            {
                let mut rules = active_rules.write().await;

                if let Some(reason) = rule_is_redundant(&spec, &rules) {
                    info!("    Rule suppressed ({}): {}", reason, spec.describe());
                    drop(rules);
                } else {

                let newly_added = upsert_rules(
                    &[spec.clone()], &mut rules, &bucket_key_to_spec,
                    &tree_dirty, &metrics_state, "RULE",
                ).await;

                if !newly_added.is_empty() {
                    warn!("    RULE:\n{}", spec.to_edn_pretty());
                    let action_str = match &spec.actions[0] {
                        RuleAction::Drop { .. } => "DROP",
                        RuleAction::RateLimit { .. } => "RATE-LIMIT",
                        RuleAction::Pass { .. } => "PASS",
                        RuleAction::Count { .. } => "COUNT",
                    };
                    let rate_pps = spec.actions.first().and_then(|a| a.rate_pps());
                    actions_taken.push(RuleInfo {
                        rule_type: "tree".to_string(),
                        value: spec.describe(),
                        action: action_str.to_string(),
                        rate_pps,
                    });
                }

                if tree_dirty.load(std::sync::atomic::Ordering::SeqCst) && args.enforce {
                    if let Err(e) = recompile_tree_and_broadcast(
                        &filter, &rules, &tree_counter_labels,
                        &tree_dirty, &metrics_state, "field tracker",
                    ).await {
                        warn!("    Failed to compile tree: {}", e);
                    }
                } else if !args.enforce {
                    info!("    Would compile tree (dry-run): {} rules", rules.len());
                }
                } // else (not redundant)
            }

            let event = DetectionEvent {
                timestamp: Utc::now(),
                window_id: ticks_processed,
                drift: anomaly.drift,
                anomalous_ratio: anomaly.anomalous_ratio,
                phase: current_phase.clone(),
                attributed_pattern: attribution.as_ref().map(|(p, _)| p.clone()),
                attributed_confidence: attribution.as_ref().map(|(_, c)| *c).unwrap_or(0.0),
                concentrated_fields: concentrated.clone(),
                action_taken: actions_taken,
                variant_similarity: None,
            };

            if let Ok(json) = serde_json::to_string(&event) {
                info!("DETECTION_EVENT: {}", json);
            }

            // Learn attack pattern for future attribution
            if attribution.as_ref().map(|(p, _)| p.as_str()) != Some("normal_baseline") {
                let norm = tracker.read().await.recent_acc.iter()
                    .map(|x| x * x).sum::<f64>().sqrt();
                if norm > 0.0 {
                    let data: Vec<i8> = tracker.read().await.recent_acc.iter()
                        .map(|&x| {
                            let normalized = x / norm;
                            if normalized > 0.01 { 1 }
                            else if normalized < -0.01 { -1 }
                            else { 0 }
                        })
                        .collect();
                    let attack_vec = Vector::from_data(data);
                    let attack_name = format!("attack_t{}", ticks_processed);
                    tracker.write().await.add_attack_pattern(&attack_name, attack_vec);
                }
            }
        } else if anomaly.drift >= args.threshold {
            if anomaly_active_since.is_some() {
                let duration = anomaly_active_since
                    .map(|start| ticks_processed - start)
                    .unwrap_or(0);
                info!("    Status: NORMAL (recovered after {} ticks)", duration);
                anomaly_active_since = None;
            } else {
                info!("    Status: NORMAL (drift above threshold)");
            }
        }

        // ── Payload rule derivation (at tick) ──
        {
            let mut payload_tracker_write = payload_tracker.write().await;

            payload_tracker_write.expire_old_dsts(Duration::from_secs(600));

            let engram_event = payload_tracker_write.tick_engram_lifecycle(ticks_processed);

            let engram_hit = matches!(engram_event, PayloadEngramEvent::Hit { .. });

            match engram_event {
                PayloadEngramEvent::Hit { stored_rules, .. } if !stored_rules.is_empty() => {
                    drop(payload_tracker_write);
                    let mut deployed = Vec::new();
                    for edn_str in &stored_rules {
                        match edn_rs::Edn::from_str(edn_str) {
                            Ok(edn) => match parse_edn_rule(&edn) {
                                Ok(spec) => deployed.push(spec),
                                Err(e) => warn!("  Failed to parse stored payload rule: {}", e),
                            },
                            Err(e) => warn!("  Failed to parse stored payload rule EDN: {}", e),
                        }
                    }
                    if !deployed.is_empty() {
                        let mut rules = active_rules.write().await;
                        let newly_added = upsert_rules(
                            &deployed, &mut rules, &bucket_key_to_spec,
                            &tree_dirty, &metrics_state, "PAYLOAD-ENGRAM-RULE",
                        ).await;
                        if !newly_added.is_empty() {
                            for spec in &deployed {
                                warn!("    PAYLOAD ENGRAM RULE:\n{}", spec.to_edn_pretty());
                            }
                        }
                        if tree_dirty.load(std::sync::atomic::Ordering::SeqCst) && args.enforce {
                            if let Err(e) = recompile_tree_and_broadcast(
                                &filter, &rules, &tree_counter_labels,
                                &tree_dirty, &metrics_state, "payload engram hit",
                            ).await {
                                warn!("  Failed to compile tree: {}", e);
                            }
                        }
                    }
                }
                PayloadEngramEvent::Minted { ref name } => {
                    let rules_snapshot: Vec<String> = active_rules.read().await
                        .values()
                        .filter(|r| !r.preloaded)
                        .filter(|r| r.spec.constraints.iter().any(|p| matches!(p, Predicate::RawByteMatch(_))))
                        .map(|r| r.spec.to_edn())
                        .collect();

                    if !rules_snapshot.is_empty() {
                        payload_tracker_write.update_engram_metadata(
                            name, "rules", serde_json::json!(rules_snapshot),
                        );
                        warn!("    Stored {} payload rule(s) in engram '{}'", rules_snapshot.len(), name);
                    }
                    drop(payload_tracker_write);
                }
                _ => { drop(payload_tracker_write); }
            }

            let payload_rules = if !engram_hit {
                payload_tracker.write().await.check_and_derive_rules(estimated_pps, ft_rate_factor)
            } else {
                Vec::new()
            };

            if !payload_rules.is_empty() {
                info!(">>> PAYLOAD ANOMALIES DETECTED: {} rule(s) derived", payload_rules.len());

                let mut rules = active_rules.write().await;
                let newly_added_keys = upsert_rules(
                    &payload_rules, &mut rules, &bucket_key_to_spec,
                    &tree_dirty, &metrics_state, "Payload rule",
                ).await;

                if tree_dirty.load(std::sync::atomic::Ordering::SeqCst) && args.enforce {
                    if let Err(e) = recompile_tree_and_broadcast(
                        &filter, &rules, &tree_counter_labels,
                        &tree_dirty, &metrics_state, "payload rules",
                    ).await {
                        warn!("    Failed to compile tree (payload rules): {}", e);
                    }
                }

                if !newly_added_keys.is_empty() {
                    let added_set: HashSet<&str> = newly_added_keys.iter().map(|s| s.as_str()).collect();
                    let mut pt = payload_tracker.write().await;
                    for spec in &payload_rules {
                        let key = rule_identity_key(spec);
                        if added_set.contains(key.as_str()) {
                            if let Some(pk) = PayloadTracker::pattern_dedup_key(spec) {
                                pt.mark_rule_active(pk, key);
                            }
                        }
                    }
                }
            }
        }

        // Snapshot history for segment detection
        tracker.write().await.snapshot_history();

        // ── Expire old rules ──
        let rule_ttl = Duration::from_secs(300);
        let mut rules = active_rules.write().await;
        let expired: Vec<String> = rules
            .iter()
            .filter(|(_, active)| !active.preloaded && active.last_seen.elapsed() > rule_ttl)
            .map(|(k, _)| k.clone())
            .collect();

        let had_expired = !expired.is_empty();
        if had_expired {
            let mut pt = payload_tracker.write().await;
            for key in &expired {
                pt.mark_rule_expired(key);
            }
        }
        for key in expired {
            if let Some(active) = rules.remove(&key) {
                info!("<<< EXPIRED RULE: {}", active.spec.describe());

                if let Some(ref state) = metrics_state {
                    state.broadcast(metrics_server::MetricsEvent::RuleEvent {
                        ts: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
                        action: "expired".to_string(),
                        key: key.clone(),
                        spec_summary: active.spec.to_edn(),
                        is_preloaded: false,
                        ttl_secs: 300,
                    });
                }
            }
        }

        if had_expired && args.enforce {
            if rules.is_empty() {
                if let Err(e) = filter.clear_tree().await {
                    warn!("Failed to clear tree: {}", e);
                } else {
                    info!("Tree cleared (all rules expired)");
                }
                tree_dirty.store(false, std::sync::atomic::Ordering::SeqCst);
            } else {
                if let Err(e) = recompile_tree_and_broadcast(
                    &filter, &rules, &tree_counter_labels,
                    &tree_dirty, &metrics_state, "after expiry",
                ).await {
                    warn!("Failed to recompile tree after expiry: {}", e);
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    #[allow(unreachable_code)]
    {
        // Save engram libraries on shutdown
        if let Some(ref path) = args.engram_library_path {
            let lib_path = path.to_string_lossy();
            let _ = std::fs::create_dir_all(path);
            tracker.read().await.subspace.save_library(&format!("{}/field_engrams.json", lib_path));
            payload_tracker.read().await.payload_subspace.save_library(&format!("{}/payload_engrams.json", lib_path));
        }

        Ok(())
    }
}
