//! Veth Lab Sidecar - Holon-based Anomaly Detection
//!
//! Reads packet samples from XDP ring buffer, encodes them with Holon,
//! detects anomalies using accumulator drift, and pushes drop rules back to XDP.
//!
//! This is a simplified version of Batch 013 detection, adapted for real-time use.

use anyhow::{Context, Result};
use chrono::Local;
use clap::Parser;
use holon::Holon;
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};
use veth_filter::{PacketSample, Rule, RuleAction, RuleType, VethFilter};

#[derive(Parser, Debug)]
#[command(name = "veth-sidecar")]
#[command(about = "Holon-based packet anomaly detection sidecar")]
struct Args {
    /// Interface with XDP filter attached
    #[arg(short, long, default_value = "veth-filter")]
    interface: String,

    /// Detection window in seconds
    #[arg(short, long, default_value = "2")]
    window: u64,

    /// Drift threshold for anomaly detection (0.0 - 1.0)
    /// Lower = more sensitive
    #[arg(short, long, default_value = "0.7")]
    threshold: f64,

    /// Minimum packets in window before detection
    #[arg(short, long, default_value = "50")]
    min_packets: usize,

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

    /// Warmup windows before detection starts
    /// During warmup, baseline is learned but no anomalies are flagged
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

    /// Perf buffer pages per CPU (smaller = less buffering, samples dropped when full)
    /// Default 4 pages = 16KB per CPU, fills/drops fast under load
    #[arg(long, default_value = "4")]
    perf_pages: usize,
}

/// Tracked statistics for a field value
struct ValueStats {
    count: u64,
    last_seen: Instant,
}

impl Default for ValueStats {
    fn default() -> Self {
        Self {
            count: 0,
            last_seen: Instant::now(),
        }
    }
}

/// Field tracker using Holon accumulators
struct FieldTracker {
    holon: Arc<Holon>,
    /// Baseline accumulator (stable reference - frozen after warmup)
    baseline_acc: Vec<f64>,
    /// Recent accumulator (current window)
    recent_acc: Vec<f64>,
    /// Packet counts per field value (for concentration)
    value_counts: HashMap<String, ValueStats>,
    /// Total packets in current window
    window_count: usize,
    /// Last window reset time
    last_reset: Instant,
    /// Whether baseline is frozen (after warmup)
    baseline_frozen: bool,
}

impl FieldTracker {
    fn new(holon: Arc<Holon>) -> Self {
        let dims = holon.dimensions();
        Self {
            holon,
            baseline_acc: vec![0.0; dims],
            recent_acc: vec![0.0; dims],
            value_counts: HashMap::new(),
            window_count: 0,
            last_reset: Instant::now(),
            baseline_frozen: false,
        }
    }

    /// Freeze the baseline (called after warmup)
    fn freeze_baseline(&mut self) {
        self.baseline_frozen = true;
    }

    /// Add a packet sample to the tracker
    fn add_sample(&mut self, sample: &PacketSample) {
        // Encode the packet structure
        let packet_json = serde_json::json!({
            "src_ip": sample.src_ip_addr().to_string(),
            "dst_ip": sample.dst_ip_addr().to_string(),
            "src_port": sample.src_port,
            "dst_port": sample.dst_port,
            "protocol": sample.protocol,
        });

        if let Ok(vec) = self.holon.encode_json(&packet_json.to_string()) {
            // Add to recent accumulator
            for (i, v) in vec.data().iter().enumerate() {
                self.recent_acc[i] += *v as f64;
            }
        }

        // Track individual field values for concentration analysis
        let fields = [
            ("src_ip", sample.src_ip_addr().to_string()),
            ("dst_ip", sample.dst_ip_addr().to_string()),
            ("src_port", sample.src_port.to_string()),
            ("dst_port", sample.dst_port.to_string()),
            ("protocol", sample.protocol.to_string()),
        ];

        for (field, value) in fields {
            let key = format!("{}:{}", field, value);
            let entry = self.value_counts.entry(key).or_default();
            entry.count += 1;
            entry.last_seen = Instant::now();
        }

        self.window_count += 1;
    }

    /// Get the similarity (drift) between baseline and recent
    fn compute_drift(&self) -> f64 {
        if self.window_count == 0 {
            return 1.0; // No drift if no data
        }

        // Normalize accumulators before comparison
        let baseline_norm = normalize(&self.baseline_acc);
        let recent_norm = normalize(&self.recent_acc);

        // Cosine similarity
        cosine_similarity(&baseline_norm, &recent_norm)
    }

    /// Find concentrated field values (potential attack indicators)
    fn find_concentrated_values(&self, threshold: f64) -> Vec<(String, String, f64)> {
        let mut results = Vec::new();

        if self.window_count == 0 {
            return results;
        }

        // Group by field
        let mut field_totals: HashMap<&str, u64> = HashMap::new();
        let mut field_values: HashMap<&str, Vec<(&str, u64)>> = HashMap::new();

        for (key, stats) in &self.value_counts {
            if let Some((field, value)) = key.split_once(':') {
                *field_totals.entry(field).or_default() += stats.count;
                field_values.entry(field).or_default().push((value, stats.count));
            }
        }

        // Find concentrated values
        for (field, total) in field_totals {
            if let Some(values) = field_values.get(field) {
                for (value, count) in values {
                    let concentration = *count as f64 / total as f64;
                    if concentration >= threshold {
                        results.push((
                            field.to_string(),
                            value.to_string(),
                            concentration,
                        ));
                    }
                }
            }
        }

        // Sort by concentration (highest first)
        results.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Reset the window (move recent to baseline, clear recent)
    fn reset_window(&mut self) {
        // Only update baseline during warmup (before frozen)
        // After warmup, baseline is frozen to prevent attack pollution
        if !self.baseline_frozen {
            let alpha = 0.3; // Weight for new data
            for i in 0..self.baseline_acc.len() {
                if self.window_count > 0 {
                    let recent_normalized = self.recent_acc[i] / self.window_count as f64;
                    self.baseline_acc[i] = (1.0 - alpha) * self.baseline_acc[i] + alpha * recent_normalized;
                }
            }
        }

        // Clear recent
        self.recent_acc.fill(0.0);
        self.value_counts.clear();
        self.window_count = 0;
        self.last_reset = Instant::now();
    }
}

/// Detection result
#[allow(dead_code)]  // Fields used for debugging/logging context
struct Detection {
    field: String,
    value: String,
    concentration: f64,
    drift: f64,
}

impl Detection {
    fn to_rule(&self) -> Option<Rule> {
        match self.field.as_str() {
            "src_ip" => {
                if let Ok(ip) = self.value.parse::<Ipv4Addr>() {
                    Some(Rule::drop_src_ip(ip))
                } else {
                    None
                }
            }
            "dst_port" => {
                if let Ok(port) = self.value.parse::<u16>() {
                    Some(Rule::drop_dst_port(port))
                } else {
                    None
                }
            }
            "src_port" => {
                if let Ok(port) = self.value.parse::<u16>() {
                    Some(Rule::drop_src_port(port))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
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

    info!("Veth Lab Sidecar - Holon Anomaly Detection");
    info!("  Interface: {}", args.interface);
    info!("  Window: {}s", args.window);
    info!("  Drift threshold: {}", args.threshold);
    info!("  Concentration threshold: {}", args.concentration);
    info!("  Enforce mode: {}", args.enforce);
    info!("  Dimensions: {}", args.dimensions);
    info!("  Warmup: {} windows / {} packets", args.warmup_windows, args.warmup_packets);
    info!("  Sample rate: 1 in {} packets", args.sample_rate);
    info!("  Perf buffer: {} pages/CPU ({}KB)", args.perf_pages, args.perf_pages * 4);
    info!("  Log file: {:?}", log_path);
    info!("");

    // Load XDP filter
    let filter = VethFilter::new(&args.interface)?;
    let filter = Arc::new(filter);

    // Configure filter
    filter.set_sample_rate(args.sample_rate).await?;  // 1 in N packets sampled
    filter.set_enforce_mode(args.enforce).await?;

    // Initialize Holon
    let holon = Arc::new(Holon::new(args.dimensions));
    info!("Holon initialized with {} dimensions", args.dimensions);

    // Create field tracker
    let tracker = Arc::new(RwLock::new(FieldTracker::new(holon.clone())));

    // Take perf array for sample reading
    let mut perf_array = filter.take_perf_array().await?;

    // Channel for samples from all CPUs (small capacity - drop if backed up)
    let (sample_tx, mut sample_rx) = tokio::sync::mpsc::channel::<PacketSample>(1000);

    // Spawn a task for each CPU to read from perf buffer
    let cpus = aya::util::online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))?;
    info!("Starting perf readers on {} CPUs ({} pages/CPU)", cpus.len(), args.perf_pages);

    for cpu_id in cpus {
        let mut buf = perf_array
            .open(cpu_id, Some(args.perf_pages))
            .context(format!("Failed to open perf buffer for CPU {}", cpu_id))?;
        let tx = sample_tx.clone();

        tokio::spawn(async move {
            use bytes::BytesMut;
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
                        // Use try_send to drop samples if channel is full (non-blocking)
                        match tx.try_send(sample) {
                            Ok(_) => {},
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                // Channel full - drop sample (expected under load)
                            }
                        }
                    }
                }
            }
        });
    }
    drop(sample_tx);  // Drop our copy so rx knows when tasks end

    // Tracked rules (so we don't add duplicates)
    let active_rules: Arc<RwLock<HashMap<String, Instant>>> = Arc::new(RwLock::new(HashMap::new()));

    info!("Starting detection loop...");
    info!("  Warmup: {} windows or {} packets", args.warmup_windows, args.warmup_packets);
    info!("");

    let window_duration = Duration::from_secs(args.window);
    let mut _samples_processed = 0u64;
    let mut windows_processed = 0u64;
    let mut total_warmup_packets = 0usize;
    let mut warmup_complete = false;

    // Track when we last checked the window
    let mut last_window_check = Instant::now();
    let check_interval = Duration::from_millis(100);

    // Max samples to process before checking window timer
    const MAX_SAMPLES_PER_CHECK: usize = 200;
    let mut samples_since_window_check = 0usize;

    loop {
        // Process a limited batch of samples
        let mut got_sample = false;
        let mut matched_rule_keys: Vec<String> = Vec::new();
        
        {
            let mut tracker = tracker.write().await;
            for _ in 0..MAX_SAMPLES_PER_CHECK {
                match sample_rx.try_recv() {
                    Ok(sample) => {
                        tracker.add_sample(&sample);
                        _samples_processed += 1;
                        samples_since_window_check += 1;
                        got_sample = true;
                        
                        // Collect matched samples to refresh rule TTLs later
                        if sample.matched_rule != 0 {
                            matched_rule_keys.push(format!("{:?}:{}", RuleType::SrcIp, sample.src_ip_addr()));
                            matched_rule_keys.push(format!("{:?}:{}", RuleType::DstPort, sample.dst_port));
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
        
        // Refresh TTL for rules that matched dropped packets (batch update)
        if !matched_rule_keys.is_empty() {
            let mut rules = active_rules.write().await;
            let now = Instant::now();
            for key in matched_rule_keys {
                if rules.contains_key(&key) {
                    rules.insert(key, now);
                }
            }
        }

        // Check window timer after each batch OR when idle
        let should_check_window = last_window_check.elapsed() >= check_interval 
            || samples_since_window_check >= 1000;  // Force check every 1000 samples
        
        if !should_check_window {
            if !got_sample {
                tokio::time::sleep(Duration::from_millis(5)).await;
            } else {
                tokio::task::yield_now().await;
            }
            continue;
        }
        
        last_window_check = Instant::now();
        samples_since_window_check = 0;

        // Check if window has elapsed
        let tracker_read = tracker.read().await;
        let window_elapsed = tracker_read.last_reset.elapsed() >= window_duration;
        let has_enough_samples = tracker_read.window_count >= args.min_packets;
        drop(tracker_read);

        if window_elapsed {
            windows_processed += 1;

            if has_enough_samples {
                // Analyze window
                let tracker_read = tracker.read().await;
                let drift = tracker_read.compute_drift();
                let concentrated = tracker_read.find_concentrated_values(args.concentration);
                let window_count = tracker_read.window_count;
                drop(tracker_read);

                // Track warmup progress
                total_warmup_packets += window_count;

                // Get stats from XDP
                let stats = filter.stats().await.ok();
                let drops = stats.as_ref().map(|s| s.dropped_packets).unwrap_or(0);
                let total = stats.as_ref().map(|s| s.total_packets).unwrap_or(0);

                // Check if warmup should complete
                if !warmup_complete {
                    let warmup_by_windows = windows_processed >= args.warmup_windows;
                    let warmup_by_packets = total_warmup_packets >= args.warmup_packets;
                    
                    if warmup_by_windows || warmup_by_packets {
                        warmup_complete = true;
                        // Freeze baseline to prevent attack pollution
                        tracker.write().await.freeze_baseline();
                        info!("========================================");
                        info!("WARMUP COMPLETE - baseline FROZEN");
                        info!("  Windows: {}, Packets: {}", windows_processed, total_warmup_packets);
                        info!("  Detection now active!");
                        info!("========================================");
                    } else {
                        info!(
                            "Window {} [WARMUP]: {} packets, drift={:.3} | XDP total: {}, dropped: {} | warmup {}/{} windows, {}/{} packets",
                            windows_processed, window_count, drift, total, drops,
                            windows_processed, args.warmup_windows,
                            total_warmup_packets, args.warmup_packets
                        );
                        // Reset window but don't do anomaly detection during warmup
                        let mut tracker_write = tracker.write().await;
                        tracker_write.reset_window();
                        continue;
                    }
                }
                
                info!(
                    "Window {}: {} packets, drift={:.3} | XDP total: {}, dropped: {}",
                    windows_processed, window_count, drift, total, drops
                );

                // Check for anomaly (only after warmup)
                if drift < args.threshold && !concentrated.is_empty() {
                    warn!(">>> ANOMALY DETECTED: drift={:.3} (threshold={})", drift, args.threshold);

                    for (field, value, conc) in &concentrated {
                        let detection = Detection {
                            field: field.clone(),
                            value: value.clone(),
                            concentration: *conc,
                            drift,
                        };

                        warn!(
                            "    Concentrated: {}={} ({:.1}%)",
                            field, value, conc * 100.0
                        );

                        // Generate and apply rule
                        if let Some(rule) = detection.to_rule() {
                            let rule_key = format!("{:?}:{}", rule.rule_type, rule.value);
                            
                            let mut rules = active_rules.write().await;
                            if rules.contains_key(&rule_key) {
                                // Rule exists - refresh TTL
                                rules.insert(rule_key, Instant::now());
                            } else {
                                // New rule - add it
                                if args.enforce {
                                    match filter.add_rule(&rule).await {
                                        Ok(_) => {
                                            warn!("    ADDED DROP RULE: {:?}={}", rule.rule_type, rule.value);
                                            rules.insert(rule_key, Instant::now());
                                        }
                                        Err(e) => {
                                            warn!("    Failed to add rule: {}", e);
                                        }
                                    }
                                } else {
                                    info!("    Would add rule (dry-run): {:?}={}", rule.rule_type, rule.value);
                                }
                            }
                        }
                    }
                } else if drift >= args.threshold {
                    info!("    Status: NORMAL (drift above threshold)");
                }
            } else {
                info!(
                    "Window {}: {} packets (below minimum {}, skipping analysis)",
                    windows_processed,
                    tracker.read().await.window_count,
                    args.min_packets
                );
            }

            // Reset window
            tracker.write().await.reset_window();

            // Expire old rules (after 5 minutes of no re-detection)
            // Note: Rules will naturally not be refreshed when attack is being blocked,
            // so TTL needs to be long enough to cover attack duration + margin
            let rule_ttl = Duration::from_secs(300);  // 5 minutes
            let mut rules = active_rules.write().await;
            let expired: Vec<String> = rules
                .iter()
                .filter(|(_, added)| added.elapsed() > rule_ttl)
                .map(|(k, _)| k.clone())
                .collect();

            for key in expired {
                // Parse key to remove rule
                if let Some((type_str, value)) = key.split_once(':') {
                    let rule_type = match type_str {
                        "SrcIp" => Some(RuleType::SrcIp),
                        "DstIp" => Some(RuleType::DstIp),
                        "SrcPort" => Some(RuleType::SrcPort),
                        "DstPort" => Some(RuleType::DstPort),
                        _ => None,
                    };

                    if let Some(rt) = rule_type {
                        let rule = Rule {
                            rule_type: rt,
                            value: value.to_string(),
                            action: RuleAction::Drop,
                            rate_pps: None,
                        };

                        if args.enforce {
                            if let Err(e) = filter.remove_rule(&rule).await {
                                warn!("Failed to remove expired rule: {}", e);
                            } else {
                                info!("<<< EXPIRED RULE: {:?}={}", rt, value);
                            }
                        }
                    }
                }
                rules.remove(&key);
            }
        }

        // Small sleep to prevent busy-waiting
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    #[allow(unreachable_code)]
    Ok(())
}

/// Normalize a vector to unit length
fn normalize(v: &[f64]) -> Vec<f64> {
    let norm: f64 = v.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm > 0.0 {
        v.iter().map(|x| x / norm).collect()
    } else {
        v.to_vec()
    }
}

/// Cosine similarity between two vectors
fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let norm_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    
    if norm_a > 0.0 && norm_b > 0.0 {
        dot / (norm_a * norm_b)
    } else {
        0.0
    }
}
