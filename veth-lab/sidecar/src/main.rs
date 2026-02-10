//! Veth Lab Sidecar - Holon-based Anomaly Detection
//!
//! Reads packet samples from XDP ring buffer, encodes them with Holon,
//! detects anomalies using accumulator drift, and pushes drop rules back to XDP.
//!
//! This is a simplified version of Batch 013 detection, adapted for real-time use.

use anyhow::{Context, Result};
use clap::Parser;
use holon::Holon;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;
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
    /// Baseline accumulator (stable reference)
    baseline_acc: Vec<f64>,
    /// Recent accumulator (current window)
    recent_acc: Vec<f64>,
    /// Packet counts per field value (for concentration)
    value_counts: HashMap<String, ValueStats>,
    /// Total packets in current window
    window_count: usize,
    /// Last window reset time
    last_reset: Instant,
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
        }
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
        // Update baseline with exponential moving average
        let alpha = 0.3; // Weight for new data
        for i in 0..self.baseline_acc.len() {
            if self.window_count > 0 {
                let recent_normalized = self.recent_acc[i] / self.window_count as f64;
                self.baseline_acc[i] = (1.0 - alpha) * self.baseline_acc[i] + alpha * recent_normalized;
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
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();

    info!("Veth Lab Sidecar - Holon Anomaly Detection");
    info!("  Interface: {}", args.interface);
    info!("  Window: {}s", args.window);
    info!("  Drift threshold: {}", args.threshold);
    info!("  Concentration threshold: {}", args.concentration);
    info!("  Enforce mode: {}", args.enforce);
    info!("  Dimensions: {}", args.dimensions);
    info!("");

    // Load XDP filter
    let filter = VethFilter::new(&args.interface)?;
    let filter = Arc::new(filter);

    // Configure filter
    filter.set_sample_rate(1).await?;  // Sample all packets
    filter.set_enforce_mode(args.enforce).await?;

    // Initialize Holon
    let holon = Arc::new(Holon::new(args.dimensions));
    info!("Holon initialized with {} dimensions", args.dimensions);

    // Create field tracker
    let tracker = Arc::new(RwLock::new(FieldTracker::new(holon.clone())));

    // Take perf array for sample reading
    let mut perf_array = filter.take_perf_array().await?;

    // Channel for samples from all CPUs
    let (sample_tx, mut sample_rx) = tokio::sync::mpsc::channel::<PacketSample>(10000);

    // Spawn a task for each CPU to read from perf buffer
    let cpus = aya::util::online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))?;
    info!("Starting perf readers on {} CPUs", cpus.len());

    for cpu_id in cpus {
        let mut buf = perf_array
            .open(cpu_id, None)
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
                        if tx.send(sample).await.is_err() {
                            return;
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
    info!("");

    let window_duration = Duration::from_secs(args.window);
    let mut _samples_processed = 0u64;
    let mut windows_processed = 0u64;

    // Track when we last checked the window
    let mut last_window_check = Instant::now();
    let check_interval = Duration::from_millis(100);

    loop {
        // Drain available samples (non-blocking after first)
        let mut samples_this_batch = 0;
        loop {
            match sample_rx.try_recv() {
                Ok(sample) => {
                    let mut tracker = tracker.write().await;
                    tracker.add_sample(&sample);
                    _samples_processed += 1;
                    samples_this_batch += 1;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    info!("Sample channel closed");
                    return Ok(());
                }
            }
        }

        // Only check window periodically
        if last_window_check.elapsed() < check_interval {
            // Small yield to avoid busy-waiting when no samples
            if samples_this_batch == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            continue;
        }
        last_window_check = Instant::now();

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

                // Get stats from XDP
                let stats = filter.stats().await.ok();
                let drops = stats.as_ref().map(|s| s.dropped_packets).unwrap_or(0);
                let total = stats.as_ref().map(|s| s.total_packets).unwrap_or(0);
                
                info!(
                    "Window {}: {} packets, drift={:.3} | XDP total: {}, dropped: {}",
                    windows_processed, window_count, drift, total, drops
                );

                // Check for anomaly
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
                            if !rules.contains_key(&rule_key) {
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

            // Expire old rules (after 30 seconds of no re-detection)
            let rule_ttl = Duration::from_secs(30);
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
