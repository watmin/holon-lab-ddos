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

mod metrics_server;

use anyhow::{Context, Result};
use chrono::{DateTime, Local, Utc};
use clap::Parser;
use edn_rs::Edn;
use holon::{Holon, Primitives, ScalarValue, SegmentMethod, Vector, WalkableValue};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::BufRead;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};
use veth_filter::{
    FieldDim, PacketSample, Predicate, RuleAction, RuleSpec, VethFilter,
};

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
}

// =============================================================================
// Detection Event Structure (Phase 6: Enhanced Logging)
// =============================================================================

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

// =============================================================================
// Attack Codebook (Phase 3.3: invert() attribution)
// =============================================================================

/// Known attack patterns for attribution
struct AttackCodebook {
    patterns: Vec<(String, Vector)>,
}

impl AttackCodebook {
    fn new() -> Self {
        Self { patterns: Vec::new() }
    }

    /// Add a named pattern to the codebook
    fn add_pattern(&mut self, name: &str, vector: Vector) {
        self.patterns.push((name.to_string(), vector));
    }

    /// Attribute a sample to the most similar pattern
    fn attribute(&self, sample_vec: &Vector) -> Option<(String, f64)> {
        if self.patterns.is_empty() {
            return None;
        }

        let codebook_vecs: Vec<Vector> = self.patterns.iter()
            .map(|(_, v)| v.clone())
            .collect();

        let matches = Primitives::invert(sample_vec, &codebook_vecs, 1, 0.3);

        matches.first().map(|(idx, sim)| {
            (self.patterns[*idx].0.clone(), *sim)
        })
    }

    /// Check if codebook has patterns
    fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

// =============================================================================
// Variant Detector (Phase 4: analogy() for zero-shot detection)
// =============================================================================

/// Zero-shot attack variant detection using analogy
struct VariantDetector {
    /// Known attack prototype (e.g., DNS reflection)
    known_attack_proto: Option<Vector>,
    /// Port vector for the known attack (e.g., port 53 for DNS)
    known_port_vec: Option<Vector>,
    /// Name of the known attack
    known_attack_name: String,
}

impl VariantDetector {
    fn new() -> Self {
        Self {
            known_attack_proto: None,
            known_port_vec: None,
            known_attack_name: String::new(),
        }
    }

    /// Train on a known attack pattern
    fn train(&mut self, name: &str, attack_proto: Vector, port_vec: Vector) {
        self.known_attack_name = name.to_string();
        self.known_attack_proto = Some(attack_proto);
        self.known_port_vec = Some(port_vec);
    }

    /// Detect variant attacks using analogy
    fn detect_variant(&self, sample_vec: &Vector, sample_port: u16, holon: &Holon) -> Option<f64> {
        let known_proto = self.known_attack_proto.as_ref()?;
        let known_port = self.known_port_vec.as_ref()?;

        // Generate port vector for sample
        let sample_port_vec = holon.get_vector(&format!("port_{}", sample_port));

        // A:B :: C:? - if known_attack is to known_port as ? is to sample_port
        let inferred_attack = Primitives::analogy(known_proto, known_port, &sample_port_vec);

        // How similar is the sample to the inferred attack?
        Some(holon.similarity(sample_vec, &inferred_attack))
    }

    fn is_trained(&self) -> bool {
        self.known_attack_proto.is_some()
    }
}

// =============================================================================
// Anomaly Details (Phase 3.1: similarity_profile analysis)
// =============================================================================

/// Detailed anomaly analysis from similarity_profile
#[derive(Debug, Clone)]
struct AnomalyDetails {
    /// Overall drift (cosine similarity to baseline)
    drift: f64,
    /// Fraction of dimensions that disagree with baseline
    anomalous_ratio: f64,
    /// Similarity profile vector
    profile: Vector,
    /// Agreement strength (mean of agreeing dimensions)
    agreement_strength: f64,
    /// Disagreement strength (mean abs of disagreeing dimensions)
    disagreement_strength: f64,
}

// =============================================================================
// Field Tracker with Extended Primitives
// =============================================================================

/// Tracked statistics for a field value with lazy exponential decay.
///
/// Instead of resetting counts each window, each entry decays independently
/// based on how many packets have elapsed since its last update.
struct ValueStats {
    count: f64,
    last_seen: Instant,
    /// Packet counter at last update (for lazy decay computation)
    last_decay_pkt: u64,
}

impl ValueStats {
    /// Return the decayed count as of `current_pkt` using per-packet factor `alpha`.
    fn decayed_count(&self, current_pkt: u64, alpha: f64) -> f64 {
        let elapsed = current_pkt.saturating_sub(self.last_decay_pkt);
        if elapsed == 0 { return self.count; }
        self.count * alpha.powi(elapsed as i32)
    }

    /// Decay to `current_pkt`, then add 1.0.
    fn add_one(&mut self, current_pkt: u64, alpha: f64) {
        let elapsed = current_pkt.saturating_sub(self.last_decay_pkt);
        if elapsed > 0 {
            self.count *= alpha.powi(elapsed as i32);
            self.last_decay_pkt = current_pkt;
        }
        self.count += 1.0;
        self.last_seen = Instant::now();
    }
}

impl Default for ValueStats {
    fn default() -> Self {
        Self {
            count: 0.0,
            last_seen: Instant::now(),
            last_decay_pkt: 0,
        }
    }
}

/// Enhanced field tracker using Holon primitives with per-packet decay.
///
/// Instead of fixed 2-second windows with hard resets, the accumulator decays
/// exponentially after each packet so recent traffic naturally dominates.
struct FieldTracker {
    holon: Arc<Holon>,
    /// Baseline accumulator (float, averaged during warmup)
    baseline_acc: Vec<f64>,
    /// Baseline vector (frozen after warmup, used for comparison)
    baseline_vec: Vector,
    /// Recent accumulator — decays per-packet after warmup
    recent_acc: Vec<f64>,
    /// Packet counts per field value (for concentration, with lazy decay)
    value_counts: HashMap<String, ValueStats>,
    /// Baseline value counts (accumulated during warmup)
    baseline_value_counts: HashMap<String, u64>,
    /// Values that were concentrated during baseline (key: "field:value")
    baseline_concentrated: HashSet<String>,
    /// Total packets seen during warmup (for proper averaging)
    warmup_total_packets: usize,
    /// Number of warmup ticks (for averaging)
    warmup_ticks_count: usize,
    /// Whether baseline is frozen (after warmup)
    baseline_frozen: bool,
    /// Window vectors for segment() detection
    window_history: VecDeque<Vector>,
    /// Drift-to-baseline similarity history for drift_rate computation.
    /// With decay-based accumulators, consecutive window vectors are nearly identical,
    /// so drift_rate must operate on the similarity-to-baseline time series instead.
    drift_history: VecDeque<f64>,
    /// Current phase (detected by segment)
    current_phase: String,
    /// Attack codebook for attribution
    codebook: AttackCodebook,
    /// Variant detector
    variant_detector: VariantDetector,
    /// Per-packet decay factor: 0.5^(1/half_life)
    decay_factor: f64,
    /// Monotonic packet counter (for lazy value-count decay)
    packets_processed: u64,
    /// Decaying effective packet count (for concentration denominator)
    total_effective: f64,
    /// Baseline per-effective-packet magnitude (set at freeze)
    baseline_steady_magnitude: f64,
    /// Time-decayed rate accumulator — magnitude encodes PPS
    rate_acc: Vec<f64>,
    /// Wall-clock time of last time-based decay application
    rate_last_update: Instant,
    /// Time-decay constant: ln(2) / half_life_seconds
    rate_lambda: f64,
    /// ||rate_acc|| at freeze time (baseline PPS encoded as magnitude)
    baseline_rate_magnitude: f64,
}

impl FieldTracker {
    fn new(holon: Arc<Holon>, decay_half_life: usize, rate_half_life_ms: u64) -> Self {
        let dims = holon.dimensions();
        let decay_factor = if decay_half_life > 0 {
            0.5_f64.powf(1.0 / decay_half_life as f64)
        } else {
            1.0 // no decay
        };
        let rate_lambda = (2.0_f64).ln() / (rate_half_life_ms as f64 / 1000.0);
        Self {
            holon,
            baseline_acc: vec![0.0; dims],
            baseline_vec: Vector::zeros(dims),
            recent_acc: vec![0.0; dims],
            value_counts: HashMap::new(),
            baseline_value_counts: HashMap::new(),
            baseline_concentrated: HashSet::new(),
            warmup_total_packets: 0,
            warmup_ticks_count: 0,
            baseline_frozen: false,
            window_history: VecDeque::new(),
            drift_history: VecDeque::new(),
            current_phase: "learning".to_string(),
            codebook: AttackCodebook::new(),
            variant_detector: VariantDetector::new(),
            decay_factor,
            packets_processed: 0,
            total_effective: 0.0,
            baseline_steady_magnitude: 0.0,
            rate_acc: vec![0.0; dims],
            rate_last_update: Instant::now(),
            rate_lambda,
            baseline_rate_magnitude: 0.0,
        }
    }

    /// Compute per-field diversity spectrum via unbinding.
    /// 
    /// Returns [(field_name, diversity_score)] sorted by diversity (low to high).
    /// Low diversity (→1.0) = concentrated (few unique values, possibly attack).
    /// High diversity (→0.0) = dispersed (many unique values, likely normal).
    // NOTE: magnitude_spectrum via unbinding was removed. The approach of
    // element-wise multiplying the accumulator by bipolar role vectors (±1)
    // and measuring L2 norm is mathematically degenerate: |a*r|² = a²·r² = a²
    // regardless of which role vector r is used, since r² = 1 for all bipolar
    // elements. This produces identical "diversity" values for every field.
    // Per-field diversity is already correctly measured by find_concentrated_values()
    // which uses actual per-value counters.

    /// Freeze the baseline (called after warmup).
    ///
    /// After freezing, snapshots the rate vector magnitude (baseline PPS) and
    /// clears the direction accumulator for decay-based monitoring.
    fn freeze_baseline(&mut self) {
        // Fold any remaining recent_acc into baseline before freezing
        self.accumulate_warmup();

        self.baseline_frozen = true;
        self.current_phase = "monitoring".to_string();

        // Create normalized baseline vector from accumulated warmup data
        let norm = self.baseline_acc.iter().map(|x| x * x).sum::<f64>().sqrt();

        info!("Baseline magnitude: total={:.2} ({} ticks, {} packets)",
              norm, self.warmup_ticks_count, self.warmup_total_packets);

        if norm > 0.0 {
            let data: Vec<i8> = self.baseline_acc.iter()
                .map(|&x| {
                    let normalized = x / norm;
                    if normalized > 0.01 { 1 }
                    else if normalized < -0.01 { -1 }
                    else { 0 }
                })
                .collect();
            self.baseline_vec = Vector::from_data(data);
        }

        // Compute what was concentrated during baseline (threshold 0.5 = majority)
        let mut field_totals: HashMap<&str, u64> = HashMap::new();
        let mut field_values: HashMap<&str, Vec<(&str, u64)>> = HashMap::new();

        for (key, &count) in &self.baseline_value_counts {
            if let Some((field, value)) = key.split_once(':') {
                *field_totals.entry(field).or_default() += count;
                field_values.entry(field).or_default().push((value, count));
            }
        }

        for (field, total) in &field_totals {
            if let Some(values) = field_values.get(field) {
                for (value, count) in values {
                    let concentration = *count as f64 / *total as f64;
                    if concentration >= 0.5 {
                        let key = format!("{}:{}", field, value);
                        self.baseline_concentrated.insert(key);
                    }
                }
            }
        }

        info!("Baseline concentrated values: {:?}", self.baseline_concentrated);

        let nnz = self.baseline_vec.data().iter().filter(|&&x| x != 0).count();
        info!("Baseline built from {} total packets, {} non-zero dimensions ({:.1}%)",
              self.warmup_total_packets, nnz, 100.0 * nnz as f64 / self.baseline_vec.dimensions() as f64);

        self.codebook.add_pattern("normal_baseline", self.baseline_vec.clone());

        // Store baseline per-effective-packet magnitude (kept for diagnostic use).
        let warmup_pkts = self.warmup_total_packets.max(1) as f64;
        self.baseline_steady_magnitude = norm / warmup_pkts;

        // Snapshot rate accumulator magnitude — this encodes baseline PPS.
        // The rate_acc has been running with time-based decay since startup,
        // so after ~10s of warmup (many half-lives) it's at steady state.
        self.baseline_rate_magnitude = self.rate_acc.iter()
            .map(|x| x * x).sum::<f64>().sqrt();
        info!("Rate vector baseline magnitude: {:.2} (time-decay lambda={:.4}, half-life={:.1}ms)",
              self.baseline_rate_magnitude, self.rate_lambda, (2.0_f64).ln() / self.rate_lambda * 1000.0);

        // Clear direction state for decay-based processing.
        // Do NOT clear rate_acc — it's already at steady state.
        self.recent_acc.fill(0.0);
        self.value_counts.clear();
        self.total_effective = 0.0;
    }

    /// Add a learned attack pattern to codebook
    fn add_attack_pattern(&mut self, name: &str, vector: Vector) {
        self.codebook.add_pattern(name, vector.clone());

        // If this is the first attack pattern, use it for variant detection
        if !self.variant_detector.is_trained() {
            // Extract dominant port from the attack for analogy
            // For now, use a simple heuristic
            let port_vec = self.holon.get_vector("port_53"); // DNS by default
            self.variant_detector.train(name, vector, port_vec);
        }
    }

    /// Add a packet sample to the tracker (using Walkable encoding).
    ///
    /// After warmup, applies per-packet exponential decay to `recent_acc` so
    /// recent traffic naturally dominates the accumulator.
    fn add_sample(&mut self, sample: &PacketSample) {
        // Apply per-packet decay BEFORE adding (so the new sample is at full weight)
        if self.baseline_frozen {
            let alpha = self.decay_factor;
            for v in &mut self.recent_acc {
                *v *= alpha;
            }
            self.total_effective = self.total_effective * alpha + 1.0;
        } else {
            self.total_effective += 1.0;
        }

        // Use Walkable encoding (5x faster than JSON)
        let vec = self.holon.encode_walkable(sample);

        // Add to recent accumulator (per-packet-decayed, direction only)
        for (i, v) in vec.data().iter().enumerate() {
            self.recent_acc[i] += *v as f64;
        }

        // Time-based decay for rate accumulator (runs during warmup AND monitoring
        // so the accumulator reaches steady state before freeze)
        let now = Instant::now();
        let dt = now.duration_since(self.rate_last_update).as_secs_f64();
        if dt > 0.0 {
            let decay = (-self.rate_lambda * dt).exp();
            for v in &mut self.rate_acc {
                *v *= decay;
            }
            self.rate_last_update = now;
        }
        // Add same VSA vector to rate accumulator (magnitude encodes PPS)
        for (i, v) in vec.data().iter().enumerate() {
            self.rate_acc[i] += *v as f64;
        }

        self.packets_processed += 1;

        // Track individual field values for concentration analysis
        // All values are raw numbers — same as wireshark/eBPF sees
        let pkt = self.packets_processed;
        let alpha = self.decay_factor;
        let mut fields = vec![
            ("src_ip", sample.src_ip_addr().to_string()),
            ("dst_ip", sample.dst_ip_addr().to_string()),
            ("src_port", sample.src_port.to_string()),
            ("dst_port", sample.dst_port.to_string()),
            ("protocol", sample.protocol.to_string()),
            ("src_port_band", sample.src_port_band().to_string()),
            ("dst_port_band", sample.dst_port_band().to_string()),
            ("direction", sample.direction().to_string()),
            ("size_class", sample.size_class().to_string()),
            // p0f-level fields (raw numeric)
            ("ttl", sample.ttl.to_string()),
            ("df_bit", sample.df_bit.to_string()),
            // IPv4 header fingerprinting fields (raw numeric)
            ("ip_id", sample.ip_id.to_string()),
            ("ip_len", sample.ip_len.to_string()),
            ("dscp", sample.dscp.to_string()),
            ("ecn", sample.ecn.to_string()),
            ("mf_bit", sample.mf_bit.to_string()),
            ("frag_offset", sample.frag_offset.to_string()),
        ];
        // TCP-only p0f fields
        if sample.protocol == 6 {
            fields.push(("tcp_flags", sample.tcp_flags.to_string()));
            fields.push(("tcp_window", sample.tcp_window.to_string()));
        }

        for (field, value) in fields {
            let key = format!("{}:{}", field, value);
            let entry = self.value_counts.entry(key).or_default();
            if self.baseline_frozen {
                entry.add_one(pkt, alpha);
            } else {
                entry.count += 1.0;
                entry.last_seen = Instant::now();
            }
        }
    }

    /// Compute magnitude ratio: ||recent_acc|| / ||baseline_steady||
    /// This gives us the rate multiplier - purely from vector operations
    /// If ratio = 10, we're seeing 10x the traffic rate
    /// Compute rate factor from the time-decayed rate accumulator.
    ///
    /// The rate_acc uses wall-clock time-based decay (e^{-lambda * dt}), making
    /// its magnitude proportional to PPS at steady state.  The ratio of current
    /// magnitude to baseline magnitude gives the traffic volume multiplier:
    ///   ratio ≈ current_pps / baseline_pps
    ///   rate_factor = 1 / ratio  (capped at 1.0)
    ///
    /// This vector encodes both DIRECTION (traffic pattern) and VOLUME (PPS),
    /// making it distributable to a fleet of scrubbers.
    #[allow(dead_code)]
    fn compute_rate_factor(&self) -> f64 {
        if self.baseline_rate_magnitude < 1e-10 { return 1.0; }
        let current_mag = self.rate_acc.iter()
            .map(|x| x * x).sum::<f64>().sqrt();
        let ratio = current_mag / self.baseline_rate_magnitude;
        if ratio > 0.0 { (1.0 / ratio).min(1.0) } else { 1.0 }
    }

    /// Compute detailed anomaly analysis using similarity_profile
    fn compute_anomaly_details(&self) -> AnomalyDetails {
        if self.total_effective < 1.0 {
            return AnomalyDetails {
                drift: 1.0,
                anomalous_ratio: 0.0,
                profile: Vector::zeros(self.holon.dimensions()),
                agreement_strength: 1.0,
                disagreement_strength: 0.0,
            };
        }

        // Create normalized recent vector
        // Use same threshold (0.01) as baseline for consistency
        let norm = self.recent_acc.iter().map(|x| x * x).sum::<f64>().sqrt();
        let recent_vec = if norm > 0.0 {
            let data: Vec<i8> = self.recent_acc.iter()
                .map(|&x| {
                    let normalized = x / norm;
                    if normalized > 0.01 { 1 }
                    else if normalized < -0.01 { -1 }
                    else { 0 }
                })
                .collect();
            Vector::from_data(data)
        } else {
            Vector::zeros(self.holon.dimensions())
        };

        // Compute similarity profile (per-dimension agreement)
        let profile = Primitives::similarity_profile(&recent_vec, &self.baseline_vec);

        // Analyze dimension agreement
        let recent_data = recent_vec.data();
        let profile_data = profile.data();

        let active_mask: Vec<bool> = recent_data.iter()
            .map(|&v| v != 0)
            .collect();
        let active_dims = active_mask.iter().filter(|&&b| b).count();

        if active_dims == 0 {
            return AnomalyDetails {
                drift: 1.0,
                anomalous_ratio: 0.0,
                profile,
                agreement_strength: 1.0,
                disagreement_strength: 0.0,
            };
        }

        // Count agreeing vs disagreeing dimensions
        let mut agreeing = 0usize;
        let mut disagreeing = 0usize;
        let mut agree_sum = 0.0f64;
        let mut disagree_sum = 0.0f64;

        for (i, &active) in active_mask.iter().enumerate() {
            if active {
                let p = profile_data[i] as f64;
                if p > 0.0 {
                    agreeing += 1;
                    agree_sum += p;
                } else if p < 0.0 {
                    disagreeing += 1;
                    disagree_sum += p.abs();
                }
            }
        }

        let agreement_strength = if agreeing > 0 { agree_sum / agreeing as f64 } else { 0.5 };
        let disagreement_strength = if disagreeing > 0 { disagree_sum / disagreeing as f64 } else { 0.0 };
        let anomalous_ratio = disagreeing as f64 / active_dims as f64;

        // Compute drift (cosine similarity)
        let drift = self.holon.similarity(&recent_vec, &self.baseline_vec);

        // Debug: log vector stats periodically
        let recent_nnz = recent_vec.data().iter().filter(|&&x| x != 0).count();
        let baseline_nnz = self.baseline_vec.data().iter().filter(|&&x| x != 0).count();
        if self.total_effective > 100.0 {
            tracing::debug!(
                "Vector stats: recent_nnz={}, baseline_nnz={}, drift={:.3}",
                recent_nnz, baseline_nnz, drift
            );
        }

        AnomalyDetails {
            drift,
            anomalous_ratio,
            profile,
            agreement_strength,
            disagreement_strength,
        }
    }

    /// Detect phase changes using segment()
    fn detect_phase_changes(&mut self) -> Option<String> {
        if self.window_history.len() < 10 {
            return None;
        }

        let breakpoints = Primitives::segment(
            self.window_history.make_contiguous(),
            5,    // window size for comparison
            0.7,  // threshold (higher = less sensitive)
            SegmentMethod::Diff
        );

        if !breakpoints.is_empty() {
            let last_bp = breakpoints.last().unwrap();
            if *last_bp == self.window_history.len() - 1 {
                let new_phase = format!("phase_{}", self.window_history.len());
                self.current_phase = new_phase.clone();
                return Some(new_phase);
            }
        }

        None
    }

    /// Record the current drift-to-baseline similarity for drift_rate computation.
    /// Must be called each post-warmup analysis tick with the latest anomaly.drift.
    fn record_drift(&mut self, drift: f64) {
        self.drift_history.push_back(drift);
        if self.drift_history.len() > 100 {
            self.drift_history.pop_front();
        }
    }

    /// Compute drift rate: average per-tick change in drift-to-baseline similarity.
    ///
    /// With decay-based accumulators, consecutive window vectors are nearly identical
    /// (differ by ~15 new packets out of thousands), so the old approach of computing
    /// Primitives::drift_rate on bipolarized window snapshots always returned ~0.
    ///
    /// Instead, we track the drift-to-baseline similarity time series directly
    /// (e.g. 0.986, 0.966, 0.945, ...) and compute the average delta over `window` ticks.
    ///
    /// Negative = similarity decreasing (attack onset).
    /// Large negative (< -0.02) = flash flood (instant onset at full volume).
    /// Moderate negative (< -0.005) = ramp-up attack (gradual escalation).
    fn compute_drift_rate(&self, window: usize) -> Option<f64> {
        if self.drift_history.len() < window + 1 {
            return None;
        }
        let len = self.drift_history.len();
        let mut total_delta = 0.0;
        for i in (len - window)..len {
            total_delta += self.drift_history[i] - self.drift_history[i - 1];
        }
        Some(total_delta / window as f64)
    }

    /// Attribute current accumulator state to known patterns
    fn attribute_pattern(&self) -> Option<(String, f64)> {
        if self.codebook.is_empty() || self.total_effective < 1.0 {
            return None;
        }

        // Create vector from recent window
        let norm = self.recent_acc.iter().map(|x| x * x).sum::<f64>().sqrt();
        if norm == 0.0 {
            return None;
        }

        let data: Vec<i8> = self.recent_acc.iter()
            .map(|&x| {
                let normalized = x / norm;
                if normalized > 0.01 { 1 }
                else if normalized < -0.01 { -1 }
                else { 0 }
            })
            .collect();
        let window_vec = Vector::from_data(data);

        self.codebook.attribute(&window_vec)
    }

    /// Find concentrated field values (potential attack indicators).
    ///
    /// Uses decayed counts so concentration naturally reflects recent traffic.
    fn find_concentrated_values(&self, threshold: f64) -> Vec<(String, String, f64)> {
        let mut results = Vec::new();

        if self.total_effective < 1.0 {
            return results;
        }

        let pkt = self.packets_processed;
        let alpha = self.decay_factor;

        // Group by field using decayed counts
        let mut field_totals: HashMap<&str, f64> = HashMap::new();
        let mut field_values: HashMap<&str, Vec<(&str, f64)>> = HashMap::new();

        for (key, stats) in &self.value_counts {
            if let Some((field, value)) = key.split_once(':') {
                let dc = if self.baseline_frozen {
                    stats.decayed_count(pkt, alpha)
                } else {
                    stats.count
                };
                if dc < 0.01 { continue; } // prune negligible entries
                *field_totals.entry(field).or_default() += dc;
                field_values.entry(field).or_default().push((value, dc));
            }
        }

        // Find concentrated values that are NEW (not in baseline)
        for (field, total) in field_totals {
            if total < 0.01 { continue; }
            if let Some(values) = field_values.get(field) {
                for (value, count) in values {
                    let concentration = *count / total;
                    if concentration >= threshold {
                        let key = format!("{}:{}", field, value);

                        // Skip values that were concentrated during baseline
                        if self.baseline_concentrated.contains(&key) {
                            continue;
                        }

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

    /// Snapshot the current accumulator state into window_history for segment() detection.
    /// Called at each analysis tick (replaces the window_history push from reset_window).
    fn snapshot_history(&mut self) {
        if self.total_effective < 1.0 { return; }

        let norm = self.recent_acc.iter().map(|x| x * x).sum::<f64>().sqrt();
        if norm > 0.0 {
            let data: Vec<i8> = self.recent_acc.iter()
                .map(|&x| {
                    let normalized = x / norm;
                    if normalized > 0.01 { 1 }
                    else if normalized < -0.01 { -1 }
                    else { 0 }
                })
                .collect();
            self.window_history.push_back(Vector::from_data(data));

            if self.window_history.len() > 100 {
                self.window_history.pop_front();
            }
        }
    }

    /// During warmup: fold current recent_acc into baseline_acc and clear for next tick.
    /// This is the warmup-only equivalent of the old reset_window() baseline path.
    fn accumulate_warmup(&mut self) {
        if self.baseline_frozen { return; }
        if self.total_effective < 1.0 { return; }

        for (i, &v) in self.recent_acc.iter().enumerate() {
            self.baseline_acc[i] += v;
        }
        self.warmup_total_packets += self.total_effective as usize;
        self.warmup_ticks_count += 1;

        // Accumulate value counts into baseline for concentration tracking
        for (key, stats) in &self.value_counts {
            *self.baseline_value_counts.entry(key.clone()).or_default() += stats.count as u64;
        }

        // Snapshot history during warmup too
        self.snapshot_history();

        // Clear for next warmup tick (no decay during warmup)
        self.recent_acc.fill(0.0);
        self.value_counts.clear();
        self.total_effective = 0.0;
    }

}

// =============================================================================
// PAYLOAD TRACKER: Windowed Payload Analysis
// =============================================================================

const PAYLOAD_WINDOW_SIZE: usize = 64;
const MAX_PAYLOAD_BYTES: usize = veth_filter::SAMPLE_DATA_SIZE; // 2048 — full XDP capture
const NUM_PAYLOAD_WINDOWS: usize = MAX_PAYLOAD_BYTES / PAYLOAD_WINDOW_SIZE; // 32

/// Per-destination payload anomaly tracking state.
struct DstPayloadState {
    /// Recent anomalous L4 payloads (truncated to MAX_PAYLOAD_BYTES)
    anomalous_samples: VecDeque<Vec<u8>>,
    /// Recent normal L4 payloads (truncated to MAX_PAYLOAD_BYTES)
    normal_samples: VecDeque<Vec<u8>>,
    /// Count of anomalous payloads seen since last rule derivation
    anomaly_count: usize,
    /// L4 header length observed for this destination (derived from packets)
    l4_header_len: usize,
    /// Last time this destination had an anomalous payload
    last_seen: Instant,
    /// Cooldown: earliest time we can derive rules again (prevents re-derive every tick)
    next_derive_at: Instant,
}

impl DstPayloadState {
    fn new(l4_header_len: usize) -> Self {
        Self {
            anomalous_samples: VecDeque::new(),
            normal_samples: VecDeque::new(),
            anomaly_count: 0,
            l4_header_len,
            last_seen: Instant::now(),
            next_derive_at: Instant::now(),
        }
    }

    fn add_anomalous(&mut self, payload: &[u8]) {
        let truncated: Vec<u8> = payload.iter().take(MAX_PAYLOAD_BYTES).copied().collect();
        self.anomalous_samples.push_back(truncated);
        if self.anomalous_samples.len() > 50 {
            self.anomalous_samples.pop_front();
        }
        self.anomaly_count += 1;
        self.last_seen = Instant::now();
    }

    fn add_normal(&mut self, payload: &[u8]) {
        let truncated: Vec<u8> = payload.iter().take(MAX_PAYLOAD_BYTES).copied().collect();
        self.normal_samples.push_back(truncated);
        if self.normal_samples.len() > 100 {
            self.normal_samples.pop_front();
        }
    }
}

/// Payload anomaly tracker using windowed VSA accumulators.
///
/// During warmup, learns a baseline of "familiar" payload byte patterns.
/// After warmup, scores each packet's payload against the baseline:
///   - If any window's absolute similarity is below the threshold, the payload
///     is classified as anomalous.
///   - Anomalous/normal payloads are stored per destination.
///   - When enough anomalies accumulate, drill-down + gap-probe + greedy
///     selection derive `l4-match` rules scoped to that destination.
/// Global maximum payload rules across all destinations
const MAX_PAYLOAD_RULES_TOTAL: usize = 64;

struct PayloadTracker {
    holon: Arc<Holon>,
    /// One f64 accumulator per window (NUM_PAYLOAD_WINDOWS x dims)
    accumulators: Vec<Vec<f64>>,
    /// Frozen baselines after warmup
    baselines: Vec<Option<Vector>>,
    /// Total packets learned during warmup
    packet_count: usize,
    /// Whether baseline is frozen
    baseline_frozen: bool,
    /// Per-destination anomaly tracking
    dst_states: HashMap<u32, DstPayloadState>,
    /// Absolute similarity threshold: windows scoring below this are anomalous.
    /// Auto-calibrated as (baseline_mean - 3*stddev) during freeze, or CLI override.
    anomaly_threshold: f64,
    /// User-supplied threshold override (None = auto-calibrate)
    threshold_override: Option<f64>,
    /// Minimum anomalies per dst before deriving rules
    min_anomalies_for_rules: usize,
    /// Warmup payloads kept for threshold calibration (cleared after freeze)
    warmup_payloads: Vec<Vec<u8>>,
    /// Whether to use rate-limit (vs drop) for derived rules
    use_rate_limit: bool,
    /// Sample rate (for estimating pps in rate-limit rules)
    sample_rate: u32,
    /// Active payload rules keyed by (offset, length, match_hex) -> rule_key
    /// Used for dedup: don't re-derive rules already in the tree
    active_rule_keys: HashMap<String, String>,
}

impl PayloadTracker {
    fn new(
        holon: Arc<Holon>,
        threshold_override: Option<f64>,
        min_anomalies: usize,
        use_rate_limit: bool,
        sample_rate: u32,
    ) -> Self {
        let dims = holon.dimensions();
        let accumulators = vec![vec![0.0; dims]; NUM_PAYLOAD_WINDOWS];
        let baselines = vec![None; NUM_PAYLOAD_WINDOWS];

        Self {
            holon,
            accumulators,
            baselines,
            packet_count: 0,
            baseline_frozen: false,
            dst_states: HashMap::new(),
            anomaly_threshold: threshold_override.unwrap_or(0.7),
            threshold_override,
            min_anomalies_for_rules: min_anomalies,
            warmup_payloads: Vec::new(),
            use_rate_limit,
            sample_rate,
            active_rule_keys: HashMap::new(),
        }
    }

    /// How many windows actually contain data for a payload of this length.
    fn active_windows(payload_len: usize) -> usize {
        if payload_len == 0 { return 0; }
        std::cmp::min(
            (payload_len + PAYLOAD_WINDOW_SIZE - 1) / PAYLOAD_WINDOW_SIZE,
            NUM_PAYLOAD_WINDOWS,
        )
    }

    /// Build a WalkableValue::Map for a window's bytes.
    /// Returns None if the window falls entirely outside the payload.
    fn window_walkable(payload: &[u8], window_idx: usize) -> Option<WalkableValue> {
        let start = window_idx * PAYLOAD_WINDOW_SIZE;
        if start >= payload.len() {
            return None;
        }
        let end = std::cmp::min(start + PAYLOAD_WINDOW_SIZE, payload.len());

        let items: Vec<(String, WalkableValue)> = (start..end)
            .map(|i| (
                format!("p{}", i - start),
                WalkableValue::Scalar(ScalarValue::String(format!("0x{:02x}", payload[i]))),
            ))
            .collect();

        Some(WalkableValue::Map(items))
    }

    /// Learn from a payload during warmup.
    fn learn(&mut self, payload: &[u8]) {
        if self.baseline_frozen { return; }

        let truncated = &payload[..std::cmp::min(payload.len(), MAX_PAYLOAD_BYTES)];
        let n_windows = Self::active_windows(truncated.len());

        for w in 0..n_windows {
            if let Some(wv) = Self::window_walkable(truncated, w) {
                let vec = self.holon.encode_walkable_value(&wv);
                for (i, &v) in vec.data().iter().enumerate() {
                    self.accumulators[w][i] += v as f64;
                }
            }
        }

        // Keep warmup payloads for threshold calibration (cap at 500)
        if self.warmup_payloads.len() < 500 {
            self.warmup_payloads.push(truncated.to_vec());
        }

        self.packet_count += 1;
    }

    /// Freeze baseline after warmup, then auto-calibrate the anomaly threshold
    /// by replaying stored warmup payloads against the frozen baselines.
    fn freeze_baseline(&mut self) {
        if self.packet_count == 0 { return; }

        // Step 1: Normalize accumulators into bipolar baseline vectors
        for w in 0..NUM_PAYLOAD_WINDOWS {
            let mut baseline = vec![0i8; self.holon.dimensions()];
            for (i, &sum) in self.accumulators[w].iter().enumerate() {
                let avg = sum / self.packet_count as f64;
                baseline[i] = if avg > 0.01 { 1 }
                              else if avg < -0.01 { -1 }
                              else { 0 };
            }
            self.baselines[w] = Some(Vector::from_data(baseline));
        }

        self.baseline_frozen = true;

        // Step 2: Auto-calibrate threshold by replaying warmup payloads
        if self.threshold_override.is_some() {
            // User explicitly provided a threshold; skip calibration
            info!("Payload threshold: {:.4} (CLI override)", self.anomaly_threshold);
            self.warmup_payloads.clear();
            return;
        }

        let mut all_min_sims: Vec<f64> = Vec::new();
        for payload in &self.warmup_payloads {
            let n_windows = Self::active_windows(payload.len());
            let mut min_sim = f64::MAX;
            for w in 0..n_windows {
                if let Some(sim) = self.score_window(payload, w) {
                    if sim < min_sim { min_sim = sim; }
                }
            }
            if min_sim < f64::MAX {
                all_min_sims.push(min_sim);
            }
        }

        if all_min_sims.is_empty() {
            self.anomaly_threshold = 0.7; // conservative fallback
            info!("Payload threshold: {:.4} (fallback, no warmup similarities)", self.anomaly_threshold);
            self.warmup_payloads.clear();
            return;
        }

        let n = all_min_sims.len() as f64;
        let mean = all_min_sims.iter().sum::<f64>() / n;
        let variance = all_min_sims.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / n;
        let raw_stddev = variance.sqrt();

        // Floor stddev at 0.1: when all warmup payloads are identical (stddev=0),
        // the threshold would be mean-0.05=0.95 which flags everything.
        // With floor=0.1: threshold = 1.0 - 0.3 = 0.7 — much more selective.
        let stddev = raw_stddev.max(0.1);

        // Threshold = mean - 3*stddev, but floor at 0.3 to avoid insensitivity
        // and cap at mean - 0.05 to ensure we catch at least modest deviations
        let calibrated = (mean - 3.0 * stddev).max(0.3).min(mean - 0.05);
        self.anomaly_threshold = calibrated;

        info!("Payload threshold auto-calibrated: {:.4} (mean={:.4}, stddev={:.4}, n={})",
              self.anomaly_threshold, mean, stddev, all_min_sims.len());

        // Free warmup payloads
        self.warmup_payloads.clear();
    }

    /// Score a single window against its baseline.  Returns similarity or None
    /// if the window has no baseline or falls outside the payload.
    fn score_window(&self, payload: &[u8], window_idx: usize) -> Option<f64> {
        let baseline = self.baselines[window_idx].as_ref()?;
        let wv = Self::window_walkable(payload, window_idx)?;
        let vec = self.holon.encode_walkable_value(&wv);
        Some(self.holon.similarity(&vec, baseline))
    }

    /// Score and classify a single sample against baseline, storing in per-dst state.
    fn process_single_sample(&mut self, sample: &PacketSample) {
        if !self.baseline_frozen { return; }

        let l4_payload = sample.l4_payload();
        if l4_payload.is_empty() { return; }
        let l4_hdr_len = sample.l4_header_len().unwrap_or(0);

        let truncated = &l4_payload[..std::cmp::min(l4_payload.len(), MAX_PAYLOAD_BYTES)];
        let n_windows = Self::active_windows(truncated.len());

        let mut is_anomalous = false;
        for w in 0..n_windows {
            if let Some(sim) = self.score_window(truncated, w) {
                if sim < self.anomaly_threshold {
                    is_anomalous = true;
                    break;
                }
            }
        }

        let dst_state = self.dst_states
            .entry(sample.dst_ip)
            .or_insert_with(|| DstPayloadState::new(l4_hdr_len));

        dst_state.l4_header_len = l4_hdr_len;

        if is_anomalous {
            dst_state.add_anomalous(l4_payload);
        } else {
            dst_state.add_normal(l4_payload);
        }
    }

    /// Process a batch of samples (delegates to process_single_sample).
    #[allow(dead_code)]
    fn process_window_samples(&mut self, samples: &[PacketSample]) {
        for sample in samples {
            self.process_single_sample(sample);
        }
    }

    /// Expire old destination states.
    fn expire_old_dsts(&mut self, ttl: Duration) {
        let now = Instant::now();
        self.dst_states.retain(|_, state| now.duration_since(state.last_seen) < ttl);
    }

    /// Track that a rule has been inserted into the active rule set.
    fn mark_rule_active(&mut self, pattern_key: String, rule_key: String) {
        self.active_rule_keys.insert(pattern_key, rule_key);
    }

    /// Remove tracking for an expired rule.
    fn mark_rule_expired(&mut self, rule_key: &str) {
        self.active_rule_keys.retain(|_, v| v != rule_key);
    }

    /// Extract a stable dedup key from a payload RuleSpec's BytePattern.
    /// Format: "off:{offset},len:{length},match:{hex}" — unique per pattern.
    fn pattern_dedup_key(spec: &RuleSpec) -> Option<String> {
        for c in &spec.constraints {
            if let Predicate::RawByteMatch(bp) = c {
                let match_hex: String = bp.match_bytes[..bp.length as usize]
                    .iter().map(|b| format!("{:02x}", b)).collect();
                let mask_hex: String = bp.mask_bytes[..bp.length as usize]
                    .iter().map(|b| format!("{:02x}", b)).collect();
                return Some(format!("off:{},len:{},m:{},k:{}", bp.offset, bp.length, match_hex, mask_hex));
            }
        }
        None
    }

    /// Check all destinations and derive rules for those ready.
    /// `estimated_current_pps` is the per-tick PPS estimate from sample counts.
    /// `rate_factor` comes from the FieldTracker's time-decayed rate vector.
    fn check_and_derive_rules(&mut self, estimated_current_pps: f64, rate_factor: f64) -> Vec<RuleSpec> {
        let mut rules = Vec::new();
        let now = Instant::now();
        let use_rate_limit = self.use_rate_limit;
        let allowed_pps = (estimated_current_pps * rate_factor).max(100.0) as u32;

        for (&dst_ip, state) in &mut self.dst_states {
            if now < state.next_derive_at {
                continue;
            }
            if state.anomaly_count < self.min_anomalies_for_rules
                || state.anomalous_samples.is_empty()
                || state.normal_samples.is_empty()
            {
                continue;
            }

            if let Some(derived) = Self::derive_rules_for_dst(
                &self.holon,
                &self.baselines,
                self.anomaly_threshold,
                dst_ip,
                state,
                use_rate_limit,
                allowed_pps,
            ) {
                state.next_derive_at = now + Duration::from_secs(4);
                state.anomalous_samples.clear();
                state.anomaly_count = 0;
                rules.extend(derived);
            }
        }

        // Dedup against active rules
        rules.retain(|spec| {
            if let Some(pk) = Self::pattern_dedup_key(spec) {
                !self.active_rule_keys.contains_key(&pk)
            } else {
                true
            }
        });

        // Enforce global budget
        let total_active = self.active_rule_keys.len();
        if total_active + rules.len() > MAX_PAYLOAD_RULES_TOTAL {
            let allowed = MAX_PAYLOAD_RULES_TOTAL.saturating_sub(total_active);
            rules.truncate(allowed);
        }

        rules
    }

    /// Derive l4-match rules for a specific destination using multi-byte patterns.
    fn derive_rules_for_dst(
        holon: &Holon,
        baselines: &[Option<Vector>],
        threshold: f64,
        dst_ip: u32,
        state: &mut DstPayloadState,
        use_rate_limit: bool,
        allowed_pps: u32,
    ) -> Option<Vec<RuleSpec>> {
        let l4_hdr_len = state.l4_header_len;

        // Step 1: Drill down anomalous windows to find unfamiliar positions
        let mut all_unfamiliar: HashSet<usize> = HashSet::new();

        for atk_payload in state.anomalous_samples.make_contiguous() {
            let truncated = &atk_payload[..std::cmp::min(atk_payload.len(), MAX_PAYLOAD_BYTES)];
            let n_windows = Self::active_windows(truncated.len());

            for w in 0..n_windows {
                let baseline = match baselines[w].as_ref() {
                    Some(b) => b,
                    None => continue,
                };
                if let Some(wv) = Self::window_walkable(truncated, w) {
                    let vec = holon.encode_walkable_value(&wv);
                    let sim = holon.similarity(&vec, baseline);
                    if sim < threshold {
                        let start = w * PAYLOAD_WINDOW_SIZE;
                        let end = std::cmp::min(start + PAYLOAD_WINDOW_SIZE, truncated.len());
                        for i in start..end {
                            let field = format!("p{}", i - start);
                            let value = format!("0x{:02x}", truncated[i]);
                            let role = holon.get_vector(&field);
                            let val = holon.get_vector(&value);
                            let bound = holon.bind(&role, &val);
                            let pos_sim = holon.similarity(&bound, baseline);
                            if pos_sim < 0.005 {
                                all_unfamiliar.insert(i);
                            }
                        }
                    }
                }
            }
        }

        if all_unfamiliar.is_empty() {
            return None;
        }

        let mut detected: Vec<usize> = all_unfamiliar.into_iter().collect();
        detected.sort();

        // Step 2: Gap probing -- extend detected positions by checking neighbors
        let atk_slice = state.anomalous_samples.make_contiguous();
        let leg_slice = state.normal_samples.make_contiguous();
        let extended = Self::gap_probe(&detected, atk_slice, leg_slice);

        // Step 3: Collect per-position byte info and find the consensus attack byte
        let pos_info = Self::collect_position_info(
            &extended, atk_slice, leg_slice,
        );

        if pos_info.is_empty() {
            return None;
        }

        // Step 4: Build multi-byte l4-match patterns from contiguous/nearby positions
        let specs = Self::build_multi_byte_rules(
            dst_ip, &pos_info, l4_hdr_len, use_rate_limit, allowed_pps,
        );

        if specs.is_empty() { None } else { Some(specs) }
    }

    /// Gap probing: extend detected positions by checking neighbors in raw bytes.
    fn gap_probe(
        detected: &[usize],
        atk_samples: &[Vec<u8>],
        leg_samples: &[Vec<u8>],
    ) -> Vec<usize> {
        if detected.is_empty() {
            return vec![];
        }

        let lo = detected[0].saturating_sub(4);
        let hi = std::cmp::min(detected[detected.len() - 1] + 4, MAX_PAYLOAD_BYTES - 1);

        let detected_set: HashSet<usize> = detected.iter().copied().collect();
        let mut probed = Vec::new();

        for pos in lo..=hi {
            if detected_set.contains(&pos) { continue; }

            let atk_bytes: HashSet<u8> = atk_samples.iter()
                .take(20)
                .filter(|p| pos < p.len())
                .map(|p| p[pos])
                .collect();
            let leg_bytes: HashSet<u8> = leg_samples.iter()
                .filter(|p| pos < p.len())
                .map(|p| p[pos])
                .collect();

            if atk_bytes.is_empty() { continue; }

            let unfam_count = atk_bytes.difference(&leg_bytes).count();
            if unfam_count > 0 {
                probed.push(pos);
            }
        }

        let mut extended = detected.to_vec();
        extended.extend(probed);
        extended.sort();
        extended.dedup();
        extended
    }

    /// Per-position info: the consensus attack byte and whether it's unfamiliar.
    fn collect_position_info(
        positions: &[usize],
        atk_samples: &[Vec<u8>],
        leg_samples: &[Vec<u8>],
    ) -> Vec<PositionInfo> {
        let mut result = Vec::new();

        for &pos in positions {
            let atk_bytes: Vec<u8> = atk_samples.iter()
                .filter(|p| pos < p.len())
                .map(|p| p[pos])
                .collect();
            let leg_set: HashSet<u8> = leg_samples.iter()
                .filter(|p| pos < p.len())
                .map(|p| p[pos])
                .collect();

            if atk_bytes.is_empty() { continue; }

            // Find the most common attack byte at this position
            let mut counts: HashMap<u8, usize> = HashMap::new();
            for &b in &atk_bytes {
                *counts.entry(b).or_insert(0) += 1;
            }

            let (&consensus_byte, &consensus_count) = counts.iter()
                .max_by_key(|(_, c)| *c)
                .unwrap();

            let is_unfamiliar = !leg_set.contains(&consensus_byte);
            let consensus_rate = consensus_count as f64 / atk_bytes.len() as f64;

            // Score: prefer bytes that are (a) unfamiliar in normal traffic,
            // (b) consistent across attack samples, (c) not padding (0x00)
            let mut score = consensus_rate;
            if !is_unfamiliar { score *= 0.1; } // heavily penalize familiar bytes
            if consensus_byte == 0x00 && leg_set.is_empty() {
                score *= 0.2; // penalize zeros beyond normal payload length
            }

            result.push(PositionInfo {
                payload_pos: pos,
                consensus_byte,
                is_unfamiliar,
                consensus_rate,
                score,
            });
        }

        // Sort by score descending
        result.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        result
    }

    /// Build multi-byte l4-match rules by grouping positions into spans.
    ///
    /// Groups nearby positions (within a gap of 8) into a single BytePattern
    /// using sparse masks. Positions with familiar bytes get mask=0x00 (don't-care).
    fn build_multi_byte_rules(
        dst_ip: u32,
        pos_info: &[PositionInfo],
        l4_hdr_len: usize,
        use_rate_limit: bool,
        allowed_pps: u32,
    ) -> Vec<RuleSpec> {
        if pos_info.is_empty() { return vec![]; }

        // Only keep positions with a reasonable score (unfamiliar or high-consensus)
        let useful: Vec<&PositionInfo> = pos_info.iter()
            .filter(|p| p.is_unfamiliar && p.consensus_rate >= 0.5)
            .collect();

        if useful.is_empty() { return vec![]; }

        // Sort by position for grouping
        let mut sorted: Vec<&PositionInfo> = useful;
        sorted.sort_by_key(|p| p.payload_pos);

        // Group into spans: positions within MAX_PATTERN_LEN and with gaps <= 8
        let mut spans: Vec<Vec<&PositionInfo>> = Vec::new();
        let mut current_span: Vec<&PositionInfo> = vec![sorted[0]];

        for pi in &sorted[1..] {
            let span_start = current_span[0].payload_pos;
            let gap = pi.payload_pos - current_span.last().unwrap().payload_pos;
            let span_len = pi.payload_pos - span_start + 1;

            if gap <= 8 && span_len <= veth_filter::MAX_PATTERN_LEN {
                current_span.push(pi);
            } else {
                spans.push(current_span);
                current_span = vec![pi];
            }
        }
        spans.push(current_span);

        let mut specs = Vec::new();
        for span in &spans {
            let first_pos = span[0].payload_pos;
            let last_pos = span.last().unwrap().payload_pos;
            let pattern_len = last_pos - first_pos + 1;

            if pattern_len > veth_filter::MAX_PATTERN_LEN { continue; }

            let mut match_bytes = [0u8; 64];
            let mut mask_bytes = [0u8; 64];
            let mut matched_positions = 0usize;

            for pi in span {
                let idx = pi.payload_pos - first_pos;
                match_bytes[idx] = pi.consensus_byte;
                mask_bytes[idx] = 0xFF;
                matched_positions += 1;
            }

            // Require at least 2 matched byte positions for a meaningful rule,
            // unless the single byte is highly distinctive (non-zero, non-FF)
            if matched_positions < 2 && (span[0].consensus_byte == 0x00 || span[0].consensus_byte == 0xFF) {
                continue;
            }

            let l4_offset = (l4_hdr_len + first_pos) as u16;
            let l4_match = Predicate::RawByteMatch(Box::new(veth_filter::BytePattern {
                offset: l4_offset,
                length: pattern_len as u8,
                _pad: 0,
                match_bytes,
                mask_bytes,
            }));

            let dst_constraint = Predicate::eq(FieldDim::DstIp, dst_ip);
            let constraints = vec![dst_constraint, l4_match];

            let stable_name = RuleSpec {
                constraints: constraints.clone(),
                actions: vec![],
                priority: 0,
                comment: None,
                label: None,
            }.constraints_to_edn();

            let action = if use_rate_limit {
                RuleAction::RateLimit { pps: allowed_pps, name: Some(("system".into(), stable_name.clone())) }
            } else {
                RuleAction::Drop { name: Some(("system".into(), stable_name.clone())) }
            };

            let match_hex: String = match_bytes[..pattern_len]
                .iter().map(|b| format!("{:02x}", b)).collect();
            let mask_hex: String = mask_bytes[..pattern_len]
                .iter().map(|b| format!("{:02x}", b)).collect();

            specs.push(RuleSpec {
                constraints,
                actions: vec![action],
                priority: 100,
                comment: Some(format!(
                    "Payload pattern L4+{}..+{} ({} bytes matched, pattern={}, mask={})",
                    l4_offset, l4_offset as usize + pattern_len - 1,
                    matched_positions, match_hex, mask_hex,
                )),
                label: None,
            });
        }

        // Cap at 4 rules per derivation (multi-byte patterns are much more powerful)
        specs.truncate(4);
        specs
    }
}

struct PositionInfo {
    payload_pos: usize,
    consensus_byte: u8,
    is_unfamiliar: bool,
    consensus_rate: f64,
    score: f64,
}

/// Detection result with enhanced metadata
struct Detection {
    field: String,
    value: String,
    concentration: f64,
    drift: f64,
    anomalous_ratio: f64,
    attributed_pattern: Option<String>,
    /// Rate factor from magnitude ratio (1/magnitude_ratio, capped at 1.0)
    /// Purely vector-derived: if we're seeing 100x traffic, rate_factor = 0.01
    rate_factor: f64,
}

impl Detection {
    /// Convert a detection field/value into a Predicate constraint.
    fn to_constraint(&self) -> Option<Predicate> {
        match self.field.as_str() {
            "src_ip" => self.value.parse::<Ipv4Addr>().ok()
                .map(|ip| Predicate::eq(FieldDim::SrcIp, u32::from_ne_bytes(ip.octets()))),
            "dst_ip" => self.value.parse::<Ipv4Addr>().ok()
                .map(|ip| Predicate::eq(FieldDim::DstIp, u32::from_ne_bytes(ip.octets()))),
            "dst_port" => self.value.parse::<u16>().ok()
                .map(|port| Predicate::eq(FieldDim::L4Word1, port as u32)),
            "src_port" => self.value.parse::<u16>().ok()
                .map(|port| Predicate::eq(FieldDim::L4Word0, port as u32)),
            "protocol" => self.value.parse::<u8>().ok()
                .map(|proto| Predicate::eq(FieldDim::Proto, proto as u32)),
            // p0f-level fields
            "tcp_flags" => self.value.parse::<u8>().ok()
                .map(|flags| Predicate::eq(FieldDim::TcpFlags, flags as u32)),
            "ttl" => self.value.parse::<u8>().ok()
                .map(|ttl| Predicate::eq(FieldDim::Ttl, ttl as u32)),
            "df_bit" => self.value.parse::<u8>().ok()
                .map(|df| Predicate::eq(FieldDim::DfBit, df as u32)),
            "tcp_window" => self.value.parse::<u16>().ok()
                .map(|win| Predicate::eq(FieldDim::TcpWindow, win as u32)),
            // IPv4 header fingerprinting fields
            "ip_id" => self.value.parse::<u16>().ok()
                .map(|id| Predicate::eq(FieldDim::IpId, id as u32)),
            "ip_len" => self.value.parse::<u16>().ok()
                .map(|len| Predicate::eq(FieldDim::IpLen, len as u32)),
            "dscp" => self.value.parse::<u8>().ok()
                .map(|d| Predicate::eq(FieldDim::Dscp, d as u32)),
            "ecn" => self.value.parse::<u8>().ok()
                .map(|e| Predicate::eq(FieldDim::Ecn, e as u32)),
            "mf_bit" => self.value.parse::<u8>().ok()
                .map(|mf| Predicate::eq(FieldDim::MfBit, mf as u32)),
            "frag_offset" => self.value.parse::<u16>().ok()
                .map(|fo| Predicate::eq(FieldDim::FragOffset, fo as u32)),
            _ => None,
        }
    }

    /// Compile a single detection into a RuleSpec
    fn compile_rule_spec(&self, use_rate_limit: bool, estimated_pps: f64) -> Option<RuleSpec> {
        let constraint = self.to_constraint()?;
        let allowed_pps = (estimated_pps * self.rate_factor).max(100.0) as u32;
        
        // Build a stable name from constraints so bucket_key() doesn't change
        // when pps wobbles across detection windows. This preserves eBPF token
        // bucket state across recompilations, preventing burst leaks.
        let stable_name = RuleSpec {
            constraints: vec![constraint.clone()],
            actions: vec![],
            priority: 0,
            comment: None,
            label: None,
        }.constraints_to_edn();
        
        let action = if use_rate_limit { 
            RuleAction::RateLimit { pps: allowed_pps, name: Some(("system".into(), stable_name)) }
        } else { 
            RuleAction::Drop { name: Some(("system".into(), stable_name)) }
        };
        
        Some(RuleSpec { 
            constraints: vec![constraint], 
            actions: vec![action], 
            priority: 100,
            comment: None,
            label: None,
        })
    }
}

// =============================================================================
// =============================================================================
// Rules File Loader (EDN Format)
// =============================================================================

/// Parse an EDN rules file (one rule per EDN map, can span multiple lines).
/// 
/// Format: EDN maps, possibly spanning multiple lines for readability
/// ```edn
/// {:constraints [(= proto 17) (= src-port 53)] 
///  :actions [(rate-limit 500)] 
///  :priority 190}
/// ```
/// Comments (lines starting with `;`) and blank lines are ignored.
/// The parser accumulates lines until a complete EDN map is found (balanced braces).
/// 
/// Validate byte match policy: every l4-match rule MUST have a destination address
/// constraint (tenant scoping), and no scope may exceed the configured density limit.
/// This enforces tenant isolation and resource boundaries in multi-tenant deployments.
fn validate_byte_match_density(rules: &[RuleSpec], max_per_scope: usize) -> Result<()> {
    use std::collections::HashMap;
    use veth_filter::{FieldRef, Predicate};

    // Group rules by dst-addr (scope discriminator).
    // Rules without dst-addr are rejected — byte matches require tenant scoping.
    let mut scope_counts: HashMap<String, usize> = HashMap::new();
    let mut total_byte_matches = 0usize;
    let mut unscoped_rules: Vec<String> = Vec::new();

    for rule in rules {
        // Count l4-match constraints in this rule
        let byte_match_count = rule.constraints.iter().filter(|p| {
            matches!(p.field_ref(), FieldRef::L4Byte { .. })
        }).count();

        if byte_match_count == 0 {
            continue;
        }

        total_byte_matches += byte_match_count;

        // Find the dst-addr for scoping (if any)
        let scope = rule.constraints.iter().find_map(|p| {
            match p {
                Predicate::Eq(FieldRef::Dim(veth_filter::FieldDim::DstIp), val) => {
                    Some(format!("{}.{}.{}.{}",
                        (val >> 24) & 0xFF, (val >> 16) & 0xFF,
                        (val >> 8) & 0xFF, val & 0xFF))
                }
                _ => None,
            }
        });

        match scope {
            Some(addr) => {
                *scope_counts.entry(addr).or_insert(0) += byte_match_count;
            }
            None => {
                // Byte match without dst-addr — policy violation
                unscoped_rules.push(rule.display_label());
            }
        }
    }

    // Reject unscoped byte match rules
    if !unscoped_rules.is_empty() {
        let examples: Vec<&str> = unscoped_rules.iter().take(3).map(|s| s.as_str()).collect();
        anyhow::bail!(
            "{} byte match rule(s) missing required (= dst-addr ...) constraint. \
             Every l4-match rule must be scoped to a destination address for tenant isolation.\n  \
             Examples: {}",
            unscoped_rules.len(),
            examples.join("\n  ")
        );
    }

    if total_byte_matches > 0 {
        let num_scopes = scope_counts.len();
        let max_scope = scope_counts.iter().max_by_key(|(_, v)| *v);
        info!("Byte match density: {} total across {} scopes (limit: {}/scope)",
              total_byte_matches, num_scopes, max_per_scope);

        for (scope, count) in &scope_counts {
            if *count > max_per_scope {
                anyhow::bail!(
                    "Scope '{}' has {} byte match rules, exceeding limit of {}. \
                     Split into separate scopes or increase --max-byte-matches-per-scope.",
                    scope, count, max_per_scope
                );
            }
        }

        if let Some((scope, count)) = max_scope {
            info!("  Densest scope: {} ({} byte matches)", scope, count);
        }
    }

    Ok(())
}

/// {:constraints [(= proto 6) (= tcp-flags 2)] :actions [(drop)] :priority 200}
/// {:constraints [(= src-addr "10.0.0.200")] :actions [(drop)] :comment "Known attacker"}
/// ```
/// 
/// Comments (lines starting with `;`) and blank lines are ignored.
/// Rules can span multiple lines - we accumulate lines until edn-rs can parse it.
fn parse_rules_file(path: &std::path::Path) -> Result<Vec<RuleSpec>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open rules file: {:?}", path))?;
    
    let mut rules = Vec::new();
    let mut skipped = 0;
    let mut accumulator = String::new();
    let mut line_count = 0;
    
    for line in std::io::BufReader::new(file).lines() {
        let line = line?;
        line_count += 1;
        
        // Skip pure comment lines when accumulator is empty
        let trimmed = line.trim();
        if accumulator.is_empty() && (trimmed.is_empty() || trimmed.starts_with(';')) {
            continue;
        }
        
        // Add line to accumulator
        accumulator.push_str(&line);
        accumulator.push('\n');
        
        // Try to parse - if it works, we have a complete expression
        match accumulator.trim().parse::<Edn>() {
            Ok(edn) => {
                // Got a complete EDN expression!
                match parse_edn_rule(&edn) {
                    Ok(rule) => rules.push(rule),
                    Err(e) => {
                        warn!("Line {}: Failed to parse rule: {}", line_count, e);
                        skipped += 1;
                    }
                }
                accumulator.clear();
            }
            Err(_) => {
                // Not complete yet, keep accumulating
                // Safety check: don't let accumulator grow unbounded
                if accumulator.len() > 100_000 {
                    warn!("Line {}: Rule exceeded 100KB, skipping", line_count);
                    accumulator.clear();
                    skipped += 1;
                }
            }
        }
    }
    
    // Check for incomplete expression at EOF
    if !accumulator.trim().is_empty() {
        warn!("EOF: Incomplete expression: {}", accumulator.trim());
        skipped += 1;
    }
    
    if skipped > 0 {
        warn!("Skipped {} malformed rules", skipped);
    }
    
    Ok(rules)
}

/// Parse a single EDN rule
fn parse_edn_rule(edn: &Edn) -> Result<RuleSpec> {
    
    // Extract map fields
    let constraints_edn = edn.get(":constraints")
        .ok_or_else(|| anyhow::anyhow!("Missing :constraints"))?;
    let actions_edn = edn.get(":actions")
        .ok_or_else(|| anyhow::anyhow!("Missing :actions"))?;
    let priority = edn.get(":priority")
        .map(|p| p.to_string().parse::<u8>().unwrap_or(100))
        .unwrap_or(100);
    let comment = edn.get(":comment")
        .map(|c| {
            let mut s = c.to_string();
            s = s.trim_matches('"').to_string();
            // Truncate to 256 chars
            if s.len() > 256 {
                s.truncate(256);
            }
            s
        });
    let label = edn.get(":label")
        .and_then(|l| {
            if let Edn::Vector(vec) = l {
                let items = vec.clone().to_vec();
                if items.len() == 2 {
                    let mut ns = items[0].to_string().trim_matches('"').to_string();
                    let mut name = items[1].to_string().trim_matches('"').to_string();
                    // Truncate to 64 chars each
                    if ns.len() > 64 { ns.truncate(64); }
                    if name.len() > 64 { name.truncate(64); }
                    Some((ns, name))
                } else {
                    None
                }
            } else {
                None
            }
        });
    
    // Parse constraints (vector of s-expressions)
    let constraints = parse_edn_constraints(constraints_edn)?;
    
    // Parse actions (vector of s-expressions)
    let actions = parse_edn_actions(actions_edn)?;
    
    if constraints.is_empty() {
        anyhow::bail!("Rule has no constraints");
    }
    
    if actions.is_empty() {
        anyhow::bail!("Rule has no actions");
    }
    
    Ok(RuleSpec {
        constraints,
        actions,
        priority,
        comment,
        label,
    })
}

/// Parse EDN constraints vector: [(= proto 17) (= src-port 53)]
fn parse_edn_constraints(edn: &Edn) -> Result<Vec<Predicate>> {
    // EDN vector is parsed as a list
    if let Edn::Vector(vec) = edn {
        let mut constraints = Vec::new();
        for item in vec.clone().to_vec() {
            if let Some(pred) = parse_edn_predicate(&item)? {
                constraints.push(pred);
            }
        }
        Ok(constraints)
    } else {
        anyhow::bail!("constraints must be a vector")
    }
}

/// Parse a single predicate s-expression: (= proto 17)
fn parse_edn_predicate(edn: &Edn) -> Result<Option<Predicate>> {
    // EDN parses (op field value) as either List or Vector depending on brackets
    let list = match edn {
        Edn::List(lst) => lst.clone().to_vec(),
        Edn::Vector(vec) => vec.clone().to_vec(),
        _ => anyhow::bail!("Predicate must be a list or vector, got: {:?}", edn),
    };
    
    if list.len() < 2 {
        anyhow::bail!("Predicate must have at least 2 elements");
    }
    
    let op = list[0].to_string();
    
    // Handle special forms that don't follow the (op field value) pattern
    match op.as_str() {
        "protocol-match" => {
            // (protocol-match match mask) — sugar for (mask-eq proto mask match)
            if list.len() != 3 {
                anyhow::bail!("protocol-match requires exactly 3 elements, got {}", list.len());
            }
            let match_val = parse_field_value(&list[1], FieldDim::Proto)?;
            let mask_val = parse_field_value(&list[2], FieldDim::Proto)?;
            if mask_val == 0xFF {
                return Ok(Some(Predicate::Eq(veth_filter::FieldRef::Dim(FieldDim::Proto), match_val)));
            } else {
                return Ok(Some(Predicate::MaskEq(veth_filter::FieldRef::Dim(FieldDim::Proto), mask_val, match_val)));
            }
        }
        "tcp-flags-match" => {
            // (tcp-flags-match match mask) — sugar for (mask-eq tcp-flags mask match)
            if list.len() != 3 {
                anyhow::bail!("tcp-flags-match requires exactly 3 elements, got {}", list.len());
            }
            let match_val = parse_field_value(&list[1], FieldDim::TcpFlags)?;
            let mask_val = parse_field_value(&list[2], FieldDim::TcpFlags)?;
            if mask_val == 0xFF {
                return Ok(Some(Predicate::Eq(veth_filter::FieldRef::Dim(FieldDim::TcpFlags), match_val)));
            } else {
                return Ok(Some(Predicate::MaskEq(veth_filter::FieldRef::Dim(FieldDim::TcpFlags), mask_val, match_val)));
            }
        }
        "l4-match" => {
            // (l4-match <offset> "<hex-match>" "<hex-mask>")
            // Multi-byte pattern match at transport-relative offset.
            if list.len() != 4 {
                anyhow::bail!("l4-match requires exactly 4 elements: (l4-match offset match-hex mask-hex), got {}", list.len());
            }
            let offset: u16 = list[1].to_string().parse()
                .with_context(|| format!("l4-match offset must be a number, got: {}", list[1]))?;
            let match_hex = edn_to_hex_string(&list[2])?;
            let mask_hex = edn_to_hex_string(&list[3])?;
            let match_bytes = hex_decode(&match_hex)
                .with_context(|| format!("l4-match: invalid match hex string: {}", match_hex))?;
            let mask_bytes = hex_decode(&mask_hex)
                .with_context(|| format!("l4-match: invalid mask hex string: {}", mask_hex))?;
            
            if match_bytes.len() != mask_bytes.len() {
                anyhow::bail!("l4-match: match and mask hex strings must be the same length ({} vs {})",
                    match_bytes.len(), mask_bytes.len());
            }
            let length = match_bytes.len();
            if length == 0 || length > veth_filter::MAX_PATTERN_LEN {
                anyhow::bail!("l4-match: pattern length must be 1-{}, got {}", veth_filter::MAX_PATTERN_LEN, length);
            }
            
            if length <= 4 {
                // Short patterns: encode as MaskEq(L4Byte) or Eq(L4Byte)
                // The compiler will resolve these to custom dimensions for fan-out.
                let mut val: u32 = 0;
                let mut mask: u32 = 0;
                for i in 0..length {
                    val = (val << 8) | (match_bytes[i] as u32);
                    mask = (mask << 8) | (mask_bytes[i] as u32);
                }
                // Pre-mask the value
                val &= mask;
                let all_ff = mask_bytes.iter().all(|&b| b == 0xFF);
                let field_ref = veth_filter::FieldRef::L4Byte { offset, length: length as u8 };
                if all_ff {
                    return Ok(Some(Predicate::Eq(field_ref, val)));
                } else {
                    return Ok(Some(Predicate::MaskEq(field_ref, mask, val)));
                }
            } else {
                // Long patterns: build a RawByteMatch with the full byte arrays.
                // Bytes are stored starting at index 0 in natural order;
                // the compiler (allocate_patterns) pre-shifts them to the
                // correct offset position for eBPF.
                let mut pat = veth_filter::BytePattern::default();
                pat.offset = offset;
                pat.length = length as u8;
                for i in 0..length {
                    pat.match_bytes[i] = match_bytes[i] & mask_bytes[i]; // Pre-mask
                    pat.mask_bytes[i] = mask_bytes[i];
                }
                return Ok(Some(Predicate::RawByteMatch(Box::new(pat))));
            }
        }
        _ => {}
    }
    
    // Standard predicates: (op field value...)
    if list.len() < 3 {
        anyhow::bail!("Predicate must have at least 3 elements: (op field value)");
    }
    
    let field = list[1].to_string();
    let dim = parse_field_name(&field)?;
    
    match op.as_str() {
        "=" => {
            // (= field value)
            if list.len() != 3 {
                anyhow::bail!("= predicate requires exactly 3 elements, got {}", list.len());
            }
            let value = parse_field_value(&list[2], dim)?;
            Ok(Some(Predicate::eq(dim, value)))
        }
        ">" => {
            // (> field value)
            if list.len() != 3 {
                anyhow::bail!("> predicate requires exactly 3 elements, got {}", list.len());
            }
            let value = parse_field_value(&list[2], dim)?;
            Ok(Some(Predicate::Gt(veth_filter::FieldRef::Dim(dim), value)))
        }
        "<" => {
            // (< field value)
            if list.len() != 3 {
                anyhow::bail!("< predicate requires exactly 3 elements, got {}", list.len());
            }
            let value = parse_field_value(&list[2], dim)?;
            Ok(Some(Predicate::Lt(veth_filter::FieldRef::Dim(dim), value)))
        }
        ">=" => {
            // (>= field value)
            if list.len() != 3 {
                anyhow::bail!(">= predicate requires exactly 3 elements, got {}", list.len());
            }
            let value = parse_field_value(&list[2], dim)?;
            Ok(Some(Predicate::Gte(veth_filter::FieldRef::Dim(dim), value)))
        }
        "<=" => {
            // (<= field value)
            if list.len() != 3 {
                anyhow::bail!("<= predicate requires exactly 3 elements, got {}", list.len());
            }
            let value = parse_field_value(&list[2], dim)?;
            Ok(Some(Predicate::Lte(veth_filter::FieldRef::Dim(dim), value)))
        }
        "mask" => {
            // Legacy: (mask field mask_value) — treated as (mask-eq field mask mask)
            // i.e., all masked bits must be set
            if list.len() != 3 {
                anyhow::bail!("mask predicate requires exactly 3 elements, got {}", list.len());
            }
            let value = parse_field_value(&list[2], dim)?;
            Ok(Some(Predicate::MaskEq(veth_filter::FieldRef::Dim(dim), value, value)))
        }
        "mask-eq" => {
            // (mask-eq field mask expected) — (field_value & mask) == expected
            if list.len() != 4 {
                anyhow::bail!("mask-eq predicate requires exactly 4 elements, got {}", list.len());
            }
            let mask = parse_field_value(&list[2], dim)?;
            let expected = parse_field_value(&list[3], dim)?;
            Ok(Some(Predicate::MaskEq(veth_filter::FieldRef::Dim(dim), mask, expected)))
        }
        _ => anyhow::bail!("Unsupported predicate operator: {}", op),
    }
}

/// Parse field name from EDN symbol
fn parse_field_name(name: &str) -> Result<FieldDim> {
    match name {
        "proto" => Ok(FieldDim::Proto),
        "src-addr" => Ok(FieldDim::SrcIp),
        "dst-addr" => Ok(FieldDim::DstIp),
        "src-port" => Ok(FieldDim::L4Word0),
        "dst-port" => Ok(FieldDim::L4Word1),
        "tcp-flags" => Ok(FieldDim::TcpFlags),
        "ttl" => Ok(FieldDim::Ttl),
        "df" => Ok(FieldDim::DfBit),
        "tcp-window" => Ok(FieldDim::TcpWindow),
        // IPv4 header fingerprinting fields
        "ip-id" => Ok(FieldDim::IpId),
        "ip-len" => Ok(FieldDim::IpLen),
        "dscp" => Ok(FieldDim::Dscp),
        "ecn" => Ok(FieldDim::Ecn),
        "mf" => Ok(FieldDim::MfBit),
        "frag-offset" => Ok(FieldDim::FragOffset),
        other => anyhow::bail!("Unknown field: {}", other),
    }
}

/// Extract a hex string from an EDN value (String, Symbol, or keyword).
/// Strips quotes, "0x" prefix, and leading ":" from keywords.
fn edn_to_hex_string(edn: &Edn) -> Result<String> {
    let s = match edn {
        Edn::Str(s) => s.to_string(),
        Edn::Symbol(s) => s.to_string(),
        _ => edn.to_string(),
    };
    let s = s.trim_matches('"').trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    Ok(s.to_string())
}

/// Decode a hex string into bytes. Each pair of hex chars = one byte.
fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        anyhow::bail!("hex string must have even length, got {}", hex.len());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i+2], 16)
            .with_context(|| format!("invalid hex byte at position {}: '{}'", i, &hex[i..i+2]))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Parse field value from EDN (number or IP string)
fn parse_field_value(edn: &Edn, dim: FieldDim) -> Result<u32> {
    match dim {
        FieldDim::SrcIp | FieldDim::DstIp => {
            // IP addresses can be Symbols or Strings in EDN
            let s = match edn {
                Edn::Str(s) => s.to_string(),
                Edn::Symbol(s) => s.to_string(),
                _ => edn.to_string(),
            };
            let s = s.trim_matches('"'); // Remove quotes if present
            let ip: Ipv4Addr = s.parse()
                .with_context(|| format!("Invalid IP address: {} (from EDN: {:?})", s, edn))?;
            Ok(u32::from_ne_bytes(ip.octets()))
        }
        _ => {
            // Everything else is a number - try to parse from string
            let s = edn.to_string();
            s.parse::<u32>()
                .with_context(|| format!("Expected number, got: {}", s))
        }
    }
}

/// Parse EDN actions vector: [(rate-limit 500) (count :name "foo")]
fn parse_edn_actions(edn: &Edn) -> Result<Vec<RuleAction>> {
    if let Edn::Vector(vec) = edn {
        let mut actions = Vec::new();
        for item in vec.clone().to_vec() {
            if let Some(action) = parse_edn_action(&item)? {
                actions.push(action);
            }
        }
        Ok(actions)
    } else {
        anyhow::bail!("actions must be a vector")
    }
}

/// Parse a single action s-expression: (rate-limit 500 :name "foo")
fn parse_edn_action(edn: &Edn) -> Result<Option<RuleAction>> {
    // EDN parses (action-type args...) as either List or Vector
    let list = match edn {
        Edn::List(lst) => lst.clone().to_vec(),
        Edn::Vector(vec) => vec.clone().to_vec(),
        _ => anyhow::bail!("Action must be a list or vector, got: {:?}", edn),
    };
    
    if list.is_empty() {
        anyhow::bail!("Action list is empty");
    }
    
    let action_type = list[0].to_string();
    
    match action_type.as_str() {
        "pass" => {
            // Check for optional :name keyword - MUST be [namespace, name] vector
            let name = if list.len() >= 3 && list[1].to_string() == ":name" {
                match &list[2] {
                    Edn::Vector(vec) => {
                        let items = vec.clone().to_vec();
                        if items.len() != 2 {
                            anyhow::bail!(":name must be [namespace, name] with exactly 2 elements");
                        }
                        let ns = items[0].to_string().trim_matches('"').to_string();
                        let n = items[1].to_string().trim_matches('"').to_string();
                        Some((ns, n))
                    }
                    _ => anyhow::bail!(":name must be a vector [namespace, name], got: {:?}", list[2]),
                }
            } else {
                None
            };
            
            Ok(Some(RuleAction::Pass { name }))
        }
        "drop" => {
            // Check for optional :name keyword - MUST be [namespace, name] vector
            let name = if list.len() >= 3 && list[1].to_string() == ":name" {
                match &list[2] {
                    Edn::Vector(vec) => {
                        // Parse as [namespace, name]
                        let items = vec.clone().to_vec();
                        if items.len() != 2 {
                            anyhow::bail!(":name must be [namespace, name] with exactly 2 elements");
                        }
                        let ns = items[0].to_string().trim_matches('"').to_string();
                        let n = items[1].to_string().trim_matches('"').to_string();
                        Some((ns, n))
                    }
                    _ => anyhow::bail!(":name must be a vector [namespace, name], got: {:?}", list[2]),
                }
            } else {
                None
            };
            
            Ok(Some(RuleAction::Drop { name }))
        }
        "rate-limit" => {
            if list.len() < 2 {
                anyhow::bail!("rate-limit requires PPS argument");
            }
            let pps = list[1].to_string().parse::<u32>()
                .with_context(|| "rate-limit PPS must be a number")?;
            
            // Check for optional :name keyword - MUST be [namespace, name] vector
            let name = if list.len() >= 4 && list[2].to_string() == ":name" {
                match &list[3] {
                    Edn::Vector(vec) => {
                        // Parse as [namespace, name]
                        let items = vec.clone().to_vec();
                        if items.len() != 2 {
                            anyhow::bail!(":name must be [namespace, name] with exactly 2 elements");
                        }
                        let ns = items[0].to_string().trim_matches('"').to_string();
                        let n = items[1].to_string().trim_matches('"').to_string();
                        Some((ns, n))
                    }
                    _ => anyhow::bail!(":name must be a vector [namespace, name], got: {:?}", list[3]),
                }
            } else {
                None
            };
            
            Ok(Some(RuleAction::RateLimit { pps, name }))
        }
        "count" => {
            // Check for optional :name keyword - MUST be [namespace, name] vector
            let name = if list.len() >= 3 && list[1].to_string() == ":name" {
                match &list[2] {
                    Edn::Vector(vec) => {
                        // Parse as [namespace, name]
                        let items = vec.clone().to_vec();
                        if items.len() != 2 {
                            anyhow::bail!(":name must be [namespace, name] with exactly 2 elements");
                        }
                        let ns = items[0].to_string().trim_matches('"').to_string();
                        let n = items[1].to_string().trim_matches('"').to_string();
                        Some((ns, n))
                    }
                    _ => anyhow::bail!(":name must be a vector [namespace, name], got: {:?}", list[2]),
                }
            } else {
                None
            };
            
            Ok(Some(RuleAction::Count { name }))
        }
            other => anyhow::bail!("Unknown action type: {}", other),
        }
}

/// Legacy JSON parser (backward compatibility)
/// Compile multiple concentrated detections into a compound RuleSpec.
/// Gathers all constraints and produces a single rule.
fn compile_compound_rule(
    detections: &[Detection],
    use_rate_limit: bool,
    estimated_pps: f64,
) -> Option<RuleSpec> {
    if detections.is_empty() { return None; }
    if detections.len() == 1 {
        return detections[0].compile_rule_spec(use_rate_limit, estimated_pps);
    }

    let constraints: Vec<Predicate> = detections.iter()
        .filter_map(|d| d.to_constraint())
        .collect();
    if constraints.is_empty() { return None; }

    let rate_factor = detections[0].rate_factor;
    let allowed_pps = (estimated_pps * rate_factor).max(100.0) as u32;
    
    // Build a stable name from constraints so bucket_key() doesn't change
    // when pps wobbles across detection windows. This preserves eBPF token
    // bucket state across recompilations, preventing burst leaks.
    let stable_name = RuleSpec {
        constraints: constraints.clone(),
        actions: vec![],
        priority: 0,
        comment: None,
        label: None,
    }.constraints_to_edn();
    
    let action = if use_rate_limit { 
        RuleAction::RateLimit { pps: allowed_pps, name: Some(("system".into(), stable_name)) }
    } else { 
        RuleAction::Drop { name: Some(("system".into(), stable_name)) }
    };

    Some(RuleSpec {
        constraints,
        actions: vec![action],
        priority: 100,
        comment: None,
        label: None,
    })
}

/// Generate a unique key for a rule based on constraints + action type (ignoring action params like rate)
fn rule_identity_key(spec: &RuleSpec) -> String {
    let constraints_part = spec.constraints_to_edn();
    let action_type = spec.actions.first().map(|a| match a {
        RuleAction::Drop { .. } => "drop",
        RuleAction::RateLimit { .. } => "rate-limit",
        RuleAction::Pass { .. } => "pass",
        RuleAction::Count { .. } => "count",
    }).unwrap_or("none");
    
    format!("{}::{}", constraints_part, action_type)
}

/// A rule currently active in the decision tree.
struct ActiveRule {
    last_seen: Instant,
    spec: RuleSpec,
    /// Pre-loaded rules never expire
    preloaded: bool,
}

/// Check if a candidate rule is redundant given the current active rules.
///
/// Returns Some(reason) if the candidate should be suppressed:
///   - "subsumed": an existing rule's constraints are a subset of the candidate's,
///     meaning the existing (broader) rule already catches all matching traffic.
///   - "over-broad": the candidate's constraints are a strict subset of an existing
///     rule's, meaning it would dangerously broaden filtering to include legitimate traffic.
fn rule_is_redundant(candidate: &RuleSpec, existing_rules: &HashMap<String, ActiveRule>) -> Option<&'static str> {
    if candidate.constraints.is_empty() {
        return Some("empty");
    }
    let candidate_action_type = candidate.actions.first().map(|a| std::mem::discriminant(a));

    for (_, active) in existing_rules.iter() {
        let existing = &active.spec;
        if existing.constraints.is_empty() { continue; }

        let existing_action_type = existing.actions.first().map(|a| std::mem::discriminant(a));
        if candidate_action_type != existing_action_type { continue; }

        let existing_subset_of_candidate = existing.constraints.iter()
            .all(|ec| candidate.constraints.contains(ec));
        let candidate_subset_of_existing = candidate.constraints.iter()
            .all(|cc| existing.constraints.contains(cc));

        if existing_subset_of_candidate && candidate.constraints.len() > existing.constraints.len() {
            return Some("subsumed");
        }
        if candidate_subset_of_existing && candidate.constraints.len() < existing.constraints.len() {
            return Some("over-broad");
        }
    }
    None
}

fn attach_manifest_labels_to_dag(
    dag_nodes: &mut [metrics_server::DagNode],
    manifest: &[veth_filter::RuleManifestEntry],
) {
    let manifest_by_rule_id: HashMap<u32, veth_filter::RuleManifestEntry> = manifest
        .iter()
        .cloned()
        .map(|entry| (entry.rule_id, entry))
        .collect();

    for node in dag_nodes.iter_mut() {
        if let Some(rule_id) = node.action_rule_id {
            if let Some(entry) = manifest_by_rule_id.get(&rule_id) {
                node.label = Some(entry.label.clone());
                node.rule_constraints = Some(entry.constraints.clone());
                node.rule_expression = Some(entry.expression.clone());
            }
        }
    }
}

/// Upsert rules into the active rule set.
///
/// For each spec: if the rule already exists, refreshes its timestamp and updates the spec
/// if changed; otherwise inserts a new rule. Broadcasts RuleEvent for both cases.
/// Returns the rule_keys of newly-added rules so callers can do their own tracking.
async fn upsert_rules(
    specs: &[RuleSpec],
    rules: &mut HashMap<String, ActiveRule>,
    bucket_key_to_spec: &RwLock<HashMap<u32, RuleSpec>>,
    tree_dirty: &std::sync::atomic::AtomicBool,
    metrics_state: &Option<metrics_server::MetricsState>,
    log_prefix: &str,
) -> Vec<String> {
    let mut newly_added = Vec::new();

    for spec in specs {
        let rule_key = rule_identity_key(spec);

        if let Some(existing) = rules.get_mut(&rule_key) {
            let spec_changed = existing.spec.to_edn() != spec.to_edn();
            existing.last_seen = Instant::now();
            if spec_changed {
                existing.spec = spec.clone();
                if let Some(bk) = spec.bucket_key() {
                    let mut bmap = bucket_key_to_spec.write().await;
                    bmap.insert(bk, spec.clone());
                }
                tree_dirty.store(true, std::sync::atomic::Ordering::SeqCst);
            }

            if let Some(ref state) = metrics_state {
                state.broadcast(metrics_server::MetricsEvent::RuleEvent {
                    ts: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
                    action: "refreshed".to_string(),
                    key: rule_key.clone(),
                    spec_summary: spec.to_edn(),
                    is_preloaded: false,
                    ttl_secs: 300,
                });
            }
        } else {
            let action_str = match &spec.actions[0] {
                RuleAction::Drop { .. } => "DROP",
                RuleAction::RateLimit { .. } => "RATE-LIMIT",
                RuleAction::Pass { .. } => "PASS",
                RuleAction::Count { .. } => "COUNT",
            };
            info!("    {} [{}]: {}", log_prefix, action_str, spec.describe());

            rules.insert(rule_key.clone(), ActiveRule {
                last_seen: Instant::now(),
                spec: spec.clone(),
                preloaded: false,
            });

            if let Some(ref state) = metrics_state {
                state.broadcast(metrics_server::MetricsEvent::RuleEvent {
                    ts: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
                    action: "added".to_string(),
                    key: rule_key.clone(),
                    spec_summary: spec.to_edn(),
                    is_preloaded: false,
                    ttl_secs: 300,
                });
            }

            if let Some(bk) = spec.bucket_key() {
                let mut bmap = bucket_key_to_spec.write().await;
                bmap.entry(bk).or_insert_with(|| spec.clone());
            }

            tree_dirty.store(true, std::sync::atomic::Ordering::SeqCst);
            newly_added.push(rule_key);
        }
    }

    newly_added
}

/// Recompile the decision tree and broadcast the updated DAG snapshot.
///
/// Shared helper that replaces three nearly-identical blocks (FieldTracker insertion,
/// PayloadTracker insertion, rule expiry). The guard condition (tree_dirty / enforce)
/// stays at the call site.
async fn recompile_tree_and_broadcast(
    filter: &VethFilter,
    rules: &HashMap<String, ActiveRule>,
    tree_counter_labels: &RwLock<HashMap<u32, (String, String)>>,
    tree_dirty: &std::sync::atomic::AtomicBool,
    metrics_state: &Option<metrics_server::MetricsState>,
    log_context: &str,
) -> Result<()> {
    let all_specs: Vec<RuleSpec> = rules.values()
        .map(|r| r.spec.clone())
        .collect();

    let (nodes, manifest, retired) = filter.compile_and_flip_tree(&all_specs).await?;
    info!("    Tree recompiled ({}): {} rules -> {} nodes", log_context, all_specs.len(), nodes);

    // Accumulate retired bucket counts BEFORE clearing labels
    if let Some(ref state) = metrics_state {
        state.accumulate_retired_counts(&retired).await;
    }

    // Refresh tree_counter_labels from manifest
    let mut tcl = tree_counter_labels.write().await;
    tcl.clear();
    for entry in &manifest {
        tcl.insert(entry.rule_id, (entry.action_kind().to_string(), entry.label.clone()));
    }
    drop(tcl);
    tree_dirty.store(false, std::sync::atomic::Ordering::SeqCst);

    // Emit DAG snapshot to metrics server
    if let Some(ref state) = metrics_state {
        let mut dag_nodes = filter.serialize_dag().await;
        attach_manifest_labels_to_dag(&mut dag_nodes, &manifest);
        state.broadcast(metrics_server::MetricsEvent::DagSnapshot {
            ts: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
            node_count: dag_nodes.len(),
            rule_count: all_specs.len(),
            nodes: dag_nodes,
        });
    }

    Ok(())
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
    let tracker = Arc::new(RwLock::new(FieldTracker::new(holon.clone(), args.decay_half_life, args.rate_half_life_ms)));
    
    // Create payload tracker
    let payload_tracker = Arc::new(RwLock::new(PayloadTracker::new(
        holon.clone(),
        args.payload_threshold,
        args.payload_min_anomalies,
        args.rate_limit,
        args.sample_rate,
    )));
    info!("PayloadTracker initialized: {} windows ({}B), threshold={}, min_anomalies={}",
        NUM_PAYLOAD_WINDOWS, MAX_PAYLOAD_BYTES,
        args.payload_threshold.map_or("auto".to_string(), |t| format!("{}", t)),
        args.payload_min_anomalies);

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
            // AsyncFd owns the RingBuf; we access it via the guard
            let mut async_fd = match AsyncFd::new(ring_buf) {
                Ok(fd) => fd,
                Err(e) => {
                    error!("Failed to create AsyncFd for ring buffer: {}", e);
                    return;
                }
            };

            loop {
                // Wait for data availability (epoll on the ring buffer fd)
                let mut guard = match async_fd.readable_mut().await {
                    Ok(g) => g,
                    Err(e) => {
                        error!("AsyncFd readable error: {}", e);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };

                // Drain all available items from the shared ring buffer
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
                                // Channel full - drop sample (back-pressure)
                            }
                        }
                    }
                }

                // Clear readiness so epoll re-arms for next notification
                guard.clear_ready();
            }
        });
    }
    drop(sample_tx);

    // Tracked rules: key -> (last_seen, spec)
    // With tree engine, we maintain the full rule set and recompile on changes.
    let active_rules: Arc<RwLock<HashMap<String, ActiveRule>>> = Arc::new(RwLock::new(HashMap::new()));
    // Whether the tree needs recompilation (set when rules change)
    let tree_dirty: Arc<std::sync::atomic::AtomicBool> = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Unified tree counter labels from compilation manifest (rule_id -> (action_kind, label))
    // Populated authoritatively from post-compilation rule manifest, not pre-compilation guesses.
    let tree_counter_labels: Arc<RwLock<std::collections::HashMap<u32, (String, String)>>> =
        Arc::new(RwLock::new(std::collections::HashMap::new()));

    let rate_limiter_names: Arc<RwLock<std::collections::HashMap<u32, (String, String)>>> = 
        Arc::new(RwLock::new(std::collections::HashMap::new()));

    // Map bucket_key → RuleSpec for display (handles unnamed limiters after In expansion)
    let bucket_key_to_spec: Arc<RwLock<std::collections::HashMap<u32, RuleSpec>>> = 
        Arc::new(RwLock::new(std::collections::HashMap::new()));

    // ── Pre-load rules from file if specified ──
    if let Some(ref rules_path) = args.rules_file {
        let start = Instant::now();
        let preloaded = parse_rules_file(rules_path)?;
        let parse_time = start.elapsed();
        info!("Parsed {} rules from {:?} in {:?}", preloaded.len(), rules_path, parse_time);

        // Validate byte match density per scope (tenant limit enforcement)
        if args.max_byte_matches_per_scope > 0 {
            validate_byte_match_density(&preloaded, args.max_byte_matches_per_scope)?;
        }

        if !preloaded.is_empty() {
            let mut rules = active_rules.write().await;
            let mut rate_map = rate_limiter_names.write().await;
            let mut bucket_map = bucket_key_to_spec.write().await;
            
            // Build rate limiter name map and bucket_key→spec map for logging
            for spec in &preloaded {
                // Store rules with rate limiters or counters in bucket_map
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
                
                // Rate limiter names (for rate limiter reporting, separate from TREE_COUNTERS)
                if let Some(key) = spec.bucket_key() {
                    for action in &spec.actions {
                        if let veth_filter::RuleAction::RateLimit { name: Some((ns, n)), .. } = action {
                            rate_map.insert(key, (ns.clone(), n.clone()));
                            break;
                        }
                    }
                }
                
                let key = rule_identity_key(&spec);
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

                // Populate tree_counter_labels from authoritative manifest
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
                // Note: no retired buckets on initial compile

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
        
        // Convert ActiveRule to ActiveRuleInfo for metrics server
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
            1000, // broadcast channel capacity
        );

        // Spawn metrics HTTP server
        let server_state = state.clone();
        let metrics_port = args.metrics_port;
        tokio::spawn(async move {
            if let Err(e) = metrics_server::run_server(server_state, metrics_port).await {
                error!("Metrics server error: {}", e);
            }
        });

        // Spawn metrics collector task
        let collector_state = state.clone();
        tokio::spawn(async move {
            metrics_server::metrics_collector_task(
                collector_state,
                Duration::from_millis(500),  // unified metrics every 500ms
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
    // Tick at which the current anomaly was first detected (for log suppression)
    let mut anomaly_active_since: Option<u64> = None;

    // Scalar PPS baseline for instant-response rate limiting.
    // The rate vector (time-decayed) also encodes PPS but lags behind rate
    // changes — it's useful for fleet distribution, not local rate_factor.
    // warmup_first_sample is set when the first sample arrives (not at program init)
    // to avoid counting pre-traffic dead time in the PPS calculation.
    let mut warmup_first_sample: Option<Instant> = None;
    let mut baseline_pps: f64 = 0.0;

    // Hybrid analysis trigger state
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
                        // Record first sample time for accurate PPS calculation
                        if warmup_first_sample.is_none() {
                            warmup_first_sample = Some(Instant::now());
                        }

                        // FieldTracker: add_sample includes per-packet decay after warmup
                        tracker_w.add_sample(&sample);

                        // PayloadTracker: inline per-packet processing
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

        // Compute PPS estimate for this tick (before resetting counters)
        let tick_secs = tick_elapsed.as_secs_f64().max(0.001);
        let estimated_pps = (packets_since_tick as f64 * args.sample_rate as f64) / tick_secs;

        ticks_processed += 1;
        packets_since_tick = 0;
        last_tick = Instant::now();

        let tracker_read = tracker.read().await;
        let current_phase = tracker_read.current_phase.clone();
        drop(tracker_read);

        // ── Warmup path ──
        // During warmup: accumulate into baseline regardless of sample count.
        // Check warmup completion thresholds every tick.
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

                // Compute scalar baseline PPS for instant-response rate limiting.
                // Use time since first sample (not program init) to exclude pre-traffic dead time.
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
            // Too few decayed samples for meaningful analysis — skip this tick
            tracker.write().await.snapshot_history();
            continue;
        }

        // Scalar PPS-based rate factor: instant response to traffic changes.
        // The rate vector (time-decayed) encodes PPS too, but lags behind —
        // useful for fleet distribution, not local rate limiting.
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
        // Same scalar rate_factor for compound rules
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

        // Compute drift rate (attack onset classification)
        // Thresholds calibrated for decay-based processing where drift_rate
        // measures per-tick change in drift-to-baseline similarity:
        //   Normal noise: |rate| < 0.002/tick
        //   Flash flood (5:1 ratio): ~ -0.015 to -0.020/tick
        //   Ramp-up (gradual): ~ -0.003 to -0.010/tick
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
        // When drift_rate confirms attack onset but drift hasn't crossed the
        // anomaly threshold yet, probe for newly-concentrated fields at a lower
        // bar. The drift_rate provides detection confidence; concentration only
        // identifies which fields to target in the rule.
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
                            concentration: *conc,
                            drift: anomaly.drift,
                            anomalous_ratio: anomaly.anomalous_ratio,
                            attributed_pattern: attribution.as_ref().map(|(p, _)| p.clone()),
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

        // Check for anomaly
        if anomaly.drift < args.threshold && !concentrated.is_empty() {
            let is_new_anomaly = anomaly_active_since.is_none();
            let ticks_in_anomaly = anomaly_active_since
                .map(|start| ticks_processed - start)
                .unwrap_or(0);
            if is_new_anomaly {
                anomaly_active_since = Some(ticks_processed);
            }

            // Log first detection, then suppress to every 20 ticks
            if is_new_anomaly || ticks_in_anomaly % 20 == 0 {
                warn!(">>> ANOMALY DETECTED: drift={:.3}, anomalous_ratio={:.1}%{}",
                      anomaly.drift, anomaly.anomalous_ratio * 100.0,
                      if !is_new_anomaly { format!(" (ongoing, tick {})", ticks_in_anomaly) } else { String::new() });
                for (field, value, conc) in &concentrated {
                    warn!("    Concentrated: {}={} ({:.1}%)", field, value, conc * 100.0);
                }
            }

            let mut actions_taken = Vec::new();

            let detections: Vec<Detection> = concentrated.iter().map(|(field, value, conc)| {
                Detection {
                    field: field.clone(),
                    value: value.clone(),
                    concentration: *conc,
                    drift: anomaly.drift,
                    anomalous_ratio: anomaly.anomalous_ratio,
                    attributed_pattern: attribution.as_ref().map(|(p, _)| p.clone()),
                    rate_factor,
                }
            }).collect();

            if let Some(spec) =
                compile_compound_rule(&detections, args.rate_limit, estimated_pps)
            {
                let mut rules = active_rules.write().await;

                // Check for subsumption/broadening before adding
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

            let payload_rules = payload_tracker_write.check_and_derive_rules(estimated_pps, ft_rate_factor);
            drop(payload_tracker_write);

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
    Ok(())
}
