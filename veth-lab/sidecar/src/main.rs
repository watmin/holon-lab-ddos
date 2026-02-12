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

use anyhow::{Context, Result};
use chrono::{DateTime, Local, Utc};
use clap::Parser;
use holon::{Holon, Primitives, SegmentMethod, Vector};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};
use veth_filter::{
    FieldDim, PacketSample, RuleAction, RuleSpec, RuleType, VethFilter,
};

#[derive(Parser, Debug)]
#[command(name = "veth-sidecar")]
#[command(about = "Enhanced Holon-based packet anomaly detection sidecar")]
struct Args {
    /// Interface with XDP filter attached
    #[arg(short, long, default_value = "veth-filter")]
    interface: String,

    /// Detection window in seconds
    #[arg(short, long, default_value = "2")]
    window: u64,

    /// Drift threshold for anomaly detection (0.0 - 1.0)
    /// Lower = more sensitive. Attack traffic typically shows drift 0.7-0.8
    #[arg(short, long, default_value = "0.85")]
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

    /// Enable rate limiting instead of binary DROP (experimental)
    #[arg(long)]
    rate_limit: bool,
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

/// Enhanced field tracker using Holon primitives
struct FieldTracker {
    holon: Arc<Holon>,
    /// Baseline accumulator (float, averaged during warmup)
    baseline_acc: Vec<f64>,
    /// Baseline vector (frozen after warmup, used for comparison)
    baseline_vec: Vector,
    /// Recent accumulator (current window)
    recent_acc: Vec<f64>,
    /// Packet counts per field value (for concentration)
    value_counts: HashMap<String, ValueStats>,
    /// Baseline value counts (accumulated during warmup)
    baseline_value_counts: HashMap<String, u64>,
    /// Values that were concentrated during baseline (key: "field:value")
    baseline_concentrated: HashSet<String>,
    /// Total packets in current window
    window_count: usize,
    /// Total packets seen during warmup (for proper averaging)
    warmup_total_packets: usize,
    /// Baseline accumulator magnitude PER WINDOW (for rate ratio calculation)
    baseline_magnitude_per_window: f64,
    /// Number of warmup windows (for averaging)
    warmup_windows_count: usize,
    /// Last window reset time
    last_reset: Instant,
    /// Whether baseline is frozen (after warmup)
    baseline_frozen: bool,
    /// Window vectors for segment() detection
    window_history: Vec<Vector>,
    /// Current phase (detected by segment)
    current_phase: String,
    /// Attack codebook for attribution
    codebook: AttackCodebook,
    /// Variant detector
    variant_detector: VariantDetector,
}

impl FieldTracker {
    fn new(holon: Arc<Holon>) -> Self {
        let dims = holon.dimensions();
        Self {
            holon,
            baseline_acc: vec![0.0; dims],
            baseline_vec: Vector::zeros(dims),
            recent_acc: vec![0.0; dims],
            value_counts: HashMap::new(),
            baseline_value_counts: HashMap::new(),
            baseline_concentrated: HashSet::new(),
            window_count: 0,
            warmup_total_packets: 0,
            baseline_magnitude_per_window: 0.0,
            warmup_windows_count: 0,
            last_reset: Instant::now(),
            baseline_frozen: false,
            window_history: Vec::new(),
            current_phase: "learning".to_string(),
            codebook: AttackCodebook::new(),
            variant_detector: VariantDetector::new(),
        }
    }

    /// Freeze the baseline (called after warmup)
    fn freeze_baseline(&mut self) {
        self.baseline_frozen = true;
        self.current_phase = "monitoring".to_string();

        // Add the final window to the baseline accumulator
        for (i, &v) in self.recent_acc.iter().enumerate() {
            self.baseline_acc[i] += v;
        }
        self.warmup_total_packets += self.window_count;
        
        // Add final window's value counts to baseline
        for (key, stats) in &self.value_counts {
            *self.baseline_value_counts.entry(key.clone()).or_default() += stats.count;
        }

        // Create normalized baseline vector from accumulated warmup data
        // Use a lower threshold (0.01) to preserve more signal
        let norm = self.baseline_acc.iter().map(|x| x * x).sum::<f64>().sqrt();
        
        // Store baseline magnitude PER WINDOW for rate ratio calculation
        // We divide by warmup_windows_count to get average magnitude per window
        // This makes ||recent_window|| / ||baseline_per_window|| comparable
        let windows_count = self.warmup_windows_count.max(1) as f64;
        self.baseline_magnitude_per_window = norm / windows_count;
        
        info!("Baseline magnitude: total={:.2}, per_window={:.2} ({} windows)",
              norm, self.baseline_magnitude_per_window, self.warmup_windows_count);
        
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
        // Group by field
        let mut field_totals: HashMap<&str, u64> = HashMap::new();
        let mut field_values: HashMap<&str, Vec<(&str, u64)>> = HashMap::new();
        
        for (key, &count) in &self.baseline_value_counts {
            if let Some((field, value)) = key.split_once(':') {
                *field_totals.entry(field).or_default() += count;
                field_values.entry(field).or_default().push((value, count));
            }
        }
        
        // Mark concentrated values (>50% of field traffic)
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

        // Debug: count non-zero dimensions
        let nnz = self.baseline_vec.data().iter().filter(|&&x| x != 0).count();
        info!("Baseline built from {} total packets, {} non-zero dimensions ({:.1}%)", 
              self.warmup_total_packets, nnz, 100.0 * nnz as f64 / self.baseline_vec.dimensions() as f64);

        // Add normal baseline to codebook
        self.codebook.add_pattern("normal_baseline", self.baseline_vec.clone());

        // IMPORTANT: Reset recent_acc so first detection window starts fresh
        // Otherwise we'd compare the last warmup window against itself (drift=0)
        self.recent_acc.fill(0.0);
        self.window_count = 0;
        self.value_counts.clear();
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

    /// Add a packet sample to the tracker (using Walkable encoding)
    fn add_sample(&mut self, sample: &PacketSample) {
        // Use Walkable encoding (5x faster than JSON)
        let vec = self.holon.encode_walkable(sample);

        // Add to recent accumulator
        for (i, v) in vec.data().iter().enumerate() {
            self.recent_acc[i] += *v as f64;
        }

        // Track individual field values for concentration analysis
        // All values are raw numbers — same as wireshark/eBPF sees
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
        ];
        // TCP-only p0f fields
        if sample.protocol == 6 {
            fields.push(("tcp_flags", sample.tcp_flags.to_string()));
            fields.push(("tcp_window", sample.tcp_window.to_string()));
        }

        for (field, value) in fields {
            let key = format!("{}:{}", field, value);
            let entry = self.value_counts.entry(key).or_default();
            entry.count += 1;
            entry.last_seen = Instant::now();
        }

        self.window_count += 1;
    }

    /// Compute magnitude ratio: ||recent_window|| / ||baseline_per_window||
    /// This gives us the rate multiplier - purely from vector operations
    /// If ratio = 10, we're seeing 10x the traffic rate
    fn compute_magnitude_ratio(&self) -> f64 {
        if self.baseline_magnitude_per_window < 1e-10 || self.window_count == 0 {
            return 1.0;
        }
        let recent_magnitude = self.recent_acc.iter().map(|x| x * x).sum::<f64>().sqrt();
        recent_magnitude / self.baseline_magnitude_per_window
    }
    
    /// Compute rate factor from magnitude ratio
    /// rate_factor = 1 / magnitude_ratio (capped at 1.0)
    /// If we're seeing 100x traffic, rate_factor = 0.01 (throttle to 1%)
    fn compute_rate_factor(&self) -> f64 {
        let ratio = self.compute_magnitude_ratio();
        if ratio > 0.0 {
            (1.0 / ratio).min(1.0)
        } else {
            1.0
        }
    }

    /// Compute detailed anomaly analysis using similarity_profile
    fn compute_anomaly_details(&self) -> AnomalyDetails {
        if self.window_count == 0 {
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
        if self.window_count > 100 {
            // Log for high-traffic windows (likely attack)
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
            &self.window_history,
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

    /// Attribute current window to known patterns
    fn attribute_pattern(&self) -> Option<(String, f64)> {
        if self.codebook.is_empty() || self.window_count == 0 {
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

        // Find concentrated values that are NEW (not in baseline)
        for (field, total) in field_totals {
            if let Some(values) = field_values.get(field) {
                for (value, count) in values {
                    let concentration = *count as f64 / total as f64;
                    if concentration >= threshold {
                        let key = format!("{}:{}", field, value);
                        
                        // Skip values that were concentrated during baseline
                        // These are "expected" concentrations
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

    /// Reset the window
    fn reset_window(&mut self) {
        // During warmup, accumulate into baseline_acc (will be normalized when frozen)
        if !self.baseline_frozen && self.window_count > 0 {
            for (i, &v) in self.recent_acc.iter().enumerate() {
                self.baseline_acc[i] += v;
            }
            self.warmup_total_packets += self.window_count;
            self.warmup_windows_count += 1;
            
            // Also accumulate value counts into baseline for concentration tracking
            for (key, stats) in &self.value_counts {
                *self.baseline_value_counts.entry(key.clone()).or_default() += stats.count;
            }
        }

        // Save window vector for segment() history
        if self.window_count > 0 {
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
                self.window_history.push(Vector::from_data(data));

                // Keep only last 100 windows
                if self.window_history.len() > 100 {
                    self.window_history.remove(0);
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
    /// Convert a detection field/value into a (FieldDim, u32) constraint.
    fn to_constraint(&self) -> Option<(FieldDim, u32)> {
        match self.field.as_str() {
            "src_ip" => self.value.parse::<Ipv4Addr>().ok()
                .map(|ip| (FieldDim::SrcIp, u32::from_ne_bytes(ip.octets()))),
            "dst_ip" => self.value.parse::<Ipv4Addr>().ok()
                .map(|ip| (FieldDim::DstIp, u32::from_ne_bytes(ip.octets()))),
            "dst_port" => self.value.parse::<u16>().ok()
                .map(|port| (FieldDim::L4Word1, port as u32)),
            "src_port" => self.value.parse::<u16>().ok()
                .map(|port| (FieldDim::L4Word0, port as u32)),
            "protocol" => self.value.parse::<u8>().ok()
                .map(|proto| (FieldDim::Proto, proto as u32)),
            // p0f-level fields
            "tcp_flags" => self.value.parse::<u8>().ok()
                .map(|flags| (FieldDim::TcpFlags, flags as u32)),
            "ttl" => self.value.parse::<u8>().ok()
                .map(|ttl| (FieldDim::Ttl, ttl as u32)),
            "df_bit" => self.value.parse::<u8>().ok()
                .map(|df| (FieldDim::DfBit, df as u32)),
            "tcp_window" => self.value.parse::<u16>().ok()
                .map(|win| (FieldDim::TcpWindow, win as u32)),
            _ => None,
        }
    }

    /// Compile a single detection into a RuleSpec
    fn compile_rule_spec(&self, use_rate_limit: bool, sample_rate: u32, window_samples: usize) -> Option<RuleSpec> {
        let constraint = self.to_constraint()?;
        let estimated_current_pps = (window_samples as f64 * sample_rate as f64) / 2.0;
        let allowed_pps = (estimated_current_pps * self.rate_factor).max(100.0) as u32;
        let action = if use_rate_limit { RuleAction::RateLimit } else { RuleAction::Drop };
        let rate_pps = if use_rate_limit { Some(allowed_pps) } else { None };
        Some(RuleSpec { constraints: vec![constraint], action, rate_pps, priority: 100 })
    }
}

/// Compile multiple concentrated detections into a compound RuleSpec.
/// Gathers all constraints and produces a single rule.
fn compile_compound_rule(
    detections: &[Detection],
    use_rate_limit: bool,
    sample_rate: u32,
    window_samples: usize,
) -> Option<RuleSpec> {
    if detections.is_empty() { return None; }
    if detections.len() == 1 {
        return detections[0].compile_rule_spec(use_rate_limit, sample_rate, window_samples);
    }

    let constraints: Vec<(FieldDim, u32)> = detections.iter()
        .filter_map(|d| d.to_constraint())
        .collect();
    if constraints.is_empty() { return None; }

    let estimated_current_pps = (window_samples as f64 * sample_rate as f64) / 2.0;
    let rate_factor = detections[0].rate_factor;
    let allowed_pps = (estimated_current_pps * rate_factor).max(100.0) as u32;
    let action = if use_rate_limit { RuleAction::RateLimit } else { RuleAction::Drop };
    let rate_pps = if use_rate_limit { Some(allowed_pps) } else { None };

    Some(RuleSpec::compound(constraints, action, rate_pps))
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
    info!("  Dimensions: {}", args.dimensions);
    info!("  Warmup: {} windows / {} packets", args.warmup_windows, args.warmup_packets);
    info!("  Sample rate: 1 in {} packets", args.sample_rate);
    info!("  Perf buffer: {} pages/CPU ({}KB)", args.perf_pages, args.perf_pages * 4);
    info!("  Log file: {:?}", log_path);
    info!("");
    info!("Enhanced features enabled:");
    info!("  - Walkable encoding (5x faster)");
    info!("  - similarity_profile() for per-dimension analysis");
    info!("  - segment() for phase detection");
    info!("  - invert() for pattern attribution");
    info!("  - analogy() for zero-shot variant detection");
    info!("  - Magnitude-aware $log encoding for packet sizes");
    info!("");

    // Load XDP filter
    let filter = VethFilter::new(&args.interface)?;
    let filter = Arc::new(filter);

    // Configure filter
    filter.set_sample_rate(args.sample_rate).await?;
    filter.set_enforce_mode(args.enforce).await?;

    // Enable tree Rete evaluation engine (blue/green decision tree)
    filter.set_eval_mode(2).await?;
    info!("Tree Rete rule engine enabled (blue/green)");

    // Initialize Holon
    let holon = Arc::new(Holon::new(args.dimensions));
    info!("Holon initialized with {} dimensions", args.dimensions);

    // Create enhanced field tracker
    let tracker = Arc::new(RwLock::new(FieldTracker::new(holon.clone())));

    // Take perf array for sample reading
    let mut perf_array = filter.take_perf_array().await?;

    // Channel for samples from all CPUs
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
                        match tx.try_send(sample) {
                            Ok(_) => {},
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return,
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                // Channel full - drop sample
                            }
                        }
                    }
                }
            }
        });
    }
    drop(sample_tx);

    // Tracked rules: key -> (last_seen, spec)
    // With tree engine, we maintain the full rule set and recompile on changes.
    struct ActiveRule {
        last_seen: Instant,
        spec: RuleSpec,
    }
    let active_rules: Arc<RwLock<HashMap<String, ActiveRule>>> = Arc::new(RwLock::new(HashMap::new()));
    // Whether the tree needs recompilation (set when rules change)
    let tree_dirty: Arc<std::sync::atomic::AtomicBool> = Arc::new(std::sync::atomic::AtomicBool::new(false));

    info!("Starting enhanced detection loop...");
    info!("  Warmup: {} windows or {} packets", args.warmup_windows, args.warmup_packets);
    info!("");

    let window_duration = Duration::from_secs(args.window);
    let mut _samples_processed = 0u64;
    let mut windows_processed = 0u64;
    let mut total_warmup_packets = 0usize;
    let mut warmup_complete = false;

    let mut last_window_check = Instant::now();
    let check_interval = Duration::from_millis(100);
    const MAX_SAMPLES_PER_CHECK: usize = 200;
    let mut samples_since_window_check = 0usize;

    loop {
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

        let should_check_window = last_window_check.elapsed() >= check_interval
            || samples_since_window_check >= 1000;

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

        let tracker_read = tracker.read().await;
        let window_elapsed = tracker_read.last_reset.elapsed() >= window_duration;
        let has_enough_samples = tracker_read.window_count >= args.min_packets;
        drop(tracker_read);

        if window_elapsed {
            windows_processed += 1;

            if has_enough_samples {
                // Get enhanced anomaly details
                let tracker_read = tracker.read().await;
                let anomaly = tracker_read.compute_anomaly_details();
                let concentrated = tracker_read.find_concentrated_values(args.concentration);
                let window_count = tracker_read.window_count;
                let current_phase = tracker_read.current_phase.clone();
                let attribution = tracker_read.attribute_pattern();
                // Get vector-derived rate factor: 1/magnitude_ratio
                let rate_factor = tracker_read.compute_rate_factor();
                drop(tracker_read);

                total_warmup_packets += window_count;

                let stats = filter.stats().await.ok();
                let drops = stats.as_ref().map(|s| s.dropped_packets).unwrap_or(0);
                let total = stats.as_ref().map(|s| s.total_packets).unwrap_or(0);

                // Check warmup
                if !warmup_complete {
                    let warmup_by_windows = windows_processed >= args.warmup_windows;
                    let warmup_by_packets = total_warmup_packets >= args.warmup_packets;

                    if warmup_by_windows || warmup_by_packets {
                        warmup_complete = true;
                        tracker.write().await.freeze_baseline();
                        info!("========================================");
                        info!("WARMUP COMPLETE - baseline FROZEN");
                        info!("  Windows: {}, Packets: {}", windows_processed, total_warmup_packets);
                        info!("  Detection now active with extended primitives!");
                        info!("========================================");
                        // Skip detection on this window - baseline was just frozen from this data
                        // Next window will be first real detection
                        continue;
                    } else {
                        info!(
                            "Window {} [WARMUP]: {} packets, drift={:.3} | XDP total: {}, dropped: {} | warmup {}/{} windows, {}/{} packets",
                            windows_processed, window_count, anomaly.drift, total, drops,
                            windows_processed, args.warmup_windows,
                            total_warmup_packets, args.warmup_packets
                        );
                        tracker.write().await.reset_window();
                        continue;
                    }
                }

                // Check for phase changes
                if let Some(new_phase) = tracker.write().await.detect_phase_changes() {
                    warn!(">>> PHASE CHANGE DETECTED: {}", new_phase);
                }

                info!(
                    "Window {}: {} packets, drift={:.3}, anom_ratio={:.1}%, phase={} | XDP total: {}, dropped: {}",
                    windows_processed, window_count, anomaly.drift, anomaly.anomalous_ratio * 100.0,
                    current_phase, total, drops
                );

                // Log attribution if available
                if let Some((pattern, confidence)) = &attribution {
                    info!("    Attribution: {} ({:.1}% confidence)", pattern, confidence * 100.0);
                }

                // Check for anomaly
                if anomaly.drift < args.threshold && !concentrated.is_empty() {
                    warn!(">>> ANOMALY DETECTED: drift={:.3}, anomalous_ratio={:.1}%",
                          anomaly.drift, anomaly.anomalous_ratio * 100.0);

                    let mut actions_taken = Vec::new();

                    // Build detections from concentrated fields
                    let detections: Vec<Detection> = concentrated.iter().map(|(field, value, conc)| {
                        warn!("    Concentrated: {}={} ({:.1}%)", field, value, conc * 100.0);
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

                    // Compile compound rule from all concentrated detections
                    if let Some(spec) =
                        compile_compound_rule(&detections, args.rate_limit, args.sample_rate, window_count)
                    {
                        let rule_key = spec.describe();

                        let mut rules = active_rules.write().await;
                        if rules.contains_key(&rule_key) {
                            rules.get_mut(&rule_key).unwrap().last_seen = Instant::now();
                        } else {
                            let action_str = match spec.action {
                                RuleAction::Drop => "DROP",
                                RuleAction::RateLimit => "RATE_LIMIT",
                                RuleAction::Pass => "PASS",
                            };
                            warn!("    RULE:\n{}", spec.to_sexpr_pretty());
                            actions_taken.push(RuleInfo {
                                rule_type: "tree".to_string(),
                                value: spec.describe(),
                                action: action_str.to_string(),
                                rate_pps: spec.rate_pps,
                            });
                            rules.insert(rule_key, ActiveRule {
                                last_seen: Instant::now(),
                                spec: spec.clone(),
                            });
                            tree_dirty.store(true, std::sync::atomic::Ordering::SeqCst);
                        }

                        // Recompile and flip tree if rules changed
                        if tree_dirty.load(std::sync::atomic::Ordering::SeqCst) && args.enforce {
                            let all_specs: Vec<RuleSpec> = rules.values()
                                .map(|r| r.spec.clone())
                                .collect();
                            match filter.compile_and_flip_tree(&all_specs).await {
                                Ok(nodes) => {
                                    info!("    Tree recompiled: {} rules -> {} nodes", all_specs.len(), nodes);
                                    tree_dirty.store(false, std::sync::atomic::Ordering::SeqCst);
                                }
                                Err(e) => {
                                    warn!("    Failed to compile tree: {}", e);
                                }
                            }
                        } else if !args.enforce {
                            info!("    Would compile tree (dry-run): {} rules", rules.len());
                        }
                    }

                    // Create detection event for logging
                    let event = DetectionEvent {
                        timestamp: Utc::now(),
                        window_id: windows_processed,
                        drift: anomaly.drift,
                        anomalous_ratio: anomaly.anomalous_ratio,
                        phase: current_phase.clone(),
                        attributed_pattern: attribution.as_ref().map(|(p, _)| p.clone()),
                        attributed_confidence: attribution.as_ref().map(|(_, c)| *c).unwrap_or(0.0),
                        concentrated_fields: concentrated.clone(),
                        action_taken: actions_taken,
                        variant_similarity: None,
                    };

                    // Log as JSON for easy parsing
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
                            let attack_name = format!("attack_w{}", windows_processed);
                            tracker.write().await.add_attack_pattern(&attack_name, attack_vec);
                        }
                    }
                } else if anomaly.drift >= args.threshold {
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

            tracker.write().await.reset_window();

            // Expire old rules
            let rule_ttl = Duration::from_secs(300);
            let mut rules = active_rules.write().await;
            let expired: Vec<String> = rules
                .iter()
                .filter(|(_, active)| active.last_seen.elapsed() > rule_ttl)
                .map(|(k, _)| k.clone())
                .collect();

            let had_expired = !expired.is_empty();
            for key in expired {
                if let Some(active) = rules.remove(&key) {
                    info!("<<< EXPIRED RULE: {}", active.spec.describe());
                }
            }

            // Recompile tree if rules were expired
            if had_expired && args.enforce {
                if rules.is_empty() {
                    // No rules left: clear the tree
                    if let Err(e) = filter.clear_tree().await {
                        warn!("Failed to clear tree: {}", e);
                    } else {
                        info!("Tree cleared (all rules expired)");
                    }
                } else {
                    let all_specs: Vec<RuleSpec> = rules.values()
                        .map(|r| r.spec.clone())
                        .collect();
                    match filter.compile_and_flip_tree(&all_specs).await {
                        Ok(nodes) => {
                            info!("Tree recompiled after expiry: {} rules -> {} nodes", all_specs.len(), nodes);
                        }
                        Err(e) => {
                            warn!("Failed to recompile tree after expiry: {}", e);
                        }
                    }
                }
                tree_dirty.store(false, std::sync::atomic::Ordering::SeqCst);
            }
        }

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    #[allow(unreachable_code)]
    Ok(())
}
