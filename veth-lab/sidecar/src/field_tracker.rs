use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use holon::kernel::{Encoder, Primitives, SegmentMethod, Similarity, Vector};
use tracing::info;
use veth_filter::PacketSample;

use crate::detectors::{
    AnomalyDetails, AttackCodebook, SubspaceDetector, ValueStats, VariantDetector,
};

/// Enhanced field tracker using Holon kernel primitives with per-packet decay.
///
/// Instead of fixed 2-second windows with hard resets, the accumulator decays
/// exponentially after each packet so recent traffic naturally dominates.
pub(crate) struct FieldTracker {
    pub(crate) encoder: Encoder,
    /// Baseline accumulator (float, averaged during warmup)
    baseline_acc: Vec<f64>,
    /// Baseline vector (frozen after warmup, used for comparison)
    baseline_vec: Vector,
    /// Recent accumulator — decays per-packet after warmup
    pub(crate) recent_acc: Vec<f64>,
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
    pub(crate) drift_history: VecDeque<f64>,
    /// Current phase (detected by segment)
    pub(crate) current_phase: String,
    /// Attack codebook for attribution
    codebook: AttackCodebook,
    /// Variant detector
    variant_detector: VariantDetector,
    /// Per-packet decay factor: 0.5^(1/half_life)
    decay_factor: f64,
    /// Monotonic packet counter (for lazy value-count decay)
    packets_processed: u64,
    /// Decaying effective packet count (for concentration denominator)
    pub(crate) total_effective: f64,
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
    /// Subspace-based anomaly detector with engram library
    pub(crate) subspace: SubspaceDetector,
    /// Per-tick maximum subspace residual from raw per-packet scoring
    tick_max_residual: f64,
    /// The raw encoded vector that produced the max residual this tick
    tick_max_vec: Option<Vec<f64>>,
}

impl FieldTracker {
    pub(crate) fn new(encoder: Encoder, decay_half_life: usize, rate_half_life_ms: u64, subspace_k: usize) -> Self {
        let dims = encoder.dimensions();
        let decay_factor = if decay_half_life > 0 {
            0.5_f64.powf(1.0 / decay_half_life as f64)
        } else {
            1.0
        };
        let rate_lambda = (2.0_f64).ln() / (rate_half_life_ms as f64 / 1000.0);
        let subspace = SubspaceDetector::new(dims, subspace_k);
        Self {
            encoder,
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
            subspace,
            tick_max_residual: 0.0,
            tick_max_vec: None,
        }
    }

    /// Freeze the baseline (called after warmup).
    ///
    /// After freezing, snapshots the rate vector magnitude (baseline PPS) and
    /// clears the direction accumulator for decay-based monitoring.
    pub(crate) fn freeze_baseline(&mut self) {
        self.accumulate_warmup();

        self.baseline_frozen = true;
        self.current_phase = "monitoring".to_string();

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

        info!("Subspace baseline: n={}, threshold={:.2}, explained_ratio={:.3}, eigenvalues={:?}",
              self.subspace.baseline.n(),
              self.subspace.baseline.threshold(),
              self.subspace.baseline.explained_ratio(),
              &self.subspace.baseline.eigenvalues()[..std::cmp::min(5, self.subspace.baseline.eigenvalues().len())]);

        let nnz = self.baseline_vec.data().iter().filter(|&&x| x != 0).count();
        info!("Baseline built from {} total packets, {} non-zero dimensions ({:.1}%)",
              self.warmup_total_packets, nnz, 100.0 * nnz as f64 / self.baseline_vec.dimensions() as f64);

        self.codebook.add_pattern("normal_baseline", self.baseline_vec.clone());

        let warmup_pkts = self.warmup_total_packets.max(1) as f64;
        self.baseline_steady_magnitude = norm / warmup_pkts;

        self.baseline_rate_magnitude = self.rate_acc.iter()
            .map(|x| x * x).sum::<f64>().sqrt();
        info!("Rate vector baseline magnitude: {:.2} (time-decay lambda={:.4}, half-life={:.1}ms)",
              self.baseline_rate_magnitude, self.rate_lambda, (2.0_f64).ln() / self.rate_lambda * 1000.0);

        self.recent_acc.fill(0.0);
        self.value_counts.clear();
        self.total_effective = 0.0;
    }

    /// Add a learned attack pattern to codebook
    pub(crate) fn add_attack_pattern(&mut self, name: &str, vector: Vector) {
        self.codebook.add_pattern(name, vector.clone());

        if !self.variant_detector.is_trained() {
            let port_vec = self.encoder.get_vector("port_53");
            self.variant_detector.train(name, vector, port_vec);
        }
    }

    /// Add a packet sample to the tracker (using Walkable encoding).
    ///
    /// After warmup, applies per-packet exponential decay to `recent_acc` so
    /// recent traffic naturally dominates the accumulator.
    pub(crate) fn add_sample(&mut self, sample: &PacketSample) {
        if self.baseline_frozen {
            let alpha = self.decay_factor;
            for v in &mut self.recent_acc {
                *v *= alpha;
            }
            self.total_effective = self.total_effective * alpha + 1.0;
        } else {
            self.total_effective += 1.0;
        }

        let vec = self.encoder.encode_walkable(sample);

        if !self.baseline_frozen {
            self.subspace.learn(&vec.to_f64());
        } else {
            let vec_f64 = vec.to_f64();
            let residual = self.subspace.score(&vec_f64);
            if residual > self.tick_max_residual {
                self.tick_max_residual = residual;
                self.tick_max_vec = Some(vec_f64);
            }
        }

        for (i, v) in vec.data().iter().enumerate() {
            self.recent_acc[i] += *v as f64;
        }

        let now = Instant::now();
        let dt = now.duration_since(self.rate_last_update).as_secs_f64();
        if dt > 0.0 {
            let decay = (-self.rate_lambda * dt).exp();
            for v in &mut self.rate_acc {
                *v *= decay;
            }
            self.rate_last_update = now;
        }
        for (i, v) in vec.data().iter().enumerate() {
            self.rate_acc[i] += *v as f64;
        }

        self.packets_processed += 1;

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
            ("ttl", sample.ttl.to_string()),
            ("df_bit", sample.df_bit.to_string()),
            ("ip_id", sample.ip_id.to_string()),
            ("ip_len", sample.ip_len.to_string()),
            ("dscp", sample.dscp.to_string()),
            ("ecn", sample.ecn.to_string()),
            ("mf_bit", sample.mf_bit.to_string()),
            ("frag_offset", sample.frag_offset.to_string()),
        ];
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

    /// Compute rate factor from the time-decayed rate accumulator.
    #[allow(dead_code)]
    pub(crate) fn compute_rate_factor(&self) -> f64 {
        if self.baseline_rate_magnitude < 1e-10 { return 1.0; }
        let current_mag = self.rate_acc.iter()
            .map(|x| x * x).sum::<f64>().sqrt();
        let ratio = current_mag / self.baseline_rate_magnitude;
        if ratio > 0.0 { (1.0 / ratio).min(1.0) } else { 1.0 }
    }

    /// Compute detailed anomaly analysis using similarity_profile
    pub(crate) fn compute_anomaly_details(&self) -> AnomalyDetails {
        if self.total_effective < 1.0 {
            return AnomalyDetails {
                drift: 1.0,
                anomalous_ratio: 0.0,
                subspace_residual: 0.0,
            };
        }

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
            Vector::zeros(self.encoder.dimensions())
        };

        let profile = Primitives::similarity_profile(&recent_vec, &self.baseline_vec);

        let recent_data = recent_vec.data();
        let profile_data = profile.data();

        let mut active_dims = 0usize;
        let mut disagreeing = 0usize;

        for (i, &v) in recent_data.iter().enumerate() {
            if v != 0 {
                active_dims += 1;
                if (profile_data[i] as f64) < 0.0 {
                    disagreeing += 1;
                }
            }
        }

        if active_dims == 0 {
            return AnomalyDetails {
                drift: 1.0,
                anomalous_ratio: 0.0,
                subspace_residual: 0.0,
            };
        }

        let anomalous_ratio = disagreeing as f64 / active_dims as f64;
        let drift = Similarity::cosine(&recent_vec, &self.baseline_vec);

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
            subspace_residual: self.compute_subspace_residual(),
        }
    }

    /// Per-tick maximum subspace residual from raw per-packet scoring.
    pub(crate) fn compute_subspace_residual(&self) -> f64 {
        self.tick_max_residual
    }

    /// Take the raw encoded vector that produced the max subspace residual this tick.
    pub(crate) fn take_tick_subspace_vec(&mut self) -> Option<Vec<f64>> {
        self.tick_max_vec.take()
    }

    /// Detect phase changes using segment()
    pub(crate) fn detect_phase_changes(&mut self) -> Option<String> {
        if self.window_history.len() < 10 {
            return None;
        }

        let breakpoints = Primitives::segment(
            self.window_history.make_contiguous(),
            5,
            0.7,
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
    pub(crate) fn record_drift(&mut self, drift: f64) {
        self.drift_history.push_back(drift);
        if self.drift_history.len() > 100 {
            self.drift_history.pop_front();
        }
    }

    /// Compute drift rate: average per-tick change in drift-to-baseline similarity.
    pub(crate) fn compute_drift_rate(&self, window: usize) -> Option<f64> {
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
    pub(crate) fn attribute_pattern(&self) -> Option<(String, f64)> {
        if self.codebook.is_empty() || self.total_effective < 1.0 {
            return None;
        }

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
    pub(crate) fn find_concentrated_values(&self, threshold: f64) -> Vec<(String, String, f64)> {
        let mut results = Vec::new();

        if self.total_effective < 1.0 {
            return results;
        }

        let pkt = self.packets_processed;
        let alpha = self.decay_factor;

        let mut field_totals: HashMap<&str, f64> = HashMap::new();
        let mut field_values: HashMap<&str, Vec<(&str, f64)>> = HashMap::new();

        for (key, stats) in &self.value_counts {
            if let Some((field, value)) = key.split_once(':') {
                let dc = if self.baseline_frozen {
                    stats.decayed_count(pkt, alpha)
                } else {
                    stats.count
                };
                if dc < 0.01 { continue; }
                *field_totals.entry(field).or_default() += dc;
                field_values.entry(field).or_default().push((value, dc));
            }
        }

        for (field, total) in field_totals {
            if total < 0.01 { continue; }
            if let Some(values) = field_values.get(field) {
                for (value, count) in values {
                    let concentration = *count / total;
                    if concentration >= threshold {
                        let key = format!("{}:{}", field, value);

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

        results.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Snapshot the current accumulator state into window_history for segment() detection.
    /// Also resets per-tick subspace tracking for the next tick.
    pub(crate) fn snapshot_history(&mut self) {
        self.tick_max_residual = 0.0;
        self.tick_max_vec = None;

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
    pub(crate) fn accumulate_warmup(&mut self) {
        if self.baseline_frozen { return; }
        if self.total_effective < 1.0 { return; }

        for (i, &v) in self.recent_acc.iter().enumerate() {
            self.baseline_acc[i] += v;
        }
        self.warmup_total_packets += self.total_effective as usize;
        self.warmup_ticks_count += 1;

        for (key, stats) in &self.value_counts {
            *self.baseline_value_counts.entry(key.clone()).or_default() += stats.count as u64;
        }

        self.snapshot_history();

        self.recent_acc.fill(0.0);
        self.value_counts.clear();
        self.total_effective = 0.0;
    }
}
