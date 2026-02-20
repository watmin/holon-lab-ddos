use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use holon::{Holon, ScalarValue, Vector, WalkableValue};
use tracing::{info, warn};
use veth_filter::{FieldDim, PacketSample, Predicate, RuleAction, RuleSpec};

use crate::detectors::PayloadSubspaceDetector;

pub(crate) enum PayloadEngramEvent {
    Nothing,
    Hit { #[allow(dead_code)] name: String, stored_rules: Vec<String> },
    Minted { name: String },
}

pub(crate) const PAYLOAD_WINDOW_SIZE: usize = 64;
pub(crate) const MAX_PAYLOAD_BYTES: usize = veth_filter::SAMPLE_DATA_SIZE;
pub(crate) const NUM_PAYLOAD_WINDOWS: usize = MAX_PAYLOAD_BYTES / PAYLOAD_WINDOW_SIZE;

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

/// Global maximum payload rules across all destinations
const MAX_PAYLOAD_RULES_TOTAL: usize = 64;

/// Payload anomaly tracker using windowed VSA accumulators.
///
/// During warmup, learns a baseline of "familiar" payload byte patterns.
/// After warmup, scores each packet's payload against the baseline:
///   - If any window's absolute similarity is below the threshold, the payload
///     is classified as anomalous.
///   - Anomalous/normal payloads are stored per destination.
///   - When enough anomalies accumulate, drill-down + gap-probe + greedy
///     selection derive `l4-match` rules scoped to that destination.
pub(crate) struct PayloadTracker {
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
    anomaly_threshold: f64,
    /// User-supplied threshold override (None = auto-calibrate)
    threshold_override: Option<f64>,
    /// Minimum anomalies per dst before deriving rules
    min_anomalies_for_rules: usize,
    /// Warmup payloads kept for threshold calibration (cleared after freeze)
    warmup_payloads: Vec<Vec<u8>>,
    /// Whether to use rate-limit (vs drop) for derived rules
    use_rate_limit: bool,
    /// Active payload rules keyed by (offset, length, match_hex) -> rule_key
    active_rule_keys: HashMap<String, String>,
    /// Subspace-based payload anomaly detector with engram library
    pub(crate) payload_subspace: PayloadSubspaceDetector,
    /// Whether any subspace anomaly was seen during the current tick
    subspace_anomaly_this_tick: bool,
    /// Bundled window vector from the first subspace-anomalous packet this tick (for library check)
    last_anomalous_bundle: Option<Vec<f64>>,
}

struct PositionInfo {
    payload_pos: usize,
    consensus_byte: u8,
    is_unfamiliar: bool,
    consensus_rate: f64,
    score: f64,
}

impl PayloadTracker {
    pub(crate) fn new(
        holon: Arc<Holon>,
        threshold_override: Option<f64>,
        min_anomalies: usize,
        use_rate_limit: bool,
        subspace_k: usize,
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
            active_rule_keys: HashMap::new(),
            payload_subspace: PayloadSubspaceDetector::new(dims, subspace_k, NUM_PAYLOAD_WINDOWS),
            subspace_anomaly_this_tick: false,
            last_anomalous_bundle: None,
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
    pub(crate) fn learn(&mut self, payload: &[u8]) {
        if self.baseline_frozen { return; }

        let truncated = &payload[..std::cmp::min(payload.len(), MAX_PAYLOAD_BYTES)];
        let n_windows = Self::active_windows(truncated.len());

        for w in 0..n_windows {
            if let Some(wv) = Self::window_walkable(truncated, w) {
                let vec = self.holon.encode_walkable_value(&wv);
                for (i, &v) in vec.data().iter().enumerate() {
                    self.accumulators[w][i] += v as f64;
                }
                self.payload_subspace.learn_window(w, &vec.to_f64());
            }
        }

        if self.warmup_payloads.len() < 500 {
            self.warmup_payloads.push(truncated.to_vec());
        }

        self.packet_count += 1;
    }

    /// Freeze baseline after warmup, then auto-calibrate the anomaly threshold.
    pub(crate) fn freeze_baseline(&mut self) {
        if self.packet_count == 0 { return; }

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

        if self.threshold_override.is_some() {
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
            self.anomaly_threshold = 0.7;
            info!("Payload threshold: {:.4} (fallback, no warmup similarities)", self.anomaly_threshold);
            self.warmup_payloads.clear();
            return;
        }

        let n = all_min_sims.len() as f64;
        let mean = all_min_sims.iter().sum::<f64>() / n;
        let variance = all_min_sims.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / n;
        let raw_stddev = variance.sqrt();
        let stddev = raw_stddev.max(0.1);
        let calibrated = (mean - 3.0 * stddev).max(0.3).min(mean - 0.05);
        self.anomaly_threshold = calibrated;

        info!("Payload threshold auto-calibrated: {:.4} (mean={:.4}, stddev={:.4}, n={})",
              self.anomaly_threshold, mean, stddev, all_min_sims.len());

        for (w, sub) in self.payload_subspace.window_subspaces.iter().enumerate() {
            if sub.n() > 0 {
                tracing::debug!("Payload window {} subspace: n={}, threshold={:.2}", w, sub.n(), sub.threshold());
            }
        }
        info!("Payload subspace baselines trained ({} windows)",
              self.payload_subspace.window_subspaces.iter().filter(|s| s.n() > 10).count());

        self.warmup_payloads.clear();
    }

    /// Score a single window against its baseline.
    fn score_window(&self, payload: &[u8], window_idx: usize) -> Option<f64> {
        let baseline = self.baselines[window_idx].as_ref()?;
        let wv = Self::window_walkable(payload, window_idx)?;
        let vec = self.holon.encode_walkable_value(&wv);
        Some(self.holon.similarity(&vec, baseline))
    }

    /// Score and classify a single sample against baseline, storing in per-dst state.
    /// Scores via both cosine similarity (for drill-down) and subspace residual (for engrams).
    pub(crate) fn process_single_sample(&mut self, sample: &PacketSample) {
        if !self.baseline_frozen { return; }

        let l4_payload = sample.l4_payload();
        if l4_payload.is_empty() { return; }
        let l4_hdr_len = sample.l4_header_len().unwrap_or(0);

        let truncated = &l4_payload[..std::cmp::min(l4_payload.len(), MAX_PAYLOAD_BYTES)];
        let n_windows = Self::active_windows(truncated.len());
        let dims = self.holon.dimensions();

        let mut is_cosine_anomalous = false;
        let mut is_subspace_anomalous = false;
        let mut bundled = vec![0.0f64; dims];
        let mut windows_encoded = 0usize;

        for w in 0..n_windows {
            if let Some(wv) = Self::window_walkable(truncated, w) {
                let vec = self.holon.encode_walkable_value(&wv);
                let vec_f64 = vec.to_f64();

                if let Some(baseline) = self.baselines[w].as_ref() {
                    let sim = self.holon.similarity(&vec, baseline);
                    if sim < self.anomaly_threshold {
                        is_cosine_anomalous = true;
                    }
                }

                if let Some(residual) = self.payload_subspace.score_window(w, &vec_f64) {
                    if residual > self.payload_subspace.window_subspaces[w].threshold() {
                        is_subspace_anomalous = true;
                    }
                }

                for (i, &v) in vec_f64.iter().enumerate() {
                    bundled[i] += v;
                }
                windows_encoded += 1;
            }
        }

        let dst_state = self.dst_states
            .entry(sample.dst_ip)
            .or_insert_with(|| DstPayloadState::new(l4_hdr_len));
        dst_state.l4_header_len = l4_hdr_len;
        if is_cosine_anomalous {
            dst_state.add_anomalous(l4_payload);
        } else {
            dst_state.add_normal(l4_payload);
        }

        if is_subspace_anomalous && windows_encoded > 0 {
            let norm = bundled.iter().map(|x| x * x).sum::<f64>().sqrt();
            if norm > 1e-10 {
                for v in &mut bundled { *v /= norm; }
            }
            self.payload_subspace.learn_attack(&bundled, truncated);
            if !self.subspace_anomaly_this_tick {
                self.last_anomalous_bundle = Some(bundled);
            }
            self.subspace_anomaly_this_tick = true;
        }
    }

    /// Process a batch of samples (delegates to process_single_sample).
    #[allow(dead_code)]
    pub(crate) fn process_window_samples(&mut self, samples: &[PacketSample]) {
        for sample in samples {
            self.process_single_sample(sample);
        }
    }

    /// Expire old destination states.
    pub(crate) fn expire_old_dsts(&mut self, ttl: Duration) {
        let now = Instant::now();
        self.dst_states.retain(|_, state| now.duration_since(state.last_seen) < ttl);
    }

    /// Track that a rule has been inserted into the active rule set.
    pub(crate) fn mark_rule_active(&mut self, pattern_key: String, rule_key: String) {
        self.active_rule_keys.insert(pattern_key, rule_key);
    }

    /// Remove tracking for an expired rule.
    pub(crate) fn mark_rule_expired(&mut self, rule_key: &str) {
        self.active_rule_keys.retain(|_, v| v != rule_key);
    }

    /// Extract a stable dedup key from a payload RuleSpec's BytePattern.
    pub(crate) fn pattern_dedup_key(spec: &RuleSpec) -> Option<String> {
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
    pub(crate) fn check_and_derive_rules(&mut self, estimated_current_pps: f64, rate_factor: f64) -> Vec<RuleSpec> {
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

        rules.retain(|spec| {
            if let Some(pk) = Self::pattern_dedup_key(spec) {
                !self.active_rule_keys.contains_key(&pk)
            } else {
                true
            }
        });

        let total_active = self.active_rule_keys.len();
        if total_active + rules.len() > MAX_PAYLOAD_RULES_TOTAL {
            let allowed = MAX_PAYLOAD_RULES_TOTAL.saturating_sub(total_active);
            rules.truncate(allowed);
        }

        rules
    }

    /// Per-tick payload engram lifecycle.
    ///
    /// Manages the payload subspace anomaly streak, library lookups,
    /// attack subspace learning, and engram minting.
    /// Returns `true` if a known engram was matched (drill-down should be skipped).
    pub(crate) fn tick_engram_lifecycle(&mut self, tick: u64) -> PayloadEngramEvent {
        let was_anomalous = self.subspace_anomaly_this_tick;
        self.subspace_anomaly_this_tick = false;

        if was_anomalous {
            self.payload_subspace.anomaly_streak += 1;

            if self.payload_subspace.anomaly_streak == 1 {
                if let Some(bundled) = self.last_anomalous_bundle.take() {
                    if let Some((name, res)) = self.payload_subspace.check_library(&bundled) {
                        let stored_rules: Vec<String> = self.payload_subspace.library.get(&name)
                            .and_then(|e| e.metadata().get("rules").cloned())
                            .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
                            .unwrap_or_default();

                        if stored_rules.is_empty() {
                            warn!(">>> PAYLOAD ENGRAM HIT: '{}' (residual={:.2}) — known attack (no stored rules)", name, res);
                        } else {
                            warn!(">>> PAYLOAD ENGRAM HIT: '{}' (residual={:.2}) — deploying {} stored rule(s)", name, res, stored_rules.len());
                        }
                        return PayloadEngramEvent::Hit { name: name.clone(), stored_rules };
                    }
                }
            } else {
                self.last_anomalous_bundle = None;
            }

            if self.payload_subspace.anomaly_streak == 1 {
                warn!(">>> PAYLOAD SUBSPACE ANOMALY — no engram match, learning attack manifold");
            }

            PayloadEngramEvent::Nothing
        } else {
            self.last_anomalous_bundle = None;
            let had_attack = self.payload_subspace.has_active_attack();
            let streak = self.payload_subspace.anomaly_streak;

            if had_attack && streak >= 5 {
                let name = format!("payload_attack_t{}", tick);
                let mut metadata = std::collections::HashMap::new();
                metadata.insert("minted_at_tick".to_string(), serde_json::Value::from(tick));
                metadata.insert("anomaly_streak".to_string(), serde_json::Value::from(streak));
                self.payload_subspace.mint_engram(&name, metadata);
                warn!(">>> PAYLOAD ENGRAM MINTED: '{}' after {} anomalous ticks (library size: {})",
                      name, streak, self.payload_subspace.library.len());
                PayloadEngramEvent::Minted { name }
            } else {
                if had_attack {
                    self.payload_subspace.cancel_attack();
                    info!("Payload attack subspace cancelled (streak {} < 5 minimum)", streak);
                }
                self.payload_subspace.anomaly_streak = 0;
                PayloadEngramEvent::Nothing
            }
        }
    }

    pub(crate) fn update_engram_metadata(&mut self, name: &str, key: &str, value: serde_json::Value) {
        if let Some(engram) = self.payload_subspace.library.get_mut(name) {
            engram.metadata_mut().insert(key.to_string(), value);
        }
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

        let atk_slice = state.anomalous_samples.make_contiguous();
        let leg_slice = state.normal_samples.make_contiguous();
        let extended = Self::gap_probe(&detected, atk_slice, leg_slice);

        let pos_info = Self::collect_position_info(
            &extended, atk_slice, leg_slice,
        );

        if pos_info.is_empty() {
            return None;
        }

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

            let mut counts: HashMap<u8, usize> = HashMap::new();
            for &b in &atk_bytes {
                *counts.entry(b).or_insert(0) += 1;
            }

            let (&consensus_byte, &consensus_count) = counts.iter()
                .max_by_key(|(_, c)| *c)
                .unwrap();

            let is_unfamiliar = !leg_set.contains(&consensus_byte);
            let consensus_rate = consensus_count as f64 / atk_bytes.len() as f64;

            let mut score = consensus_rate;
            if !is_unfamiliar { score *= 0.1; }
            if consensus_byte == 0x00 && leg_set.is_empty() {
                score *= 0.2;
            }

            result.push(PositionInfo {
                payload_pos: pos,
                consensus_byte,
                is_unfamiliar,
                consensus_rate,
                score,
            });
        }

        result.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        result
    }

    /// Build multi-byte l4-match rules by grouping positions into spans.
    fn build_multi_byte_rules(
        dst_ip: u32,
        pos_info: &[PositionInfo],
        l4_hdr_len: usize,
        use_rate_limit: bool,
        allowed_pps: u32,
    ) -> Vec<RuleSpec> {
        if pos_info.is_empty() { return vec![]; }

        let useful: Vec<&PositionInfo> = pos_info.iter()
            .filter(|p| p.is_unfamiliar && p.consensus_rate >= 0.5)
            .collect();

        if useful.is_empty() { return vec![]; }

        let mut sorted: Vec<&PositionInfo> = useful;
        sorted.sort_by_key(|p| p.payload_pos);

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

        specs.truncate(4);
        specs
    }
}
