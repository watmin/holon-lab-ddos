use std::collections::HashMap;
use std::time::Instant;

use holon::kernel::{Encoder, Primitives, Vector};
use holon::memory::{EngramLibrary, OnlineSubspace};
use tracing::{error, info};

/// Known attack patterns for attribution
pub(crate) struct AttackCodebook {
    patterns: Vec<(String, Vector)>,
}

impl AttackCodebook {
    pub(crate) fn new() -> Self {
        Self { patterns: Vec::new() }
    }

    /// Add a named pattern to the codebook
    pub(crate) fn add_pattern(&mut self, name: &str, vector: Vector) {
        self.patterns.push((name.to_string(), vector));
    }

    /// Attribute a sample to the most similar pattern
    pub(crate) fn attribute(&self, sample_vec: &Vector) -> Option<(String, f64)> {
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
    pub(crate) fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

/// Zero-shot attack variant detection using analogy
pub(crate) struct VariantDetector {
    /// Known attack prototype (e.g., DNS reflection)
    known_attack_proto: Option<Vector>,
    /// Port vector for the known attack (e.g., port 53 for DNS)
    known_port_vec: Option<Vector>,
    /// Name of the known attack
    known_attack_name: String,
}

impl VariantDetector {
    pub(crate) fn new() -> Self {
        Self {
            known_attack_proto: None,
            known_port_vec: None,
            known_attack_name: String::new(),
        }
    }

    /// Train on a known attack pattern
    pub(crate) fn train(&mut self, name: &str, attack_proto: Vector, port_vec: Vector) {
        self.known_attack_name = name.to_string();
        self.known_attack_proto = Some(attack_proto);
        self.known_port_vec = Some(port_vec);
    }

    pub(crate) fn is_trained(&self) -> bool {
        self.known_attack_proto.is_some()
    }
}

/// Detailed anomaly analysis from similarity_profile
#[derive(Debug, Clone)]
pub(crate) struct AnomalyDetails {
    /// Overall drift (cosine similarity to baseline)
    pub(crate) drift: f64,
    /// Fraction of dimensions that disagree with baseline
    pub(crate) anomalous_ratio: f64,
    /// Subspace residual (reconstruction error, higher = more anomalous)
    pub(crate) subspace_residual: f64,
}

/// Field-level subspace detector using OnlineSubspace for manifold-aware
/// anomaly detection and EngramLibrary for attack pattern memory.
pub(crate) struct SubspaceDetector {
    /// Baseline subspace trained during warmup
    pub(crate) baseline: OnlineSubspace,
    /// Attack subspace built online during an active anomaly
    attack_subspace: Option<OnlineSubspace>,
    /// Persistent attack memory
    pub(crate) library: EngramLibrary,
    /// Consecutive anomalous ticks (for minting threshold)
    pub(crate) anomaly_streak: usize,
    /// Collected anomalous vectors during current attack (f64 for subspace ops)
    attack_vecs: Vec<Vec<f64>>,
    /// Dimensionality
    dim: usize,
    /// Number of principal components
    k: usize,
}

impl SubspaceDetector {
    pub(crate) fn new(dim: usize, k: usize) -> Self {
        Self {
            baseline: OnlineSubspace::with_params(dim, k, 2.0, 0.01, 3.5, 500),
            attack_subspace: None,
            library: EngramLibrary::new(dim),
            anomaly_streak: 0,
            attack_vecs: Vec::new(),
            dim,
            k,
        }
    }

    /// Feed a vector to the baseline subspace during warmup.
    pub(crate) fn learn(&mut self, vec_f64: &[f64]) {
        self.baseline.update(vec_f64);
    }

    /// Score a vector against the baseline. Higher = more anomalous.
    pub(crate) fn score(&self, vec_f64: &[f64]) -> f64 {
        self.baseline.residual(vec_f64)
    }

    /// Check the engram library for a known attack pattern.
    /// Returns (engram_name, residual) if a match is found below the engram's own threshold.
    pub(crate) fn check_library(&mut self, vec_f64: &[f64]) -> Option<(String, f64)> {
        if self.library.is_empty() {
            return None;
        }
        let matches = self.library.match_vec(vec_f64, 1, self.dim);
        if let Some((name, _similarity)) = matches.first() {
            if let Some(engram) = self.library.get_mut(name) {
                let res = engram.residual(vec_f64);
                if res < engram.subspace().threshold() * 2.0 {
                    return Some((name.clone(), res));
                }
            }
        }
        None
    }

    /// Feed a vector to the attack subspace during an active anomaly.
    pub(crate) fn learn_attack(&mut self, vec_f64: &[f64]) {
        if self.attack_subspace.is_none() {
            self.attack_subspace = Some(OnlineSubspace::with_params(
                self.dim, self.k, 2.0, 0.01, 3.5, 500,
            ));
        }
        if let Some(sub) = &mut self.attack_subspace {
            sub.update(vec_f64);
        }
        self.attack_vecs.push(vec_f64.to_vec());
    }

    /// Mint an engram from the current attack subspace.
    pub(crate) fn mint_engram(&mut self, name: &str, surprise: HashMap<String, f64>, metadata: HashMap<String, serde_json::Value>) {
        if let Some(sub) = self.attack_subspace.take() {
            self.library.add(name, &sub, Some(surprise), metadata);
            info!("Engram minted: '{}' (library size: {})", name, self.library.len());
        }
        self.attack_vecs.clear();
        self.anomaly_streak = 0;
    }

    /// Compute per-field surprise fingerprint via anomalous component unbinding.
    pub(crate) fn surprise_fingerprint(&self, vec_f64: &[f64], encoder: &Encoder, fields: &[&str]) -> Vec<(String, f64)> {
        let anomaly = self.baseline.anomalous_component(vec_f64);
        let anomaly_vec = Vector::from_f64(&anomaly);
        let mut scores: Vec<(String, f64)> = fields.iter().map(|&field| {
            let role = encoder.get_vector(field);
            let unbound = Primitives::bind(&anomaly_vec, &role);
            let norm = unbound.data().iter().map(|&x| (x as f64).powi(2)).sum::<f64>().sqrt();
            (field.to_string(), norm)
        }).collect();
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scores
    }

    /// Reset the attack state without minting.
    pub(crate) fn cancel_attack(&mut self) {
        self.attack_subspace = None;
        self.attack_vecs.clear();
        self.anomaly_streak = 0;
    }

    /// Whether an attack subspace is currently being built.
    pub(crate) fn has_active_attack(&self) -> bool {
        self.attack_subspace.is_some()
    }

    /// Load library from disk if path exists.
    pub(crate) fn load_library(&mut self, path: &str) {
        match EngramLibrary::load(path) {
            Ok(lib) => {
                info!("Loaded engram library from '{}' ({} engrams)", path, lib.len());
                self.library = lib;
            }
            Err(e) => {
                info!("No existing engram library at '{}': {}", path, e);
            }
        }
    }

    /// Save library to disk.
    pub(crate) fn save_library(&self, path: &str) {
        if let Err(e) = self.library.save(path) {
            error!("Failed to save engram library to '{}': {}", path, e);
        } else {
            info!("Saved engram library to '{}' ({} engrams)", path, self.library.len());
        }
    }
}

/// Payload-level subspace detector with per-window OnlineSubspaces
/// and an engram library for known payload attack patterns.
pub(crate) struct PayloadSubspaceDetector {
    /// Per-window subspaces (one per payload window)
    pub(crate) window_subspaces: Vec<OnlineSubspace>,
    /// Payload attack pattern memory
    pub(crate) library: EngramLibrary,
    /// Attack subspace for payload-level patterns
    attack_subspace: Option<OnlineSubspace>,
    /// Raw payloads collected during current attack
    attack_payloads: Vec<Vec<u8>>,
    /// Consecutive anomalous ticks
    pub(crate) anomaly_streak: usize,
    /// Dimensionality
    dim: usize,
    /// Number of principal components
    k: usize,
}

impl PayloadSubspaceDetector {
    pub(crate) fn new(dim: usize, k: usize, num_windows: usize) -> Self {
        let window_subspaces = (0..num_windows)
            .map(|_| OnlineSubspace::with_params(dim, k, 2.0, 0.01, 3.5, 500))
            .collect();
        Self {
            window_subspaces,
            library: EngramLibrary::new(dim),
            attack_subspace: None,
            attack_payloads: Vec::new(),
            anomaly_streak: 0,
            dim,
            k,
        }
    }

    /// Feed a window vector to the corresponding window subspace during warmup.
    pub(crate) fn learn_window(&mut self, window_idx: usize, vec_f64: &[f64]) {
        if window_idx < self.window_subspaces.len() {
            self.window_subspaces[window_idx].update(vec_f64);
        }
    }

    /// Score a window vector against its subspace. Higher = more anomalous.
    pub(crate) fn score_window(&self, window_idx: usize, vec_f64: &[f64]) -> Option<f64> {
        if window_idx < self.window_subspaces.len() && self.window_subspaces[window_idx].n() > 10 {
            Some(self.window_subspaces[window_idx].residual(vec_f64))
        } else {
            None
        }
    }

    /// Check the payload engram library for a known pattern.
    pub(crate) fn check_library(&mut self, vec_f64: &[f64]) -> Option<(String, f64)> {
        if self.library.is_empty() {
            return None;
        }
        let matches = self.library.match_vec(vec_f64, 1, self.dim);
        if let Some((name, _similarity)) = matches.first() {
            if let Some(engram) = self.library.get_mut(name) {
                let res = engram.residual(vec_f64);
                if res < engram.subspace().threshold() * 2.0 {
                    return Some((name.clone(), res));
                }
            }
        }
        None
    }

    /// Feed a payload vector to the attack subspace.
    pub(crate) fn learn_attack(&mut self, vec_f64: &[f64], raw_payload: &[u8]) {
        if self.attack_subspace.is_none() {
            self.attack_subspace = Some(OnlineSubspace::with_params(
                self.dim, self.k, 2.0, 0.01, 3.5, 500,
            ));
        }
        if let Some(sub) = &mut self.attack_subspace {
            sub.update(vec_f64);
        }
        self.attack_payloads.push(raw_payload.to_vec());
    }

    /// Mint a payload engram.
    pub(crate) fn mint_engram(&mut self, name: &str, metadata: HashMap<String, serde_json::Value>) {
        if let Some(sub) = self.attack_subspace.take() {
            self.library.add(name, &sub, None, metadata);
            info!("Payload engram minted: '{}' (library size: {})", name, self.library.len());
        }
        self.attack_payloads.clear();
        self.anomaly_streak = 0;
    }

    pub(crate) fn cancel_attack(&mut self) {
        self.attack_subspace = None;
        self.attack_payloads.clear();
        self.anomaly_streak = 0;
    }

    pub(crate) fn has_active_attack(&self) -> bool {
        self.attack_subspace.is_some()
    }

    pub(crate) fn load_library(&mut self, path: &str) {
        match EngramLibrary::load(path) {
            Ok(lib) => {
                info!("Loaded payload engram library from '{}' ({} engrams)", path, lib.len());
                self.library = lib;
            }
            Err(e) => {
                info!("No existing payload engram library at '{}': {}", path, e);
            }
        }
    }

    pub(crate) fn save_library(&self, path: &str) {
        if let Err(e) = self.library.save(path) {
            error!("Failed to save payload engram library to '{}': {}", path, e);
        } else {
            info!("Saved payload engram library to '{}' ({} engrams)", path, self.library.len());
        }
    }
}

/// Tracked statistics for a field value with lazy exponential decay.
///
/// Instead of resetting counts each window, each entry decays independently
/// based on how many packets have elapsed since its last update.
pub(crate) struct ValueStats {
    pub(crate) count: f64,
    pub(crate) last_seen: Instant,
    /// Packet counter at last update (for lazy decay computation)
    last_decay_pkt: u64,
}

impl ValueStats {
    /// Return the decayed count as of `current_pkt` using per-packet factor `alpha`.
    pub(crate) fn decayed_count(&self, current_pkt: u64, alpha: f64) -> f64 {
        let elapsed = current_pkt.saturating_sub(self.last_decay_pkt);
        if elapsed == 0 { return self.count; }
        self.count * alpha.powi(elapsed as i32)
    }

    /// Decay to `current_pkt`, then add 1.0.
    pub(crate) fn add_one(&mut self, current_pkt: u64, alpha: f64) {
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
