//! SubspaceDetector and EngramLibrary wrappers for HTTP fields.
//!
//! Adapted from veth-lab/sidecar/src/detectors.rs with HTTP-specific fields.

use std::collections::HashMap;
use std::time::Instant;

use holon::kernel::{Encoder, Primitives, Vector};
use holon::memory::{EngramLibrary, OnlineSubspace};
use tracing::{error, info};

// =============================================================================
// SubspaceDetector — online manifold learning + engram memory
// =============================================================================

/// Field-level subspace detector using OnlineSubspace for manifold-aware
/// anomaly detection and EngramLibrary for attack pattern memory.
pub struct SubspaceDetector {
    pub baseline: OnlineSubspace,
    attack_subspace: Option<OnlineSubspace>,
    pub library: EngramLibrary,
    pub anomaly_streak: usize,
    attack_vecs: Vec<Vec<f64>>,
    dim: usize,
    k: usize,
}

impl SubspaceDetector {
    pub fn new(dim: usize, k: usize) -> Self {
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

    /// Feed a vector to the baseline during warmup.
    pub fn learn(&mut self, vec_f64: &[f64]) {
        self.baseline.update(vec_f64);
    }

    /// Score a vector against the baseline. Higher = more anomalous.
    pub fn score(&self, vec_f64: &[f64]) -> f64 {
        self.baseline.residual(vec_f64)
    }

    /// Check engram library for a known attack pattern.
    pub fn check_library(&mut self, vec_f64: &[f64]) -> Option<(String, f64)> {
        if self.library.is_empty() { return None; }
        let matches = self.library.match_vec(vec_f64, 1, self.dim);
        if let Some((name, _)) = matches.first() {
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
    pub fn learn_attack(&mut self, vec_f64: &[f64]) {
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
    pub fn mint_engram(
        &mut self,
        name: &str,
        surprise: HashMap<String, f64>,
        metadata: HashMap<String, serde_json::Value>,
    ) {
        if let Some(sub) = self.attack_subspace.take() {
            self.library.add(name, &sub, Some(surprise), metadata);
            info!("Engram minted: '{}' (library size: {})", name, self.library.len());
        }
        self.attack_vecs.clear();
        self.anomaly_streak = 0;
    }

    /// Compute per-field surprise fingerprint via anomalous component unbinding.
    pub fn surprise_fingerprint(
        &self,
        vec_f64: &[f64],
        encoder: &Encoder,
        fields: &[&str],
    ) -> Vec<(String, f64)> {
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

    pub fn cancel_attack(&mut self) {
        self.attack_subspace = None;
        self.attack_vecs.clear();
        self.anomaly_streak = 0;
    }

    pub fn has_active_attack(&self) -> bool {
        self.attack_subspace.is_some()
    }

    pub fn load_library(&mut self, path: &str) {
        match EngramLibrary::load(path) {
            Ok(lib) => {
                info!("Loaded engram library from '{}' ({} engrams)", path, lib.len());
                self.library = lib;
            }
            Err(e) => info!("No existing engram library at '{}': {}", path, e),
        }
    }

    pub fn save_library(&self, path: &str) {
        if let Err(e) = self.library.save(path) {
            error!("Failed to save engram library to '{}': {}", path, e);
        } else {
            info!("Saved engram library to '{}' ({} engrams)", path, self.library.len());
        }
    }
}

// =============================================================================
// ValueStats — per-field-value tracking with lazy exponential decay
// =============================================================================

/// Tracked statistics for a field value with lazy exponential decay.
pub struct ValueStats {
    pub count: f64,
    pub last_seen: Instant,
    last_decay_req: u64,
}

impl ValueStats {
    pub fn decayed_count(&self, current_req: u64, alpha: f64) -> f64 {
        let elapsed = current_req.saturating_sub(self.last_decay_req);
        if elapsed == 0 { return self.count; }
        self.count * alpha.powi(elapsed as i32)
    }

    pub fn add_one(&mut self, current_req: u64, alpha: f64) {
        let elapsed = current_req.saturating_sub(self.last_decay_req);
        if elapsed > 0 {
            self.count *= alpha.powi(elapsed as i32);
            self.last_decay_req = current_req;
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
            last_decay_req: 0,
        }
    }
}
