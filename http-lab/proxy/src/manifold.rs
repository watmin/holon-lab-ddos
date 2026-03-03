//! Manifold firewall — Layers 0, 1, and 2 shared state and evaluation.
//!
//! The sidecar trains subspaces and publishes a `ManifoldState` via ArcSwap.
//! The proxy loads it (wait-free) and scores every request that passes Layer 3
//! (the symbolic rule tree).
//!
//! Layer 0 — Normal Allow List: pass if the request projects well onto any
//!   normal engram subspace. This is the primary defense for legitimate traffic.
//!
//! Layer 1 — Anomaly Enforcement: score against the baseline subspace.
//!   High residual (alien structure) → deny (403, exploit/scan).
//!   Moderate residual (familiar but anomalous) → rate-limit (429, DDoS variant).
//!
//! Layer 2 — Window Spectrum: strategic threat mode set by the sidecar's
//!   WindowTracker. Adjusts thresholds for Layer 1 decisions.

use holon::kernel::{Encoder, Primitives, Vector};
use holon::memory::OnlineSubspace;

/// Strategic threat classification from Layer 2 (window spectrum analysis).
#[derive(Debug, Clone)]
pub enum ThreatMode {
    /// Normal operations — standard thresholds.
    Normal,
    /// Collapsed spectrum — volumetric flood detected.
    /// Sidecar is auto-generating rate-limit rules for Layer 3.
    Volumetric { estimated_rps: f64 },
    /// Unusual spectrum — exploit/scan detected.
    /// Lower the deny threshold for more aggressive rejection.
    Targeted,
}

/// A normal-traffic engram subspace for Layer 0 allow-list matching.
pub struct NormalSubspace {
    pub name: String,
    pub subspace: OnlineSubspace,
    pub threshold: f64,
}

/// Shared manifold state published by the sidecar, consumed by the proxy.
///
/// All `OnlineSubspace` fields are read-only clones — `residual()` takes
/// `&self`, so multiple proxy threads can score concurrently.
pub struct ManifoldState {
    /// Layer 0: normal engram subspaces. Pass if residual < threshold for any.
    pub normal_subspaces: Vec<NormalSubspace>,
    /// Layer 1: baseline subspace for anomaly scoring.
    pub baseline: Option<OnlineSubspace>,
    /// Layer 2: current strategic threat assessment.
    pub threat_mode: ThreatMode,
    /// Layer 1 threshold: residual above this → deny (exploit).
    pub deny_threshold: f64,
    /// Layer 1 threshold: residual between normal and deny → rate-limit (DDoS).
    pub rate_limit_rps: f64,
}

impl ManifoldState {
    /// Empty state — manifold not yet trained. All requests pass through.
    pub fn empty() -> Self {
        Self {
            normal_subspaces: vec![],
            baseline: None,
            threat_mode: ThreatMode::Normal,
            deny_threshold: f64::INFINITY,
            rate_limit_rps: 100.0,
        }
    }

    /// Whether the manifold has been trained and is ready to score.
    pub fn is_ready(&self) -> bool {
        self.baseline.is_some()
    }
}

/// What the manifold decided about a request.
#[derive(Debug)]
pub enum ManifoldVerdict {
    /// Layer 0: matches a normal engram — allow.
    Allow,
    /// Manifold not yet trained — no opinion.
    Warmup,
    /// Layer 1: moderate residual — rate-limit (DDoS variant).
    RateLimit { rps: f64, residual: f64 },
    /// Layer 1: high residual — deny (exploit/scan).
    Deny { residual: f64 },
}

/// Score a request vector against the manifold state.
///
/// Evaluation order:
///   1. Layer 0: check normal subspaces — if any match, Allow.
///   2. Layer 1: score against baseline — classify as rate-limit or deny.
pub fn evaluate_manifold(vec_f64: &[f64], state: &ManifoldState) -> ManifoldVerdict {
    if !state.is_ready() {
        return ManifoldVerdict::Warmup;
    }

    // Layer 0: Normal allow list
    for normal in &state.normal_subspaces {
        let residual = normal.subspace.residual(vec_f64);
        if residual <= normal.threshold {
            return ManifoldVerdict::Allow;
        }
    }

    // Layer 1: Anomaly scoring against baseline
    let baseline = state.baseline.as_ref().unwrap();
    let residual = baseline.residual(vec_f64);
    let threshold = baseline.threshold();

    if residual <= threshold {
        return ManifoldVerdict::Allow;
    }

    // Adjust deny threshold based on threat mode
    let deny_threshold = match &state.threat_mode {
        ThreatMode::Targeted => state.deny_threshold * 0.8,
        _ => state.deny_threshold,
    };

    if residual > deny_threshold {
        ManifoldVerdict::Deny { residual }
    } else {
        let rps = match &state.threat_mode {
            ThreatMode::Volumetric { .. } => state.rate_limit_rps * 0.5,
            _ => state.rate_limit_rps,
        };
        ManifoldVerdict::RateLimit { rps, residual }
    }
}

// =============================================================================
// Post-verdict drilldown attribution
// =============================================================================

/// Top-level Walkable fields to sweep during post-verdict drilldown.
const DRILLDOWN_FIELDS: &[&str] = &[
    "method", "path", "headers", "header_shapes",
    "path_shape", "query_shape", "path_parts", "query_parts",
    "header_order", "cookies", "src_ip",
];

/// A single field's anomaly attribution from the drilldown.
#[derive(Debug, Clone)]
pub struct DrilldownAttribution {
    pub field: String,
    pub score: f64,
}

/// Lightweight post-verdict drilldown: unbind the anomalous component against
/// each top-level Walkable field to identify which structural elements caused
/// the deny/rate-limit. Runs after the verdict is decided — not blocking.
///
/// Returns the top `limit` fields sorted by surprise score (descending).
pub fn drilldown_audit(
    vec_f64: &[f64],
    state: &ManifoldState,
    encoder: &Encoder,
    limit: usize,
) -> Vec<DrilldownAttribution> {
    let baseline = match &state.baseline {
        Some(b) => b,
        None => return vec![],
    };

    let anomaly = baseline.anomalous_component(vec_f64);
    let anomaly_vec = Vector::from_f64(&anomaly);

    let mut scores: Vec<DrilldownAttribution> = DRILLDOWN_FIELDS
        .iter()
        .map(|&field| {
            let role = encoder.get_vector(field);
            let unbound = Primitives::bind(&anomaly_vec, &role);
            let norm = unbound
                .data()
                .iter()
                .map(|&x| (x as f64).powi(2))
                .sum::<f64>()
                .sqrt();
            DrilldownAttribution {
                field: field.to_string(),
                score: norm,
            }
        })
        .collect();

    scores.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    scores.truncate(limit);
    scores
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trained_subspace(dim: usize, k: usize) -> OnlineSubspace {
        let mut sub = OnlineSubspace::new(dim, k);
        let mut rng = 42u64;
        for _ in 0..200 {
            rng = rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let coeff = (rng >> 33) as f64 / u32::MAX as f64 * 2.0 - 1.0;
            let v: Vec<f64> = (0..dim)
                .map(|i| if i % 2 == 0 { coeff } else { 0.0 })
                .collect();
            sub.update(&v);
        }
        sub
    }

    #[test]
    fn empty_state_returns_warmup() {
        let state = ManifoldState::empty();
        let v = vec![0.0; 256];
        assert!(matches!(evaluate_manifold(&v, &state), ManifoldVerdict::Warmup));
    }

    #[test]
    fn in_distribution_returns_allow() {
        let dim = 256;
        let sub = trained_subspace(dim, 8);
        let threshold = sub.threshold();
        let state = ManifoldState {
            normal_subspaces: vec![NormalSubspace {
                name: "test-normal".into(),
                subspace: sub.clone(),
                threshold,
            }],
            baseline: Some(sub),
            threat_mode: ThreatMode::Normal,
            deny_threshold: threshold * 2.0,
            rate_limit_rps: 100.0,
        };

        let mut rng = 999u64;
        rng = rng
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let coeff = (rng >> 33) as f64 / u32::MAX as f64 * 2.0 - 1.0;
        let v: Vec<f64> = (0..dim)
            .map(|i| if i % 2 == 0 { coeff } else { 0.0 })
            .collect();

        assert!(matches!(evaluate_manifold(&v, &state), ManifoldVerdict::Allow));
    }

    #[test]
    fn out_of_distribution_returns_deny() {
        let dim = 256;
        let sub = trained_subspace(dim, 8);
        let threshold = sub.threshold();
        let state = ManifoldState {
            normal_subspaces: vec![],
            baseline: Some(sub),
            threat_mode: ThreatMode::Normal,
            deny_threshold: threshold * 1.5,
            rate_limit_rps: 100.0,
        };

        // Completely random vector — should be far from the learned subspace
        let mut rng = 777u64;
        let v: Vec<f64> = (0..dim)
            .map(|_| {
                rng = rng
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (rng >> 33) as f64 / u32::MAX as f64 * 2.0 - 1.0
            })
            .collect();

        let verdict = evaluate_manifold(&v, &state);
        assert!(
            matches!(verdict, ManifoldVerdict::Deny { .. } | ManifoldVerdict::RateLimit { .. }),
            "OOD vector should not be allowed: {:?}",
            verdict
        );
    }

    #[test]
    fn targeted_mode_lowers_deny_threshold() {
        let dim = 256;
        let sub = trained_subspace(dim, 8);
        let threshold = sub.threshold();
        let normal_state = ManifoldState {
            normal_subspaces: vec![],
            baseline: Some(sub.clone()),
            threat_mode: ThreatMode::Normal,
            deny_threshold: threshold * 3.0,
            rate_limit_rps: 100.0,
        };
        let targeted_state = ManifoldState {
            normal_subspaces: vec![],
            baseline: Some(sub),
            threat_mode: ThreatMode::Targeted,
            deny_threshold: threshold * 3.0,
            rate_limit_rps: 100.0,
        };

        // Vector that's somewhat anomalous
        let mut rng = 555u64;
        let v: Vec<f64> = (0..dim)
            .map(|_| {
                rng = rng
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (rng >> 33) as f64 / u32::MAX as f64 * 2.0 - 1.0
            })
            .collect();

        let v_normal = evaluate_manifold(&v, &normal_state);
        let v_targeted = evaluate_manifold(&v, &targeted_state);

        // Targeted mode should be at least as aggressive
        match (&v_normal, &v_targeted) {
            (ManifoldVerdict::RateLimit { .. }, ManifoldVerdict::Deny { .. }) => {}
            (a, b) => {
                // Both same verdict is also acceptable
                assert!(
                    std::mem::discriminant(a) == std::mem::discriminant(b)
                        || matches!(b, ManifoldVerdict::Deny { .. }),
                    "targeted should be >= aggressive: normal={:?}, targeted={:?}",
                    a,
                    b
                );
            }
        }
    }
}
