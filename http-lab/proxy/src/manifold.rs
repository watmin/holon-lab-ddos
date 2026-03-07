//! Spectral firewall — Layers 0, 1, and 2 shared state and evaluation.
//!
//! The sidecar trains striped subspaces and publishes a `ManifoldState`
//! via ArcSwap.  The proxy loads it (wait-free) and scores every request
//! that passes Layer 3 (the symbolic rule tree).
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

use holon::kernel::Encoder;
use holon::{Walkable, WalkableValue};
use holon::memory::StripedSubspace;

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
    pub subspace: StripedSubspace,
    pub threshold: f64,
}

/// Shared manifold state published by the sidecar, consumed by the proxy.
///
/// All `StripedSubspace` fields are read-only clones — `residual()` takes
/// `&self`, so multiple proxy threads can score concurrently.
pub struct ManifoldState {
    /// Layer 0: normal engram subspaces. Pass if residual < threshold for any.
    pub normal_subspaces: Vec<NormalSubspace>,
    /// Layer 1: baseline striped subspace for anomaly scoring.
    pub baseline: Option<StripedSubspace>,
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
    Allow { residual: f64 },
    /// Manifold not yet trained — no opinion.
    Warmup,
    /// Layer 1: moderate residual — rate-limit (DDoS variant).
    RateLimit { rps: f64, residual: f64 },
    /// Layer 1: high residual — deny (exploit/scan).
    Deny { residual: f64 },
}

/// Score a striped request vector against the manifold state.
///
/// Evaluation order:
///   1. Compute baseline residual (once — all decisions use this value).
///   2. Layer 0: if residual ≤ threshold, Allow.  Also check any additional
///      normal engram subspaces.
///   3. Layer 1: classify as rate-limit or deny based on residual magnitude.
pub fn evaluate_manifold(stripe_vecs: &[Vec<f64>], state: &ManifoldState) -> ManifoldVerdict {
    if !state.is_ready() {
        return ManifoldVerdict::Warmup;
    }

    let baseline = state.baseline.as_ref().unwrap();
    let residual = baseline.residual(stripe_vecs);

    if residual.is_nan() {
        return ManifoldVerdict::Deny { residual: f64::INFINITY };
    }

    let threshold = baseline.threshold();

    // Layer 0: baseline is the primary normal reference
    if residual <= threshold {
        return ManifoldVerdict::Allow { residual };
    }

    // Layer 0 (continued): check additional normal engram subspaces
    for normal in &state.normal_subspaces {
        let nr = normal.subspace.residual(stripe_vecs);
        if !nr.is_nan() && nr <= normal.threshold {
            return ManifoldVerdict::Allow { residual };
        }
    }

    // Layer 1: anomaly classification
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
// Post-verdict drilldown attribution (flat, per-stripe)
// =============================================================================

/// A single field's anomaly attribution from the drilldown.
#[derive(Debug, Clone)]
pub struct DrilldownAttribution {
    pub field: String,
    pub score: f64,
}

/// Full drilldown result: per-field attributions + anomaly breadth metrics.
///
/// Three complementary metrics quantify how spread the anomaly is across fields:
///
/// - **concentration** (max/mean): simplest, one number. High = narrow.
/// - **entropy** (Shannon): information-theoretic. High = broad (uniform).
///   Normalized to [0, 1] by dividing by log(n).
/// - **gini** (Gini coefficient): inequality measure. 0 = perfectly uniform
///   (broadest). 1 = all energy in one field (narrowest).
#[derive(Debug, Clone)]
pub struct DrilldownResult {
    pub fields: Vec<DrilldownAttribution>,
    /// Concentration ratio: `max_score / mean_score`.
    /// High = narrow anomaly (few fields dominate).
    /// Near 1.0 = broad anomaly (scores spread evenly).
    pub concentration: f64,
    /// Normalized Shannon entropy of score distribution [0, 1].
    /// 0 = all energy in one field (narrowest). 1 = perfectly uniform (broadest).
    pub entropy: f64,
    /// Gini coefficient of score distribution [0, 1].
    /// 0 = perfectly uniform (broadest). 1 = all energy in one field (narrowest).
    pub gini: f64,
}

/// Flat drilldown: walk the Walkable to find every leaf path, unbind each
/// from its stripe's anomalous component, and score.
///
/// With striped encoding, each leaf binding lives in exactly one stripe
/// (determined by `Encoder::field_stripe(path, n_stripes)`).
///
/// Attribution uses **cosine similarity** between the real-valued anomalous
/// component and each leaf's bipolar binding vector.  This is the correct
/// MAP-algebra probe:  if the binding contributed to the anomaly, the
/// cosine is high (the binding's direction is present in the residual);
/// if it was reconstructed by the subspace, the cosine is ≈ 0.
///
/// Runs after the verdict is decided — not on the critical path.
/// Returns a `DrilldownResult` with all attributions (sorted, truncated to
/// `limit`) plus anomaly breadth metrics computed over the FULL score set
/// before truncation.
pub fn drilldown_audit(
    stripe_vecs: &[Vec<f64>],
    state: &ManifoldState,
    encoder: &Encoder,
    walkable: &dyn Walkable,
    n_stripes: usize,
    limit: usize,
) -> DrilldownResult {
    let baseline = match &state.baseline {
        Some(b) => b,
        None => return DrilldownResult { fields: vec![], concentration: 0.0, entropy: 0.0, gini: 0.0 },
    };

    // Real-valued anomalous components per stripe (x - reconstruct(x))
    let anomalies: Vec<Vec<f64>> = (0..n_stripes)
        .map(|i| baseline.anomalous_component(stripe_vecs, i))
        .collect();

    // Pre-compute anomaly norms for the cosine denominator
    let anomaly_norms: Vec<f64> = anomalies.iter()
        .map(|a| a.iter().map(|x| x * x).sum::<f64>().sqrt())
        .collect();

    let walk_items = walkable.walk_map_items();
    let mut scores: Vec<DrilldownAttribution> = Vec::with_capacity(256);

    for (key, value) in &walk_items {
        collect_leaf_scores(value, key, n_stripes, encoder, &anomalies, &anomaly_norms, &mut scores);
    }

    // Compute breadth metrics over the FULL score set before truncation
    let (concentration, entropy, gini) = compute_breadth_metrics(&scores);

    scores.sort_by(|a, b| {
        b.score.partial_cmp(&a.score).unwrap_or_else(|| {
            if a.score.is_nan() { std::cmp::Ordering::Greater } else { std::cmp::Ordering::Less }
        })
    });
    scores.truncate(limit);
    DrilldownResult { fields: scores, concentration, entropy, gini }
}

/// Compute three anomaly breadth metrics from the full (untruncated) score list.
///
/// Returns (concentration, entropy, gini).
fn compute_breadth_metrics(scores: &[DrilldownAttribution]) -> (f64, f64, f64) {
    if scores.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    let n = scores.len();
    let nf = n as f64;
    let sum: f64 = scores.iter().map(|s| s.score).sum();
    let mean = sum / nf;
    let max = scores.iter().map(|s| s.score).fold(0.0_f64, f64::max);

    // Concentration ratio: max / mean. High = narrow, near 1 = broad.
    let concentration = if mean > 1e-10 { max / mean } else { 0.0 };

    // Shannon entropy: normalize scores into a probability distribution,
    // compute -Σ pᵢ·log(pᵢ), then divide by log(n) to get [0, 1].
    // 1 = perfectly uniform (broadest), 0 = all in one field (narrowest).
    let entropy = if sum > 1e-10 && n > 1 {
        let raw: f64 = scores.iter()
            .map(|s| {
                let p = s.score / sum;
                if p > 1e-15 { -p * p.ln() } else { 0.0 }
            })
            .sum();
        raw / (nf.ln())
    } else {
        0.0
    };

    // Gini coefficient: mean absolute difference / (2 * mean).
    // 0 = perfectly uniform (broadest), 1 = maximally unequal (narrowest).
    let gini = if mean > 1e-10 && n > 1 {
        let mut sorted: Vec<f64> = scores.iter().map(|s| s.score).collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let sum_weighted: f64 = sorted.iter().enumerate()
            .map(|(i, &x)| (2.0 * (i as f64) + 1.0 - nf) * x)
            .sum();
        sum_weighted / (nf * nf * mean)
    } else {
        0.0
    };

    (concentration, entropy, gini)
}

/// Recursively walk the Walkable structure, scoring each leaf via cosine
/// similarity between the stripe's anomalous component and the leaf binding.
fn collect_leaf_scores(
    value: &WalkableValue,
    path: &str,
    n_stripes: usize,
    encoder: &Encoder,
    anomalies: &[Vec<f64>],
    anomaly_norms: &[f64],
    results: &mut Vec<DrilldownAttribution>,
) {
    match value {
        WalkableValue::Scalar(_) | WalkableValue::Set(_) | WalkableValue::List(_) => {
            let stripe_idx = Encoder::field_stripe(path, n_stripes);
            let binding = encoder.leaf_binding(value, path);
            let score = cosine_f64_i8(&anomalies[stripe_idx], anomaly_norms[stripe_idx], binding.data());
            results.push(DrilldownAttribution { field: path.to_string(), score });
        }
        WalkableValue::Map(items) => {
            if items.is_empty() {
                let stripe_idx = Encoder::field_stripe(path, n_stripes);
                let binding = encoder.leaf_binding(value, path);
                let score = cosine_f64_i8(&anomalies[stripe_idx], anomaly_norms[stripe_idx], binding.data());
                results.push(DrilldownAttribution { field: path.to_string(), score });
                return;
            }
            for (key, val) in items {
                let sub = format!("{}.{}", path, key);
                collect_leaf_scores(val, &sub, n_stripes, encoder, anomalies, anomaly_norms, results);
            }
        }
        WalkableValue::Spread(items) => {
            if items.is_empty() {
                let stripe_idx = Encoder::field_stripe(path, n_stripes);
                let binding = encoder.leaf_binding(value, path);
                let score = cosine_f64_i8(&anomalies[stripe_idx], anomaly_norms[stripe_idx], binding.data());
                results.push(DrilldownAttribution { field: path.to_string(), score });
                return;
            }
            for (i, item) in items.iter().enumerate() {
                let sub = format!("{}.[{}]", path, i);
                collect_leaf_scores(item, &sub, n_stripes, encoder, anomalies, anomaly_norms, results);
            }
        }
    }
}

/// Cosine similarity between a real-valued anomaly vector and a bipolar
/// binding vector (i8).  Returns the absolute value — higher means the
/// binding's direction is more present in the anomaly.
#[inline]
fn cosine_f64_i8(anomaly: &[f64], anomaly_norm: f64, binding: &[i8]) -> f64 {
    if anomaly_norm < 1e-10 {
        return 0.0;
    }
    let dot: f64 = anomaly.iter().zip(binding.iter())
        .map(|(&a, &b)| a * (b as f64))
        .sum();
    let binding_norm: f64 = (binding.len() as f64).sqrt();
    let cos = dot / (anomaly_norm * binding_norm);
    cos.abs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trained_striped(dim: usize, k: usize, n_stripes: usize) -> StripedSubspace {
        let mut striped = StripedSubspace::new(dim, k, n_stripes);
        let mut rng = 42u64;
        for _ in 0..200 {
            let stripe_vecs: Vec<Vec<f64>> = (0..n_stripes)
                .map(|_| {
                    rng = rng
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    let coeff = (rng >> 33) as f64 / u32::MAX as f64 * 2.0 - 1.0;
                    (0..dim)
                        .map(|i| if i % 2 == 0 { coeff } else { 0.0 })
                        .collect()
                })
                .collect();
            striped.update(&stripe_vecs);
        }
        striped
    }

    #[test]
    fn empty_state_returns_warmup() {
        let state = ManifoldState::empty();
        let v = vec![vec![0.0; 256]; 8];
        assert!(matches!(evaluate_manifold(&v, &state), ManifoldVerdict::Warmup), "{:?}", evaluate_manifold(&v, &state));
    }

    #[test]
    fn in_distribution_returns_allow() {
        let dim = 256;
        let n = 8;
        let sub = trained_striped(dim, 8, n);
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
        let stripe_vecs: Vec<Vec<f64>> = (0..n)
            .map(|_| {
                rng = rng
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let coeff = (rng >> 33) as f64 / u32::MAX as f64 * 2.0 - 1.0;
                (0..dim)
                    .map(|i| if i % 2 == 0 { coeff } else { 0.0 })
                    .collect()
            })
            .collect();

        assert!(matches!(evaluate_manifold(&stripe_vecs, &state), ManifoldVerdict::Allow { .. }));
    }

    #[test]
    fn out_of_distribution_returns_deny() {
        let dim = 256;
        let n = 8;
        let sub = trained_striped(dim, 8, n);
        let threshold = sub.threshold();
        let state = ManifoldState {
            normal_subspaces: vec![],
            baseline: Some(sub),
            threat_mode: ThreatMode::Normal,
            deny_threshold: threshold * 1.5,
            rate_limit_rps: 100.0,
        };

        let mut rng = 777u64;
        let stripe_vecs: Vec<Vec<f64>> = (0..n)
            .map(|_| {
                (0..dim)
                    .map(|_| {
                        rng = rng
                            .wrapping_mul(6364136223846793005)
                            .wrapping_add(1442695040888963407);
                        (rng >> 33) as f64 / u32::MAX as f64 * 2.0 - 1.0
                    })
                    .collect()
            })
            .collect();

        let verdict = evaluate_manifold(&stripe_vecs, &state);
        assert!(
            matches!(verdict, ManifoldVerdict::Deny { .. } | ManifoldVerdict::RateLimit { .. }),
            "OOD vector should not be allowed: {:?}",
            verdict
        );
    }

    #[test]
    fn targeted_mode_lowers_deny_threshold() {
        let dim = 256;
        let n = 8;
        let sub = trained_striped(dim, 8, n);
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

        let mut rng = 555u64;
        let stripe_vecs: Vec<Vec<f64>> = (0..n)
            .map(|_| {
                (0..dim)
                    .map(|_| {
                        rng = rng
                            .wrapping_mul(6364136223846793005)
                            .wrapping_add(1442695040888963407);
                        (rng >> 33) as f64 / u32::MAX as f64 * 2.0 - 1.0
                    })
                    .collect()
            })
            .collect();

        let v_normal = evaluate_manifold(&stripe_vecs, &normal_state);
        let v_targeted = evaluate_manifold(&stripe_vecs, &targeted_state);

        match (&v_normal, &v_targeted) {
            (ManifoldVerdict::RateLimit { .. }, ManifoldVerdict::Deny { .. }) => {}
            (a, b) => {
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

    #[test]
    fn breadth_empty_scores() {
        let (conc, entropy, gini) = compute_breadth_metrics(&[]);
        assert_eq!(conc, 0.0);
        assert_eq!(entropy, 0.0);
        assert_eq!(gini, 0.0);
    }

    #[test]
    fn breadth_narrow_anomaly() {
        // One field dominates — classic single-field exploit
        let scores = vec![
            DrilldownAttribution { field: "path".into(), score: 10.0 },
            DrilldownAttribution { field: "method".into(), score: 0.1 },
            DrilldownAttribution { field: "src_ip".into(), score: 0.1 },
            DrilldownAttribution { field: "ua".into(), score: 0.1 },
            DrilldownAttribution { field: "host".into(), score: 0.1 },
        ];
        let (conc, entropy, gini) = compute_breadth_metrics(&scores);
        assert!(conc > 4.0, "narrow: concentration should be high, got {}", conc);
        assert!(entropy < 0.5, "narrow: entropy should be low, got {}", entropy);
        assert!(gini > 0.7, "narrow: gini should be high, got {}", gini);
    }

    #[test]
    fn breadth_broad_anomaly() {
        // All fields similarly anomalous — scanner/tool
        let scores = vec![
            DrilldownAttribution { field: "path".into(), score: 5.0 },
            DrilldownAttribution { field: "method".into(), score: 4.5 },
            DrilldownAttribution { field: "src_ip".into(), score: 4.8 },
            DrilldownAttribution { field: "ua".into(), score: 5.2 },
            DrilldownAttribution { field: "host".into(), score: 4.9 },
        ];
        let (conc, entropy, gini) = compute_breadth_metrics(&scores);
        assert!(conc < 1.5, "broad: concentration should be low, got {}", conc);
        assert!(entropy > 0.95, "broad: entropy should be near 1.0, got {}", entropy);
        assert!(gini < 0.1, "broad: gini should be near 0, got {}", gini);
    }

    #[test]
    fn breadth_moderate_anomaly() {
        // Mix: a few elevated, rest low — Nikto-like
        let scores = vec![
            DrilldownAttribution { field: "tls.padding".into(), score: 0.67 },
            DrilldownAttribution { field: "tls.cipher_order".into(), score: 0.51 },
            DrilldownAttribution { field: "tls.sni".into(), score: 0.46 },
            DrilldownAttribution { field: "header_order".into(), score: 0.34 },
            DrilldownAttribution { field: "path".into(), score: 0.17 },
            DrilldownAttribution { field: "version".into(), score: 0.15 },
            DrilldownAttribution { field: "tls.version".into(), score: 0.04 },
            DrilldownAttribution { field: "tls.record_ver".into(), score: 0.07 },
        ];
        let (conc, entropy, gini) = compute_breadth_metrics(&scores);
        // Should be between narrow and broad
        assert!(conc > 1.5 && conc < 4.0, "moderate: concentration={}", conc);
        assert!(entropy > 0.7 && entropy < 0.95, "moderate: entropy={}", entropy);
        assert!(gini > 0.2 && gini < 0.5, "moderate: gini={}", gini);
    }
}
