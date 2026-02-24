//! HTTP WAF Sidecar — async detection library.
//!
//! Runs two detection loops in-process with the proxy:
//!   - TLS loop: one SubspaceDetector over TLS context vectors (one sample per connection)
//!   - Request loop: one SubspaceDetector over full RequestSample vectors (one per request)
//!
//! Both loops share one RuleManager and write to the shared ArcSwap<CompiledTree>.
//! The proxy tasks read the tree via ArcSwap::load() — wait-free.

pub mod detection;
pub mod detectors;
pub mod field_tracker;
pub mod metrics_server;
pub mod rule_manager;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use arc_swap::ArcSwap;
use holon::kernel::{Encoder, VectorManager};
use tokio::sync::{mpsc, Mutex};
use tracing::info;

use http_proxy::types::{CompiledTree, RequestSample, SampleMessage, TlsSample};
use crate::detection::{compile_compound_rule, Detection};
use crate::detectors::SubspaceDetector;
use crate::field_tracker::FieldTracker;
use crate::metrics_server::{new_shared_stats, run_metrics_server};
use crate::rule_manager::RuleManager;

// =============================================================================
// Configuration
// =============================================================================

/// Fields the sidecar attributes anomalies to (request-level).
const REQ_FIELDS: &[&str] = &[
    "method", "path", "src_ip", "user_agent",
    "host", "content_type", "tls_group_hash",
    "tls_cipher_hash", "tls_ext_order_hash",
    "header_count", "has_cookie",
];

/// Fields the sidecar attributes anomalies to (TLS-level).
const TLS_FIELDS: &[&str] = &[
    "tls_version", "cipher_count", "ext_count",
    "group_count", "sig_alg_count", "has_sni",
    "session_ticket", "cipher_hash", "ext_order_hash",
    "group_hash", "alpn_first",
];

const VSA_DIM: usize = 4096;
const VSA_K: usize = 8;
const TICK_INTERVAL: Duration = Duration::from_secs(2);
const WARMUP_TICKS: usize = 15;        // 30 seconds
const ANOMALY_STREAK_THRESHOLD: usize = 3;
const RULE_TTL_SECS: u64 = 300;
const DECAY_ALPHA: f64 = 0.9999;

// =============================================================================
// Entry point — called by proxy main.rs
// =============================================================================

/// Start the sidecar. Runs until the sample_rx channel is closed.
pub async fn run(
    mut sample_rx: mpsc::Receiver<SampleMessage>,
    tree: Arc<ArcSwap<CompiledTree>>,
    engram_path: String,
    metrics_addr: SocketAddr,
) -> Result<()> {
    info!("Sidecar starting");

    let encoder = Arc::new(Encoder::new(VectorManager::new(VSA_DIM)));
    let stats = new_shared_stats();
    let rule_mgr = Arc::new(Mutex::new(RuleManager::new(RULE_TTL_SECS)));

    // Spawn metrics server
    {
        let stats_c = stats.clone();
        tokio::spawn(async move {
            run_metrics_server(metrics_addr, stats_c).await;
        });
    }

    // Sidecar state
    let mut tls_detector = SubspaceDetector::new(VSA_DIM, VSA_K);
    let mut req_detector = SubspaceDetector::new(VSA_DIM, VSA_K);
    let mut req_tracker = FieldTracker::new(DECAY_ALPHA);

    // Load persisted engrams
    tls_detector.load_library(&format!("{}.tls", engram_path));
    req_detector.load_library(&format!("{}.req", engram_path));

    let mut tls_warmup_ticks = 0usize;
    let mut req_warmup_ticks = 0usize;
    let mut last_tick = Instant::now();
    let mut tick_tls_vecs: Vec<Vec<f64>> = Vec::new();
    let mut tick_req_vecs: Vec<Vec<f64>> = Vec::new();
    #[allow(unused_assignments)]
    let mut estimated_rps = 0f64;
    let mut req_count_tick = 0u64;

    // Accumulation buffers (collect samples between ticks)
    let mut tls_buf: Vec<TlsSample> = Vec::new();
    let mut req_buf: Vec<RequestSample> = Vec::new();

    loop {
        // Drain available samples (non-blocking)
        loop {
            match sample_rx.try_recv() {
                Ok(SampleMessage::TlsSample(s)) => {
                    stats.write().await.tls_samples_received += 1;
                    tls_buf.push(s);
                }
                Ok(SampleMessage::RequestSample(s)) => {
                    stats.write().await.req_samples_received += 1;
                    req_count_tick += 1;
                    req_buf.push(s);
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    info!("Sample channel closed — sidecar shutting down");
                    // Save engrams on shutdown
                    tls_detector.save_library(&format!("{}.tls", engram_path));
                    req_detector.save_library(&format!("{}.req", engram_path));
                    return Ok(());
                }
            }
        }

        // Wait a short time before next poll to avoid busy-spinning
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Check if it's time for a detection tick
        if last_tick.elapsed() < TICK_INTERVAL {
            continue;
        }

        // -----------------------------------------------------------------------
        // Detection tick
        // -----------------------------------------------------------------------
        let elapsed_secs = last_tick.elapsed().as_secs_f64();
        last_tick = Instant::now();
        estimated_rps = req_count_tick as f64 / elapsed_secs;
        req_count_tick = 0;

        let tls_tick_count = tls_buf.len();
        let req_tick_count = req_buf.len();

        info!(
            tls = tls_tick_count,
            req = req_tick_count,
            rps = format!("{:.0}", estimated_rps),
            "tick"
        );

        // Encode TLS samples (use the pre-computed VSA vector from ConnectionContext)
        for sample in tls_buf.drain(..) {
            let vec_f64: Vec<f64> = sample.tls_vec.data().iter()
                .map(|&b| b as f64)
                .collect();
            tick_tls_vecs.push(vec_f64);
        }

        // Encode request samples + update field tracker
        for sample in req_buf.drain(..) {
            let req_vec = encoder.encode_walkable(&sample);
            let vec_f64: Vec<f64> = req_vec.data().iter()
                .map(|&b| b as f64)
                .collect();
            tick_req_vecs.push(vec_f64);

            // Track field values for attribution
            let pairs: Vec<(&str, String)> = vec![
                ("method", sample.method.clone()),
                ("path", sample.path.clone()),
                ("src_ip", sample.src_ip.to_string()),
                ("user_agent", sample.user_agent.clone().unwrap_or_default()),
                ("host", sample.host.clone().unwrap_or_default()),
                ("tls_group_hash", sample.tls_ctx.tls_group_hash().to_string()),
            ];
            req_tracker.observe(&pairs);
        }

        // -----------------------------------------------------------------------
        // TLS detection loop
        // -----------------------------------------------------------------------
        if !tick_tls_vecs.is_empty() {
            let bundle = bundle_vecs(&tick_tls_vecs);
            tick_tls_vecs.clear();

            if tls_warmup_ticks < WARMUP_TICKS {
                tls_detector.learn(&bundle);
                tls_warmup_ticks += 1;
                info!("[TLS] warmup {}/{}", tls_warmup_ticks, WARMUP_TICKS);
            } else {
                // Check engram library first
                if let Some((engram_name, residual)) = tls_detector.check_library(&bundle) {
                    info!("[TLS] Known attack pattern matched: '{}' (residual={:.3})", engram_name, residual);
                    // Known attack — keep rule alive via rule_manager refresh
                } else {
                    let score = tls_detector.score(&bundle);
                    let threshold = tls_detector.baseline.threshold();
                    let is_anomalous = score > threshold;

                    info!("[TLS] score={:.4} threshold={:.4} anomalous={}", score, threshold, is_anomalous);

                    // Update metrics
                    {
                        let mut s = stats.write().await;
                        s.tls_score = score;
                        s.tls_threshold = threshold;
                        s.tls_samples_per_tick = tls_tick_count;
                    }

                    if is_anomalous {
                        tls_detector.anomaly_streak += 1;
                        tls_detector.learn_attack(&bundle);

                        if tls_detector.anomaly_streak >= ANOMALY_STREAK_THRESHOLD {
                            info!(
                                "[TLS] Anomaly confirmed (streak={}, score={:.3})",
                                tls_detector.anomaly_streak, score
                            );

                            // Attribute to top field values
                            let surprise = tls_detector.surprise_fingerprint(&bundle, &encoder, TLS_FIELDS);
                            let top_fields: Vec<Detection> = surprise.iter().take(3).map(|(f, _score)| {
                                let val = get_tls_field_top_value(&req_tracker, f);
                                Detection {
                                    field: f.clone(),
                                    value: val,
                                    rate_factor: 0.01,
                                }
                            }).collect();

                            if let Some(rule) = compile_compound_rule(&top_fields, false, estimated_rps, true) {
                                let mut mgr = rule_mgr.lock().await;
                                if mgr.is_redundant(&rule).is_none() {
                                    mgr.upsert(&[rule]);
                                    mgr.recompile_and_deploy(&tree);
                                }
                            }

                            // Mint engram after enough samples
                            if tls_detector.anomaly_streak >= ANOMALY_STREAK_THRESHOLD * 3 {
                                let name = format!("tls-attack-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
                                let surprise_map: HashMap<String, f64> = surprise.into_iter().collect();
                                let metadata = serde_json::json!({ "rps": estimated_rps }).as_object().unwrap().iter()
                                    .map(|(k, v)| (k.clone(), v.clone())).collect();
                                tls_detector.mint_engram(&name, surprise_map, metadata);
                            }
                        }
                    } else {
                        if tls_detector.has_active_attack() {
                            tls_detector.cancel_attack();
                        }
                        tls_detector.anomaly_streak = 0;
                        tls_detector.learn(&bundle);
                    }
                }
            }
        }

        // -----------------------------------------------------------------------
        // Request detection loop
        // -----------------------------------------------------------------------
        if !tick_req_vecs.is_empty() {
            let bundle = bundle_vecs(&tick_req_vecs);
            tick_req_vecs.clear();

            if req_warmup_ticks < WARMUP_TICKS {
                req_detector.learn(&bundle);
                req_warmup_ticks += 1;
                info!("[REQ] warmup {}/{}", req_warmup_ticks, WARMUP_TICKS);
            } else {
                if let Some((engram_name, residual)) = req_detector.check_library(&bundle) {
                    info!("[REQ] Known attack pattern matched: '{}' (residual={:.3})", engram_name, residual);
                } else {
                    let score = req_detector.score(&bundle);
                    let threshold = req_detector.baseline.threshold();
                    let is_anomalous = score > threshold;

                    info!("[REQ] score={:.4} threshold={:.4} anomalous={}", score, threshold, is_anomalous);

                    // Update metrics
                    {
                        let mut s = stats.write().await;
                        s.req_score = score;
                        s.req_threshold = threshold;
                        s.req_samples_per_tick = req_tick_count;
                        s.estimated_rps = estimated_rps;
                    }

                    if is_anomalous {
                        req_detector.anomaly_streak += 1;
                        req_detector.learn_attack(&bundle);

                        if req_detector.anomaly_streak >= ANOMALY_STREAK_THRESHOLD {
                            info!(
                                "[REQ] Anomaly confirmed (streak={}, score={:.3}, rps={:.0})",
                                req_detector.anomaly_streak, score, estimated_rps
                            );

                            let surprise = req_detector.surprise_fingerprint(
                                &bundle, &encoder, REQ_FIELDS,
                            );

                            // Build detections from top anomalous fields + their top values
                            let top_fields: Vec<Detection> = surprise.iter().take(3).filter_map(|(f, _)| {
                                let top = req_tracker.top_values(f, 1);
                                top.into_iter().next().map(|(val, _)| Detection {
                                    field: f.clone(),
                                    value: val,
                                    rate_factor: (1.0 / (score / threshold)).min(1.0),
                                })
                            }).collect();

                            if let Some(rule) = compile_compound_rule(&top_fields, true, estimated_rps, false) {
                                let mut mgr = rule_mgr.lock().await;
                                if mgr.is_redundant(&rule).is_none() {
                                    mgr.upsert(&[rule]);
                                    mgr.recompile_and_deploy(&tree);
                                }
                            }

                            if req_detector.anomaly_streak >= ANOMALY_STREAK_THRESHOLD * 3 {
                                let name = format!("req-attack-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
                                let surprise_map: HashMap<String, f64> = surprise.into_iter().collect();
                                let metadata = serde_json::json!({ "rps": estimated_rps }).as_object().unwrap().iter()
                                    .map(|(k, v)| (k.clone(), v.clone())).collect();
                                req_detector.mint_engram(&name, surprise_map, metadata);
                            }
                        }
                    } else {
                        if req_detector.has_active_attack() {
                            req_detector.cancel_attack();
                        }
                        req_detector.anomaly_streak = 0;
                        req_detector.learn(&bundle);
                    }
                }
            }
        }

        // Expire old rules periodically
        {
            let mut mgr = rule_mgr.lock().await;
            let expired = mgr.expire();
            if expired > 0 {
                mgr.recompile_and_deploy(&tree);
            }
        }

        // Update metrics
        {
            let mgr = rule_mgr.lock().await;
            let mut s = stats.write().await;
            s.warmup_tls = tls_warmup_ticks < WARMUP_TICKS;
            s.warmup_req = req_warmup_ticks < WARMUP_TICKS;
            s.anomaly_streak_tls = tls_detector.anomaly_streak;
            s.anomaly_streak_req = req_detector.anomaly_streak;
            s.engrams_tls = tls_detector.library.len();
            s.engrams_req = req_detector.library.len();
            s.active_rules = mgr.rule_count();
        }
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Bundle a set of per-sample f64 vectors into a single window vector via
/// element-wise sum, then normalize. Equivalent to bundling in VSA terms.
fn bundle_vecs(vecs: &[Vec<f64>]) -> Vec<f64> {
    if vecs.is_empty() { return Vec::new(); }
    let dim = vecs[0].len();
    let mut sum = vec![0.0f64; dim];
    for v in vecs {
        for (i, &x) in v.iter().enumerate() {
            sum[i] += x;
        }
    }
    let n = vecs.len() as f64;
    sum.iter_mut().for_each(|x| *x /= n);
    sum
}

/// Get the top value for a TLS-level field from the field tracker.
/// TLS fields store their values under request-level tracking using the same names.
fn get_tls_field_top_value(tracker: &FieldTracker, field: &str) -> String {
    tracker.top_values(field, 1)
        .into_iter()
        .next()
        .map(|(v, _)| v)
        .unwrap_or_else(|| "unknown".to_string())
}
