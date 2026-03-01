//! HTTP WAF Sidecar — async detection library.
//!
//! Runs two detection loops in-process with the proxy:
//!   - TLS loop: one SubspaceDetector over TLS context vectors (one sample per connection)
//!   - Request loop: one SubspaceDetector over full RequestSample vectors (one per request)
//!
//! Detection approach (matching veth-lab):
//!   - Each sample is individually scored against the subspace (no bundling/averaging)
//!   - Per-tick max residual drives anomaly decisions
//!   - Hybrid tick trigger: fires on sample count OR elapsed time, whichever first
//!   - Per-sample exponential decay on accumulation buffers
//!   - Two-tier detection: subspace anomaly detection + engram-based fast mitigation
//!
//! Both loops share one RuleManager and write to the shared ArcSwap<ExprCompiledTree>.
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
use tokio::sync::{broadcast, mpsc, Mutex};
use tracing::{info, warn};

use http_proxy::expr::RuleExpr;
use http_proxy::expr_tree::ExprCompiledTree;
use http_proxy::types::{RequestSample, RuleAction, SampleMessage, TlsSample};
use crate::detection::{compile_compound_rule_expr, compile_merged_rule_expr, Detection};
use crate::detectors::{SubspaceDetector, SurpriseHistory, drilldown_probe};
use crate::field_tracker::FieldTracker;
use crate::metrics_server::{
    DashboardEvent, MetricsAppState, RuleSummary,
    new_shared_stats, new_shared_rules, now_ts, run_metrics_server,
};
use crate::rule_manager::RuleManager;

// =============================================================================
// Configuration
// =============================================================================

/// Fields the sidecar attributes anomalies to (request-level).
const REQ_FIELDS: &[&str] = &[
    "method", "path", "src_ip", "user_agent",
    "host", "content_type", "tls_group_hash",
    "tls_cipher_hash", "tls_ext_order_hash",
    "tls_cipher_set", "tls_ext_set", "tls_group_set",
    "header_count", "has_cookie",
];

/// Fields the sidecar attributes anomalies to (TLS-level).
/// These MUST match the Walkable field names from TlsContext so that
/// surprise_fingerprint correctly unbinds encoded vector components.
const TLS_FIELDS: &[&str] = &[
    "version", "ciphers", "cipher_order",
    "ext_types", "ext_order", "groups",
    "sig_algs", "sni", "alpn",
    "session_id_len", "compression",
];

const VSA_DIM: usize = 4096;
const VSA_K: usize = 64;

/// Hybrid tick trigger: fire after this many REQ samples OR ANALYSIS_MAX_MS, whichever first.
const ANALYSIS_INTERVAL: usize = 200;
/// Maximum time between ticks (ms). Ensures ticks fire even at low request volume.
const ANALYSIS_MAX_MS: u64 = 500;

/// Warmup requires this many individual samples (not ticks).
const WARMUP_SAMPLES_TLS: usize = 30;
const WARMUP_SAMPLES_REQ: usize = 500;

const ANOMALY_STREAK_THRESHOLD: usize = 3;
const RULE_TTL_SECS: u64 = 300;

/// Per-sample exponential decay factor: 0.5^(1/DECAY_HALF_LIFE).
/// At half_life=500 requests, a sample's influence halves every 500 new requests.
const DECAY_HALF_LIFE: usize = 500;

// =============================================================================
// Entry point — called by proxy main.rs
// =============================================================================

/// Start the sidecar. Runs until the sample_rx channel is closed.
/// `engram_path`: if `Some`, load/save engram libraries to disk for persistence.
/// `rule_ttl_secs`: if `Some`, override the default rule TTL (300s).
pub async fn run(
    mut sample_rx: mpsc::Receiver<SampleMessage>,
    tree: Arc<ArcSwap<ExprCompiledTree>>,
    engram_path: Option<String>,
    metrics_addr: SocketAddr,
    rule_ttl_secs: Option<u64>,
) -> Result<()> {
    let ttl = rule_ttl_secs.unwrap_or(RULE_TTL_SECS);
    info!("Sidecar starting (rule_ttl={}s)", ttl);

    let encoder = Arc::new(Encoder::new(VectorManager::new(VSA_DIM)));
    let stats = new_shared_stats();
    let shared_rules = new_shared_rules();
    let rule_mgr = Arc::new(Mutex::new(RuleManager::new(ttl)));

    let (event_tx, _) = broadcast::channel::<DashboardEvent>(256);

    // Metrics server runs on its own OS thread + tokio runtime so it's never
    // starved by the proxy's connection-handling load during attack bursts.
    {
        let app_state = MetricsAppState {
            stats: stats.clone(),
            event_tx: event_tx.clone(),
            rules: shared_rules.clone(),
        };
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("metrics runtime");
            rt.block_on(run_metrics_server(metrics_addr, app_state));
        });
    }

    // Sidecar state
    // TLS gets ~1-2 samples/tick vs REQ's ~50-200, so use faster EMA convergence
    // and a tighter threshold (2.0σ vs 3.5σ) for sensitivity to TLS profile changes.
    let mut tls_detector = SubspaceDetector::with_subspace_params(
        VSA_DIM, VSA_K,
        2.0,   // amnesia
        0.05,  // ema_alpha (5x faster convergence than REQ)
        2.0,   // sigma_mult (tighter anomaly gate)
        500,   // reorth_interval
    );
    let mut req_detector = SubspaceDetector::new(VSA_DIM, VSA_K);
    let mut req_tracker = FieldTracker::new(decay_factor(DECAY_HALF_LIFE));

    if let Some(ref path) = engram_path {
        tls_detector.load_library(&format!("{}.tls", path));
        req_detector.load_library(&format!("{}.req", path));
    }

    let decay_alpha = decay_factor(DECAY_HALF_LIFE);

    let mut tls_warmup_count = 0usize;
    let mut req_warmup_count = 0usize;
    let mut tls_warmup_done = false;
    let mut req_warmup_done = false;

    // Per-tick max-residual tracking
    let mut tls_tick_max_residual = 0.0f64;
    let mut tls_tick_max_vec: Option<Vec<f64>> = None;
    let mut req_tick_max_residual = 0.0f64;
    let mut req_tick_max_vec: Option<Vec<f64>> = None;
    let mut req_tick_max_sample: Option<RequestSample> = None;

    // Surprise history for cross-tick consistency (content-before-shape prioritization)
    let mut surprise_history = SurpriseHistory::new(5);

    let mut last_tick = Instant::now();
    let mut req_since_tick = 0usize;
    let mut tls_since_tick = 0usize;
    #[allow(unused_assignments)]
    let mut estimated_rps = 0f64;
    let mut baseline_rps = 0f64;
    let mut warmup_start: Option<Instant> = None;
    let mut req_count_tick = 0u64;
    let mut tick_count = 0u64;

    let analysis_max_dur = Duration::from_millis(ANALYSIS_MAX_MS);

    info!("  Analysis trigger: every {} REQ samples or {}ms (hybrid)", ANALYSIS_INTERVAL, ANALYSIS_MAX_MS);
    info!("  Decay half-life: {} requests (factor={:.6})", DECAY_HALF_LIFE, decay_alpha);
    info!("  Warmup: {} TLS samples, {} REQ samples", WARMUP_SAMPLES_TLS, WARMUP_SAMPLES_REQ);

    loop {
        // =====================================================================
        // Per-sample processing: drain channel, encode, score individually
        // =====================================================================
        let mut got_sample = false;
        let mut tls_received_this_drain = 0u64;
        let mut req_received_this_drain = 0u64;
        let drain_limit = 512; // Cap per drain pass to keep ticks responsive

        loop {
            if (tls_received_this_drain + req_received_this_drain) >= drain_limit {
                break;
            }
            match sample_rx.try_recv() {
                Ok(SampleMessage::TlsSample(s)) => {
                    tls_received_this_drain += 1;
                    got_sample = true;
                    tls_since_tick += 1;
                    process_tls_sample(
                        &s, &mut tls_detector,
                        &mut tls_warmup_count, tls_warmup_done,
                        &mut tls_tick_max_residual, &mut tls_tick_max_vec,
                    );
                }
                Ok(SampleMessage::RequestSample(s)) => {
                    req_received_this_drain += 1;
                    got_sample = true;
                    req_since_tick += 1;
                    req_count_tick += 1;
                    if warmup_start.is_none() {
                        warmup_start = Some(Instant::now());
                    }
                    process_req_sample(
                        &s, &encoder, &mut req_detector, &mut req_tracker,
                        &mut req_warmup_count, req_warmup_done, decay_alpha,
                        &mut req_tick_max_residual, &mut req_tick_max_vec,
                        &mut req_tick_max_sample,
                    );
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    info!("Sample channel closed — sidecar shutting down");
                    if let Some(ref path) = engram_path {
                        tls_detector.save_library(&format!("{}.tls", path));
                        req_detector.save_library(&format!("{}.req", path));
                    }
                    return Ok(());
                }
            }
        }

        // Update sample counters outside the hot loop (no async lock in drain path)
        if tls_received_this_drain > 0 || req_received_this_drain > 0 {
            let mut s = stats.write().await;
            s.tls_samples_received += tls_received_this_drain;
            s.req_samples_received += req_received_this_drain;
        }

        // =====================================================================
        // Hybrid tick trigger: sample count OR elapsed time
        // =====================================================================
        let tick_elapsed = last_tick.elapsed();
        let should_tick = req_since_tick >= ANALYSIS_INTERVAL
            || tick_elapsed >= analysis_max_dur;

        if !should_tick {
            if !got_sample {
                tokio::time::sleep(Duration::from_millis(5)).await;
            } else {
                tokio::task::yield_now().await;
            }
            continue;
        }

        // =====================================================================
        // Detection tick
        // =====================================================================
        let elapsed_secs = tick_elapsed.as_secs_f64().max(0.001);
        last_tick = Instant::now();
        estimated_rps = req_count_tick as f64 / elapsed_secs;
        req_count_tick = 0;
        tick_count += 1;

        let tls_tick_count = tls_since_tick;
        let req_tick_count = req_since_tick;
        tls_since_tick = 0;
        req_since_tick = 0;

        let mut tick_tls_score = 0.0f64;
        let mut tick_tls_threshold = 0.0f64;
        let mut tick_req_score = 0.0f64;
        let mut tick_req_threshold = 0.0f64;

        info!(
            tick = tick_count,
            tls = tls_tick_count,
            req = req_tick_count,
            rps = format!("{:.0}", estimated_rps),
            "tick"
        );

        // Check if warmup just completed
        if !tls_warmup_done && tls_warmup_count >= WARMUP_SAMPLES_TLS {
            tls_warmup_done = true;
            info!("[TLS] Warmup complete ({} samples, threshold={:.2})",
                  tls_warmup_count, tls_detector.baseline.threshold());
        }
        if !req_warmup_done && req_warmup_count >= WARMUP_SAMPLES_REQ {
            req_warmup_done = true;
            let warmup_secs = warmup_start
                .map(|t| t.elapsed().as_secs_f64())
                .unwrap_or(1.0)
                .max(0.1);
            baseline_rps = req_warmup_count as f64 / warmup_secs;
            req_tracker.freeze_baseline(0.5);
            info!("[REQ] Warmup complete ({} samples, threshold={:.2}, baseline_rps={:.0})",
                  req_warmup_count, req_detector.baseline.threshold(), baseline_rps);
        }

        // -------------------------------------------------------------------
        // TLS detection
        // -------------------------------------------------------------------
        if tls_warmup_done && tls_tick_max_residual > 0.0 {
            let score = tls_tick_max_residual;
            let threshold = tls_detector.baseline.threshold();
            let is_anomalous = score > threshold;
            tick_tls_score = score;
            tick_tls_threshold = threshold;

            info!("[TLS] score={:.4} threshold={:.4} anomalous={}", score, threshold, is_anomalous);

            if is_anomalous {
                if let Some(ref max_vec) = tls_tick_max_vec {
                    tls_detector.anomaly_streak += 1;
                    if let Some((engram_name, engram_res)) = tls_detector.check_library(max_vec) {
                        if tls_detector.anomaly_streak == 1 {
                            warn!("[TLS] ENGRAM HIT: '{}' (residual={:.2}) — deploying stored rules",
                                  engram_name, engram_res);
                            let _ = event_tx.send(DashboardEvent::DetectionEvent {
                                ts: now_ts(), detector: "TLS".into(), kind: "engram_hit".into(),
                                detail: format!("'{}' residual={:.2}", engram_name, engram_res),
                            });
                            deploy_engram_rules(&tls_detector, &engram_name, &rule_mgr, &tree, &event_tx, baseline_rps).await;
                        }
                    }

                    tls_detector.learn_attack(max_vec);

                    if tls_detector.anomaly_streak >= ANOMALY_STREAK_THRESHOLD {
                        warn!("[TLS] Anomaly confirmed (streak={}, score={:.3})",
                              tls_detector.anomaly_streak, score);
                        let _ = event_tx.send(DashboardEvent::DetectionEvent {
                            ts: now_ts(), detector: "TLS".into(), kind: "anomaly_confirmed".into(),
                            detail: format!("streak={} score={:.3}", tls_detector.anomaly_streak, score),
                        });

                        let surprise = tls_detector.surprise_fingerprint(max_vec, &encoder, TLS_FIELDS);
                        let rate_factor = if estimated_rps > 0.0 {
                            (baseline_rps / estimated_rps).min(1.0)
                        } else {
                            1.0
                        };
                        let mut seen_fields = std::collections::HashSet::new();
                        let top_fields: Vec<Detection> = surprise.iter()
                            .filter_map(|(f, _s)| {
                                get_tls_field_top_value(&req_tracker, f)
                                    .and_then(|(det_field, val)| {
                                        if seen_fields.insert(det_field.clone()) {
                                            warn!("  TLS surprise: {} → {}={}", f, det_field, val);
                                            Some(Detection { field: det_field, value: val, rate_factor })
                                        } else {
                                            None
                                        }
                                    })
                            })
                            .take(3)
                            .collect();

                        if let Some(rule) = compile_compound_rule_expr(&top_fields, true, estimated_rps, false) {
                            let mut mgr = rule_mgr.lock().await;
                            if mgr.is_redundant(&rule).is_none() {
                                let _ = event_tx.send(DashboardEvent::RuleEvent {
                                    ts: now_ts(), action: "added".into(),
                                    summary: rule.to_edn_compact(),
                                    engram_name: None, rule_count: None,
                                });
                                tls_detector.attack_rules.push(rule.clone());
                                mgr.upsert(&[rule]);
                                mgr.recompile_and_deploy(&tree);
                                broadcast_dag(&tree, &event_tx);
                            }
                        }
                    }
                }
            } else {
                if tls_detector.has_active_attack() {
                    let streak = tls_detector.anomaly_streak;
                    if streak >= ANOMALY_STREAK_THRESHOLD {
                        let _ = event_tx.send(DashboardEvent::DetectionEvent {
                            ts: now_ts(), detector: "TLS".into(), kind: "attack_ended".into(),
                            detail: format!("streak={}", streak),
                        });
                        if let Some(ref max_vec) = tls_tick_max_vec {
                            let surprise = tls_detector.surprise_fingerprint(max_vec, &encoder, TLS_FIELDS);
                            mint_engram_with_rules(&mut tls_detector, "tls", &surprise, estimated_rps, &rule_mgr, &event_tx).await;
                        }
                    } else {
                        tls_detector.cancel_attack();
                    }
                }
                tls_detector.anomaly_streak = 0;
                if let Some(ref max_vec) = tls_tick_max_vec {
                    tls_detector.learn(max_vec);
                }
            }
        } else if !tls_warmup_done && tls_tick_count > 0 {
            info!("[TLS] warmup {}/{}", tls_warmup_count, WARMUP_SAMPLES_TLS);
        }

        // -------------------------------------------------------------------
        // Request detection
        // -------------------------------------------------------------------
        if req_warmup_done && req_tick_max_residual > 0.0 {
            let score = req_tick_max_residual;
            let threshold = req_detector.baseline.threshold();
            let is_anomalous = score > threshold;
            tick_req_score = score;
            tick_req_threshold = threshold;

            info!("[REQ] score={:.4} threshold={:.4} anomalous={}", score, threshold, is_anomalous);

            if is_anomalous {
                if let Some(ref max_vec) = req_tick_max_vec {
                    req_detector.anomaly_streak += 1;

                    if let Some((engram_name, engram_res)) = req_detector.check_library(max_vec) {
                        if req_detector.anomaly_streak == 1 {
                            warn!("[REQ] ENGRAM HIT: '{}' (residual={:.2}) — deploying stored rules",
                                  engram_name, engram_res);
                            let _ = event_tx.send(DashboardEvent::DetectionEvent {
                                ts: now_ts(), detector: "REQ".into(), kind: "engram_hit".into(),
                                detail: format!("'{}' residual={:.2}", engram_name, engram_res),
                            });
                            deploy_engram_rules(&req_detector, &engram_name, &rule_mgr, &tree, &event_tx, baseline_rps).await;
                        }
                    }

                    req_detector.learn_attack(max_vec);

                    if req_detector.anomaly_streak >= ANOMALY_STREAK_THRESHOLD {
                        let rate_factor = if estimated_rps > 0.0 {
                            (baseline_rps / estimated_rps).min(1.0)
                        } else {
                            1.0
                        };
                        warn!("[REQ] Anomaly confirmed (streak={}, score={:.3}, rps={:.0}, baseline_rps={:.0})",
                              req_detector.anomaly_streak, score, estimated_rps, baseline_rps);
                        let _ = event_tx.send(DashboardEvent::DetectionEvent {
                            ts: now_ts(), detector: "REQ".into(), kind: "anomaly_confirmed".into(),
                            detail: format!("streak={} score={:.3} rps={:.0}", req_detector.anomaly_streak, score, estimated_rps),
                        });

                        // 1. FieldTracker concentration (existing 12 scalar fields)
                        let concentrated = req_tracker.find_concentrated_values(0.5);
                        let top_fields: Vec<Detection> = concentrated.iter().take(3).map(|(f, v, conc)| {
                            warn!("  concentrated: {}={} ({:.1}%)", f, v, conc * 100.0);
                            Detection {
                                field: f.clone(),
                                value: v.clone(),
                                rate_factor,
                            }
                        }).collect();

                        // 2. Surprise probing: drill-down against anomalous component
                        if let Some(ref sample) = req_tick_max_sample {
                            let probe_hits = drilldown_probe(
                                &req_detector, max_vec, &encoder, sample,
                            );
                            if !probe_hits.is_empty() {
                                for hit in probe_hits.iter().take(3) {
                                    warn!("  surprise probe: {:?} score={:.2} header={} content={} shape={}",
                                          hit.target, hit.score, hit.header_name,
                                          hit.content_value, hit.shape_value);
                                }
                            }

                            // 3. Push into SurpriseHistory for cross-tick consistency
                            surprise_history.push(probe_hits);
                        }

                        // 4. Derive surprise detections (content-before-shape)
                        let surprise_dets = surprise_history.derive_detections(
                            ANOMALY_STREAK_THRESHOLD, rate_factor,
                        );
                        if !surprise_dets.is_empty() {
                            for sd in &surprise_dets {
                                warn!("  surprise detection: {:?} {}={} ({})",
                                      sd.kind, sd.header_name, sd.value, sd.top_name);
                            }
                        }

                        // 5. Merge FieldTracker + surprise detections, compile rule
                        if let Some(rule) = compile_merged_rule_expr(
                            &top_fields, &surprise_dets,
                            true, estimated_rps, false,
                        ) {
                            let mut mgr = rule_mgr.lock().await;
                            if mgr.is_redundant(&rule).is_none() {
                                let _ = event_tx.send(DashboardEvent::RuleEvent {
                                    ts: now_ts(), action: "added".into(),
                                    summary: rule.to_edn_compact(),
                                    engram_name: None, rule_count: None,
                                });
                                req_detector.attack_rules.push(rule.clone());
                                mgr.upsert(&[rule]);
                                mgr.recompile_and_deploy(&tree);
                                broadcast_dag(&tree, &event_tx);
                            }
                        }
                    }
                }
            } else {
                if req_detector.has_active_attack() {
                    let streak = req_detector.anomaly_streak;
                    if streak >= ANOMALY_STREAK_THRESHOLD {
                        let _ = event_tx.send(DashboardEvent::DetectionEvent {
                            ts: now_ts(), detector: "REQ".into(), kind: "attack_ended".into(),
                            detail: format!("streak={}", streak),
                        });
                        if let Some(ref max_vec) = req_tick_max_vec {
                            let surprise = req_detector.surprise_fingerprint(max_vec, &encoder, REQ_FIELDS);
                            mint_engram_with_rules(&mut req_detector, "req", &surprise, estimated_rps, &rule_mgr, &event_tx).await;
                        }
                    } else {
                        req_detector.cancel_attack();
                    }
                    surprise_history.clear();
                }
                req_detector.anomaly_streak = 0;
                if let Some(ref max_vec) = req_tick_max_vec {
                    req_detector.learn(max_vec);
                }
            }
        } else if !req_warmup_done && req_tick_count > 0 {
            info!("[REQ] warmup {}/{}", req_warmup_count, WARMUP_SAMPLES_REQ);
        }

        // Reset per-tick max tracking
        tls_tick_max_residual = 0.0;
        tls_tick_max_vec = None;
        req_tick_max_residual = 0.0;
        req_tick_max_vec = None;
        req_tick_max_sample = None;

        // Expire old rules periodically
        {
            let mut mgr = rule_mgr.lock().await;
            let expired = mgr.expire();
            if expired > 0 {
                mgr.recompile_and_deploy(&tree);
                broadcast_dag(&tree, &event_tx);
                let _ = event_tx.send(DashboardEvent::RuleEvent {
                    ts: now_ts(), action: "expired".into(),
                    summary: format!("{} rules expired ({} remaining)", expired, mgr.rule_count()),
                    engram_name: None, rule_count: Some(expired),
                });
            }
        }

        // Update metrics + emit SSE
        let rules_count;
        let (pass, blocks, rate_limits, close_conn) = http_proxy::enforcement_counts();
        {
            let mgr = rule_mgr.lock().await;
            rules_count = mgr.rule_count();

            // Update shared rules snapshot for /api/rules
            let summaries: Vec<RuleSummary> = mgr.all_rules_with_age()
                .into_iter()
                .map(|(spec, age)| RuleSummary {
                    edn: spec.to_edn_compact(),
                    action: format!("{:?}", spec.action),
                    age_secs: age,
                })
                .collect();
            *shared_rules.write().await = summaries;

            let mut s = stats.write().await;
            s.tls_score = tick_tls_score;
            s.tls_threshold = tick_tls_threshold;
            s.tls_samples_per_tick = tls_tick_count;
            s.req_score = tick_req_score;
            s.req_threshold = tick_req_threshold;
            s.req_samples_per_tick = req_tick_count;
            s.warmup_tls = !tls_warmup_done;
            s.warmup_req = !req_warmup_done;
            s.warmup_samples_tls = tls_warmup_count;
            s.warmup_samples_req = req_warmup_count;
            s.anomaly_streak_tls = tls_detector.anomaly_streak;
            s.anomaly_streak_req = req_detector.anomaly_streak;
            s.engrams_tls = tls_detector.library.len();
            s.engrams_req = req_detector.library.len();
            s.active_rules = rules_count;
            s.tick_count = tick_count;
            s.estimated_rps = estimated_rps;
            s.enforced_pass = pass;
            s.enforced_blocks = blocks;
            s.enforced_rate_limits = rate_limits;
            s.enforced_close_conn = close_conn;
        }

        // Emit SSE event from local values (no extra lock acquisition)
        let _ = event_tx.send(DashboardEvent::Metrics {
            ts: now_ts(),
            enforced_pass: pass,
            enforced_rate_limits: rate_limits,
            enforced_blocks: blocks,
            enforced_close_conn: close_conn,
            tls_score: tick_tls_score,
            tls_threshold: tick_tls_threshold,
            req_score: tick_req_score,
            req_threshold: tick_req_threshold,
            estimated_rps,
            anomaly_streak_tls: tls_detector.anomaly_streak,
            anomaly_streak_req: req_detector.anomaly_streak,
            engrams_tls: tls_detector.library.len(),
            engrams_req: req_detector.library.len(),
            warmup_tls: !tls_warmup_done,
            warmup_req: !req_warmup_done,
            active_rules: rules_count,
            tick_count,
        });

        // Emit per-rule counters
        {
            let snapshot = http_proxy::rule_counter_snapshot();
            let compiled = tree.load();
            let counters: Vec<metrics_server::RuleCounter> = snapshot.iter()
                .filter_map(|(&rid, &count)| {
                    compiled.rule_labels.get(&rid).map(|(label, action)| {
                        metrics_server::RuleCounter {
                            id: rid,
                            label: label.clone(),
                            action: action.clone(),
                            count,
                        }
                    })
                })
                .collect();
            if !counters.is_empty() {
                let _ = event_tx.send(DashboardEvent::RuleCounters {
                    ts: now_ts(),
                    counters,
                });
            }
        }

        // Periodic metrics snapshot (every 10 ticks)
        if tick_count % 10 == 0 {
            let s = stats.read().await;
            info!(
                "[METRICS] tick={} samples(tls={},req={}) rps={:.0} \
                 tls[score={:.2},thr={:.2},streak={}] \
                 req[score={:.2},thr={:.2},streak={}] \
                 rules={} engrams(tls={},req={}) warmup(tls={},req={}) \
                 enforced(pass={},block={},rate_limit={},close={})",
                s.tick_count,
                s.tls_samples_received, s.req_samples_received,
                s.estimated_rps,
                s.tls_score, s.tls_threshold, s.anomaly_streak_tls,
                s.req_score, s.req_threshold, s.anomaly_streak_req,
                s.active_rules,
                s.engrams_tls, s.engrams_req,
                if s.warmup_tls { format!("{}/{}", s.warmup_samples_tls, WARMUP_SAMPLES_TLS) } else { "done".into() },
                if s.warmup_req { format!("{}/{}", s.warmup_samples_req, WARMUP_SAMPLES_REQ) } else { "done".into() },
                s.enforced_pass, s.enforced_blocks, s.enforced_rate_limits, s.enforced_close_conn,
            );
        }
    }
}

// =============================================================================
// Per-sample processing (called for each sample, not per tick)
// =============================================================================

/// Process a single TLS sample: learn during warmup, score individually after.
fn process_tls_sample(
    sample: &TlsSample,
    detector: &mut SubspaceDetector,
    warmup_count: &mut usize,
    warmup_done: bool,
    tick_max_residual: &mut f64,
    tick_max_vec: &mut Option<Vec<f64>>,
) {
    let vec_f64: Vec<f64> = sample.tls_vec.data().iter()
        .map(|&b| b as f64)
        .collect();

    if !warmup_done {
        detector.learn(&vec_f64);
        *warmup_count += 1;
    } else {
        let residual = detector.score(&vec_f64);
        if residual > *tick_max_residual {
            *tick_max_residual = residual;
            *tick_max_vec = Some(vec_f64);
        }
    }
}

/// Process a single REQ sample: encode, decay accumulator, learn/score, track fields.
/// When a sample achieves the max residual for this tick, stores both the f64 vector
/// AND the original sample (for drill-down probing at detection time).
fn process_req_sample(
    sample: &RequestSample,
    encoder: &Encoder,
    detector: &mut SubspaceDetector,
    tracker: &mut FieldTracker,
    warmup_count: &mut usize,
    warmup_done: bool,
    decay_alpha: f64,
    tick_max_residual: &mut f64,
    tick_max_vec: &mut Option<Vec<f64>>,
    tick_max_sample: &mut Option<RequestSample>,
) {
    let req_vec = encoder.encode_walkable(sample);
    let vec_f64: Vec<f64> = req_vec.data().iter()
        .map(|&b| b as f64)
        .collect();

    if !warmup_done {
        detector.learn(&vec_f64);
        *warmup_count += 1;
    } else {
        let residual = detector.score(&vec_f64);
        if residual > *tick_max_residual {
            *tick_max_residual = residual;
            *tick_max_vec = Some(vec_f64);
            *tick_max_sample = Some(sample.clone());
        }
    }

    // Track field values for concentration detection (with per-request decay)
    let pairs: Vec<(&str, String)> = vec![
        ("method", sample.method.clone()),
        ("path", sample.path.clone()),
        ("src_ip", sample.src_ip.to_string()),
        ("user_agent", sample.user_agent.clone().unwrap_or_default()),
        ("host", sample.host.clone().unwrap_or_default()),
        ("content_type", sample.content_type.clone().unwrap_or_default()),
        ("tls_group_hash", sample.tls_ctx.group_string()),
        ("tls_cipher_hash", sample.tls_ctx.cipher_string()),
        ("tls_ext_order_hash", sample.tls_ctx.ext_order_string()),
        ("tls_cipher_set", sample.tls_ctx.cipher_set_string()),
        ("tls_ext_set", sample.tls_ctx.ext_set_string()),
        ("tls_group_set", sample.tls_ctx.group_set_string()),
    ];
    tracker.observe_with_decay(&pairs, decay_alpha);
}

// =============================================================================
// Engram helpers
// =============================================================================

/// Deploy rules stored in an engram's metadata, recalculating rate limits
/// based on current baseline_rps rather than using stale stored values.
async fn deploy_engram_rules(
    detector: &SubspaceDetector,
    engram_name: &str,
    rule_mgr: &Arc<Mutex<RuleManager>>,
    tree: &Arc<ArcSwap<ExprCompiledTree>>,
    event_tx: &broadcast::Sender<DashboardEvent>,
    baseline_rps: f64,
) {
    let stored_edns: Vec<String> = detector.library.get(engram_name)
        .and_then(|e| e.metadata().get("rules").cloned())
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();

    if stored_edns.is_empty() {
        warn!("  Engram '{}' has no stored rules", engram_name);
        return;
    }

    let specs: Vec<RuleExpr> = stored_edns.iter().filter_map(|edn| {
        match http_proxy::expr::parse_edn(edn) {
            Ok(mut rule) => {
                if let RuleAction::RateLimit { ref mut rps, .. } = rule.action {
                    *rps = baseline_rps.max(10.0) as u32;
                }
                Some(rule)
            }
            Err(e) => {
                warn!("  Failed to parse stored rule EDN: {}", e);
                None
            }
        }
    }).collect();

    if specs.is_empty() {
        warn!("  Engram '{}': {} stored values but 0 parsed", engram_name, stored_edns.len());
        return;
    }

    let mut mgr = rule_mgr.lock().await;
    mgr.upsert(&specs);
    mgr.recompile_and_deploy(tree);
    broadcast_dag(tree, event_tx);
    warn!("  Deployed {} rules from engram '{}' (rate recalculated to baseline_rps={:.0}):",
          specs.len(), engram_name, baseline_rps);
    for spec in &specs {
        warn!("  ENGRAM RULE:\n{}", spec.to_edn_pretty());
        let _ = event_tx.send(DashboardEvent::RuleEvent {
            ts: now_ts(), action: "engram_deployed".into(),
            summary: spec.to_edn_compact(),
            engram_name: Some(engram_name.to_string()),
            rule_count: None,
        });
    }
}

/// Mint an engram, storing only rules that THIS detector generated during this attack.
async fn mint_engram_with_rules(
    detector: &mut SubspaceDetector,
    prefix: &str,
    surprise: &[(String, f64)],
    estimated_rps: f64,
    _rule_mgr: &Arc<Mutex<RuleManager>>,
    event_tx: &broadcast::Sender<DashboardEvent>,
) {
    if detector.attack_rules.is_empty() {
        warn!("[{}] Skipping engram mint — no rules generated during attack", prefix.to_uppercase());
        return;
    }

    let name = format!("{}-attack-{}", prefix, chrono::Utc::now().format("%Y%m%d-%H%M%S"));
    let surprise_map: HashMap<String, f64> = surprise.iter().cloned().collect();

    let rule_edns: Vec<String> = detector.attack_rules.iter()
        .map(|rule| rule.to_edn())
        .collect();

    let mut metadata: HashMap<String, serde_json::Value> = HashMap::new();
    metadata.insert("rps".into(), serde_json::json!(estimated_rps));
    metadata.insert("streak".into(), serde_json::json!(detector.anomaly_streak));
    metadata.insert("rules".into(), serde_json::json!(rule_edns));

    detector.mint_engram(&name, surprise_map, metadata);
    let lib_size = detector.library.len();
    let rules_stored = rule_edns.len();
    warn!("[{}] Engram minted: '{}' (library size: {}, {} rules stored)",
          prefix.to_uppercase(), name, lib_size, rules_stored);
    let _ = event_tx.send(DashboardEvent::DetectionEvent {
        ts: now_ts(), detector: prefix.to_uppercase(),
        kind: "engram_minted".into(),
        detail: format!("'{}' library={} rules={}", name, lib_size, rules_stored),
    });
}

// =============================================================================
// Helpers
// =============================================================================

fn broadcast_dag(tree: &ArcSwap<ExprCompiledTree>, event_tx: &broadcast::Sender<DashboardEvent>) {
    let compiled = tree.load();
    let nodes = compiled.to_dag_nodes();
    if let Ok(json) = serde_json::to_string_pretty(&nodes) {
        let path = format!("http-lab/logs/dag_{}.json", chrono::Utc::now().format("%Y%m%d_%H%M%S_%3f"));
        if let Err(e) = std::fs::write(&path, &json) {
            warn!("Failed to write DAG log to {}: {}", path, e);
        } else {
            info!(nodes = nodes.len(), path = %path, "DAG snapshot written");
        }
    }
    let _ = event_tx.send(DashboardEvent::DagSnapshot { ts: now_ts(), nodes });
}

/// Compute per-sample decay factor from half-life.
fn decay_factor(half_life: usize) -> f64 {
    if half_life > 0 {
        0.5_f64.powf(1.0 / half_life as f64)
    } else {
        1.0
    }
}

/// For a Walkable field name, return the ordered and set tracker/detection
/// field pairs. Returns (ordered_option, set_option).
fn tls_field_candidates(walkable_name: &str) -> Option<(Option<(&str, &str)>, Option<(&str, &str)>)> {
    match walkable_name {
        "ciphers"      => Some((None,                                          Some(("tls_cipher_set", "tls_cipher_set")))),
        "cipher_order" => Some((Some(("tls_cipher_hash", "tls_cipher_hash")),  Some(("tls_cipher_set", "tls_cipher_set")))),
        "ext_types"    => Some((None,                                          Some(("tls_ext_set",    "tls_ext_set")))),
        "ext_order"    => Some((Some(("tls_ext_order_hash", "tls_ext_order_hash")), Some(("tls_ext_set", "tls_ext_set")))),
        "groups"       => Some((None,                                          Some(("tls_group_set",  "tls_group_set")))),
        _ => None,
    }
}

/// Get the best TLS field value for rule generation.
/// If the ordered version concentrates (attacker uses fixed order), prefer it
/// for maximum specificity. Otherwise fall back to the set version (catches shuffled).
fn get_tls_field_top_value(tracker: &FieldTracker, walkable_field: &str) -> Option<(String, String)> {
    let (ordered, set) = tls_field_candidates(walkable_field)?;

    // Try ordered first: use it if concentration is high (attacker has consistent order)
    if let Some((ord_tracker, ord_det)) = ordered {
        let concentrated = tracker.find_concentrated_values(0.4);
        for (field, value, _conc) in &concentrated {
            if field == ord_tracker {
                return Some((ord_det.to_string(), value.clone()));
            }
        }
    }

    // Fall back to set version
    if let Some((set_tracker, set_det)) = set {
        let val = tracker.top_values(set_tracker, 1)
            .into_iter()
            .next()
            .map(|(v, _)| v)?;
        return Some((set_det.to_string(), val));
    }

    None
}
