//! Axum-based metrics server for the WAF sidecar.
//!
//! Provides:
//! - `GET /`                  — dashboard HTML (embedded)
//! - `GET /api/metrics/events` — SSE stream of DashboardEvents
//! - `GET /api/rules`          — snapshot of active rules as JSON
//! - `GET /metrics`            — legacy JSON stats
//! - `GET /health`             — health check

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive};
use axum::response::{Html, IntoResponse, Sse};
use axum::routing::get;
use axum::{Json, Router};
use futures::stream::{self, Stream};
use http_proxy::types::DagNode;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use tower_http::cors::CorsLayer;
use tracing::info;

// =============================================================================
// SSE event types
// =============================================================================

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DashboardEvent {
    Metrics {
        ts: f64,
        enforced_pass: u64,
        enforced_rate_limits: u64,
        enforced_blocks: u64,
        enforced_close_conn: u64,
        tls_score: f64,
        tls_threshold: f64,
        req_score: f64,
        req_threshold: f64,
        estimated_rps: f64,
        anomaly_streak_tls: usize,
        anomaly_streak_req: usize,
        engrams_tls: usize,
        engrams_req: usize,
        warmup_tls: bool,
        warmup_req: bool,
        active_rules: usize,
        tick_count: u64,
        manifold_allow: u64,
        manifold_warmup: u64,
        manifold_rate_limit: u64,
        manifold_deny: u64,
    },
    RuleEvent {
        ts: f64,
        action: String,
        summary: String,
        engram_name: Option<String>,
        rule_count: Option<usize>,
    },
    DetectionEvent {
        ts: f64,
        detector: String,
        kind: String,
        detail: String,
    },
    DagSnapshot {
        ts: f64,
        nodes: Vec<DagNode>,
    },
    RuleCounters {
        ts: f64,
        counters: Vec<RuleCounter>,
    },
    Verdict {
        ts: f64,
        src_ip: String,
        method: String,
        path: String,
        query: Option<String>,
        user_agent: Option<String>,
        residual: f64,
        threshold: f64,
        deny_threshold: f64,
        verdict: String,
        /// Full Walkable representation of the request as JSON.
        request_walk: serde_json::Value,
        /// Drilldown attribution — empty for allow/warmup verdicts.
        attribution: Vec<DenyField>,
        /// Concentration ratio: max_score / mean_score.
        concentration: f64,
        /// Normalized Shannon entropy [0,1]. 1 = broad, 0 = narrow.
        entropy: f64,
        /// Gini coefficient [0,1]. 0 = broad, 1 = narrow.
        gini: f64,
        /// Traffic source label (e.g. "browser-agent"). Empty for unlabeled.
        traffic_source: String,
    },
    Heartbeat {
        ts: f64,
    },
}

/// Field-level anomaly attribution sent in deny events.
#[derive(Debug, Clone, Serialize)]
pub struct DenyField {
    pub field: String,
    pub score: f64,
}

/// Per-rule hit counter sent to the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCounter {
    pub id: u32,
    pub label: String,
    pub action: String,
    pub count: u64,
}

// =============================================================================
// Legacy stats (for /metrics endpoint)
// =============================================================================

#[derive(Debug, Clone, Default, Serialize)]
pub struct SidecarStats {
    pub tls_samples_received: u64,
    pub req_samples_received: u64,
    pub tls_samples_dropped: u64,
    pub req_samples_dropped: u64,
    pub active_rules: usize,
    pub warmup_tls: bool,
    pub warmup_req: bool,
    pub warmup_samples_tls: usize,
    pub warmup_samples_req: usize,
    pub anomaly_streak_tls: usize,
    pub anomaly_streak_req: usize,
    pub engrams_tls: usize,
    pub engrams_req: usize,
    pub tls_score: f64,
    pub tls_threshold: f64,
    pub req_score: f64,
    pub req_threshold: f64,
    pub estimated_rps: f64,
    pub tls_samples_per_tick: usize,
    pub req_samples_per_tick: usize,
    pub tick_count: u64,
    pub enforced_pass: u64,
    pub enforced_blocks: u64,
    pub enforced_rate_limits: u64,
    pub enforced_close_conn: u64,
    pub manifold_allow: u64,
    pub manifold_warmup: u64,
    pub manifold_rate_limit: u64,
    pub manifold_deny: u64,
}

pub type SharedStats = Arc<RwLock<SidecarStats>>;

pub fn new_shared_stats() -> SharedStats {
    Arc::new(RwLock::new(SidecarStats::default()))
}

// =============================================================================
// Active rules snapshot (for /api/rules endpoint)
// =============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct RuleSummary {
    pub edn: String,
    pub action: String,
    pub age_secs: f64,
}

pub type SharedRules = Arc<RwLock<Vec<RuleSummary>>>;

pub fn new_shared_rules() -> SharedRules {
    Arc::new(RwLock::new(Vec::new()))
}

// =============================================================================
// Server state
// =============================================================================

#[derive(Clone)]
pub struct MetricsAppState {
    pub stats: SharedStats,
    pub event_tx: broadcast::Sender<DashboardEvent>,
    pub rules: SharedRules,
}

pub fn now_ts() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

// =============================================================================
// Server
// =============================================================================

pub async fn run_metrics_server(
    addr: SocketAddr,
    state: MetricsAppState,
) {
    let app = Router::new()
        .route("/", get(serve_dashboard))
        .route("/waf", get(serve_waf_dashboard))
        .route("/api/metrics/events", get(sse_handler))
        .route("/api/rules", get(rules_handler))
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .layer(CorsLayer::permissive())
        .with_state(state);

    info!("Metrics server on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// =============================================================================
// Handlers
// =============================================================================

async fn serve_dashboard() -> impl IntoResponse {
    Html(include_str!("../static/dashboard.html"))
}

async fn serve_waf_dashboard() -> impl IntoResponse {
    Html(include_str!("../static/waf_dashboard.html"))
}

async fn sse_handler(
    State(state): State<MetricsAppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.event_tx.subscribe();

    let stream = stream::unfold(rx, |mut rx| async move {
        match rx.recv().await {
            Ok(event) => {
                let json = serde_json::to_string(&event).unwrap_or_default();
                let sse_event = Event::default().data(json);
                Some((Ok(sse_event), rx))
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                let msg = format!("{{\"type\":\"lagged\",\"skipped\":{}}}", n);
                let sse_event = Event::default().data(msg);
                Some((Ok(sse_event), rx))
            }
            Err(broadcast::error::RecvError::Closed) => None,
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn rules_handler(State(state): State<MetricsAppState>) -> Json<Vec<RuleSummary>> {
    Json(state.rules.read().await.clone())
}

async fn metrics_handler(State(state): State<MetricsAppState>) -> Json<SidecarStats> {
    Json(state.stats.read().await.clone())
}

async fn health_handler() -> &'static str {
    "ok"
}
