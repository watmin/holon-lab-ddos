//! Axum-based metrics server for the WAF sidecar.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{Json, Router};
use axum::extract::State;
use axum::routing::get;
use serde::Serialize;
use tokio::sync::RwLock;
use tracing::info;

#[derive(Debug, Clone, Default, Serialize)]
pub struct SidecarStats {
    pub tls_samples_received: u64,
    pub req_samples_received: u64,
    pub tls_samples_dropped: u64,
    pub req_samples_dropped: u64,
    pub active_rules: usize,
    pub warmup_tls: bool,
    pub warmup_req: bool,
    pub anomaly_streak_tls: usize,
    pub anomaly_streak_req: usize,
    pub engrams_tls: usize,
    pub engrams_req: usize,
    // Per-tick detection state
    pub tls_score: f64,
    pub tls_threshold: f64,
    pub req_score: f64,
    pub req_threshold: f64,
    pub estimated_rps: f64,
    pub tls_samples_per_tick: usize,
    pub req_samples_per_tick: usize,
}

pub type SharedStats = Arc<RwLock<SidecarStats>>;

pub fn new_shared_stats() -> SharedStats {
    Arc::new(RwLock::new(SidecarStats::default()))
}

pub async fn run_metrics_server(addr: SocketAddr, stats: SharedStats) {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .with_state(stats);

    info!("Metrics server on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn metrics_handler(State(stats): State<SharedStats>) -> Json<SidecarStats> {
    Json(stats.read().await.clone())
}

async fn health_handler() -> &'static str {
    "ok"
}
