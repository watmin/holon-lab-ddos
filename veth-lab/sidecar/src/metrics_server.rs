//! Metrics HTTP server with SSE streaming for veth-lab dashboard
//!
//! Provides real-time metrics streaming via Server-Sent Events (SSE) and REST endpoints
//! for rule inspection and DAG visualization.

use anyhow::{Context, Result};
use axum::{
    extract::State,
    response::{
        sse::{Event, KeepAlive},
        Html, IntoResponse, Sse,
    },
    routing::get,
    Json, Router,
};
use futures::stream::{self, Stream};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, RwLock};
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};
use veth_filter::{RuleSpec, VethFilter};

// Re-export the SerializableDagNode from veth_filter
pub use veth_filter::tree::SerializableDagNode as DagNode;

/// Event types broadcast to SSE clients
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MetricsEvent {
    Metrics {
        ts: f64,
        total: u64,
        passed: u64,
        dropped: u64,
        rate_limited: u64,
        sampled: u64,
        rules: Vec<RuleCounter>,
    },
    RuleEvent {
        ts: f64,
        action: String, // "added", "expired", "refreshed"
        key: String,
        spec_summary: String,
        is_preloaded: bool,
        ttl_secs: u64,
    },
    DagSnapshot {
        ts: f64,
        node_count: usize,
        rule_count: usize,
        nodes: Vec<DagNode>,
    },
    Heartbeat {
        ts: f64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCounter {
    pub id: u32,
    pub label: String,
    pub action: String,
    pub count: u64,
}

/// Active rule metadata shared with metrics server
#[derive(Debug, Clone)]
pub struct ActiveRuleInfo {
    pub spec: RuleSpec,
    pub preloaded: bool,
}

/// Shared state for the metrics server
#[derive(Clone)]
pub struct MetricsState {
    pub filter: Arc<VethFilter>,
    pub active_rules: Arc<RwLock<HashMap<String, ActiveRuleInfo>>>,
    pub tree_counter_labels: Arc<RwLock<HashMap<u32, (String, String)>>>,
    /// Accumulated counter offsets for retired eBPF buckets, keyed by rule label.
    /// When a rate-limit rule is recompiled, the old bucket is deleted.
    /// We capture its final count here so per-rule totals remain monotonic.
    pub counter_offsets: Arc<RwLock<HashMap<String, u64>>>,
    pub event_tx: broadcast::Sender<MetricsEvent>,
}

impl MetricsState {
    pub fn new(
        filter: Arc<VethFilter>,
        active_rules: Arc<RwLock<HashMap<String, ActiveRuleInfo>>>,
        tree_counter_labels: Arc<RwLock<HashMap<u32, (String, String)>>>,
        channel_capacity: usize,
    ) -> Self {
        let (event_tx, _) = broadcast::channel(channel_capacity);
        Self {
            filter,
            active_rules,
            tree_counter_labels,
            counter_offsets: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
        }
    }

    /// Broadcast an event to all SSE subscribers
    pub fn broadcast(&self, event: MetricsEvent) {
        // Ignore send errors (no active subscribers)
        let _ = self.event_tx.send(event);
    }
    
    /// Accumulate retired bucket counts by label so per-rule totals remain monotonic
    pub async fn accumulate_retired_counts(&self, retired: &[(u32, u64)]) {
        if retired.is_empty() {
            return;
        }
        let labels = self.tree_counter_labels.read().await;
        let mut offsets = self.counter_offsets.write().await;
        for &(bucket_id, final_count) in retired {
            if let Some((_action, label)) = labels.get(&bucket_id) {
                let offset = offsets.entry(label.clone()).or_insert(0);
                *offset += final_count;
                info!("Counter offset: label='{}' bucket={} retired_count={} total_offset={}", 
                      label, bucket_id, final_count, *offset);
            }
        }
    }
}

/// Start the metrics HTTP server
pub async fn run_server(state: MetricsState, port: u16) -> Result<()> {
    let app = Router::new()
        .route("/", get(serve_dashboard))
        .route("/api/metrics/events", get(sse_handler))
        .route("/api/rules", get(rules_handler))
        .route("/api/dag", get(dag_handler))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    info!("Metrics server ready at http://localhost:{} (listening on {})", port, addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("Failed to bind metrics server")?;

    axum::serve(listener, app)
        .await
        .context("Metrics server error")?;

    Ok(())
}

/// Serve the dashboard HTML
async fn serve_dashboard() -> impl IntoResponse {
    Html(include_str!("../static/dashboard.html"))
}

/// SSE endpoint for streaming metrics
async fn sse_handler(
    State(state): State<MetricsState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.event_tx.subscribe();

    let stream = stream::unfold(rx, |mut rx| async move {
        match rx.recv().await {
            Ok(event) => {
                let json = serde_json::to_string(&event).ok()?;
                Some((Ok(Event::default().data(json)), rx))
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!("SSE client lagged, skipped {} messages", skipped);
                // Send heartbeat and continue
                let heartbeat = MetricsEvent::Heartbeat { ts: timestamp() };
                let json = serde_json::to_string(&heartbeat).ok()?;
                Some((Ok(Event::default().data(json)), rx))
            }
            Err(broadcast::error::RecvError::Closed) => None,
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// REST endpoint for current rules snapshot
async fn rules_handler(State(state): State<MetricsState>) -> Json<serde_json::Value> {
    let rules = state.active_rules.read().await;
    let rules_list: Vec<_> = rules
        .iter()
        .map(|(key, info)| {
            serde_json::json!({
                "key": key,
                "preloaded": info.preloaded,
                "spec": format!("{:?}", info.spec),
            })
        })
        .collect();

    Json(serde_json::json!({
        "count": rules_list.len(),
        "rules": rules_list,
    }))
}

/// REST endpoint for DAG structure
async fn dag_handler(State(state): State<MetricsState>) -> Json<serde_json::Value> {
    let mut nodes = state.filter.serialize_dag().await;
    let labels = state.tree_counter_labels.read().await;
    for node in &mut nodes {
        if let Some(rule_id) = node.action_rule_id {
            if let Some((_, label)) = labels.get(&rule_id) {
                node.label = Some(label.clone());
            }
        }
    }
    Json(serde_json::json!({
        "node_count": nodes.len(),
        "nodes": nodes,
    }))
}

/// Background task that collects metrics and broadcasts events
pub async fn metrics_collector_task(
    state: MetricsState,
    interval: Duration,
) {
    info!(
        "Starting metrics collector (interval: {:?})",
        interval,
    );

    let mut ticker = tokio::time::interval(interval);
    let mut heartbeat_ticker = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Err(e) = collect_metrics(&state).await {
                    error!("Failed to collect metrics: {}", e);
                }
            }
            _ = heartbeat_ticker.tick() => {
                state.broadcast(MetricsEvent::Heartbeat { ts: timestamp() });
            }
        }
    }
}

/// Collect global stats and per-rule counters from eBPF maps in one shot
async fn collect_metrics(state: &MetricsState) -> Result<()> {
    // Read global stats
    let stats = state.filter.stats().await?;

    // Read per-rule counters (COUNT actions)
    let counter_values = state.filter.read_counters().await?;
    
    // Read per-rule rate-limit stats
    let rate_limit_stats = state.filter.read_rate_limit_stats().await?;

    let labels = state.tree_counter_labels.read().await;
    let offsets = state.counter_offsets.read().await;
    let mut rules = Vec::new();

    // Add COUNT action rules (with offsets for retired buckets)
    for (rule_id, count) in &counter_values {
        let (label, action) = if let Some((action, label)) = labels.get(rule_id) {
            (label.clone(), action.clone())
        } else {
            (format!("unknown-{}", rule_id), "Unknown".to_string())
        };
        let offset = offsets.get(&label).copied().unwrap_or(0);
        rules.push(RuleCounter {
            id: *rule_id,
            label,
            action,
            count: *count + offset,
        });
    }

    // Add RATE_LIMIT action rules (allowed + dropped + offset for retired buckets)
    for (bucket_id, allowed, dropped) in &rate_limit_stats {
        let total_hits = allowed + dropped;
        let (label, action) = if let Some((action, label)) = labels.get(bucket_id) {
            (label.clone(), action.clone())
        } else {
            (format!("unknown-{}", bucket_id), "Unknown".to_string())
        };
        let offset = offsets.get(&label).copied().unwrap_or(0);
        rules.push(RuleCounter {
            id: *bucket_id,
            label,
            action,
            count: total_hits + offset,
        });
    }
    
    // Log sanity check: sum of per-rule counters (with offsets) vs global stats
    let rule_total: u64 = rules.iter().map(|r| r.count).sum();
    let stats_total = stats.passed_packets + stats.dropped_packets + stats.rate_limited_packets;
    let total_offset: u64 = offsets.values().sum();
    let diff = (stats_total as i64) - (rule_total as i64);
    info!(
        "METRICS SANITY | stats total={} (passed={} dropped={} rate_limited={}) | rules sum={} (offset={}) ({} count + {} rate_limit entries) | diff={}",
        stats_total,
        stats.passed_packets,
        stats.dropped_packets,
        stats.rate_limited_packets,
        rule_total,
        total_offset,
        counter_values.len(),
        rate_limit_stats.len(),
        diff,
    );
    if !rate_limit_stats.is_empty() {
        for (bucket_id, allowed, dropped) in &rate_limit_stats {
            let label = labels.get(bucket_id).map(|(_, l)| l.as_str()).unwrap_or("?");
            info!(
                "  RATE_LIMIT bucket={} label={} allowed={} dropped={} total={}",
                bucket_id, label, allowed, dropped, allowed + dropped,
            );
        }
    }

    let event = MetricsEvent::Metrics {
        ts: timestamp(),
        total: stats.total_packets,
        passed: stats.passed_packets,
        dropped: stats.dropped_packets,
        rate_limited: stats.rate_limited_packets,
        sampled: stats.sampled_packets,
        rules,
    };

    state.broadcast(event);
    Ok(())
}

/// Helper to get current Unix timestamp as f64
fn timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}
