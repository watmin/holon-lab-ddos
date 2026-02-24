# http-lab Metrics Dashboard — Plan

## Reference

The veth-lab has a complete real-time metrics dashboard:
- `veth-lab/sidecar/src/metrics_server.rs` — SSE streaming, REST endpoints (`/api/rules`, `/api/dag`), broadcast channel
- `veth-lab/sidecar/static/dashboard.html` — 2K-line single-file HTML+JS+CSS with uPlot charts, rule event log, DAG visualizer
- Served at `/` from the sidecar process, streams `MetricsEvent` types via Server-Sent Events

We need to adapt this for http-lab's L7 WAF context.

## Current State

The http-lab sidecar (`http-lab/sidecar/src/metrics_server.rs`) has:
- `GET /metrics` — returns JSON `SidecarStats` (samples received/dropped, active rules, warmup status, anomaly streaks, engram counts)
- `GET /health` — returns `"ok"`
- Shared state via `Arc<RwLock<SidecarStats>>` updated by the detection loops

**What's missing:**
1. No SSE streaming — clients must poll `/metrics`
2. No HTML dashboard — JSON only
3. No per-rule counters or rule event log
4. No live charts (packet rates, anomaly scores, rule timeline)
5. No DAG/tree visualization

## Plan

### Phase 1: SSE + Event Types

Upgrade `sidecar/src/metrics_server.rs`:

1. Add `broadcast::channel<MetricsEvent>` to sidecar state
2. Define event types:
   - `Metrics` — periodic snapshot: `{ tls_samples_rate, req_samples_rate, samples_dropped, active_rules, anomaly_scores_tls, anomaly_scores_req }`
   - `RuleEvent` — when rules are added/expired: `{ action, key, spec_summary, ttl }`
   - `DetectionEvent` — anomaly detected: `{ domain (tls|http), score, top_fields }`
   - `Heartbeat` — keepalive
3. Add `GET /api/metrics/events` SSE endpoint (mirror veth-lab pattern)
4. Add `GET /api/rules` REST endpoint — current active rules snapshot
5. Keep `GET /metrics` as simple JSON for scripting/curl

Wire broadcasts into:
- `sidecar/src/lib.rs` detection loops (anomaly events, rule events)
- `sidecar/src/rule_manager.rs` (rule add/expire events)
- Periodic metrics collector task (rate calculations over sliding window)

### Phase 2: Dashboard HTML

Create `sidecar/static/dashboard.html` (single-file, self-contained):

**Layout** (dark theme, grid, similar to veth-lab):
```
┌─────────────────────────────────────────────────────┐
│ header: http-lab WAF Dashboard  │ status │ counters  │
├────────────────────────┬────────────────────────────┤
│ Traffic Rate Chart     │ Anomaly Score Chart        │
│ (uPlot, 2 series:     │ (uPlot, 2 series:          │
│  TLS samples/s,        │  TLS anomaly,              │
│  HTTP samples/s)       │  HTTP anomaly)             │
├────────────────────────┴────────────────────────────┤
│ Rule Timeline (horizontal bar/events)               │
├────────────────────────┬────────────────────────────┤
│ Active Rules Table     │ Event Log (scrolling)       │
│ (constraints, action,  │ (rule added/expired,        │
│  TTL, hit count)       │  anomalies detected)        │
└────────────────────────┴────────────────────────────┘
```

**Charts** (uPlot, same library as veth-lab):
- Traffic rate: TLS connections/s + HTTP requests/s (dual y-axis)
- Anomaly score: TLS + HTTP detector scores over time
- Optional: per-IP or per-path request distribution (top-N)

**Event log:**
- Scrolling log of rule events and detections
- Color-coded: green=pass, red=block, yellow=rate-limit, blue=detection

**Active rules table:**
- Live-updating table of current rules from `/api/rules`
- Shows: constraints (human-readable), action, priority, time remaining

### Phase 3: Serve from Sidecar

- `include_str!("../static/dashboard.html")` in metrics_server.rs
- `GET /` serves the dashboard
- Dashboard connects to `GET /api/metrics/events` for SSE stream
- No external deps beyond uPlot CDN (same as veth-lab)

## Dependencies

- `axum` (already present)
- `tower-http` (already present, add CORS layer)
- `futures` (already present)
- `tokio::sync::broadcast` (already available via tokio)
- `serde` (already present)
- uPlot via CDN in HTML (same as veth-lab)

## Files to Change

| File | Change |
|------|--------|
| `sidecar/src/metrics_server.rs` | Rewrite: SSE, broadcast, event types, dashboard serving |
| `sidecar/src/lib.rs` | Wire broadcast sends into detection loops |
| `sidecar/src/rule_manager.rs` | Emit rule events on add/expire |
| `sidecar/static/dashboard.html` | New: full dashboard (adapt from veth-lab) |
| `sidecar/Cargo.toml` | May need `broadcast` feature if not already enabled |

## Scope

This is a **visual observability** task — no changes to proxy logic, rule engine, or detection algorithms. The dashboard is read-only and consumes events the sidecar already produces internally.

Estimated effort: the veth-lab dashboard was ~2K lines of HTML and ~350 lines of Rust. This should be comparable, with HTTP-specific adaptations (TLS context display, header inspection, etc.).
