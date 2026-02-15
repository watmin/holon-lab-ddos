# veth-lab Metrics Dashboard

Real-time observability dashboard for the veth-lab XDP/eBPF DDoS defense sidecar.

https://github.com/user-attachments/assets/8c755b9d-2d03-4718-bef0-ac846f9903b3

## Quick Start

```bash
# Build
./veth-lab/scripts/build.sh

# Start sidecar with metrics (default port 9100)
sudo ./target/release/veth-sidecar --interface veth-filter --metrics-port 9100

# Open dashboard
open http://localhost:9100
```

Disable metrics with `--metrics-port 0`.

## Features

### Timeline (uPlot)
- Grafana-like dark theme with sub-second rendering
- Global rates: passed, dropped, rate-limited packets/sec
- Per-rule trendlines for top 5 active rules
- Live legend with current throughput values
- Data point tooltips on hover
- 2-minute rolling window at 500ms intervals (240 data points)

### DAG Viewer
- Interactive visualization of the compiled eBPF filter tree
- Clickable nodes with tooltips showing:
  - Dimension, match value, and fan-out
  - Terminating action and original EDN expression
  - Rule constraints in user-expressed form
- Leaf nodes for terminating rules (rate-limit, drop, count)
- Real-time updates on rule recompilation

### Rule Activity
- Scrolling log of rule lifecycle events (added, refreshed, expired)
- Visual indicators for new vs refreshed rules
- Full EDN expression display

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│ Kernel (eBPF)                                            │
│  ├── STATS PerCpuArray       (global packet counters)    │
│  ├── TREE_COUNTERS HashMap   (per-rule count actions)    │
│  └── TREE_RATE_STATE HashMap (rate-limit token buckets)  │
└──────────────────┬───────────────────────────────────────┘
                   │ map reads (500ms)
                   ▼
┌──────────────────────────────────────────────────────────┐
│ Sidecar (Rust, axum + tokio)                             │
│  ├── Unified Metrics Collector                           │
│  │    └── Reads all maps atomically, applies offsets     │
│  ├── Broadcast Channel (tokio::sync::broadcast)          │
│  ├── HTTP Server (port 9100)                             │
│  │    ├── GET /                  → dashboard.html        │
│  │    ├── GET /api/metrics/events → SSE stream           │
│  │    ├── GET /api/rules         → active rules JSON     │
│  │    └── GET /api/dag           → DAG structure JSON    │
│  └── Detection Loop                                      │
│       └── Emits rule_event + dag_snapshot on changes     │
└──────────────────┬───────────────────────────────────────┘
                   │ SSE (Server-Sent Events)
                   ▼
┌──────────────────────────────────────────────────────────┐
│ Browser Dashboard (single HTML file, zero build tools)   │
│  ├── uPlot timeline with per-rule series                 │
│  ├── Canvas 2D DAG viewer with interactive tooltips      │
│  └── Rule activity log with lifecycle tracking           │
└──────────────────────────────────────────────────────────┘
```

## SSE Event Types

All metrics are delivered in a single unified event:

**Metrics** (500ms intervals):
```json
{
  "type": "metrics",
  "ts": 1739500000.0,
  "total": 1284000,
  "passed": 1200000,
  "dropped": 80000,
  "rate_limited": 4000,
  "sampled": 12840,
  "rules": [
    {"id": 3415138916, "label": "[global udp-baseline]", "action": "rate-limit", "count": 1200000},
    {"id": 2928213011, "label": "[system [(= src-addr 10.0.0.100) ...]]", "action": "rate-limit", "count": 80000}
  ]
}
```

**Rule Events** (on rule lifecycle changes):
```json
{
  "type": "rule_event",
  "action": "added|refreshed|expired",
  "key": "[(= proto 17)]__rate-limit",
  "spec_summary": "{:constraints [(= proto 17)] :actions [(rate-limit 50000)]}",
  "is_preloaded": false,
  "ttl_secs": 300
}
```

**DAG Snapshot** (after tree recompilation):
```json
{
  "type": "dag_snapshot",
  "node_count": 33,
  "rule_count": 15,
  "nodes": [...]
}
```

## Key Design Decisions

### Monotonic Counter Tracking
When dynamic rate-limit rules are recompiled, eBPF token buckets are destroyed and
recreated. To prevent per-rule counters from resetting to zero:

1. **Retire capture**: Before deleting an old bucket, read its final `allowed + dropped` count
2. **Offset accumulation**: Add the retired count to a persistent offset keyed by rule label
3. **Apply on read**: Each metrics read adds the offset to the live count before broadcasting

This ensures per-rule counts are monotonically increasing, enabling simple `delta / dt`
rate computation on the frontend with no interpolation or normalization hacks.

### Stable Bucket Keys
System-generated detection rules use a `:name` derived from their constraints (not the
rate-limit value). This ensures `bucket_key()` produces the same hash across recompilations
when only the rate value changes, preserving the existing token bucket state and preventing
burst leaks during rate adjustments.

### In-Place Rate Updates
When a rule's rate-limit pps changes but its bucket key is stable, the `rate_pps` field
is updated in-place on the existing eBPF `TokenBucket`, preserving `tokens`,
`last_update_ns`, and counters. No fresh token burst on rate adjustment.

### Rule Deduplication
The frontend deduplicates rules by `constraints + action_type`, ignoring action config
(e.g., rate-limit value). This provides stable UI identity across dynamic rate adjustments.

## Dependencies

```toml
axum = "0.7"
tower-http = { version = "0.5", features = ["fs", "cors"] }
futures = "0.3"
```
