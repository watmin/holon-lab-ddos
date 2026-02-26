# HTTP Lab Architecture

**Status:** Complete — all attack types mitigated autonomously
**Date:** February 2026

## Overview

HTTP Lab is a Layer 7 Web Application Firewall that detects and mitigates HTTP-layer attacks without signatures, training data, or human-authored rules. It uses Vector Symbolic Architecture (VSA) to encode structured representations of TLS ClientHello messages and HTTP requests into high-dimensional vectors, then applies manifold-aware anomaly detection to identify deviations from learned traffic baselines.

The system consists of four crates compiled into two binaries (proxy + generator), running in a single tokio async runtime. The proxy and sidecar share memory — no IPC, no serialization on the hot path.

## Data Path

```
Client
  │
  │ TCP connect
  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ TLS Accept                                                               │
│  ├─ Read raw ClientHello bytes (before rustls processes them)            │
│  ├─ Parse into TlsContext (lossless, wire order, all extensions)         │
│  ├─ Encode TlsContext → 4096-dim bipolar vector (holon-rs)              │
│  ├─ try_send TlsSample to sidecar channel                               │
│  └─ Complete handshake via tokio-rustls                                  │
│                                                                          │
│ HTTP Handler (per request on the established TLS connection)             │
│  ├─ Parse request → RequestSample (method, path, headers, query, ...)   │
│  ├─ Enforcer: load CompiledTree from ArcSwap (wait-free)                │
│  │    ├─ Walk DAG with request field values                              │
│  │    ├─ Verdict: Pass / Block(403) / RateLimit(rps) / CloseConnection  │
│  │    └─ If RateLimit: check per-IP token bucket                        │
│  ├─ try_send RequestSample to sidecar channel                           │
│  └─ Forward to upstream or respond with 403/429                         │
└──────────────────────────────────────────────────────────────────────────┘
                    │ mpsc channel (capacity=512, try_send)
                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ Sidecar Detection Loop                                                   │
│  ├─ Drain channel (up to 512 samples per pass)                          │
│  ├─ Per-sample: encode, score against SubspaceDetector, track fields    │
│  ├─ Hybrid tick: fires after 200 samples OR 500ms (whichever first)     │
│  │                                                                       │
│  ├─ TLS Detector tick                                                    │
│  │    ├─ Compare max residual against adaptive threshold                 │
│  │    ├─ On anomaly: check engram library → instant rule deploy          │
│  │    ├─ On sustained anomaly (streak ≥ 3): generate rules              │
│  │    └─ On attack end: mint engram with surprise fingerprint + rules   │
│  │                                                                       │
│  ├─ REQ Detector tick (same structure, different parameters)             │
│  │                                                                       │
│  ├─ Rule Manager: compile → ArcSwap deploy                              │
│  └─ SSE broadcast: metrics, rule events, detection events               │
└──────────────────────────────────────────────────────────────────────────┘
```

## Data Model

### TlsContext

Full lossless capture of a TLS ClientHello. Fields stored in wire order — order itself is a detection signal. DDoS tools produce identical, perfectly ordered ClientHellos; browsers randomize extension ordering.

```
TlsContext {
    record_version:       u16          // outer TLS record version
    handshake_version:    u16          // ClientHello.client_version
    session_id_len:       u8           // 0 or 32 (TLS 1.3 compat mode)
    cipher_suites:        Vec<u16>     // wire order, GREASE included
    compression_methods:  Vec<u8>      // TLS 1.3 always [0x00]
    extensions:           Vec<(u16, Vec<u8>)>  // type + raw bytes, wire order
    supported_groups:     Vec<u16>     // pre-parsed from ext 0x000a
    sig_algs:             Vec<u16>     // pre-parsed from ext 0x000d
    alpn:                 Vec<String>  // pre-parsed from ext 0x0010
    sni:                  Option<String>
    ...
}
```

The `Walkable` implementation encodes TlsContext as a structured map with both **ordered** and **set** representations:

- `ciphers` (set) — which cipher suites are offered, order-independent
- `cipher_order` (list) — the exact ordering of cipher suites
- `ext_types` (set) — which extensions are present
- `ext_order` (list) — the exact ordering of extensions
- `groups` (set) — supported key exchange groups
- `extensions` (map) — per-extension parsed values (SNI, ALPN, versions, etc.)

This dual representation is critical: the detection pipeline dynamically selects ordered or set-based fields depending on whether an attacker maintains consistent ordering or randomizes it.

All TLS values are rendered with human-readable names (e.g., `TLS_AES_128_GCM_SHA256` instead of `0x1301`) via lookup tables in `tls_names.rs`, with graceful fallback to hex for unknowns.

### RequestSample

Full HTTP request capture with zero normalization — the raw data as expressed by the client.

```
RequestSample {
    method:       String                  // "GET", "POST", etc.
    path:         String                  // raw path including trailing slash
    path_parts:   Vec<String>             // path split by '/' for ngram-style analysis
    query_raw:    Option<String>          // raw query string
    query_params: Vec<(String, String)>   // parsed key=value pairs, preserving duplicates
    query_flags:  Vec<String>             // keys with no '=' assignment
    headers:      Vec<(String, String)>   // pairs in wire order, original casing
    header_count: usize
    host:         Option<String>
    user_agent:   Option<String>
    content_type: Option<String>
    has_cookie:   bool
    src_ip:       IpAddr
    tls_ctx:      Arc<TlsContext>         // shared across all requests on the connection
    tls_vec:      Vector                  // pre-encoded TLS vector
    ...
}
```

Both `TlsContext` and `RequestSample` implement the holon `Walkable` trait, enabling direct encoding into high-dimensional bipolar vectors via `encoder.encode_walkable()`.

## Detection Pipeline

### Two-Tier Flow

The detection pipeline mirrors veth-lab's proven architecture:

**Tier 1: SubspaceDetector (anomaly detection)**

Each detector maintains an `OnlineSubspace` — an online PCA approximation (CCIPCA) that learns the principal components of normal traffic. New samples are scored by their residual: the component of the vector that falls outside the learned subspace.

- The **threshold** adapts via EMA of residual statistics (mean + sigma_mult * std)
- Each sample is individually scored (no bundling/averaging)
- The per-tick maximum residual drives anomaly decisions
- If the max residual exceeds the threshold for `ANOMALY_STREAK_THRESHOLD` (3) consecutive ticks, the system confirms an attack and generates rules

Two independent detectors run concurrently:

| Detector | Input | Tuning | Rationale |
|----------|-------|--------|-----------|
| TLS | `TlsContext` vector (1 per connection) | `ema_alpha=0.05`, `sigma_mult=2.0` | Low sample volume → faster convergence, tighter threshold |
| REQ | `RequestSample` vector (1 per request) | `ema_alpha=0.01`, `sigma_mult=3.5` | High sample volume → standard convergence |

**Tier 2: EngramLibrary (fast-path re-mitigation)**

When an attack ends, the system mints an **engram**: a snapshot of the attack subspace with associated metadata (surprise fingerprint, active rules, estimated RPS). The engram is stored persistently (JSON on disk).

On subsequent anomalies, the vector is checked against the library *before* waiting for a streak. If a match is found (vector projects well onto a stored attack subspace), the stored rules are deployed immediately — typically 1 tick vs. 3+ ticks for first-time detection.

### Warmup

The system requires a minimum number of samples before detection activates:

- TLS: 30 samples
- REQ: 500 samples

During warmup, all samples are fed to `OnlineSubspace::update()` to learn the baseline. When warmup completes, the system records `baseline_rps` (used for rate limit calculation) and freezes the `FieldTracker` baseline (so always-dominant values aren't flagged as anomalous during attacks).

## Rule Generation

### Concentration-Based Field Attribution

When an anomaly is confirmed, the system must determine *which* fields characterize the attack. Two complementary mechanisms are used:

**For REQ rules: Concentration**

The `FieldTracker` records per-field-value frequencies with exponential decay (half-life = 500 requests). When an attack is confirmed, `find_concentrated_values(0.5)` returns fields where a single value accounts for >50% of recent traffic — but only values that *weren't* already dominant during baseline.

Example: If during an attack 90% of requests hit `path=/api/search`, but during baseline `method=GET` was already at 80%, the rule targets `path=/api/search` and ignores `method`.

**For TLS rules: Surprise + Concentration**

The surprise fingerprint identifies which Walkable fields contribute most to the anomalous vector component (via role unbinding). The system then maps each Walkable field to its corresponding tracker field and retrieves the concentrated value.

The adaptive ordered-vs-set selection works as follows:

1. For each surprised Walkable field (e.g., `cipher_order`), identify both candidates:
   - Ordered: `tls_cipher_hash` (the exact ordering of cipher suites)
   - Set: `tls_cipher_set` (sorted, order-independent cipher suites)
2. Check if the *ordered* version shows high concentration (>40%) in the FieldTracker
3. If yes: use the ordered field for maximum specificity (attacker uses fixed order)
4. If no: fall back to the set field (attacker randomizes order, but uses the same set)

This makes rule generation adaptive: it catches both fixed-order bots (curl, python-requests) and sophisticated randomizers (bot_shuffled) with the same code path.

### EDN Rule Syntax

Rules are rendered in EDN (Extensible Data Notation), matching veth-lab's s-expression format:

```clojure
;; Single constraint
(rule
  (and
    (= path-prefix "/api/search"))
  (rate-limit :rps 200))

;; Compound TLS rule (set-based, order-independent)
(rule
  (and
    (= tls-cipher-set "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256")
    (= tls-ext-set "server_name,supported_groups,ec_point_formats,..."))
  (rate-limit :rps 200))
```

## Rule Engine

### Rete-Spirit DAG

Rules are compiled into a discrimination tree — a directed acyclic graph where each level corresponds to one field dimension. The `DIM_ORDER` controls traversal order, placing primary discriminators first:

```
DIM_ORDER: [SrcIp, TlsGroupHash, TlsCipherHash, TlsExtOrderHash,
            TlsCipherSet, TlsExtSet, TlsGroupSet,
            Method, PathPrefix, Host, UserAgent, ContentType]
```

At each level, the tree branches on the field's value. Rules that don't constrain a dimension follow the wildcard path. Evaluation walks the tree depth-first, checking specific children first, then wildcards.

The compiled tree is stored behind an `ArcSwap<CompiledTree>`:
- **Proxy** reads via `ArcSwap::load()` — wait-free, no locking, no contention
- **Sidecar** writes via `ArcSwap::store()` — brief pointer swap, proxy sees the new tree on next request

### Rule Lifecycle

1. **Generation**: Detection pipeline produces `Vec<Detection>` (field/value/rate_factor)
2. **Compilation**: `compile_compound_rule()` creates a `RuleSpec` (constraints + action)
3. **Redundancy check**: `RuleManager::is_redundant()` rejects subsumed or over-broad rules
4. **Upsert**: Rule added to active set with last-seen timestamp
5. **Deploy**: All active rules compiled to a new `CompiledTree`, atomically swapped
6. **Expire**: Rules not refreshed within TTL (300s) are removed

Engram rules follow the same pipeline but skip redundancy checking and recalculate rate limits based on current `baseline_rps`.

## Rate Limiting

Rate limiting uses a per-IP token bucket (`RateLimiter` in `enforcer.rs`):

- Each source IP gets its own bucket, capacity = `rps` tokens
- Refills at `rps` tokens/second
- Each request consumes one token; excess requests get 429
- Bucket arithmetic is pure math — the `Mutex` hold time has no I/O or allocation
- Rate limits are dynamically recalculated: engram deployments set `rps = max(baseline_rps, 10)`

This provides true rate limiting (not hard blocking): legitimate traffic up to the baseline rate passes through, only excess is throttled.

## Monitoring Dashboard

The sidecar runs an Axum HTTP server on `:9090` with:

| Endpoint | Purpose |
|----------|---------|
| `GET /` | Real-time dashboard (embedded HTML/JS, served from `static/dashboard.html`) |
| `GET /api/metrics/events` | SSE stream of `DashboardEvent` (metrics, rules, detections) |
| `GET /api/rules` | JSON snapshot of active rules with age |
| `GET /metrics` | Legacy JSON stats blob |
| `GET /health` | Health check |

The dashboard uses **Server-Sent Events (SSE)** for real-time streaming via `tokio::sync::broadcast`. Events are emitted every tick (~200 requests or 500ms):

- `Metrics`: enforcement counts, detection scores, thresholds, RPS, streaks, engram counts
- `RuleEvent`: rule added/expired/engram-deployed with EDN summary
- `DetectionEvent`: anomaly confirmed, engram hit, engram minted, attack ended

The frontend renders two **uPlot** charts (enforcement rates and detection scores vs. thresholds), header metrics, detection state, active rules, and a unified event log. All panels are bounded — the event log and rules list have max-height with scroll, and the timeline uses a 120-second time-based window.

## Performance Considerations

- **No proxy blocking**: The proxy never waits for the sidecar. `try_send` drops samples when the channel is full (capacity 512). The proxy's hot path is: `ArcSwap::load()` → DAG walk → token bucket check → respond.
- **No async lock in drain loop**: Stats are updated in a single `stats.write().await` after draining, not per-sample. This eliminated a 14-second stall regression caused by `RwLock` contention.
- **Drain cap**: The sidecar drains at most 512 samples per pass to keep ticks responsive during bursts.
- **Tick hybrid trigger**: Fires on sample count (200) or elapsed time (500ms), preventing both starvation at low volume and lag at high volume.
- **Decay is lazy**: `ValueStats` tracks a `last_decay_req` counter and applies decay on read, avoiding per-request exponentiation across all tracked values.

## Crate Dependencies

```
runner (binary: http-proxy)
  ├── proxy (lib: http_proxy)
  │     └── holon-rs
  └── sidecar (lib: http_sidecar)
        ├── proxy (for shared types)
        └── holon-rs

generator (binary: http-generator)
  └── proxy (for TlsContext, shared types)
```

The `runner` crate exists to avoid circular dependencies: `proxy` defines types, `sidecar` depends on proxy types, and `runner` links both into a single binary.
