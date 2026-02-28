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
│  ├─ Enforcer: load ExprCompiledTree from ArcSwap (wait-free)            │
│  │    ├─ Walk DAG with request field values (best-match evaluator)      │
│  │    ├─ Returns (Verdict, Option<rule_id>)                             │
│  │    ├─ Verdict: Pass / Block(403) / RateLimit(rps) / CloseConnection  │
│  │    ├─ If RateLimit: check per-IP token bucket                        │
│  │    └─ If rule matched: increment per-rule counter                    │
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

Rules are rendered in EDN (Extensible Data Notation), a composable s-expression format. The full language specification is in `RULE-LANGUAGE.md`. Live-generated rules from the detection pipeline:

```clojure
;; HTTP path concentration (auto-generated from FieldTracker)
{:constraints [(= path "/api/search")]
 :actions     [(rate-limit 83)]}

;; Cross-layer TLS+HTTP compound rule (auto-generated from surprise + concentration)
{:constraints [(= path "/api/v1/auth/login")
               (= method "POST")
               (= (first (header "content-type")) "application/json")]
 :actions     [(rate-limit 83)]}

;; TLS fingerprint with set-based matching (order-independent)
{:constraints [(= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"})
               (= tls-ciphers #{"0x00ff" "0x1301" "0x1302" "0x1303" "0xc02b" "0xc02c" "0xc02f" "0xc030" "0xcca8" "0xcca9"})
               (= tls-groups #{"0x0017" "0x0018" "0x001d"})]
 :actions     [(rate-limit 83)]}

;; Cross-layer HTTP+TLS (auto-generated: REQ concentration + TLS surprise in same tick)
{:constraints [(= method "POST")
               (= (first (header "content-type")) "application/json")
               (= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"})]
 :actions     [(rate-limit 83)]}
```

Dimension accessors compose: `(first (header "content-type"))` extracts the first value of the `Content-Type` header. This is not a special-cased field — any header, cookie, or query parameter can be targeted with the same composition functions.

## Rule Engine

### Rete-Spirit DAG

Rules are compiled into a discrimination tree — a directed acyclic graph where each level corresponds to one field dimension. The `DIM_ORDER` controls traversal order, placing primary discriminators first:

```
DIM_ORDER: [SrcIp, TlsGroupHash, TlsCipherHash, TlsExtOrderHash,
            TlsCipherSet, TlsExtSet, TlsGroupSet,
            Method, PathPrefix, Host, UserAgent, ContentType]
```

At each level, the tree branches on the field's value. Rules that don't constrain a dimension follow the wildcard path.

### Best-Match Evaluation

Evaluation walks the tree depth-first, exploring **both** specific and wildcard branches at every level. When multiple terminal nodes match, the evaluator selects the most specific match using a structured `Specificity` ranking:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Specificity {
    pub layers: u8,       // cross-layer (TLS+HTTP = 2) > single (1) > none (0)
    pub has_http: u8,     // HTTP constraints (1) preferred over TLS-only (0)
    pub constraints: u8,  // more constraints = narrower match
}
```

The `Specificity` struct derives `Ord`, giving lexicographic comparison over its fields. Each field is an independent policy rule:

1. **layers**: Cross-layer rules (TLS+HTTP) always beat single-layer rules, regardless of constraint count. Correlating signals across protocol boundaries is the strongest evidence of a specific attacker.
2. **has_http**: At the same layer count, HTTP constraints (path, method, user-agent) are more actionable than TLS-only constraints. This breaks the tie between an HTTP-only rule and a TLS-only rule with the same number of constraints.
3. **constraints**: More constraints = narrower match = higher priority. A rule matching `method + path + user-agent` is more surgical than one matching only `method`.

This replaces the previous `specific.or(wildcard)` short-circuit, which would always prefer the specific branch even when the wildcard branch led to a more constrained (and more surgical) terminal rule.

Adding a new tiebreaker is a one-line field insertion into the struct — no arithmetic changes, no multiplier rebalancing.

### Per-Rule Counters

Every time a rule matches a request, the proxy increments a global counter (`Mutex<HashMap<u32, u64>>`) keyed by rule ID. Each sidecar tick, the counters are snapshotted, joined with the tree's `rule_labels` map (populated during compilation with `constraints_sexpr()` and action descriptions), and broadcast as a `RuleCounters` SSE event. The dashboard computes per-rule rates and overlays the top-5 rules as dashed lines on the enforcement chart.

The compiled tree is stored behind an `ArcSwap<ExprCompiledTree>`:
- **Proxy** reads via `ArcSwap::load()` — wait-free, no locking, no contention
- **Sidecar** writes via `ArcSwap::store()` — brief pointer swap, proxy sees the new tree on next request

### Rule Lifecycle

1. **Generation**: Detection pipeline produces `Vec<Detection>` (field/value/rate_factor)
2. **Compilation**: `compile_compound_rule_expr()` creates a `RuleExpr` with composable constraints (e.g., `(= (first (header "user-agent")) "python-requests/2.31.0")`)
3. **Redundancy check**: `RuleManager::is_redundant()` rejects subsumed or over-broad rules
4. **Upsert**: Rule added to active set with last-seen timestamp
5. **Deploy**: All active rules compiled to a new `ExprCompiledTree` via `compile_expr()`, atomically swapped
6. **Expire**: Rules not refreshed within TTL (300s) are removed

Engram rules are serialized as EDN strings (not JSON structs), enabling human-readable engram metadata and round-trip fidelity through `parse_edn()` / `to_edn()`. On re-detection, stored EDN rules are parsed back into `RuleExpr` values, rate limits recalculated to current `baseline_rps`, and deployed through the same pipeline.

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
- `RuleCounters`: per-rule hit counts with labels and actions, used for rate computation
- `DagSnapshot`: full rule tree serialized as nodes/edges for DAG visualization

The frontend renders:
- **Enforcement chart** (uPlot): passed/rate-limited/blocked rates + top-5 per-rule rates as dashed overlay lines
- **Detection chart** (uPlot): TLS/REQ anomaly scores vs. adaptive thresholds
- **DAG panel**: interactive rule tree visualization with tooltips showing full EDN rule expressions (Clojure-formatted)
- **Legend overlays**: series names in kebab-case, per-rule section with constraint labels, action badges, and rates (capped at 75% width)
- **Active rules** and **event log** panels (bounded, scrollable)
- 120-second time-based timeline window

## Performance Considerations

- **No proxy blocking**: The proxy never waits for the sidecar. `try_send` drops samples when the channel is full (capacity 512). The proxy's hot path is: `ArcSwap::load()` → DAG walk → token bucket check → respond.
- **No async lock in drain loop**: Stats are updated in a single `stats.write().await` after draining, not per-sample. This eliminated a 14-second stall regression caused by `RwLock` contention.
- **Drain cap**: The sidecar drains at most 512 samples per pass to keep ticks responsive during bursts.
- **Tick hybrid trigger**: Fires on sample count (200) or elapsed time (500ms), preventing both starvation at low volume and lag at high volume.
- **Decay is lazy**: `ValueStats` tracks a `last_decay_req` counter and applies decay on read, avoiding per-request exponentiation across all tracked values.

## Rule Tree Performance (Benchmarked)

The expression tree (`ExprCompiledTree`) was stress-tested across rule counts (100 to 1M) and constraint complexity (1 to 6 dimensions), using randomized rules with unique per-rule rate limits and correctness verification at every point. Results from release builds (February 2026).

### Evaluation Latency by Complexity (100K rules)

Rules range from 1 constraint (src-ip only) to 6 constraints spanning both TLS and HTTP layers (src-ip + method + path-prefix + user-agent + content-type + sni):

```
 dims   layers    compile    nodes    hit p50    hit p99    miss p50    evals/s
 ────   ──────    ───────    ─────    ───────    ───────    ────────    ───────
    1     HTTP      227ms   100001      669ns     1139ns       116ns    1.5M/s
    2     HTTP      195ms   100006      756ns     1336ns        50ns    1.3M/s
    3     HTTP      246ms   100006      737ns     1367ns        48ns    1.4M/s
    4     HTTP      293ms   100037     1282ns     2245ns        63ns    780K/s
    5     HTTP      395ms   100096     1482ns     2731ns        48ns    675K/s
    6  TLS+HTTP     516ms   100146     1800ns     3400ns        46ns    556K/s
```

Evaluation cost scales with tree **depth** (number of constraint dimensions), not rule count. Each level is one HashMap lookup. The jump at 4-dim comes from header accessor extraction (`(first (header "user-agent"))`) which involves a linear scan of the headers list — still under 2µs.

### Evaluation Latency by Scale (fixed complexity)

Holding complexity constant and scaling rules from 100 to 1M:

```
2-dim (ip + method)                        4-dim (ip + method + path + ua)
─────────────────────────────────────      ─────────────────────────────────────
  rules    compile    hit p50  miss p50      rules    compile    hit p50  miss p50
    100       0ms      379ns     60ns          100       0ms      724ns     63ns
  1,000       1ms      526ns     65ns        1,000       8ms      997ns     76ns
 10,000      20ms      816ns     70ns       10,000      35ms     1323ns     65ns
100,000     318ms      960ns     71ns      100,000     335ms     1411ns     70ns
500,000    1805ms     1154ns     65ns      500,000    2330ms     1689ns     72ns
  1,000K   3160ms     1109ns     53ns        1,000K   4263ms     1875ns     50ns

6-dim (ip + method + path + ua + ct + sni)
─────────────────────────────────────────
  rules    compile    hit p50  miss p50
    100       3ms     1527ns     41ns
  1,000       4ms     1670ns     48ns
 10,000      55ms     1636ns     43ns
100,000     494ms     1921ns     40ns
500,000    2788ms     2114ns     38ns
  1,000K   5881ms     2573ns     48ns
```

Hit latency stays nearly flat as rules scale 10,000x. Miss latency is ~50ns regardless (falls through the root immediately). A single core at 6-dim complexity evaluates **~390K rules/sec** against a million-rule tree. At 2-dim, it exceeds **900K/sec**.

### Mixed-Complexity Workload (100K rules)

Simulates a realistic deployment with rules of varying specificity (10% 1-dim, 25% 2-dim, 30% 3-dim, 20% 4-dim, 10% 5-dim, 5% 6-dim):

```
 target    rules    hit p50    hit p99    miss p50    correct
 ──────    ─────    ───────    ───────    ────────    ───────
  1-dim    10000     1454ns     2676ns       124ns    2000/2000
  2-dim    25000     1633ns     3004ns       124ns    2000/2000
  3-dim    30000     1543ns     2682ns       126ns    2000/2000
  4-dim    20000     1754ns     2846ns       122ns    2000/2000
  5-dim    10000     2044ns     3387ns       122ns    2000/2000
  6-dim     5000     2353ns     4078ns       122ns    2000/2000
```

All tiers achieve 100% correctness. A 16-core host could evaluate **~6M+ requests/sec** against a 100K mixed-complexity rule tree — well above any realistic HTTP throughput. This makes fully inline evaluation (no sampling) viable.

### Compilation Cost

Compilation is O(n) — each rule is touched once per dimension level:

```
 complexity    100     1K      10K     100K      500K      1M
 ──────────   ────   ─────   ─────   ──────   ──────   ──────
    2-dim      0ms     1ms    20ms    318ms    1.8s     3.2s
    4-dim      0ms     8ms    35ms    335ms    2.3s     4.3s
    6-dim      3ms     4ms    55ms    494ms    2.8s     5.9s
```

In practice, the detection system produces tens of rules per attack wave, making compilation sub-millisecond. The ArcSwap atomic flip means the proxy never blocks during recompilation.

### Optimizations Applied

- **Zero-clone recursion**: `compile_recursive` borrows rules (`&[&RuleExpr]`) instead of deep-cloning at each tree level. Only the winning action at terminal nodes is cloned.
- **Lightweight dim ordering**: `compute_dim_order` counts rules per dimension instead of collecting all unique values — eliminates a million-entry HashMap.
- **Hash-based fingerprint**: FNV hash over sorted rule identity hashes instead of concatenating and sorting 1M identity key strings.
- **Lazy labels**: `rule_labels` computed on demand rather than eagerly for every rule at compilation.
- **Cow canonical keys**: `canonical_key_cow()` borrows for the common `Value::Str` case, reducing heap allocations during tree grouping.

These optimizations brought 1M-rule compilation from ~8.3s to 3.3s (release) for 2-dim rules, matching veth-lab's eBPF tree compiler.

### Why This Matters

Traditional WAF engines evaluate rules sequentially — O(n) per request, often involving regex matching against each rule's pattern. Adding rules linearly degrades throughput. The expression tree eliminates this entirely: rules are compiled into a discrimination DAG where evaluation is a fixed number of hash lookups (one per constraint dimension). At runtime, no rule is ever "checked" — the request's field values are hashed and used to navigate directly to the matching terminal node.

The miss path makes this concrete: ~50ns regardless of tree size. A non-matching request does a single hash miss at the root and returns immediately. No rule was consulted. Even the most complex 6-dimension cross-layer rule (TLS fingerprint + method + path + user-agent + content-type + SNI) evaluates in under 2.6µs at 1M rules — faster than a single PCRE regex match in most production WAF engines. This is what makes fully inline enforcement viable without sampling: the evaluation cost is determined by the expressiveness of the rule language (number of dimensions), not the number of rules deployed.

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
