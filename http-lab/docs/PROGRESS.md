# http-lab Progress

**Status:** All attack types mitigated — GET floods, credential stuffing, scrapers, TLS-randomized floods
**Date:** February 2026
**Latest Update:** February 26, 2026
**Result:** Autonomous L7 WAF with dual-tier VSA detection, adaptive TLS rule generation, engram memory, per-IP rate limiting, and real-time monitoring dashboard
**Key Achievement:** Adaptive TLS detection — dynamically selects ordered or set-based constraints based on attacker behavior concentration. Full mitigation of randomized TLS attacks without hardcoded patterns.

## Overview

L7 WAF lab — HTTP flood DDoS detection and mitigation via TLS-terminating reverse
proxy + holon-rs sidecar running a Rete-spirit rule engine. Mirrors veth-lab structure
and philosophy at Layer 7. Built in three days of after-hours work.

## Phase 1: DDoS

### Component Status

| Component | Status | Notes |
|-----------|--------|-------|
| proxy/src/types.rs | Done | TlsContext (lossless), RequestSample (structured), rule types, EDN output |
| proxy/src/tls.rs | Done | ClientHello parser + ReplayStream + tokio-rustls handshake |
| proxy/src/tls_names.rs | Done | Human-readable TLS name lookups (cipher suites, extensions, groups, etc.) |
| proxy/src/http.rs | Done | Hyper HTTP/1.1 + upstream forwarding + sample enqueue + rate limit enforcement |
| proxy/src/tree.rs | Done | Rete-spirit DAG compiler (12 dimensions, String keys) |
| proxy/src/enforcer.rs | Done | ArcSwap rule check + per-IP token bucket rate limiter |
| runner/src/main.rs | Done | Binary: spawns proxy + sidecar, wires ArcSwap + channels + rate limiter |
| sidecar/src/detectors.rs | Done | SubspaceDetector (tunable params) + EngramLibrary wrappers |
| sidecar/src/detection.rs | Done | Detection → RuleSpec compilation (12 field dimensions) |
| sidecar/src/field_tracker.rs | Done | Per-field value tracking with decay, baseline freezing, concentration detection |
| sidecar/src/rule_manager.rs | Done | Upsert, expire, redundancy check, compile, ArcSwap write |
| sidecar/src/lib.rs | Done | Dual detection loops (TLS + REQ), concentration + surprise rule gen, engram memory |
| sidecar/src/metrics_server.rs | Done | Axum SSE dashboard, /api/rules, /api/metrics/events, /metrics, /health |
| sidecar/static/dashboard.html | Done | Real-time UI: uPlot charts, detection state, rules, event log |
| generator/src/main.rs | Done | Multi-phase HTTP flood with 5 TLS profiles, status code tracking |
| scenarios/multi_attack.json | Done | 15-phase scenario: 4 attacks + 4 replays + warmup/lull/cooldown |
| scripts/ | Done | build.sh, setup.sh, demo.sh, teardown.sh |

### Phase 1a — Working Proxy (no rules) COMPLETE

- [x] `types.rs` — TlsContext, ConnectionContext, RequestSample, rule types, CompiledTree
- [x] `tls.rs` — Raw ClientHello parser, TlsContext → holon Vector, tokio-rustls handshake
- [x] `http.rs` — Hyper HTTP/1.1 server, upstream forwarding, sample enqueue
- [x] `runner/main.rs` — TLS accept loop, spawns sidecar tasks in-process
- [x] `setup.sh` — start mock backend (python http.server)
- [x] `build.sh` — cargo build wrapper

**Result**: working TLS-terminating reverse proxy that parses ClientHello and logs TlsContext per connection.

### Phase 1b — Detection + Rules COMPLETE

- [x] `tree.rs` — Rete-spirit DAG compiler for HTTP dimensions
- [x] `enforcer.rs` — synchronous rule check via ArcSwap on every request
- [x] `sidecar/detectors.rs` — SubspaceDetector, EngramLibrary wrappers
- [x] `sidecar/detection.rs` — Detection → RuleSpec compilation
- [x] `sidecar/field_tracker.rs` — per-field value tracking with decay
- [x] `sidecar/rule_manager.rs` — upsert, expire, compile, redundancy check, ArcSwap write
- [x] `sidecar/lib.rs` — dual detection loops (TLS + request), ArcSwap wiring
- [x] `sidecar/metrics_server.rs` — axum /metrics + /health
- [x] `runner/main.rs` updated — spawns sidecar tasks, wires ArcSwap + channels

**Result**: proxy detects anomalies and enforces auto-generated rules.

### Phase 1c — Generator + Demo COMPLETE

- [x] `generator/` — scenario-driven HTTP flood with named TLS profiles
- [x] `demo.sh` — end-to-end: warmup → GET flood → calm → detection → mitigation
- [x] `scenarios/ddos-demo.json` — reference scenario file

**Result**: reproducible DDoS detection demo.

### Phase 1d — Rich Data Model + EDN Rules COMPLETE

- [x] `types.rs` — Rich `TlsContext` with named cipher suites, extensions, groups via `tls_names.rs`
- [x] `types.rs` — Rich `RequestSample` with path_parts, query_params, query_flags, header pairs in wire order
- [x] `types.rs` — Walkable implementations for both TlsContext and RequestSample
- [x] `types.rs` — `Predicate` enum uses `String` values (not FNV-1a hashes)
- [x] `types.rs` — `RuleSpec::to_edn_pretty()` and `to_edn_compact()` for human-readable rule output
- [x] `tree.rs` — `TreeNode` HashMap keys changed from `u32` to `String`
- [x] `tls_names.rs` — 100+ cipher suite, 50+ extension, 20+ group name mappings with hex fallback

**Result**: rich, structured data representations that preserve full request fidelity. Human-readable EDN rules like `(= tls-cipher-set "TLS_AES_128_GCM_SHA256,...")`.

### Phase 1e — Detection Pipeline Alignment with veth-lab COMPLETE

- [x] Individual sample scoring (no bundling/averaging)
- [x] Hybrid tick trigger: fires on 200 samples OR 500ms (whichever first)
- [x] Per-sample exponential decay (half-life=500 requests)
- [x] Per-tick max-residual tracking drives anomaly decisions
- [x] Two-tier detection: SubspaceDetector anomaly + EngramLibrary fast-path
- [x] `SubspaceDetector::with_subspace_params()` for per-detector tuning
- [x] TLS detector tuned separately: `ema_alpha=0.05` (5x faster), `sigma_mult=2.0` (tighter)
- [x] Baseline RPS tracking during warmup for rate limit calculation
- [x] FieldTracker baseline freezing at warmup completion

**Result**: detection pipeline matches veth-lab's proven approach, adapted for HTTP's different traffic characteristics (per-connection TLS vs per-request HTTP, different sample volumes).

### Phase 1f — Rate Limiting + Engram Memory COMPLETE

- [x] `enforcer.rs` — Per-IP token bucket `RateLimiter` (true rate limiting, not hard block)
- [x] `http.rs` — Integrated rate limiter: check `allow()` before forwarding, 429 on excess
- [x] `lib.rs` — Rate factor calculation: `baseline_rps / estimated_rps` (veth-lab approach)
- [x] `lib.rs` — Engram minting with surprise fingerprint + active rules stored as metadata
- [x] `lib.rs` — Engram deployment: deserialize stored `RuleSpec`, recalculate rate limits to current baseline
- [x] `lib.rs` — Concentration-based rule generation: `find_concentrated_values(0.5)` replaces raw surprise for REQ rules
- [x] `lib.rs` — FieldTracker baseline freezing: concentrated values during warmup excluded from attack attribution
- [x] Engram persistence: load/save to disk as JSON

**Result**: true per-IP rate limiting (allows baseline RPS, 429s excess). Engram memory enables sub-tick rule deployment on re-detected attacks with dynamically recalculated rate limits.

### Phase 1g — Multi-Attack Scenarios + TLS Randomization COMPLETE

- [x] `scenarios/multi_attack.json` — 15-phase scenario covering 4 attack types + replay waves
- [x] `generator/` — `bot_shuffled` TLS profile: consistent cipher/extension values in random order
- [x] `types.rs` — Set-based TLS fields: `cipher_set_string()`, `ext_set_string()`, `group_set_string()` (sorted, order-independent)
- [x] `types.rs` — New `FieldDim` variants: `TlsCipherSet`, `TlsExtSet`, `TlsGroupSet`
- [x] `lib.rs` — Adaptive ordered-vs-set TLS rule generation via `tls_field_candidates()` + `get_tls_field_top_value()`
- [x] `lib.rs` — Deduplication of TLS constraints (prevents both ordered and set versions of same field)
- [x] `lib.rs` — TLS rules use `RateLimit` action (not `CloseConnection`)
- [x] `detection.rs` — Set-based field mappings in `to_predicate()` and `StoredRule::to_rule_spec()`

**Result**: all attacks mitigated including TLS-randomized floods. The system adaptively selects ordered or set-based constraints based on observed concentration — no hardcoded patterns.

### Phase 1h — Real-Time Monitoring Dashboard COMPLETE

- [x] `metrics_server.rs` — `DashboardEvent` enum (Metrics, RuleEvent, DetectionEvent, Heartbeat)
- [x] `metrics_server.rs` — SSE streaming via `tokio::sync::broadcast`
- [x] `metrics_server.rs` — `/api/rules` endpoint with `RuleSummary` (EDN, action, age)
- [x] `static/dashboard.html` — Real-time UI with SSE auto-reconnect
- [x] Dashboard: uPlot charts for enforcement rates and detection scores vs thresholds
- [x] Dashboard: header metrics (RPS, tick, enforcement counts)
- [x] Dashboard: detection state panel (TLS + REQ scores, thresholds, streaks, engrams)
- [x] Dashboard: active rules panel with EDN display (bounded, scrollable)
- [x] Dashboard: unified event log (bounded, scrollable)
- [x] Dashboard: 120-second time-based timeline window
- [x] `lib.rs` — SSE event emission for rule adds, engram deploys, detections, attacks ending

**Result**: real-time monitoring dashboard at `http://localhost:9090/` showing enforcement, detection, rules, and events.

### Phase 1i — Performance Optimization COMPLETE

- [x] Eliminated 14-second stall caused by `stats.write().await` inside inner drain loop
- [x] Consolidated all stats updates to single lock acquisition after drain
- [x] Drain loop capped at 512 samples per pass
- [x] Sample channel capacity reduced from 4096 to 512 (prevents sidecar lag during rate transitions)
- [x] Generator status code tracking (2xx, 403, 429, other) for accurate load measurement

**Result**: consistent sub-second tick times, no stalls during rule deployment or high traffic.

## Key Decisions

### 2026-02-23

- Same-process architecture (sidecar is a lib, proxy binary owns everything via `runner` crate)
- Full ClientHello parser from day one — parse raw bytes before handing to rustls
- TlsContext (not "fingerprint") — lossless, ordered, raw extension bytes preserved
- RequestSample headers: Vec<(String,String)> — wire order, duplicates preserved
- Proxy always acts synchronously (ArcSwap::load); sidecar enqueue is try_send (drop on full)
- Body inspection deferred to phase 2
- `runner` crate added as binary to avoid circular dep: proxy lib ← sidecar lib ← runner bin

### 2026-02-24

- Switched from FNV-1a hashes to String keys in Predicate/TreeNode — HTTP is clear-text, readability matters
- EDN syntax for rules (matching veth-lab) — `(= path-prefix "/api/search")` instead of opaque hashes
- Individual sample scoring (not bundled/averaged) — aligned with veth-lab's proven approach
- Concentration-based field attribution — surprise alone produces overly specific rules, concentration identifies the dominant signal
- TLS detector gets separate tuning params — lower sample volume needs faster convergence and tighter thresholds
- `baseline_rps` tracked during warmup — used as the anchor for rate limit calculations
- FieldTracker baseline freeze — prevents flagging always-dominant values during attacks
- Per-IP token bucket for true rate limiting — allows baseline rate through, 429s excess

### 2026-02-25

- Stall root cause identified as `RwLock` contention in drain loop — moved stats writes outside hot path
- SSE dashboard architecture — broadcast channel for fan-out, no polling overhead
- Detection state split into TLS and REQ panels in dashboard
- Time-based timeline trimming (120s window) instead of fixed point count

### 2026-02-26

- Set-based TLS fields (cipher_set, ext_set, group_set) for order-independent detection
- Adaptive ordered-vs-set selection: check concentration of ordered version first, fall back to set
- Deduplication of TLS constraints — prevents conflicting AND conditions in compound rules
- TLS rules switched from CloseConnection to RateLimit — rate limiting is more proportional
- TLS_FIELDS aligned with actual Walkable field names — surprise fingerprint was attributing to wrong fields

## Performance Observations

- Python mock backend is the throughput bottleneck — proxy serves 429s much faster than forwarding to origin (Rust vs Python, expected)
- During non-attack periods, RPS is choppy (~100) limited by backend. During mitigated attacks, proxy handles 1000+ rps easily since most are 429s
- Sample channel capacity of 512 balances sidecar responsiveness vs sample coverage during burst transitions
- Tick time consistently <100ms even at 2000 rps attack load (after stall fixes)
- Engram re-detection deploys rules in 1 tick vs 3+ ticks for first-time detection

## Resolved Questions

- **Rate-limit granularity**: Per-IP with dynamic RPS based on baseline. Works well — different IPs get independent buckets.
- **Warmup duration**: 500 REQ samples (20-30s at 80 rps baseline). Sufficient for HTTP traffic diversity.
- **ArcSwap vs RwLock**: ArcSwap confirmed as correct choice. RwLock in the stats path caused the only serious performance regression.

## Open Questions

- Query string structure for detection — how to handle malformed/double query strings as attack signals?
- Path ngram analysis — path_parts are captured but not yet used for detection dimensions
- Header ordering as detection signal — captured in RequestSample but not yet encoded into detection fields
- Connection-level metrics (requests per connection, connection duration) for slow-loris type attacks

## Phase 2 (Future)

- Body inspection (streaming windowed VSA, PayloadSubspaceDetector)
- Exploit detection: SQLi, XSS, path traversal
- Connection RST via SO_LINGER
- JA4 string output for external tool correlation
- XDP integration for kernel-level enforcement (shared rule tree with veth-lab)
- Path ngram dimensions for directory traversal / enumeration detection
- Header ordering dimension for HTTP fingerprinting
- Geo-IP integration for geographic anomaly detection
- Rule confidence scoring and automatic threshold adjustment
