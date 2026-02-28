# http-lab Progress

**Status:** All attack types mitigated — GET floods, credential stuffing, scrapers, TLS-randomized floods
**Date:** February 2026
**Latest Update:** February 28, 2026
**Result:** Autonomous L7 WAF with VSA surprise-driven rule generation, composable rule expression language, Rete-spirit DAG compiler achieving sub-microsecond evaluation at million-rule scale, three-layer field attribution (concentration + surprise probing + shape detection), engram memory with resilient fast-path deployment, per-IP rate limiting, best-match specificity evaluator, per-rule counters, and real-time monitoring dashboard
**Key Achievement:** The system autonomously generates surgical, compound rules from raw traffic — no signatures, no training data, no human rules. VSA surprise probing discovers per-header, per-path-segment, and per-shape signals. Rules like `{path + user-agent + (nth path-parts 1) + (count (nth path-parts 2))}` are generated fully autonomously. Every attack in a 7-wave scenario (GET floods, credential stuffing, scrapers, TLS-randomized floods, replays) is mitigated. Expression tree evaluation is O(tree depth), not O(rule count). 1M rules evaluate in ~1.1µs to ~2.6µs. Miss path: ~50ns.

## Overview

L7 WAF lab — HTTP flood DDoS detection and mitigation via TLS-terminating reverse
proxy + holon-rs sidecar running a Rete-spirit rule engine. Mirrors veth-lab structure
and philosophy at Layer 7. Built in three days of after-hours work.

## Phase 1: DDoS

### Component Status

| Component | Status | Notes |
|-----------|--------|-------|
| proxy/src/types.rs | Done | TlsContext (lossless), RequestSample (structured), rule types, EDN output, Specificity ranking, best-match DFS evaluator |
| proxy/src/tls.rs | Done | ClientHello parser + ReplayStream + tokio-rustls handshake |
| proxy/src/tls_names.rs | Done | Human-readable TLS name lookups (cipher suites, extensions, groups, etc.) |
| proxy/src/http.rs | Done | Hyper HTTP/1.1 + upstream forwarding + sample enqueue + rate limit enforcement |
| proxy/src/expr.rs | Done | Composable rule expression language: RuleExpr, Expr, Dimension (26 fields), Operator (13 ops), Value types, EDN parser/serializer, dimension extraction |
| proxy/src/expr_tree.rs | Done | Expression tree compiler: Rete-spirit DAG from RuleExpr, O(depth) evaluation, zero-clone compilation, dynamic dim ordering, guard predicates |
| proxy/src/tree.rs | Done | Legacy DAG compiler (12 dimensions, String keys), specificity scoring, rule labels |
| proxy/src/enforcer.rs | Done | ExprCompiledTree rule check + per-IP token bucket rate limiter, returns (Verdict, rule_id) |
| runner/src/main.rs | Done | Binary: spawns proxy + sidecar, wires ArcSwap + channels + rate limiter |
| sidecar/src/detectors.rs | Done | SubspaceDetector, EngramLibrary, drilldown_probe, SurpriseHistory, ProbeTarget, DetectionKind |
| sidecar/src/detection.rs | Done | Detection → RuleExpr: surprise_to_expr, merge_detections_to_exprs, compile_merged_rule_expr |
| sidecar/src/field_tracker.rs | Done | Per-field value tracking with decay, baseline freezing, concentration detection |
| sidecar/src/rule_manager.rs | Done | Upsert, expire, redundancy check, compile_expr, ArcSwap<ExprCompiledTree> write |
| sidecar/src/lib.rs | Done | Dual detection loops (TLS + REQ), concentration + surprise rule gen, engram memory with EDN serialization |
| sidecar/src/metrics_server.rs | Done | Axum SSE dashboard, /api/rules, /api/metrics/events, /metrics, /health, RuleCounters + DagSnapshot events |
| sidecar/static/dashboard.html | Done | Real-time UI: uPlot charts, DAG viz, per-rule counters, detection state, rules, event log |
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
- [x] `lib.rs` — Engram deployment: parse stored EDN rules via `parse_edn()`, recalculate rate limits to current baseline
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

### Phase 1j — Dashboard UX: DAG Visualization, Legends, Tooltips COMPLETE

- [x] Dashboard: 2/3 + 1/3 grid layout — charts on left, DAG panel spanning both chart rows on right
- [x] Dashboard: uPlot timestamp x-axis and legend overlays with series names, colors, current values
- [x] Dashboard: hover tooltips on chart data points with detailed values
- [x] Dashboard: DAG canvas ported from veth-lab — tree layout, edge rendering, mouse interaction
- [x] Dashboard: bottom row split 1/2 + 1/2 for Active Rules and Event Log panels
- [x] `types.rs` — `CompiledTree::to_dag_nodes()` serializes rule tree into `DagNode`/`DagEdge` structs
- [x] `metrics_server.rs` — `DagSnapshot` SSE event broadcasts tree state on every recompile
- [x] `lib.rs` — `broadcast_dag()` helper + DAG JSON logging to disk for debugging

**Result**: real-time rule tree visualization with interactive tooltips showing node details and ancestry.

### Phase 1k — Tree Compiler Fix + DAG Polish COMPLETE

- [x] `tree.rs` — Fixed combinatorial explosion: wildcard rules no longer duplicated into specific branches (pure DAG, matching veth-lab)
- [x] `types.rs` — Terminal nodes labeled `"terminal"` instead of inheriting last dimension name
- [x] Dashboard: two-pass pruning (dead-end leaf removal + wildcard chain collapse) with post-pruning connectivity check
- [x] Dashboard: terminal nodes rendered as orange diamonds (distinct from circle branch nodes)
- [x] Dashboard: canvas coordinate scaling fix — mouse-to-canvas transform accounts for CSS/buffer size mismatch
- [x] Dashboard: bounding-box hit detection (consistent for all node shapes)
- [x] Dashboard: `buildRuleExpression()` walks ancestry to reconstruct full EDN rule string on terminal tooltips
- [x] Dashboard: pretty-printed Clojure-style EDN rule display in tooltips
- [x] Dashboard: wildcard edges rendered with brighter dashed lines for visibility

**Result**: clean, readable rule tree with proper branching. Terminal tooltips show the full rule in EDN format. Node count reduced from 107 to 42 raw nodes (22 after pruning) for a 6-rule tree.

### Phase 1l — Per-Rule Counters + Legend Polish COMPLETE

- [x] `types.rs` — `evaluate_req`/`evaluate_tls` now return `(action, rule_id)` — rule_id threaded through DFS
- [x] `lib.rs` (proxy) — Global `RULE_COUNTERS` map: `increment_rule_counter(rule_id)` called on every match
- [x] `tree.rs` — `CompiledTree.rule_labels` map populated during compilation: rule_id → (constraints_sexpr, action)
- [x] `metrics_server.rs` — `RuleCounters` SSE event with `Vec<RuleCounter>` (id, label, action, count)
- [x] `lib.rs` (sidecar) — Counter snapshot joined with tree labels, broadcast each tick
- [x] Dashboard: top-5 rules by rate as dashed lines on enforcement chart
- [x] Dashboard: per-rule legend section with constraint label, action badge, rate
- [x] Dashboard: legend names switched to kebab-case (passed, rate-limited, blocked, tls-score, etc.)
- [x] Dashboard: action labels lowercased (rate-limit, block, close, count, pass)
- [x] Dashboard: rule labels show `constraints_sexpr()` only — no `{:constraints ... :actions ...}` wrapper
- [x] Dashboard: legend capped at 75% panel width to keep latest chart data visible
- [x] Dashboard: chart tooltip allows text wrap for long rule expressions

**Result**: per-rule hit counters with real-time rate computation, overlaid as dashed chart series. Full rule expressions visible in legend and tooltip without truncation.

### Phase 1m — Best-Match Evaluator with Specificity Ranking COMPLETE

- [x] `types.rs` — `Specificity` struct with `derive(Ord)`: lexicographic comparison over named fields
- [x] `types.rs` — `FieldDim::is_tls()` / `is_http()` classify constraint dimensions into layers
- [x] `types.rs` — `pick_best()` selects the match with highest `Specificity` (ties go to specific branch)
- [x] `types.rs` — DFS evaluator explores BOTH specific and wildcard branches, picks best globally (mirrors veth-lab's `best_prio` accumulator)
- [x] `tree.rs` — `specificity_score()` computes `Specificity { layers, has_http, constraints }` per terminal
- [x] Previous behavior: `specific.or(wildcard)` — specific branch always shadows wildcard regardless of rule quality
- [x] New behavior: both branches explored, most surgical match wins

Specificity ranking (lexicographic, each field is an independent policy rule):
1. `layers` — cross-layer (TLS+HTTP = 2) > single-layer (1) > unconstrained (0)
2. `has_http` — HTTP constraints more surgical than TLS-only (1 > 0)
3. `constraints` — more constraints = narrower match

**Result**: cross-layer TLS+HTTP rules now correctly beat single-layer TLS-only rules. HTTP-only rules preferred over TLS-only at same constraint count. Adding a new ranking tiebreaker is a one-line field insertion.

### Phase 1n — Composable Rule Expression Language COMPLETE

- [x] `expr.rs` — `RuleExpr` struct: constraints + action + optional comment/label/name fields
- [x] `expr.rs` — `Expr` constraint type: operator + dimension + value (tier-1 tree-native, tier-2 guard predicates)
- [x] `expr.rs` — `Dimension` enum: `Simple(SimpleDim)` + `Header(name)` + `Cookie(name)` + `Query(name)` + composition functions (`First`, `Last`, `Nth`, `Get`, `Key`, `Val`, `Count`, `Keys`, `Vals`, `SetOf`, `Lower`)
- [x] `expr.rs` — `SimpleDim`: 26 field dimensions (11 HTTP + 15 TLS) covering request line, headers, cookies, query params, path parts, TLS scalar/set/list/map fields
- [x] `expr.rs` — `Operator` enum: `Eq`, `Exists`, `Gt`, `Lt`, `Gte`, `Lte`, `Prefix`, `Suffix`, `Contains`, `Regex`, `Not`, `Subset`, `Superset`
- [x] `expr.rs` — `Value` enum: `Str`, `Num`, `Bool`, `List`, `Set`, `Pair`, `Nil` with canonical key rendering
- [x] `expr.rs` — EDN parser (via `edn-rs` crate): full round-trip `parse_rule_edn()` ↔ `to_edn()` / `to_edn_pretty()`
- [x] `expr.rs` — `RuleAction` enum with structured `name: Option<(String, String)>` (namespace, name) for all variants
- [x] `expr.rs` — Dimension extraction: `extract_from_request()` and `extract_from_tls()` resolve full accessor chains against live protocol data
- [x] `docs/RULE-LANGUAGE.md` — full language specification with examples, dimension catalog, operator reference, composition functions

**Result**: Lisp-like composable rule language with EDN serialization. Rules like `(= (first (header "user-agent")) "python-requests/2.31.0")` and `(exists (set (lower (keys query-params))) "debug")` express arbitrary constraints over TLS and HTTP fields. The language is extensible — new dimensions and operators can be added without changing the grammar or tree compiler.

### Phase 1o — Expression Tree Compiler + Sub-Microsecond Evaluation COMPLETE

- [x] `expr_tree.rs` — `ExprCompiledTree`: Rete-spirit DAG compiled from `Vec<RuleExpr>`, one level per constraint dimension
- [x] `expr_tree.rs` — Dynamic dimension ordering: `compute_dim_order()` ranks dimensions by rule participation count for optimal branching
- [x] `expr_tree.rs` — Dual match modes: `Exact` (single value → HashMap get, O(1)) and `Membership` (collection → iterate + probe, O(|collection|))
- [x] `expr_tree.rs` — Guard predicates: tier-2 operators (prefix, suffix, contains, gt/lt, regex, subset/superset) evaluated as post-match filters on terminal nodes
- [x] `expr_tree.rs` — Best-match DFS evaluator: explores specific + wildcard branches, selects highest `Specificity`
- [x] `expr_tree.rs` — `evaluate_req()` and `evaluate_tls()` for HTTP and TLS-only rule evaluation
- [x] `expr_tree.rs` — Zero-clone compilation: borrows rules (`&[&RuleExpr]`) during recursion, `Cow` canonical keys
- [x] `expr_tree.rs` — FNV hash-based fingerprint for O(1) tree identity comparison
- [x] `expr_tree.rs` — Lazy rule labels: deferred to access time, not computed during compilation
- [x] `proxy/tests/tree_perf.rs` — Comprehensive performance benchmarks: complexity sweep (1–6 dims), scale sweep (100–1M rules), mixed-complexity workload

Performance (release, February 2026):

| Metric | 2-dim @ 1M rules | 6-dim @ 1M rules | Miss (any) |
|--------|-------------------|-------------------|------------|
| eval p50 | 1,109 ns | 2,573 ns | ~50 ns |
| evals/sec/core | 900K+ | 390K+ | — |
| compile time | 3.2s | 5.9s | — |

Evaluation is O(tree depth). 100 rules or 1,000,000 — same number of hash lookups. Miss latency is ~50ns regardless of tree size (single hash miss at root). No rule is ever "checked" at runtime — field values navigate directly to the matching terminal. This is fundamentally different from traditional WAF architectures that do O(n) sequential rule evaluation.

**Result**: expression tree achieves constant-time rule evaluation independent of rule count. A 16-core host can evaluate ~6M+ requests/sec against a 100K mixed-complexity rule tree. Fully inline enforcement is viable without sampling — the rule engine is no longer the bottleneck.

### Phase 1p — Expression Tree Integration + Live Detection Pipeline COMPLETE

- [x] `enforcer.rs` — Swapped from `CompiledTree` to `ExprCompiledTree` for both `evaluate()` and `evaluate_tls()`
- [x] `http.rs` — `serve_connection` and `handle_request` now use `Arc<ArcSwap<ExprCompiledTree>>`
- [x] `runner/main.rs` — Initializes `ArcSwap<ExprCompiledTree>::empty()`
- [x] `sidecar/rule_manager.rs` — `RuleManager` stores `RuleExpr`, compiles with `compile_expr()`, deploys to `ArcSwap<ExprCompiledTree>`
- [x] `sidecar/detectors.rs` — `attack_rules` changed from `Vec<RuleSpec>` to `Vec<RuleExpr>`
- [x] `sidecar/lib.rs` — Detection loop uses `compile_compound_rule_expr()`, engram rules serialized/parsed as EDN strings
- [x] `expr_tree.rs` — `to_dag_nodes()` added for DAG visualization, `rule_labels` populated during compilation
- [x] `proxy/benches/tree_perf.rs` — Performance tests moved from `tests/` to `benches/` for on-demand invocation
- [x] All 287 tests passing (237 proxy + 42 sidecar + 8 integration)
- [x] Live validation: multi-attack scenario produces composable rules with accessor chains, TLS set matching, cross-layer compound rules

Live-generated rules from the detection pipeline (first time the composable language was exercised end-to-end):

```clojure
;; HTTP path concentration
{:constraints [(= path "/api/search")] :actions [(rate-limit 83)]}

;; TLS fingerprint (set-based, order-independent)
{:constraints [(= tls-ext-types #{"0x0000" "0x0005" ...})
               (= tls-ciphers #{"0x00ff" "0x1301" ...})
               (= tls-groups #{"0x0017" "0x0018" "0x001d"})]
 :actions [(rate-limit 83)]}

;; Composable accessor chain — first value of Content-Type header
{:constraints [(= path "/api/v1/auth/login")
               (= method "POST")
               (= (first (header "content-type")) "application/json")]
 :actions [(rate-limit 83)]}

;; Cross-layer HTTP+TLS — compound rule spanning both protocol layers
{:constraints [(= method "POST")
               (= (first (header "content-type")) "application/json")
               (= tls-ext-types #{"0x0000" "0x0005" ...})]
 :actions [(rate-limit 83)]}
```

The system now produces complementary layered rules: an HTTP-path rule catches the attack at the endpoint level, while a cross-layer HTTP+TLS rule catches the attacker by their TLS fingerprint regardless of which endpoint they target. The redundancy checker correctly allows both because neither subsumes the other — they defend different attack surfaces with the same composable language.

**Result**: the full pipeline from anomaly detection through rule generation to sub-microsecond enforcement now speaks the composable expression language. Legacy `RuleSpec`/`CompiledTree` types remain in the codebase but are no longer in the live path. The only remaining gap is `FieldTracker` coverage — expanding the tracked fields unlocks all 26+ dimensions the language already supports.

### Phase 1q — VSA Surprise-Driven Rule Generation + Engram Resilience COMPLETE

The system now generates surgical, compound rules by combining FieldTracker concentration with VSA-based surprise probing and cross-tick consistency analysis. Two critical design flaws were identified and fixed, completing the autonomous mitigation pipeline.

**VSA Surprise Probing:**

- [x] `detectors.rs` — `ProbeTarget` enum (`TopLevel`, `Position`, `Nested`) for structured field identification without string-concatenated keys
- [x] `detectors.rs` — `DetectionKind` enum (`Content`, `Shape`, `Duplicate`) for categorizing surprise signals
- [x] `detectors.rs` — `ProbeHit` struct storing per-probe results (target, score, content value, shape value, header name)
- [x] `detectors.rs` — `drilldown_probe()`: unbinds anomalous component against role vectors for every walkable field, ranks by residual reduction
- [x] `detectors.rs` — `SurpriseHistory` ring buffer: tracks `ProbeHit` results across ticks for cross-tick consistency analysis
- [x] `detectors.rs` — `derive_detections()`: requires a field to appear consistently across `min_ticks` before generating a detection. Content (same literal value) takes priority over Shape (same length, different content) over Duplicate (repeated headers)

**Shape Encoding:**

- [x] `types.rs` — `path_shape`: path segment lengths encoded via `ScalarValue::linear` (e.g., `/api/products/12345` → `[0, 3, 8, 5]`)
- [x] `types.rs` — `query_shape`: query parameter key/value lengths (e.g., `foo=bar` → `[[3, 3]]`)
- [x] `types.rs` — `header_shapes`: per-header `[name, value_length]` pairs enabling detection of fixed-length high-cardinality attacks (e.g., random 26-char user agents)

**Merged Rule Compilation:**

- [x] `detection.rs` — `surprise_to_expr()`: converts `SurpriseDetection` into composable `Expr` (Content → literal match, Shape → count/length match, Duplicate → count match)
- [x] `detection.rs` — `merge_detections_to_exprs()`: combines FieldTracker and surprise detections, deduplicating by header name (FieldTracker takes priority)
- [x] `detection.rs` — `compile_merged_rule_expr()`: produces a single compound `RuleExpr` from merged detections

**Bug Fix A — Rule Refinement:**

- [x] `rule_manager.rs` — Removed `"subsumed"` check from `is_redundant()`: previously, a more specific rule (superset of existing constraints) was rejected because the broader rule already covered its match space. Now, more specific rules are allowed alongside broader ones. The compiled tree's `Specificity` ranking ensures the most surgical match wins during evaluation, while the broader rule remains as a fallback.
- [x] Effect: at streak=3 (before surprise data is ready), the system creates a broad rule like `(= path "/api/search")`. At streak=5, when surprise probing matures, it adds the surgical compound rule `{path + user-agent + path-parts}`. Previously the compound rule was silently discarded.

**Bug Fix B — Engram Resilience:**

- [x] `lib.rs` — Engram hit no longer short-circuits `learn_attack()` and fresh rule generation. The `if/else` structure was changed so that engram rules deploy as a fast-path at streak=1 AND the system always falls through to learn the current attack's vectors and generate fresh rules. If the engram's rules match the traffic, the anomaly resolves quickly. If they don't (e.g., engram false-matches due to structural similarity from shape encoding), fresh rules provide the actual mitigation.
- [x] No poisoning risk: `deploy_engram_rules` adds old rules to `rule_mgr` (enforcement only), while fresh rules go to `attack_rules`. New engrams store only fresh rules from `attack_rules`, never inheriting old engram rules.
- [x] Both TLS and REQ detection paths updated with the same fix.

**Validation — Full Scenario Results (7 attack waves, all mitigated):**

```
Wave  Attack                              rate_limit Δ   Result
────  ──────                              ────────────   ──────
1     GET flood /api/search (libwww-perl)  0 → 53,990    MITIGATED
2     Credential stuffing (python-req)     → 119,114     MITIGATED
3     Scraper (Scrapy)                     → 158,664     MITIGATED (shape detection!)
4     Shuffled TLS /api/data (bot)         → ~195,272    MITIGATED (was broken before fix)
5     Replay wave 1                        → 195,272     MITIGATED (existing rules)
5b    Replay wave 4                        → 222,581     MITIGATED (engram hit)
6     Replay wave 2                        → 249,889     MITIGATED (engram hit)
```

Live-generated rules demonstrating the full capability:

```clojure
;; Surgical compound rule — perl UA captured via surprise probing (Bug A fix)
{:constraints [(= path "/api/search")
               (= (nth path-parts 2) "search")
               (= (nth path-parts 1) "api")
               (= (first (header "user-agent")) "libwww-perl/6.72")]
 :actions     [(rate-limit 80)]}

;; Shape detection — scraper hitting 5-char product IDs
{:constraints [(= tls-ext-types #{"0x0000" "0x0005" ...})
               (= (first (header "user-agent")) "Scrapy/2.11.0 (+https://scrapy.org)")
               (= (nth path-parts 1) "products")
               (= (count (nth path-parts 2)) 5)]
 :actions     [(rate-limit 80)]}

;; Fresh rules generated despite engram false-match (Bug B fix)
;; bot_shuffled TLS correctly identified with 0x0010 extension
{:constraints [(= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0010" ...})
               (= tls-ciphers #{"0x00ff" "0x1301" ...})
               (= tls-groups #{"0x0017" "0x0018" "0x001d"})]
 :actions     [(rate-limit 80)]}

;; Fresh compound rule for wave 4 — generated alongside (ineffective) engram rules
{:constraints [(= path "/api/data")
               (= (nth path-parts 1) "api")
               (= (nth path-parts 2) "data")
               (= (first (header "user-agent")) "libwww-perl/6.72")]
 :actions     [(rate-limit 80)]}
```

**Result**: the system now autonomously generates surgical, compound rules that capture the full distinguishing characteristics of each attack. Shape-based detection identifies structural patterns (fixed-length fields) even when content varies. Engram false-matches no longer prevent fresh mitigation. Every attack in the multi-wave scenario is mitigated, including replays handled by engram memory. The gap between "what the system observes" and "what the system acts on" is closed.

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

### 2026-02-26 (continued — DAG + Dashboard)

- Dashboard layout: single DAG panel spanning both chart rows (not per-chart) — gives tree more vertical space
- Tree compiler pure DAG: specific branches only get their own rules, wildcard branches only get wildcard rules — no cross-product explosion
- Terminal node labeling: action-bearing leaf nodes labeled "terminal" not "content-type" — prevents confusion in DAG visualization
- Canvas coordinate scaling: mouse events must transform CSS→buffer space to handle panel resize drift
- Rule expression reconstruction: walk from terminal to root collecting specific edge constraints — matches veth-lab's `buildRepresentativeConstraints`
- Per-sample processing: ~0.4ms amortized (encode_walkable + CCIPCA score + field tracker), ~2,500 samples/s single-threaded throughput

### 2026-02-26 (continued — Rule Counters + Specificity)

- Per-rule counter map uses `Mutex<HashMap<u32, u64>>` — incremented on every rule match, snapshotted + broadcast each tick
- Rule labels use `constraints_sexpr()` (constraint array only) instead of full EDN with `{:constraints ... :actions ...}` — less noise in legend
- Legend capped at 75% width — prevents overlapping live chart data where latest values are most important
- Best-match evaluator: DFS explores both specific AND wildcard branches, `pick_best` selects highest `Specificity`
- `Specificity` struct with derived `Ord` replaces ad-hoc numeric formula (`layers*100 + has_http*10 + cc`) — lexicographic comparison is robust to new tiebreakers
- Tiebreaker design: `(layers, has_http, constraints)` — each field is independently motivated, not entangled by arithmetic
- Cross-layer (TLS+HTTP) rules: 2 layers always beats 1 layer, regardless of constraint count — cross-layer correlation is the strongest signal
- HTTP > TLS tiebreaker: at same layer count, HTTP constraints (path, method, UA) are more actionable than TLS-only

### 2026-02-27 / 2026-02-28 (Rule Language + Expression Tree)

- Composable rule language over EDN — Clojure-like s-expressions, not a custom DSL. Rules are data.
- `edn-rs` crate for parsing instead of hand-rolled parser — veth-lab parity, standard format
- Dimension accessor chains (`(first (header "user-agent"))`) compose generically — no magic named headers
- `Value::Set` uses a proper set type with quoted string elements in EDN serialization — not comma-delimited strings
- `RuleAction` and `RuleExpr` parity with veth-lab: structured names `(namespace, name)`, optional comment/label
- `RateLimit` period extensibility deferred — current structure supports `(rate-limit (period (minutes 5)) 300)` as additive future work
- Tree compiler zero-clone: `&[&RuleExpr]` slices through recursion instead of deep-cloning `RuleExpr` vecs at each level
- `canonical_key_cow()` returns `Cow<'_, str>` for zero-alloc grouping on the hot path
- `compute_dim_order` simplified to rule-count-per-dimension instead of unique-value-set collection — eliminates million-entry HashMaps
- Hash-based fingerprint (FNV over sorted rule identity hashes) instead of string concatenation — O(n) instead of O(n log n) with less allocation
- Lazy rule labels — only materialized when the dashboard requests them, not during compilation of 1M rules that may never be displayed

### 2026-02-28 (Expression Tree Integration)

- Full pipeline swap from `RuleSpec`/`CompiledTree` to `RuleExpr`/`ExprCompiledTree` — detection through enforcement
- Engram rules serialized as EDN strings instead of JSON structs — human-readable, round-trip stable via `parse_edn()` / `to_edn()`
- Performance benchmarks moved from `tests/` to `benches/` — `cargo test` stays fast, `cargo bench` for on-demand profiling
- Cross-layer compound rules emerge naturally: REQ detector and TLS detector independently generate complementary rules in the same attack
- Redundancy checker correctly allows complementary rules: `path + method + content-type` and `method + content-type + tls-ext-types` target different surfaces
- Legacy types (`RuleSpec`, `CompiledTree`, `tree.rs`) retained but no longer in live path — available for reference/comparison

### 2026-02-28 (VSA Surprise Probing + Engram Resilience)

- VSA `drilldown_probe()` unbinds anomalous vector component against every walkable role vector — ranks fields by residual reduction, not magic field lists
- `ProbeTarget` enum replaces string-concatenated keys for structured field identification — prevents hash collision attacks and key explosions
- `SurpriseHistory` ring buffer requires cross-tick consistency before emitting a detection — prevents transient noise from becoming rules
- Content-before-shape priority: if the same field appears with both a consistent literal value and a consistent length, the literal match wins (more surgical)
- Shape encoding via `ScalarValue::linear` for segment/header lengths — enables detection of fixed-length high-cardinality attacks (random strings of identical length)
- `is_redundant` subsumed check removed: the compiled tree's `Specificity` ranking handles the prioritization question, not the rule manager. Admitting more specific rules creates a refinement progression.
- Engram hit decoupled from fresh rule generation: engrams are a fast-path optimization, not a substitute for learning. The system always learns attack vectors and generates fresh rules, even when an engram matches. Engram rules are deployed AND fresh rules are generated in parallel.
- Engram poisoning prevented by architecture: `deploy_engram_rules` populates `rule_mgr` (enforcement), `attack_rules` accumulates fresh rules (engram minting). These are separate data paths — new engrams never inherit old engram rules.
- Merged rule compilation: `merge_detections_to_exprs()` combines FieldTracker concentration with surprise probing, deduplicating by header name (concentration takes priority — it has more observations)

## Performance Observations

- Python mock backend is the throughput bottleneck — proxy serves 429s much faster than forwarding to origin (Rust vs Python, expected)
- During non-attack periods, RPS is choppy (~100) limited by backend. During mitigated attacks, proxy handles 1000+ rps easily since most are 429s
- Sample channel capacity of 512 balances sidecar responsiveness vs sample coverage during burst transitions
- Tick time consistently <100ms even at 2000 rps attack load (after stall fixes)
- Engram re-detection deploys rules in 1 tick vs 3+ ticks for first-time detection
- Per-sample processing: ~0.4ms (encode_walkable ~0.2ms, CCIPCA score ~0.05ms, field tracking ~0.05ms, overhead ~0.1ms)
- Theoretical inline WAF throughput: ~2,800 RPS/core, ~45K RPS on 16 cores (score + enforce are read-only, scale linearly)
- **Rule evaluation is scale-independent**: 1M rules evaluate in ~1.1µs (2-dim) to ~2.6µs (6-dim). Cost is O(tree depth), not O(rule count). 10,000x more rules adds <2x latency.
- **Miss path is ~50ns**: a non-matching request does one hash miss at the root and returns. No rules consulted.
- **Compilation scales linearly**: 1M 2-dim rules compile in 3.2s, 6-dim in 5.9s. In practice, attack waves produce tens of rules — sub-millisecond compilation.
- **Mixed-complexity realistic workload**: 100K rules with distribution from 1-dim to 6-dim, all p50 evals under 2.4µs, 100% correctness across all tiers.
- **Single-core rule evaluation throughput**: 900K+ evals/sec (2-dim), 556K+ (6-dim). On 16 cores: ~6M+ evals/sec for mixed workloads — rule engine is not the bottleneck.

## Resolved Questions

- **Rate-limit granularity**: Per-IP with dynamic RPS based on baseline. Works well — different IPs get independent buckets.
- **Warmup duration**: 500 REQ samples (20-30s at 80 rps baseline). Sufficient for HTTP traffic diversity.
- **ArcSwap vs RwLock**: ArcSwap confirmed as correct choice. RwLock in the stats path caused the only serious performance regression.

## Resolved Questions (continued)

- **Path parts in detection**: Resolved via `drilldown_probe`. Path segments are individually probed by VSA surprise attribution. Segments that deviate from normal traffic become constraints like `(= (nth path-parts 1) "api")`. Shape encoding captures segment length for high-cardinality segments.
- **Engram false-match strategy**: Engrams are a fast-path, not exclusive. Fresh rules always generated in parallel. If the engram's rules match the traffic, anomaly resolves. If not, fresh rules cover the gap.
- **Rule refinement vs. redundancy**: Broader rules are fallbacks, not gatekeepers. The tree's Specificity evaluator picks the most surgical match. `is_redundant` only rejects exact duplicates and strictly over-broad candidates.

## Open Questions

- Query string structure for detection — how to handle malformed/double query strings as attack signals?
- Header ordering as detection signal — captured in RequestSample but not yet encoded into detection fields
- Connection-level metrics (requests per connection, connection duration) for slow-loris type attacks
- Multi-tenant memory isolation — how to bound per-customer VSA state (VsaFieldRing deferred)
- H2/H3 field integration — pseudo-headers, SETTINGS, HPACK state as detection dimensions

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
