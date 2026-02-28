# http-lab Technical Debt & Improvements

Captured 2026-02-26. Not blocking current feature work — address when stabilizing.

## 1. Split types.rs (~1,900 lines)

`proxy/src/types.rs` is the largest file and mixes several concerns:

- **Data model**: `TlsContext`, `RequestSample`, `RuleSpec`, `Predicate`, `FieldDim`, `RuleAction`
- **Walkable implementations**: `encode_walkable()` for both TLS and HTTP
- **EDN serialization**: `to_edn_pretty()`, `to_edn_compact()`, `constraints_sexpr()`
- **DFS evaluator**: `evaluate_req()`, `evaluate_tls()`, `dfs_req()`, `dfs_tls()`, `pick_best()`
- **Specificity ranking**: `Specificity` struct and layer classification
- **DAG serialization**: `DagNode`, `DagEdge`, `to_dag_nodes()`

Suggested split:

| New module | Contents |
|------------|----------|
| `types.rs` | Data model structs, `FieldDim`, `Predicate`, `RuleAction`, `RuleSpec` |
| `walkable.rs` | `Walkable` trait implementations for `TlsContext` and `RequestSample` |
| `edn.rs` | EDN serialization (`to_edn_pretty`, `to_edn_compact`, `constraints_sexpr`) |
| `evaluator.rs` | `Specificity`, `pick_best`, `dfs_req`, `dfs_tls`, `evaluate_req`, `evaluate_tls` |
| `dag.rs` | `DagNode`, `DagEdge`, `to_dag_nodes()` |

The evaluator is the highest-priority extraction — it has the most complex logic and is where future ranking changes land. The Walkable implementations are second — they're long but stable.

Tests for each module move with their code. No public API changes needed; just re-export from `lib.rs` or a prelude.

## 2. Test Coverage Gaps

Current test distribution (111 total):

| File | Tests | Risk |
|------|-------|------|
| `types.rs` | 37 | Low — well covered |
| `tls.rs` | 22 | Low — parser edge cases covered |
| `enforcer.rs` | 11 | Low |
| `detection.rs` | 11 | Low |
| `tree.rs` | 9 | Medium — compiler correctness is critical |
| `rule_manager.rs` | 9 | Low |
| `field_tracker.rs` | 6 | Medium — decay math is subtle |
| `http.rs` | 6 | Low |
| **`sidecar/lib.rs`** | **0** | **High — 856 lines, orchestrates entire detection pipeline** |

Priority additions:

### sidecar/lib.rs (highest priority)
- **Tick trigger logic**: verify hybrid 200-sample / 500ms trigger fires correctly
- **Rule generation from concentration**: mock a FieldTracker with known concentrated values, verify the produced `RuleSpec` constraints
- **Engram deploy path**: mock an EngramLibrary match, verify rules are deployed with recalculated rate limits
- **TLS field candidate selection**: verify ordered-vs-set adaptive logic with controlled FieldTracker state
- **Attack end → engram minting**: verify surprise fingerprint and rule metadata are correctly captured

These don't need a running proxy — the detection functions can be unit-tested with synthetic samples and mocked dependencies.

### tree.rs (medium priority)
- **Specificity propagation**: compile rules with known constraints, verify `Specificity` values on terminal nodes
- **Best-match across branches**: tree with overlapping specific/wildcard paths, verify the more surgical rule wins
- **Rule label population**: verify `rule_labels` map contains `constraints_sexpr()` output, not full EDN

## 3. Multi-Core Detection

Current: single tokio task drains the sample channel and runs both TLS and REQ detectors sequentially. Throughput ceiling is ~2,500 samples/s.

### Option A: Sharded detection (2-4 cores)

Shard incoming samples by source IP (or connection ID) across N detector tasks:

```
channel → shard_0 (SubspaceDetector_0, FieldTracker_0)
        → shard_1 (SubspaceDetector_1, FieldTracker_1)
        → ...
```

Each shard maintains its own learned subspace. Rule generation aggregates across shards.

**Pros**: Linear throughput scaling, no shared mutable state on hot path.
**Cons**: Each shard sees a subset of traffic — baseline learning is slower, concentration thresholds need adjustment. Engram library must be shared (read-mostly, Arc is fine).

### Option B: Split scoring from learning

Separate the read-only scoring path (CCIPCA residual computation) from the write path (subspace update, field tracking):

```
samples → N scorer tasks (read-only subspace snapshot) → scored results → 1 learner task (updates subspace)
```

**Pros**: Scoring is embarrassingly parallel. Learner sees all samples for correct baseline.
**Cons**: Subspace snapshot staleness. More complex data flow.

### Option C: Inline scoring, sampled learning

Score every request inline in the proxy (like enforcement), but only send a sample to the sidecar for learning/rule generation:

```
proxy hot path:  ArcSwap<Subspace>::load() → score → enforce
sidecar:         sampled updates to subspace + field tracking + rule gen
```

**Pros**: Zero-latency scoring at proxy throughput. Sidecar load decoupled from request rate.
**Cons**: Subspace must be ArcSwap'd like the rule tree. Scoring cost (~0.25ms) added to every request.

**Recommendation**: Option A with 2 shards is the simplest win. At 2 shards you get ~5K samples/s which covers most realistic L7 attack volumes. The sharding key (src_ip hash) naturally groups related traffic.

## 4. Protocol Coverage

### TLS 1.3 0-RTT (Early Data)

The ClientHello parser handles TLS 1.3 correctly, but 0-RTT early data is not intercepted. An attacker could send a malicious request in early data that bypasses the first enforcement check (the request arrives before the handshake callback fires).

**Impact**: Low for DDoS (volume attacks don't benefit from 0-RTT), higher for exploit detection (Phase 2).
**Fix**: Intercept the early data extension (0x002a) in ClientHello and either reject 0-RTT or buffer early data for post-handshake inspection.

### HTTP/2 and HTTP/3 (QUIC)

The proxy is HTTP/1.1 only (hyper with `http1::Builder`). Modern browsers and CDNs default to HTTP/2.

**HTTP/2**: Hyper supports it — the main work is adapting `RequestSample` for multiplexed streams (multiple concurrent requests per connection, shared TLS context). The detection model is unaffected since samples are per-request.

**HTTP/3 (QUIC)**: Requires a different transport stack entirely (quinn or s2n-quic). The ClientHello parser doesn't apply — QUIC embeds the TLS handshake in its own framing. The detection and rule engine are transport-agnostic and would work unchanged, but the proxy frontend is a rewrite.

**Recommendation**: HTTP/2 support is a moderate lift and high value. HTTP/3 is a major effort and can wait until there's a concrete use case.

## 5. Dashboard Maintainability

The dashboard is a single 1,572-line HTML file with inline CSS and JS. This is standard for lab/tool dashboards (veth-lab uses the same pattern), but it has a practical cost: changes require scanning a monolith, and LLM-assisted edits need large context windows to avoid breaking state management.

### If it becomes a problem

Split into 3 files served by the same axum static handler:

| File | Contents |
|------|----------|
| `dashboard.html` | Markup + CSS (~400 lines) |
| `dashboard-state.js` | SSE handling, state management, data transforms (~500 lines) |
| `dashboard-charts.js` | uPlot setup, series config, legend rendering, DAG canvas (~700 lines) |

The split boundary is clean: state.js owns the `state` object and exposes `getState()` / `updateState()`. Charts.js consumes state and owns DOM updates.

**Not recommended now** — the current file is stable, works, and the veth-lab precedent shows this pattern holds up. Only split if you find yourself repeatedly breaking unrelated features during edits.
