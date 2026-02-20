# Engram Memory: Instant Rule Deploy on Known Attacks

**Status:** Implemented and Verified  
**Date:** February 19–20, 2026  
**Result:** Sub-second rule deployment on re-detected attacks — engram fires ~765ms before drift-based detection

## Overview

The engram system adds **manifold-aware anomaly detection** and **attack pattern memory** to the sidecar's existing drift-based pipeline. When a new attack is detected, the system learns its manifold (via online PCA), mints a named engram containing the learned subspace and the deployed mitigation rules, and stores it in a persistent library. When the same attack pattern returns, the engram fires on the first anomalous tick — deploying stored rules instantly without waiting for drift accumulation or field concentration analysis.

This closes the gap between "we've seen this attack before" and "we're mitigating it" from seconds to milliseconds.

## Architecture

```
Per-packet scoring                    Per-tick lifecycle
─────────────────                    ──────────────────
                                     
  raw packet                          subspace_residual > threshold?
      │                                       │
  encode_walkable()                    ┌──────┴──────┐
      │                                │  YES        │  NO
  vec.to_f64()                         │             │
      │                           streak++      had_attack?
  subspace.score()                     │             │
      │                           check_library  ┌──┴──┐
  track max residual                   │         │ YES │ NO
  per tick                        ┌────┴────┐    │     │
                                  │ HIT     │ NO │  streak ≥ 5?
                                  │         │    │     │
                            deploy stored   learn   ┌──┴──┐
                            rules from      attack  │ YES │ NO
                            engram          manifold │     │
                            metadata                mint   cancel
                                                   engram  attack
                                                   (store
                                                    rules)
```

## How It Works

### 1. Baseline Subspace Training (Warmup)

During warmup, every encoded packet vector is fed to an `OnlineSubspace` (CCIPCA — Candid Covariance-free Incremental PCA). This learns the k-dimensional manifold that "normal" traffic occupies in the 4096-dimensional vector space.

```
OnlineSubspace::new(4096, 32)
    dim:  4096  (vector dimensionality)
    k:    32    (principal components)
    algo: CCIPCA (Weng et al., 2003)
```

After warmup, the subspace has:
- A **mean vector** — the centroid of normal traffic
- **32 principal components** — the directions of maximum variance
- An **adaptive threshold** — EMA(residual) + 3.5σ

### 2. Per-Packet Subspace Scoring (Live)

After baseline freezing, each incoming packet is encoded and scored against the baseline subspace:

```
residual(x) = ||x - mean - Σ proj_i(x) · component_i||
```

The residual measures reconstruction error — how far the vector falls from the learned manifold. Normal packets reconstruct well (low residual); attack packets with novel field combinations produce high residuals.

The per-tick **maximum residual** and its corresponding raw vector are tracked. This is critical: the subspace must be scored with raw encoded vectors (elements in `{-1, 0, 1}`, L2 norm ~56), not normalized accumulators (L2 norm = 1). The centering step `x - mean` is scale-sensitive.

### 3. Engram Lifecycle (Per-Tick)

Each tick, the maximum subspace residual is compared against the adaptive threshold:

**Anomalous tick** (residual > threshold):
1. Increment `anomaly_streak`
2. On streak == 1: check the engram library for a known pattern
   - **HIT**: Deploy stored rules immediately, skip drift-based drill-down
   - **MISS**: Begin learning the attack manifold (new `OnlineSubspace`)
3. On subsequent ticks: continue feeding vectors to the attack subspace

**Normal tick** (residual ≤ threshold):
1. If an attack subspace was active:
   - **streak ≥ 5**: Mint an engram — snapshot the attack subspace, capture active rules as EDN, store in library
   - **streak < 5**: Cancel — false positive or transient anomaly
2. Reset streak to 0

### 4. Engram Minting (Rule Storage)

When an attack ends after a sustained anomaly (streak ≥ 5 ticks), the system:

1. **Snapshots the attack subspace** — the `OnlineSubspace` trained on the attack's vectors
2. **Computes a surprise fingerprint** — unbinds the anomalous component with each field role vector to identify which fields contributed most to the anomaly
3. **Captures active rules** — reads all non-preloaded rules from `active_rules` and stores their EDN representations in the engram's metadata
4. **Adds to the library** — `EngramLibrary::add()` stores the subspace snapshot with an L2-normalized eigenvalue signature for fast pre-filtering

```
metadata = {
    "minted_at_tick": 459,
    "anomaly_streak": 98,
    "rules": [
        "{:constraints [(= src-addr \"10.0.0.100\") (= dst-port 9999) (= ttl 255) (= df 0)] :actions [(rate-limit 2844)]}"
    ]
}
```

### 5. Engram Hit (Instant Rule Deploy)

When a known attack returns:

1. The subspace residual exceeds the baseline threshold
2. On the first anomalous tick, `check_library()` matches the probe vector against all stored engrams using two-tier matching:
   - **Eigenvalue pre-filter** (O(k·n)): rank by eigenvalue energy
   - **Full residual** (O(k·dim)): score top candidates against their stored subspace
3. If the residual is below the engram's own threshold × 2.0: **HIT**
4. The stored EDN rules are parsed back into `RuleSpec` objects via `parse_edn_rule()`
5. Rules are deployed through `upsert_rules()` — same path as drift-derived rules
6. The XDP tree is recompiled and atomically flipped via `recompile_tree_and_broadcast()`

The entire sequence — from subspace hit to XDP tree active — completes in under 3ms.

### 6. Surprise Fingerprint (Field Attribution)

At mint time, the system computes which fields drove the anomaly:

```rust
let anomaly = baseline.anomalous_component(vec_f64);  // x - reconstruct(x)
let anomaly_vec = Vector::from_f64(&anomaly);

for field in ["src_ip", "dst_port", "ttl", "df_bit", ...] {
    let role = holon.get_vector(field);
    let unbound = Primitives::bind(&anomaly_vec, &role);
    let surprise = unbound.norm();  // higher = more surprising
}
```

This exploits VSA's binding algebra: unbinding the anomalous component with a field's role vector isolates how much that field contributed to the out-of-subspace direction. The result is a ranked list of fields by surprise magnitude.

## Payload-Level Engrams

The same lifecycle applies to payload-level anomaly detection, with differences:

- **Per-window subspaces**: Each 64-byte payload window has its own `OnlineSubspace`
- **Bundled scoring**: All windows are encoded, scored independently, then bundled into a single vector for library matching
- **Rule filtering**: Only rules containing `RawByteMatch` predicates are stored in payload engrams
- **`PayloadEngramEvent` enum**: Returns `Nothing`, `Hit { stored_rules }`, or `Minted { name }` so `main.rs` can handle rule deployment

## Measured Performance

### Timeline: Second Attack (SYN Flood)

```
08:14:43.320  ENGRAM HIT 'attack_t459' (residual=58.70) — deploying 1 stored rule
08:14:43.320  Tree compiled: 5 nodes, 4 edges, 1 rate bucket
08:14:43.322  Tree recompiled (engram hit) — rule LIVE in XDP
                                                                    ← 765ms gap
08:14:44.084  ANOMALY DETECTED: drift=0.848 — drift detector fires
08:14:44.084  RULE deployed via drift path
```

The engram deploys rules **765ms before** the drift-based detector even notices the attack. During that window, the XDP filter is already rate-limiting attack traffic.

### Full Lifecycle Demonstration

```
Tick  361: Subspace anomaly — learning attack manifold
Tick  361: EARLY-RULE deployed (drift_rate-based)
Tick  459: ENGRAM MINTED 'attack_t459' (98 ticks, 1 stored rule)
              ↓ recovery ↓
Tick  498: ENGRAM HIT — rule already active, timestamp refreshed
              ↓ second attack ↓
Tick  556: ENGRAM HIT — rule deployed from engram, tree recompiled
Tick  561: Drift detector fires (765ms later)
              ↓ third attack ↓
Tick  731: ENGRAM HIT — instant deploy on third attack onset
```

### False Positive Handling

Short-lived anomalies (streak < 5) are correctly cancelled:

```
Tick  457: Borderline subspace anomaly (residual=32.76, threshold=32.76)
Tick  458: Attack subspace cancelled (streak 1 < 5 minimum)
```

## Module Layout

| Module | Role |
|--------|------|
| `holon-rs/memory/subspace.rs` | `OnlineSubspace` — CCIPCA algorithm, residual scoring, adaptive threshold |
| `holon-rs/memory/engram.rs` | `Engram` + `EngramLibrary` — snapshot storage, two-tier matching, persistence |
| `sidecar/detectors.rs` | `SubspaceDetector` + `PayloadSubspaceDetector` — lifecycle wrappers |
| `sidecar/field_tracker.rs` | Per-packet scoring, max residual tracking, `take_tick_subspace_vec()` |
| `sidecar/payload_tracker.rs` | Payload windowing, per-window scoring, `PayloadEngramEvent` lifecycle |
| `sidecar/main.rs` | Orchestration — engram hit deploy, mint rule capture, tree recompile |
| `sidecar/rules_parser.rs` | `parse_edn_rule()` — EDN string → `RuleSpec` for stored rule recovery |
| `filter/lib.rs` | `sexpr_value()` — quoted IP serialization for EDN round-trip correctness |

## Key Design Decisions

### Raw vectors, not normalized accumulators

The subspace is trained on raw encoded vectors (`vec.to_f64()`, elements in `{-1, 0, 1}`). Scoring must use vectors from the same domain. An earlier implementation scored normalized accumulator vectors (L2 norm = 1.0), causing a domain mismatch that made the residual perpetually high. The fix tracks the per-tick maximum residual from raw per-packet scoring.

### EDN round-trip for rule storage

Rules are stored as EDN strings in engram metadata and parsed back via `edn_rs + parse_edn_rule()`. IP addresses must be quoted (`"10.0.0.100"`) for valid EDN — bare IPs fail `edn_rs` parsing because `10.0.0.100` looks like a malformed number.

### Streak-based minting threshold

The minimum streak of 5 ticks prevents short transient anomalies from polluting the engram library. Real attacks persist; noise doesn't.

### Library check only on streak == 1

The library is checked only on the first anomalous tick of a new streak. This avoids redundant matching on every tick during an extended anomaly.

## Persistence

The engram library can be saved to and loaded from JSON files:

```rust
library.save("engrams.json")?;
let library = EngramLibrary::load("engrams.json")?;
```

The `SubspaceSnapshot` (mean, components, threshold state) is fully serializable. On restart, previously learned attack patterns are immediately available for matching.
