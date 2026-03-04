# Design: Striped Multi-Vector Encoding

**Status:** Implemented and validated — March 4, 2026
**Problem:** VSA crosstalk degrading drilldown attribution accuracy
**Solution:** FQDN leaf hashing across N independent vectors

## The Problem: Crosstalk in Single-Vector Encoding

When encoding a structured request (HTTP headers, TLS fingerprint, path, query, etc.)
into a single 4096-dimensional vector via role-filler binding, the resulting superposition
contains ~80–120 leaf bindings. Drilldown attribution works by unbinding each role from
the anomalous component and measuring the residual — but with 80+ bindings superimposed,
unbinding any single role picks up interference ("crosstalk") from every other binding.

### Observed symptom

During Nikto scans against a DVWA backend with warmup training from `dvwa_browse` traffic:

- `src_ip` (constant `127.0.0.1` across all traffic) scored ~47–48 in drilldown — nearly
  as high as genuinely anomalous fields like `path_parts.[2]` or `tls.ext_order.[9]`.
- Every field appeared approximately equally anomalous, making the attribution useless
  for determining *why* a request was denied.

### Root cause

With D=4096 and ~100 bindings, the binding-to-dimension ratio is ~1:40. The Kanerva
capacity bound for near-orthogonal superposition is approximately D/(4·ln(D)) ≈ 123 items
at 4096 dimensions. We were operating near the capacity ceiling, and the noise floor
from interference was high enough to swamp the actual signal for individual fields.

## Rejected Alternative: Top-Level Sharding

The first idea was to hash by the top-level key (`src_ip`, `tls`, `headers`, etc.) and
assign each top-level field and all its children to a single stripe.

**Why it was rejected:** This creates severe imbalance. The `tls` object alone has ~40
leaf bindings (cipher order, extension order, versions, etc.), while `src_ip` has exactly
one. One stripe would be overloaded and still suffer crosstalk while others would be
nearly empty.

## Chosen Solution: FQDN Leaf Hashing

Every leaf binding — a `Scalar` or `Set` value at the bottom of the Walkable tree — is
assigned to a stripe by hashing its **full qualified domain name** (the dotted path from
root to leaf). Examples:

```
src_ip                        → FNV-1a hash → stripe 3
tls.cipher_order.[5]          → FNV-1a hash → stripe 1
tls.extensions.session_ticket → FNV-1a hash → stripe 6
headers.[0].[1]               → FNV-1a hash → stripe 0
path_parts.[2]                → FNV-1a hash → stripe 4
```

This distributes bindings uniformly across stripes regardless of the tree structure.
A request with 100 leaf bindings and N=8 stripes yields ~12–13 bindings per stripe,
bringing the ratio to ~1:320 — well within Kanerva capacity and producing clean
drilldown scores.

### Flat encoding (not hierarchical)

The encoding is **flat**: each leaf's role vector is the FQDN string itself (e.g.,
`"tls.cipher_order.[5]"`), not a nested chain of `bind(role_tls, bind(role_cipher_order, bind(role_5, filler)))`.

This is a deliberate design choice:
- **Simpler**: one `bind(role_FQDN, filler)` per leaf, one `bundle()` per stripe
- **Faster**: no cascading binds through the tree hierarchy
- **Clean drilldown**: unbinding a leaf's FQDN role from the stripe's anomalous component
  gives a direct score for exactly that leaf — no hierarchical decomposition needed

The tradeoff is that compositional relationships between sibling fields within a map are
lost (the system doesn't "know" that `tls.version` and `tls.ciphers` are siblings). In
practice this doesn't matter — the drilldown reports each leaf independently, and the UI
groups them visually by common path prefix.

### Leaf type rules

| WalkableValue | Treatment |
|---|---|
| `Scalar` | Leaf — hash FQDN, bind role+filler, place in stripe |
| `Set` | Leaf — hash FQDN, encode membership set, place in stripe |
| `Map` | Recurse — extend path with `.key` for each child |
| `List` | Recurse — extend path with `.[index]` for each element |
| Empty `Map`/`List` | Leaf — bind FQDN role + `"__empty__"` filler |

## StripedSubspace: N Independent Learners

Each stripe has its own `OnlineSubspace` (incremental PCA with exponentially-weighted
forgetting). Training and scoring operate independently per stripe:

```
StripedSubspace {
    stripes: Vec<OnlineSubspace>,   // N independent subspaces
}
```

### RSS aggregation

The system-wide residual score for a request is the **root-sum-of-squares** of per-stripe
residuals:

```
residual = √( r₀² + r₁² + ... + r₇² )
```

Similarly for the threshold:

```
threshold = √( t₀² + t₁² + ... + t₇² )
```

RSS was chosen over alternatives (sum, max, mean) because:
- It preserves the geometric interpretation (Euclidean distance in product space)
- A single anomalous stripe dominates the score (desirable: an exploit only needs to
  touch a few fields to be alien)
- It's numerically stable and easy to reason about

### Drilldown with stripes — cosine probing

For attribution, the system uses the MAP algebra's native similarity measure:

1. Computes the real-valued anomalous component for each stripe: `anomaly[i] = x[i] - reconstruct(x[i])`
2. For each leaf, reconstructs the **exact binding** (`bind(role, filler)`) that was used during encoding
3. Computes **cosine similarity** between the float anomaly and the bipolar binding

```
score(field) = |cos(anomaly_float[stripe], binding_bipolar)| 
             = |dot(anomaly, binding)| / (||anomaly|| × ||binding||)
```

If a binding contributed to the anomaly (its direction is present in the residual),
the cosine is high. If the binding was fully captured by the learned subspace and
removed during reconstruction, the cosine is ≈ 0.

**Why not L2 norm of unbinding?** For bipolar MAP vectors, `bind(A, R)` is
element-wise multiplication by ±1, which preserves L2 norm: `||bind(A, R)|| = ||A||`
for any R. Every field in the same stripe would get the identical score — the metric
contains zero attribution information. Cosine similarity against the specific binding
direction is the correct MAP-algebra probe operation.

## Sidecar Compatibility

The sidecar maintains both representations:

- **Striped baseline** (`StripedSubspace`): used for manifold enforcement (allow/deny/rate-limit)
  and drilldown attribution in the proxy
- **Aggregated single vector**: the per-stripe vectors bundled into one for the existing
  `SubspaceDetector`, `WindowTracker`, and `EngramLibrary` which still operate on single
  vectors for DDoS detection and window-level spectrum analysis

This dual-path approach avoids cascading changes to the DDoS detection pipeline while
giving the WAF path the benefit of clean per-field attribution.

## Configuration

Three constants control the encoding:

| Parameter | Default | Location | Notes |
|---|---|---|---|
| `N_STRIPES` | 32 | `http-lab/proxy/src/lib.rs` | Stripe count for FQDN hashing |
| `VSA_DIM` | 4096 | Holon default dimensionality | Per-stripe vector dimensions |
| `STRIPED_K` | 8 | `http-lab/sidecar/src/lib.rs` | PCA components per stripe |

With 32 stripes × 4096 dimensions, total vector memory per request is 32 × 4096 × 8 bytes = 1 MB.
This is acceptable for per-request scoring at WAF throughput levels.

### Why k=8 per stripe (not k=64)

The sidecar's single-vector `SubspaceDetector` uses k=64 PCA components because a single
4096-dim vector encodes ~100 superimposed bindings with significant inter-request variance.
The striped baseline only needs to learn the variance within each stripe, which holds ~3
bindings. k=8 is more than sufficient to capture this low-rank signal.

Using k=64 per stripe caused a **5x throughput regression** (100 rps → 20 rps) because
CCIPCA update cost scales as O(2 × k × D) per stripe:

| Configuration | CCIPCA ops/request | Residual ops/request | Total subspace math |
|---|---|---|---|
| 32 × k=64 | 32 × 2 × 64 × 4096 = 16.8M | 32 × 64 × 4096 = 8.4M | ~25M |
| 32 × k=8  | 32 × 2 × 8 × 4096 = 2.1M  | 32 × 8 × 4096 = 1.0M  | ~3M  |

The k=8 configuration provides an **8x reduction** in subspace math per request.

### Capacity analysis

- Leaves per request: ~80–120
- Leaves per stripe (uniform): ~2.5–3.75
- Kanerva capacity per stripe at D=4096: ~123
- Headroom factor: ~33–49x → very clean superposition

### Why D doesn't help attribution

Cross-talk from VSA unbinding is dimensionality-independent. When unbinding `role_A`
from a superposition containing M other anomalous bindings, the cross-talk L2 norm
scales as `sqrt(M * D)` while the signal scales as `sqrt(D)`. The ratio is always
`1/sqrt(M)` — D cancels. Increasing D from 4096 to 10000 yields zero improvement
in per-field attribution quality. Only reducing M (via more stripes) helps.

If future extensions add significantly more fields (hundreds of leaves), either
`N_STRIPES` or `VSA_DIM` can be increased. The FNV-1a hash distributes uniformly
regardless of the number of stripes.

## Experimental Validation

### Before (single vector, D=4096)

- `src_ip` scored ~47.5 (should be ~0, it's constant)
- All fields scored within a ~2-point band (~47–49)
- Attribution was effectively useless — everything looked equally anomalous

### After (32 stripes, D=4096 each)

- `src_ip` dropped out of the top attributions entirely
- System-wide residual scales with RSS aggregation (√N_STRIPES × single-vector residual)
- Top attributions cleanly identify specific anomalous sub-fields:
  - `tls.ext_order.[9]` (49.92), `tls.ext_order.[1]` (49.84)
  - `tls.cipher_order.[21]` (49.68)
  - `header_order.[2]` (49.56)
  - `path_shape.[1]` (49.49)
- Constant fields like `src_ip` no longer appear in the top-k
- Nikto denial rate: 5,273 denies / 0 false positives on normal traffic
- Anomaly score 187.08 vs threshold 36.08 → 5.2x deviation for attack traffic

## Relationship to veth-lab PayloadTracker

The `veth-lab` packet processing layer already uses a multi-vector approach for similar
reasons: `PayloadTracker` maintains separate vectors for source, destination, protocol,
and payload fields. The striped encoding in `http-lab` generalizes this pattern — instead
of manually choosing which fields go where, the FQDN hash assigns stripes automatically,
making it work for any `Walkable` data structure without manual configuration.

## Files Changed

| File | Change |
|---|---|
| `holon-rs/src/kernel/encoder.rs` | `field_stripe()`, `encode_walkable_striped()`, `collect_leaf_bindings()` |
| `holon-rs/src/memory/subspace.rs` | `StripedSubspace`, `StripedSubspaceSnapshot` |
| `holon-rs/src/memory/mod.rs` | Export new types |
| `http-lab/proxy/src/lib.rs` | `N_STRIPES` constant |
| `http-lab/proxy/src/manifold.rs` | Striped `ManifoldState`, `drilldown_audit` with flat leaf walk |
| `http-lab/proxy/src/http.rs` | Stripe encoding in request pipeline |
| `http-lab/sidecar/src/lib.rs` | Dual-path training (striped + aggregated) |
