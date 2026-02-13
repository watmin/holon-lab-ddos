# Novel VSA/HDC Techniques in Holon DDoS Detection

**Where this system departs from classical VSA/HDC and what that means.**

Classical VSA/HDC (Plate 1995, Kanerva 2009, Gayler 2003) defines three
operations — binding, bundling, permutation — and uses them for associative
memory, analogical reasoning, and symbolic AI. The standard usage pattern is:
encode, store, query by similarity.

This system uses the same algebra but exploits **geometric properties of the
accumulator space** that the literature hasn't explored in this way. The
accumulator isn't just a noisy memory — it's a measurement instrument whose
geometry encodes volume, diversity, and correlation.

---

## 1. Magnitude as Volume Proxy (Implemented)

### Classical View

In standard VSA, the accumulator is normalized before use. The magnitude is
discarded — only the direction (sign pattern) matters. Normalization throws
away the "how much" and keeps only the "what."

### What We Do Instead

We keep the raw float accumulator and use its L2 norm as a traffic volume
signal:

```
||accumulator|| ∝ packet_count × coherence
```

The magnitude grows with every packet added. But the growth rate depends on
coherence: if every packet is identical, magnitude grows linearly (N). If
every packet is different, magnitude grows as √N. This is a consequence of
the Pythagorean theorem in high dimensions — orthogonal contributions add
in quadrature.

### The Rate Derivation

```
rate_factor = ||baseline_per_window|| / ||recent_window||
```

If the recent window has 10× the traffic volume of baseline, the magnitude
is ~10× larger, and the rate factor is ~0.1. The allowed PPS becomes 1/10th
of the estimated current PPS.

**The rate limit converges to approximately the baseline PPS without ever
measuring or storing baseline PPS.** The magnitude ratio does the division
for us — it's implicit in the geometry of the accumulator.

### Why This Is Novel

No VSA/HDC paper we're aware of uses accumulator magnitude as an operational
signal. The standard pipeline is: accumulate → normalize → compare direction.
We insert a step: accumulate → **measure magnitude** → normalize → compare
direction. The magnitude measurement is the entire rate-limiting system.

---

## 2. Unbinding as Cardinality Estimator (Designed, Not Yet Implemented)

### Classical View

Unbinding (`bind(accumulator, role)`) is used to query: "what was bound to
this role?" The result is compared to a codebook of known fillers via
similarity search.

### What We Propose

Use the **magnitude** of the unbound result — not its direction — as a
cardinality signal for that specific field:

```rust
let src_ip_component = Primitives::bind(&accumulator, &role_src_ip);
let src_ip_diversity = src_ip_component.norm() / packet_count;
```

The reasoning:
- Each unique source IP contributes a near-orthogonal vector to the accumulator
  (because different filler values produce orthogonal bindings)
- Unbinding with `role_src_ip` extracts this subspace
- If all packets had the same source IP: one vector repeated N times → magnitude ≈ N
- If all packets had different source IPs: N orthogonal vectors → magnitude ≈ √N
- The ratio `magnitude / count` tells you the cardinality class

### Attack Classification from Cardinality Profile

| src_ip diversity | dst_port diversity | Interpretation |
|---|---|---|
| Very low (→1.0) | Very low | Amplification (few sources, one target) |
| Very high (→1/√N) | Very low | Botnet (many sources, one target) |
| Very low | Very high | Port scan from single source |
| Very high | Very high | Distributed scan |

This falls out of the algebra. No HyperLogLog. No counting. Just measure the
magnitude of unbound components.

### Why This Is Novel

Standard VSA unbinding asks "what filler was bound to this role?" (direction
query). We ask "how diverse were the fillers bound to this role?" (magnitude
query). Same operation, different measurement axis, entirely different signal.

---

## 3. Magnitude Spectrum (Designed, Not Yet Implemented)

### Concept

Systematically unbind the accumulator with every role vector to produce a
per-field diversity profile — a "fingerprint" of traffic structure:

```
spectrum = { field_name → ||bind(accumulator, role_field)|| / count }
```

### What It Gives You

**Normal traffic:**
```
src_ip: 0.05    (many unique clients)
dst_ip: 0.92    (one server)
proto:  0.85    (mostly TCP, some UDP)
src_port: 0.03  (ephemeral, very diverse)
dst_port: 0.15  (a few services: 80, 443, 22)
```

**DNS amplification attack:**
```
src_ip: 0.95    (1-3 reflectors)     ← SPIKE
dst_ip: 0.99    (one victim)
proto:  0.99    (all UDP)            ← SPIKE
src_port: 0.99  (all port 53)       ← SPIKE
dst_port: 0.03  (randomized)
```

**Botnet SYN flood:**
```
src_ip: 0.02    (50,000 bots)       ← FLAT
dst_ip: 0.99    (one victim)
proto:  0.99    (all TCP)
src_port: 0.01  (randomized)
dst_port: 0.99  (one port)          ← SPIKE
```

The spectrum shape IS the attack signature. Amplification has spikes on
source fields. Botnets have flat source diversity with spikes on target
fields. You can classify attacks by spectrum shape without ever defining
what an "amplification attack" is.

### Why This Is Novel

Per-field analysis in standard VSA uses unbinding to retrieve specific
values. Using unbinding to produce a **diversity spectrum** — a structural
fingerprint of the entire accumulator — appears to be new. It's the
difference between asking "what source IP did I see?" and asking "how
varied were the source IPs?"

---

## 4. Interference Detection for Correlated Attacks (Designed, Not Yet Implemented)

### Concept

When two independent attacks overlap in the accumulator, their contributions
are orthogonal (different sources, different patterns). Magnitudes add in
quadrature:

```
||A + B||² = ||A||² + ||B||²    (if A ⊥ B)
```

If the observed magnitude is **super-additive** — larger than quadrature sum
would predict — the attacks share structure. They're correlated.

### What This Detects

- **Same botnet, multiple attack types:** A botnet running SYN flood on port
  80 AND DNS amplification via the same C2. The shared source IPs reinforce
  in the accumulator, pushing magnitude above the independence threshold.

- **Coordinated timing:** Two attacks launched simultaneously from
  independent infrastructure still add orthogonally. But if they're
  coordinated (same timing, same ramp pattern), the temporal structure
  creates non-orthogonal overlap.

### Why This Is Novel

Classical VSA treats superposition as information storage — you bundle things
to remember them together. We treat superposition as a **measurement of
structural similarity between the superimposed things.** The magnitude of
the superposition tells you whether the components were independent or
correlated. This is closer to quantum interference than to classical
associative memory.

---

## 5. Difference Unbinding for Continuous Attribution (Designed, Not Yet Implemented)

### Concept

Instead of asking "what changed?" (binary: drift exceeded threshold), ask
"how much did each field change?" (continuous: per-field delta magnitude):

```rust
let delta = recent_acc - baseline_acc;  // element-wise subtraction
let src_ip_delta = bind(&delta, &role_src_ip).norm();
let dst_port_delta = bind(&delta, &role_dst_port).norm();
```

### What This Gives You

A continuous "blame" metric per field. "Source IPs changed by magnitude 42,
destination ports changed by magnitude 3, protocol changed by magnitude 0.5."

This is richer than the current binary concentration analysis ("src_ip
exceeds 50% threshold? yes/no"). It tells you the relative magnitude of
each field's contribution to the overall drift.

### Why This Is Novel

Standard VSA difference vectors are used for analogical reasoning (A:B::C:?).
We use the **per-component magnitude of a difference vector** as an
attribution signal — decomposing drift into per-field contributions via
the same unbinding algebra.

---

## 6. Scalar Encoding Choices: When to Quantize vs Log-Scale

### The Current Approach

Most packet fields are encoded as **discrete filler vectors** — each unique
value gets its own random vector:

```
encode(proto=6)  → V_6    (random vector seeded by "6")
encode(proto=17) → V_17   (random vector seeded by "17")
```

Proto 6 and proto 17 are orthogonal. This is correct for protocol numbers —
TCP and UDP are categorically different, not "close."

One field already uses **logarithmic encoding:**

```
pkt_len → ScalarValue::log(pkt_len)  // ratios matter, not absolutes
```

A 100-byte packet and a 110-byte packet are "close" (similar vectors). A
100-byte packet and a 1000-byte packet are "far" (dissimilar vectors). The
log scale captures the intuition that size ratios matter more than absolute
differences.

### The Problem: TTL and Fuzziness

TTL values are **inherently fuzzy.** A TTL of 64 at the source might arrive
as 60, 59, or 58 depending on the path. These should be "similar" — they
indicate the same class of originating OS (Linux default TTL=64).

But with discrete encoding:
```
encode(ttl=64) ⊥ encode(ttl=60) ⊥ encode(ttl=59)
```

They're all orthogonal. A packet with TTL 60 is as "different" from TTL 64
as it is from TTL 255. This is wrong.

### The Fix: Log-Scale Encoding for TTL

```rust
// Before: discrete (each TTL value gets its own random vector)
visitor("ttl", WalkableRef::int(self.ttl as i64));

// After: log-scaled (nearby TTLs produce similar vectors)
visitor("ttl", WalkableRef::Scalar(ScalarRef::log(self.ttl as f64)));
```

With log-scale encoding:
- TTL 64 and TTL 60 → similar vectors (close on log scale)
- TTL 64 and TTL 128 → moderately different (one doubling)
- TTL 64 and TTL 255 → very different (two doublings)

This clusters the OS-default TTL ranges naturally:
- Linux/Android: ~64 (arrives as 50-64)
- Windows: ~128 (arrives as 110-128)
- Network gear: ~255 (arrives as 240-255)

### Which Fields Should Be Log-Scaled?

| Field | Encoding | Rationale |
|---|---|---|
| `proto` | Discrete | TCP≠UDP≠ICMP, categorically different |
| `src_ip` | Discrete (string) | Each IP is a distinct entity |
| `dst_ip` | Discrete (string) | Same |
| `src_port` | Discrete | Port 53 ≠ port 54, different services |
| `dst_port` | Discrete | Same |
| `tcp_flags` | Discrete | SYN ≠ ACK, categorically different |
| `df_bit` | Discrete | Binary, only two values |
| `pkt_len` | **Log-scaled** | Already implemented. Ratios matter. |
| `ttl` | **Log-scaled** | Path-dependent jitter, OS clustering |
| `tcp_window` | **Log-scaled** | OS-dependent defaults, stack tuning |

The rule: **log-scale when nearby values are "the same thing seen through
noise."** Discrete when each value is categorically distinct.

`tcp_window` is a good candidate for the same reason as TTL — different OS
stacks use different defaults (65535, 8192, 29200, etc.) and the exact value
varies with stack tuning and negotiation. Ratios between window sizes are
more meaningful than absolute differences.

Ports should stay discrete. Port 53 (DNS) and port 54 (unassigned) are
categorically different services. Port numbers are identifiers, not
measurements.

### Implementation

Change in `filter/src/lib.rs`, `Walkable` implementation for `PacketSample`:

```rust
// Change these two lines:
visitor("ttl", WalkableRef::int(self.ttl as i64));
visitor("tcp_window", WalkableRef::int(self.tcp_window as i64));

// To:
visitor("ttl", WalkableRef::Scalar(ScalarRef::log(self.ttl.max(1) as f64)));
visitor("tcp_window", WalkableRef::Scalar(ScalarRef::log(self.tcp_window.max(1) as f64)));
```

**Impact on detection:** TTL-based anomalies will now detect "OS class
changed" rather than "exact TTL value changed." A shift from TTL 64 to TTL
128 (Linux → Windows) registers as a significant change. A shift from TTL
64 to TTL 60 (same OS, different path) is minor noise.

**Impact on rules:** Rules still use discrete `(= ttl 64)` in the eBPF tree
— the encoding change only affects the Holon detection side. If we later want
range-based TTL rules (`(> ttl 200)`), the log-scaled encoding would make
Holon's anomaly detection naturally align with range predicates.

---

## Summary: Classical vs Holon Usage

| Concept | Classical VSA/HDC | Holon |
|---|---|---|
| Accumulator magnitude | Discarded (normalized away) | **Volume proxy** → rate derivation |
| Unbinding result | Direction query (content retrieval) | **Magnitude query** → cardinality |
| Superposition | Information storage | **Interference measurement** → correlation |
| Difference vector | Analogical reasoning (A:B::C:?) | **Per-field attribution** → blame |
| Scalar encoding | Not standard (discrete codebooks) | **Log-scale for fuzzy fields** → clustering |
| Baseline comparison | Nearest-neighbor in codebook | **Drift + spectrum** → anomaly + fingerprint |

The common thread: **every vector operation has two outputs — direction and
magnitude — and the literature only uses direction.** Holon uses both.
