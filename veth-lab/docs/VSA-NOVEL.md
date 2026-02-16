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

## 7. The Holon-rs Primitive Library: Kernel Design

### Design Philosophy

Holon-rs is modeled after two design precedents:

- **Linux kernel:** Provides syscalls, scheduling, memory management.
  Applications build everything else.
- **Clojure core:** Provides persistent data structures, sequences,
  transducers. Applications build everything else.
- **Holon-rs:** Provides vectors, binding, bundling, similarity, encoding.
  Applications build everything else.

The library boundary is: **given structured data, produce vectors. Given
vectors, perform algebra.** Everything domain-specific — anomaly detection,
rate derivation, rule generation, tree compilation — lives in "userland"
(the sidecar). The library has no concept of packets, attacks, or network
traffic.

This boundary was a deliberate design choice, debated extensively. The
temptation was to build "anomaly detection" into the library. The
counter-argument (which won): the magnitude-as-volume trick, the
unbinding-as-cardinality trick, the interference detection — none of these
were predictable at library design time. They emerged from creative
application of general primitives. If the library had a built-in "detect
anomaly" function, it would have normalized the accumulator (destroying
magnitude information) because that's what the literature says to do.

**The less the library assumes, the more the application can discover.**

### The Full Primitive Inventory

The library provides far more than the DDoS lab currently uses. Here's the
complete inventory, with usage status and potential DDoS applications:

#### Encoding Primitives

| Primitive | Used in DDoS | Potential Application |
|---|---|---|
| `encode_walkable()` | **Yes** | Zero-serialization packet encoding |
| `encode_json()` | No | Rule file encoding (EDN/JSON rules as vectors) |
| `encode_sequence(Bundle)` | No | Unordered packet burst encoding |
| `encode_sequence(Positional)` | No | **Ordered flow encoding** (SYN→SYN-ACK→ACK as a sequence) |
| `encode_sequence(Chained)` | No | Protocol state machine encoding |
| `encode_sequence(Ngram)` | No | **Packet n-gram patterns** (detect recurring 3-packet motifs) |
| `ScalarValue::log()` | **Yes** (pkt_len) | TTL, tcp_window (proposed in this doc) |
| `ScalarValue::linear()` | No | Inter-arrival time encoding |
| `ScalarValue::circular()` | No | **Time-of-day encoding** (hour 23 ≈ hour 0) |

**Sequence encoding is the big untapped one.** Currently each packet is
encoded independently. But network traffic has temporal structure: a TCP
handshake is SYN → SYN-ACK → ACK. An HTTP request is SYN → ... → PSH →
FIN. Encoding packet *sequences* (not just individual packets) would let
Holon detect anomalous *flows*, not just anomalous packets.

The `Ngram` mode is particularly interesting: encode every 3-packet window
as a vector. The accumulator of 3-grams becomes a representation of "what
packet sequences are normal." A novel attack sequence (SYN → RST → SYN →
RST → ...) would show up as a drift in the 3-gram accumulator even if
individual packets look normal.

**Circular encoding** is interesting for time-based features. If we encode
the hour of day circularly, traffic at 23:00 and 01:00 are "close" — which
is correct (they're both late-night traffic). Linear encoding would make
them distant (22 hours apart on a 0-23 scale).

#### Core VSA Primitives

| Primitive | Used in DDoS | Potential Application |
|---|---|---|
| `bind(a, b)` | **Yes** (in encoder) | Role-filler association |
| `unbind(bound, key)` | Not directly | **Per-field cardinality** (proposed in this doc) |
| `bundle(vectors)` | **Yes** (in encoder) | Superposition of bound pairs |
| `weighted_bundle()` | No | **Confidence-weighted accumulation** (weight recent packets higher) |
| `negate(super, component)` | No | **Remove known traffic pattern from accumulator** |
| `amplify(super, component, k)` | No | Strengthen a weak signal in noise |
| `prototype(vectors, threshold)` | No | **Extract common pattern across attack windows** |
| `prototype_add(proto, example, n)` | No | Incremental attack profile update |
| `difference(before, after)` | No | **Continuous attribution** (proposed in this doc) |
| `blend(a, b, alpha)` | No | Interpolate between two attack profiles |
| `resonance(vec, ref)` | No | **Extract only the agreeing dimensions** between two windows |
| `permute(vec, k)` | No | Sequence position encoding |
| `cleanup(noisy, codebook)` | No | Classify noisy packet vector to nearest known pattern |

**`negate` is powerful and unused.** Imagine: you've detected a DNS
amplification attack and generated a rule for it. But the overall traffic
still drifts. Is there a SECOND attack hidden under the first? Use `negate`
to remove the known DNS attack pattern from the accumulator:

```rust
let cleaned = Primitives::negate(&recent_acc, &known_dns_attack_pattern);
// Now compute drift on `cleaned` — does the REMAINDER still drift?
// If yes: there's a second attack hiding under the first.
```

This is **peeling** — removing known signals to expose hidden ones. It's
how radio engineers separate overlapping signals. In the DDoS context, it
lets you detect layered attacks where one attack masks another.

**`prototype` extracts the common pattern across multiple vectors.** If you
have 10 anomalous windows, `prototype` gives you the "essence" of the
anomaly — what all 10 windows share. This is a more robust attack profile
than any single window.

**`resonance` filters a vector to keep only dimensions that agree with a
reference.** Apply it to a recent window + baseline: you get a vector
containing ONLY the dimensions where traffic matches the baseline. Everything
else (the anomaly) is zeroed out. The complement (recent - resonance) is
the pure anomaly signal with baseline noise removed.

**`weighted_bundle` could weight recent packets higher** — a form of
exponential decay within a window. The last 100 packets matter more than
the first 100 packets in a window because attacks ramp up.

#### Extended Algebra

| Primitive | Used in DDoS | Potential Application |
|---|---|---|
| `similarity_profile(a, b)` | **Yes** | Per-dimension agreement vector |
| `attend(query, memory, str, mode)` | No | **Attention-weighted anomaly scoring** |
| `analogy(a, b, c)` | **Yes** | Zero-shot attack variant detection |
| `project(vec, subspace, ortho)` | No | **Extract specific field subspace from accumulator** |
| `conditional_bind(a, b, gate, mode)` | No | **Selective encoding** (only encode fields that are active) |
| `complexity(vec)` | No | **Measure how mixed/structured a window is** |
| `invert(vec, codebook, k, threshold)` | **Yes** | Pattern attribution to known attack types |
| `segment(stream, window, threshold)` | **Yes** | Phase change detection |

**`attend` is the bridge to transformers.** In Hard mode, it's a gate that
passes only dimensions where query matches memory. In Soft mode, it's a
weighted modulation. In Amplify mode, it boosts matching dimensions.

Applied to DDoS: the "query" is the current window, the "memory" is the
baseline. `attend(recent, baseline, strength, Soft)` produces a vector that
emphasizes dimensions where recent traffic AGREES with baseline. The
complement emphasizes where they disagree. This is a softer version of
`resonance` with a tuneable strength parameter.

**`project` extracts a subspace.** Given a set of role vectors, project the
accumulator onto that subspace to get ONLY the contribution of those fields.
This is a cleaner version of unbinding for multi-field extraction:

```rust
// Extract the [src_ip, src_port] subspace
let attack_source_profile = Primitives::project(
    &recent_vec,
    &[role_src_ip.clone(), role_src_port.clone()],
    false,  // don't orthogonalize (we want overlap if it exists)
);
```

**`complexity` measures how "mixed" a vector is.** A pure signal (one
dominant pattern) has low complexity. A superposition of many patterns has
high complexity. For traffic: low complexity = homogeneous (possibly attack).
High complexity = diverse (possibly normal). This is a single-number
anomaly signal that doesn't require a baseline.

**`conditional_bind` with gating** could enable per-protocol encoding: only
bind TCP-specific fields (tcp_flags, tcp_window) when the protocol dimension
is active. This is already done manually in the Walkable impl (`if proto == 6`),
but `conditional_bind` makes it algebraic rather than procedural.

#### Streaming & Similarity

| Primitive | Used in DDoS | Potential Application |
|---|---|---|
| `accumulator.add()` | **Yes** | Frequency-preserving accumulation |
| `accumulator.add_weighted()` | No | Importance-weighted packets |
| `accumulator.decay(factor)` | No | **Exponential forgetting** (recent > old) |
| `accumulator.merge(other)` | No | **Parallel accumulation** (multi-core) |
| `similarity(Cosine)` | **Yes** | Drift detection |
| `similarity(Hamming)` | No | Structural similarity (count of agreeing dims) |
| `similarity(Overlap)` | No | Non-zero agreement (ignore inactive dimensions) |

**`decay` is unused but important.** Currently the accumulator sums all
packets equally within a window, then resets. With decay, old packets
contribute less — the accumulator naturally forgets. This would let you use
a **single continuous accumulator** instead of windowed resets:

```rust
// Every N packets, decay the accumulator slightly
accumulator.decay(0.99);  // multiply all sums by 0.99
accumulator.add(&new_packet_vec);
```

Over time, the accumulator converges to a running average weighted toward
recent traffic. No window boundaries needed. Drift becomes continuous
instead of discrete.

**`merge` enables parallel accumulation.** If multiple cores process packet
samples, each maintains a local accumulator. Periodically merge them. This
is important at high PPS where a single-threaded accumulation loop is a
bottleneck.

### What the Library Design Enables

The key insight from this inventory: **most of the unused primitives have
direct applications to DDoS detection that weren't envisioned at library
design time.** This validates the kernel-like boundary:

| Primitive | Designed For | Discovered Application |
|---|---|---|
| `negate` | Removing known concepts | **Attack peeling** (layered attack detection) |
| `prototype` | Common pattern extraction | **Robust attack profile** from multiple windows |
| `resonance` | Agreement filtering | **Anomaly isolation** (remove baseline agreement) |
| `attend` | Transformer-like attention | **Soft anomaly scoring** with tuneable sensitivity |
| `complexity` | Vector introspection | **Single-number anomaly signal** (no baseline needed) |
| `sequence(Ngram)` | Text/sequence patterns | **Flow anomaly detection** (packet sequence motifs) |
| `decay` | Time-weighted streaming | **Continuous detection** (no window boundaries) |
| `circular` | Periodic features | **Time-of-day baseline** (late night ≈ early morning) |

Not a single one of these was "designed for DDoS." They're algebraic
primitives that happen to have network security applications. The library
authors (you, with Grok's help) couldn't have predicted the
magnitude-as-volume trick because the library was designed to normalize
magnitudes away. The trick was discovered by a different "userland"
application that looked at the raw accumulator differently.

This is the Linux kernel analogy in action: `mmap` was designed for file
I/O. It turned out to be the foundation of shared memory, memory-mapped
databases, and zero-copy networking. The primitive was more general than its
original use case. Holon's primitives are the same.

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
| Negation | Remove concept from memory | **Attack peeling** → layered detection |
| Sequence encoding | Text/NLP | **Flow-level anomaly** → protocol motifs |
| Complexity | Vector quality metric | **Single-number anomaly** → no baseline needed |
| Decay | Forgetting in memory | **Continuous detection** → no window boundaries |
| Library boundary | Application-specific APIs | **General primitives** → emergent applications |

The common thread: **every vector operation has two outputs — direction and
magnitude — and the literature only uses direction.** Holon uses both.

And the meta-insight: **a library that provides less domain-specific
functionality enables more domain-specific discovery.** The primitives you
don't use today are the tricks you'll discover tomorrow.

---

## 8. Coherence as Baseline-Free Attack Detection (Proposed)

### Classical View

Anomaly detection requires a baseline: accumulate normal traffic, then
measure drift from that baseline. If you don't have a baseline (cold start,
model reset, corrupted state), you can't detect anything.

### What We Propose

Use `coherence(vectors)` — mean pairwise cosine similarity — as a
**baseline-free** attack signal. Coherence measures how *homogeneous* a
set of vectors is, without any reference to what "normal" looks like:

```python
window_vecs = [encode(pkt) for pkt in recent_window]
c = coherence(window_vecs)
# c → 0.0: diverse traffic (likely normal)
# c → 1.0: homogeneous traffic (likely attack)
```

Normal traffic is diverse: different source IPs, different protocols,
different payload sizes. Coherence near 0 (vectors are nearly orthogonal).
DDoS traffic is repetitive: same source pattern, same protocol, same
payload profile. Coherence near 1 (vectors are nearly identical).

### Why This Is Novel

This exploits the **distribution of pairwise similarity** within a window —
a property no VSA/HDC paper uses. Standard VSA asks "is this vector
similar to that reference?" (point comparison). Coherence asks "are these
vectors similar to *each other*?" (distribution property). No baseline,
no codebook, no training. Just measure the internal structure of a window.

### Combined with Significance

Raw coherence is a number. But is 0.15 "high enough" to be suspicious?
`significance(coherence, dimensions)` converts it to a z-score:

```python
z = significance(coherence_val, dimensions)
# z > 3.0 → statistically significant homogeneity (p < 0.003)
# z > 5.0 → essentially certain attack signal
```

This eliminates magic thresholds. The math tells you whether the observed
coherence is explainable by chance.

---

## 9. Drift Rate for Attack Onset Classification (Proposed)

### Classical View

Drift detection is binary: similarity dropped below threshold → alert.
The operational response is the same regardless of how the similarity
dropped.

### What We Propose

Use `drift_rate(stream, window)` — the temporal derivative of similarity —
to classify the *type* of attack onset:

```python
rates = drift_rate(window_vectors, window=1)
# Classify by drift shape:
#   - Gradual negative drift → organic growth (don't throttle)
#   - Massive negative spike  → flash flood (block immediately)
#   - Accelerating negative   → ramp-up attack (escalate response)
```

### The Three Regimes

| Drift Pattern | Interpretation | Response |
|---|---|---|
| Low magnitude, steady | Organic traffic growth | No action |
| Large negative spike (< -0.5) | Flash flood DDoS | Immediate block |
| Accelerating negative | Ramp-up attack | Progressive throttle |
| Oscillating ±0.1 | Pulsed / rotating attack | Pattern-based blocking |

Same raw similarity data, fundamentally different operational responses.
A flash flood and a gradual shift both produce "low similarity to baseline"
but require opposite responses (instant block vs. gradual adaptation).

### Why This Is Novel

Standard anomaly detection measures *state* (how different is current from
baseline). Drift rate measures the *dynamics* (how fast is the state
changing). This is the difference between a thermometer reading (current
temperature) and its derivative (heating or cooling rate). Both are useful.
Neither subsumes the other.

---

## 10. Bundle with Confidence for Trust-Aware Drift (Proposed)

### Classical View

When bundling vectors (majority vote), all dimensions are treated equally.
The resulting bipolar vector discards the margin of victory per dimension.
A 512-to-512 vote is the same as a 1000-to-24 vote.

### What We Propose

Use `bundle_with_confidence(vectors)` to preserve per-dimension agreement
margins, then feed these into `weighted_cosine_similarity` for drift
detection that trusts high-confidence dimensions more:

```python
baseline_vec, margins = bundle_with_confidence(baseline_vectors)

# Use margins as weights for drift detection
drift = 1.0 - weighted_cosine_similarity(recent_vec, baseline_vec, margins)
```

### Why This Matters for DDoS

In packet traffic, some fields have strong consensus in the baseline (e.g.,
all traffic goes to the same `dst_ip` → margin = 1.0). Other fields are
noisy (e.g., `src_port` is ephemeral → margin near 0). Standard cosine
drift weights both equally. Weighted cosine focuses on the fields that
matter — detecting when the stable `dst_ip` suddenly diversifies while
ignoring normal `src_port` churn.

The confidence margins are essentially a learned feature importance that
emerges from the data, without any machine learning.

### Why This Is Novel

VSA bundles discard margin information. We preserve it and use it as a
**trust signal** — a per-dimension measure of how much the baseline "knows"
about each dimension. This is conceptually similar to Fisher information
in statistics: dimensions with high confidence carry more signal.

---

## 11. Reject for Novel Attack Isolation (Proposed)

### Classical View

`project(vec, subspace)` extracts the component of a vector that lies
within a known subspace. Used for: "how much does this look like known
pattern X?"

### What We Propose

Use `reject(vec, subspace)` — the orthogonal complement of project — to
extract what CANNOT be explained by known patterns:

```python
# Build subspace from known attack profiles
known_attacks = [dns_amplification_profile, syn_flood_profile, udp_flood_profile]

# What part of this traffic isn't any known attack?
residual = reject(anomalous_traffic, known_attacks)

# If residual has high magnitude → novel attack vector
novelty = cosine_similarity(anomalous_traffic, residual)
```

### The Peeling Pipeline

Combined with `negate`, this enables layered attack discovery:

```
1. Detect anomaly (similarity drift)
2. Project onto known attacks → identify known component
3. Reject known attacks → isolate novel component
4. If novel residual is significant → new attack type discovered
5. Negate the known attack → re-examine remaining traffic
6. Repeat until residual is noise
```

This is iterative signal separation — the same principle as independent
component analysis (ICA) but using VSA algebra.

### Why This Is Novel

VSA uses projection for membership testing ("is this in my subspace?").
Using the complement — what's NOT in the subspace — as an operational
signal for novel pattern discovery appears to be new. It's the difference
between asking "do I recognize this?" and "what don't I recognize?"

---

## 12. Purity and Complexity as Baseline-Free Multi-Signal Detection (Proposed)

### Classical View

Anomaly detection requires a baseline. No baseline → no detection.

### What We Propose

Combine three baseline-free measures for anomaly detection without any
reference state:

| Measure | What It Captures | Normal Traffic | Attack Traffic |
|---|---|---|---|
| `coherence()` | Window homogeneity | Low (~0) | High (~1) |
| `complexity()` | Pattern mixedness | High (~1) | Low (~0) |
| `purity()` | Accumulator concentration | Low (~1/N) | High (~1) |

These three are conceptually related but mathematically independent:
- **Coherence** measures pairwise similarity between individual packets
- **Complexity** measures entropy of the dimension distribution
- **Purity** measures accumulator concentration (quantum-inspired)

```python
# Three independent baseline-free signals
c = coherence(window_vecs)
x = complexity(accumulated_vec)
p = purity(accumulator)

# Combined score (all three point the same direction for attacks)
anomaly_score = c * (1 - x) * p
```

### Why This Matters

Cold start is the Achilles heel of baseline-based detection. When the
sidecar starts, the first N seconds have no baseline. With these three
measures, you can detect attacks from the first window — no warmup needed.

Also useful for **baseline corruption**: if an attacker slowly ramps up
over hours (boiling frog), the baseline drifts with the attack. Similarity
to baseline stays high. But coherence/complexity/purity still detect the
homogeneity of attack traffic.

### Why This Is Novel

Using quantum-inspired purity alongside classical coherence and information-
theoretic complexity as three independent axes of the same phenomenon
(traffic homogeneity) appears to be new. Each measures a different
mathematical property of the same underlying signal.

---

## 13. Decode Scalar Log: Closing the Rate Limiting Loop (Proposed)

### Classical View

VSA encodes information into vectors. Decoding back to scalar values is
not a standard operation — vectors are compared by similarity, not decoded.

### What We Propose

Use `decode_scalar_log(vec)` to recover scalar values from rate-encoded
vectors. This closes the loop on vector-derived rate limiting (Batch 013):

```python
# Encode baseline rate
baseline_rate_vec = encode_scalar_log(100.0, 4096)  # 100 pps baseline

# Accumulate rate observations
for rate in observed_rates:
    accumulate(acc, encode_scalar_log(rate, 4096))

# Decode back to actual PPS
effective_rate = decode_scalar_log(normalize(acc))
# → ~100.0 pps (the consensus rate from all observations)
```

### The Full Rate Limiting Pipeline

```
1. Encode each window's packet rate: encode_scalar_log(rate)
2. Accumulate rate vectors (frequency-preserving)
3. Compute drift: similarity(current_rate_vec, baseline_rate_vec)
4. Compute significance: significance(drift, dimensions)
5. Decode consensus rate: decode_scalar_log(normalized_accumulator)
6. Generate rate limit rule: limit_pps = decoded_rate * (1 + tolerance)
```

Every step is a vector operation. The rate limit emerges from the algebra.

### Why This Is Novel

Bidirectional encoding (scalar → vector → scalar) with lossy but useful
round-tripping. The decoded value isn't the exact input — it's the
**consensus** of all accumulated observations, weighted by frequency.
This is implicit averaging in vector space without ever computing a mean.

---

## Updated Summary: Classical vs Holon Usage

| Concept | Classical VSA/HDC | Holon |
|---|---|---|
| Accumulator magnitude | Discarded (normalized away) | **Volume proxy** → rate derivation |
| Unbinding result | Direction query (content retrieval) | **Magnitude query** → cardinality |
| Superposition | Information storage | **Interference measurement** → correlation |
| Difference vector | Analogical reasoning (A:B::C:?) | **Per-field attribution** → blame |
| Scalar encoding | Not standard (discrete codebooks) | **Log-scale for fuzzy fields** → clustering |
| Baseline comparison | Nearest-neighbor in codebook | **Drift + spectrum** → anomaly + fingerprint |
| Negation | Remove concept from memory | **Attack peeling** → layered detection |
| Sequence encoding | Text/NLP | **Flow-level anomaly** → protocol motifs |
| Complexity | Vector quality metric | **Single-number anomaly** → no baseline needed |
| Decay | Forgetting in memory | **Continuous detection** → no window boundaries |
| **Coherence** | Not used | **Baseline-free homogeneity** → cold-start detection |
| **Drift rate** | Not used | **Attack dynamics** → onset classification |
| **Confidence margins** | Discarded in bundling | **Trust weights** → dimension-aware drift |
| **Subspace rejection** | Not used | **Novel pattern isolation** → residual analysis |
| **Purity** | Not used (quantum concept) | **Accumulator health** → concentration signal |
| **Scalar decode** | Not standard | **Rate recovery** → closed-loop rate limiting |
| **Significance** | Not used | **Principled thresholds** → dimension-aware z-scores |
| Library boundary | Application-specific APIs | **General primitives** → emergent applications |

The expanded common thread: **vectors have more measurable properties than
the literature uses.** Direction, magnitude, pairwise distribution,
temporal derivative, per-dimension confidence, subspace residuals, spectral
purity — each carries independent signal. Traditional VSA exploits one
(direction via cosine similarity). This system exploits all of them.
