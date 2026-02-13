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
