# Holon and VSA/HDC: How Hyperdimensional Computing Drives DDoS Detection

**Summary:** This system uses Vector Symbolic Architecture (VSA) / Hyperdimensional Computing (HDC) to autonomously detect network anomalies and derive mitigation rules — with zero training data, zero signatures, and zero hardcoded thresholds. Every decision the system makes traces back to operations on high-dimensional vectors.

## Background: VSA/HDC in 60 Seconds

Vector Symbolic Architecture (Plate, 1995; Kanerva, 2009) represents structured data as high-dimensional vectors (~4096 dimensions). Three core operations:

| Operation | Symbol | What It Does | Property |
|---|---|---|---|
| **Binding** | ⊗ (XOR) | Associates two concepts: `role ⊗ filler` | Invertible, distributes over bundling |
| **Bundling** | + (majority) | Superimposes concepts: `A + B + C` | Result is similar to all inputs |
| **Permutation** | π (shift) | Creates sequence/structure | Distinguishes position |

The key insight: in high dimensions, **random vectors are nearly orthogonal**. This means you can superimpose thousands of bound pairs into a single vector and later query which pairs are present — because unrelated bindings cancel out statistically while matching bindings reinforce.

This gives you:
- **O(1) similarity** — cosine similarity between two vectors, regardless of content complexity
- **O(1) encoding** — bind and bundle operations are element-wise
- **Graceful degradation** — more noise reduces accuracy gradually, never catastrophically
- **No training** — the algebra works from the first observation

## How Holon Encodes Packets

### The Encoding: Structured Binding

Each packet sample is a structured record with named fields. Holon encodes it using the **MAP encoding** pattern from VSA:

```
packet_vector = Σ (role_vector ⊗ filler_vector)
              = (V_src_ip ⊗ V_"10.0.0.100")
              + (V_dst_port ⊗ V_9999)
              + (V_protocol ⊗ V_17)
              + (V_ttl ⊗ V_255)
              + (V_df_bit ⊗ V_0)
              + ...
```

Each field name (`src_ip`, `dst_port`, etc.) has a deterministic random **role vector** — a 4096-dimensional bipolar vector (`{+1, -1}`) generated from the field name via a seeded PRNG. Each field value (`"10.0.0.100"`, `9999`, etc.) has a deterministic **filler vector** generated from the value.

The binding operation (⊗) creates a vector that is dissimilar to both the role and the filler individually, but can be unbound later: `role ⊗ (role ⊗ filler) = filler` (because XOR is its own inverse).

The bundling operation (+) superimposes all the bound role-filler pairs into a single vector. The result is a holographic representation — every field is encoded everywhere in the vector, and no single dimension is "the TTL dimension."

In code, this happens through the `Walkable` trait:

```rust
impl Walkable for PacketSample {
    fn walk_map_visitor(&self, visitor: &mut dyn FnMut(&str, WalkableRef<'_>)) {
        visitor("src_ip", WalkableRef::string(&src_ip_str));
        visitor("dst_port", WalkableRef::int(self.dst_port as i64));
        visitor("protocol", WalkableRef::int(self.protocol as i64));
        visitor("ttl", WalkableRef::int(self.ttl as i64));
        visitor("df_bit", WalkableRef::int(self.df_bit as i64));
        // ... all fields
    }
}
```

Holon's `encode_walkable()` walks the structure and performs the bind+bundle algebra internally:

```rust
let vec: Vector = holon.encode_walkable(&sample);  // 4096-dim bipolar vector
```

### Semantic Fields: Enriching the Encoding

Beyond raw packet fields, the encoding includes **derived semantic fields** that help Holon group similar traffic:

| Field | Type | Purpose |
|---|---|---|
| `src_port_band` | "well_known" / "registered" / "ephemeral" | Distinguishes server vs client ports |
| `dst_port_band` | same | Same for destination |
| `direction` | "normal" / "response" / "peer" | Infers traffic direction from port ranges |
| `size_class` | "tiny" / "small" / "medium" / "large" / "jumbo" | Groups packet sizes |
| `pkt_len` | `ScalarValue::log(len)` | Logarithmic encoding — ratios matter, not absolutes |

These fields don't exist in the packet — they're computed from raw values. But because VSA encoding is compositional, they seamlessly coexist with raw fields in the same vector. The encoding for a packet is the superposition of ~12-14 bound pairs.

## How Holon Detects Anomalies

### Step 1: Baseline Accumulation (Bundling Over Time)

During warmup, the system accumulates packet vectors into a **baseline accumulator**:

```
baseline_acc += encode(packet_1)
baseline_acc += encode(packet_2)
...
baseline_acc += encode(packet_N)
```

In VSA terms, this is **bundling** — the accumulator becomes a superposition of all observed traffic. Role-filler pairs that appear frequently reinforce (their contributions add constructively), while rare or random patterns cancel out.

After warmup, the accumulator is normalized to a bipolar vector:

```
baseline_vec = sign(baseline_acc)    // +1 where positive, -1 where negative
```

This baseline vector is a **prototype** — a holographic summary of "what normal traffic looks like." It's similar (high cosine similarity) to any individual normal packet, and dissimilar to packets with unusual field combinations.

The baseline magnitude is also stored:

```
||baseline_per_window|| = ||baseline_acc|| / num_windows
```

This captures not just the *pattern* of traffic but its *volume* — crucial for rate derivation later.

### Step 2: Drift Detection (Cosine Similarity)

Each detection window accumulates recent packets the same way:

```
recent_acc += encode(packet)     // for each packet in the window
recent_vec = sign(recent_acc)     // normalize
```

Then **cosine similarity** measures how much the recent traffic resembles the baseline:

```
drift = similarity(recent_vec, baseline_vec)     // -1.0 to 1.0
```

In VSA, cosine similarity between bundled vectors measures **overlap in role-filler content**. If the recent window contains mostly the same field-value combinations as the baseline, `drift ≈ 1.0` (normal). If new combinations dominate (attack traffic with different TTL, ports, flags), `drift` drops.

The threshold is `0.85` — if `drift < 0.85`, the system investigates further.

This is classical **HDC classification**: the baseline vector is a class prototype, and each window is classified by its similarity to the prototype. No model, no weights, no training — just the algebra.

### Step 3: Similarity Profile (Per-Dimension Analysis)

When drift is low, `similarity_profile()` provides a **per-dimension breakdown** of agreement:

```rust
let profile = Primitives::similarity_profile(&recent_vec, &baseline_vec);
```

This produces a vector where each dimension indicates whether the recent and baseline vectors agree (+1), disagree (-1), or are ambiguous (0) at that dimension. The `anomalous_ratio` counts what fraction of active dimensions disagree.

In VSA terms, this is probing the **interference pattern** between two superpositions. Where the recent window introduced new role-filler bindings (attack traffic), those dimensions flip sign relative to the baseline. The profile reveals which dimensions carry the anomalous signal — though because VSA distributes information holographically, you can't read individual fields from individual dimensions. The concentration analysis (next step) does that.

### Step 4: Concentration Analysis (Field-Level Attribution)

While vector operations detect *that* something changed, **concentration analysis** identifies *what* changed:

```rust
let concentrated = tracker.find_concentrated_values(0.5);
// → [("ttl", "255", 1.0), ("df_bit", "0", 1.0), ("src_ip", "10.0.0.100", 1.0)]
```

This examines the raw field-value frequency distribution in the current window. If any single value dominates a field (>50% concentration) AND that value was NOT concentrated during baseline, it's flagged as anomalous.

The baseline exclusion is critical: `dst_port=8888` might be 100% concentrated in both baseline and attack (because all traffic goes to port 8888), so it's excluded. But `ttl=255` appearing at 100% when the baseline was `ttl=64` is a strong signal.

This is not a vector operation per se — it's a complementary analysis running in parallel. The vector drift triggers the investigation; the concentration analysis pinpoints the fields. Together they answer: "traffic changed (drift) because these specific field values appeared (concentration)."

### Step 5: Pattern Attribution (Invert)

```rust
let (pattern_name, confidence) = codebook.attribute(&recent_vec);
```

The codebook contains labeled prototype vectors (e.g., `"normal_baseline"`). `invert()` finds which prototype the recent window most resembles — this is the VSA **inverse** operation, querying a superposition to find the closest match from a set of known patterns.

### Step 6: Phase Detection (Segment)

```rust
let breakpoints = Primitives::segment(&window_history, 5, 0.7, SegmentMethod::Diff);
```

`segment()` analyzes the sequence of window vectors to find **phase transitions** — points where traffic character changes abruptly. This uses sequential similarity: comparing sliding windows of vectors to detect when the recent past diverges from the slightly-less-recent past.

In HDC terms, this is **temporal pattern analysis** on a sequence of holographic snapshots.

### Step 7: Subspace Anomaly Detection (OnlineSubspace / CCIPCA)

While drift detection operates on the normalized accumulator prototype, a parallel **manifold-aware detector** scores individual packet vectors against a learned subspace:

```
residual(x) = ||x − mean − Σ projᵢ(x) · componentᵢ||
```

During warmup, an `OnlineSubspace` (CCIPCA — Candid Covariance-free Incremental PCA, Weng et al. 2003) incrementally learns the k-dimensional manifold that normal traffic occupies in the 4096-dimensional encoded space. It tracks:

- A **running mean** of all observations
- **k unnormalized eigenvectors** whose L2 norms approximate eigenvalues
- An **adaptive threshold**: EMA(residual) + σ_mult × √variance

After warmup, each encoded packet is scored by projecting onto the learned components and measuring the reconstruction error. Normal packets lie near the learned manifold (low residual); packets with novel field combinations project poorly and produce high residuals.

The key advantage over cosine drift: the subspace detector works on **individual vectors** and fires on the **first anomalous tick**, not after accumulating a window of deviant traffic.

### Step 8: Engram Memory (Attack Pattern Library)

When an anomaly persists (≥5 consecutive ticks above threshold), the system **mints an engram** — a named snapshot of the attack's learned manifold:

```
Attack subspace (trained on 98 ticks of attack vectors)
    ↓ snapshot()
Engram { name, subspace_snapshot, eigenvalue_signature, surprise, metadata }
    ↓ add to library
EngramLibrary { engram_1, engram_2, ... }
```

On subsequent anomalies, the library is checked on the **first tick** using two-tier matching:

1. **Eigenvalue pre-filter** (O(k·n)) — ranks engrams by eigenvalue energy similarity
2. **Full residual** (O(k·dim)) — scores top candidates against their stored subspace

If a match is found (residual below the engram's own threshold × 2.0), stored mitigation rules are deployed **immediately** — bypassing drift accumulation and concentration analysis entirely. This closes the detection gap from seconds to milliseconds.

The engram also stores a **surprise fingerprint** computed at mint time — per-field attribution scores derived by unbinding the anomalous component with each field's role vector:

```
anomaly = x − reconstruct(x)          // out-of-subspace component
for each field:
    surprise[field] = ||bind(anomaly, role_field)||    // energy from that field
```

This exploits VSA's binding algebra: unbinding isolates how much each field contributed to the out-of-manifold direction.

## How Holon Derives Rate Limits

This is the part that makes the system fully autonomous. No hardcoded "normal rate." No hardcoded "attack threshold." Everything comes from the vector algebra.

### Magnitude as Volume

The L2 norm (magnitude) of an accumulator vector correlates with the number of observations bundled into it:

```
||acc|| ∝ √(n × d)     where n = packet count, d = dimensions
```

This isn't exact (correlated packets reinforce more than independent ones), but the ratio between two accumulators of the same traffic type is stable:

```
magnitude_ratio = ||recent_window_acc|| / ||baseline_per_window_acc||
```

If the attack window sees 25x the normal traffic volume, the accumulator magnitude is ~25x larger. This ratio is computed directly from the raw float accumulators (before normalization to bipolar):

```rust
fn compute_magnitude_ratio(&self) -> f64 {
    let recent_magnitude = self.recent_acc.iter()
        .map(|x| x * x).sum::<f64>().sqrt();
    recent_magnitude / self.baseline_magnitude_per_window
}
```

### Rate Factor from Magnitude

The rate factor is simply the inverse:

```
rate_factor = 1 / magnitude_ratio
```

If we're seeing 25x the baseline traffic → `rate_factor = 0.04` → allow 4% of current traffic through → which is approximately the baseline rate.

```
allowed_pps = estimated_current_pps × rate_factor ≈ baseline_pps
```

The rate limit converges to baseline PPS **without ever measuring or storing the baseline PPS directly.** It emerges from the magnitude ratio of two accumulators — a purely vector-derived quantity.

### The Complete Derivation

```
Packet samples → encode_walkable() → accumulate into recent_acc
                                    ↓
                            ||recent_acc|| / ||baseline_per_window||
                                    ↓
                            magnitude_ratio (e.g., 25.0)
                                    ↓
                            rate_factor = 1/25 = 0.04
                                    ↓
                            estimated_pps × 0.04 = ~baseline_pps
                                    ↓
                            RuleSpec { rate_pps: 2042 }
```

Every number in this chain traces back to vector operations on holographic packet encodings.

## How Rules Are Generated

The final step connects vector-derived knowledge to the Rete rule engine:

1. **Drift drops below threshold** — vector similarity says "something changed"
2. **Concentration analysis** identifies which fields changed — `ttl=255`, `df_bit=0`, `src_ip=10.0.0.100`
3. **Magnitude ratio** determines how much to throttle — 25x volume → allow 4%
4. **Compound rule compiled** from concentrated fields + derived rate:

```
((and (= ttl 255)
      (= df 0)
      (= src-addr 10.0.0.100)
      (= dst-port 9999))
 =>
 (rate-limit 2091))
```

5. **Tree recompiled** — the new rule joins the existing 1M rules in the DAG
6. **Blue/green flip** — atomically deployed to XDP
7. **BPF tail-call DFS** — enforced at line rate, ~5 tail calls per packet

The rule is a **crystallization of vector knowledge into discrete logic.** The VSA detected the anomaly, identified the fingerprint, and derived the rate. The Rete network enforces it.

## Comparison to Classical Approaches

| Aspect | Signature-Based | ML-Based | VSA/HDC (Ours) |
|---|---|---|---|
| Training data | Requires known attacks | Requires labeled datasets | **None** |
| New attack types | Misses them | Requires retraining | **Detects from first packet window** |
| Rate limit derivation | Hardcoded | Learned from data | **Emerges from vector magnitude ratio** |
| Rule generation | Manual | Offline model → rules | **Autonomous, real-time** |
| Encoding cost | N/A | Feature engineering | **O(1) per field, compositional** |
| Similarity cost | N/A | Model inference | **O(d) dot product, d=4096** |
| Interpretability | High (signatures are readable) | Low (black box) | **High (concentrated fields + s-expression rules)** |
| Time to first detection | Infinite (no signature) | Training time | **One window (~2 seconds)** |

## The VSA Primitives Used

| Primitive | Classical VSA Operation | How We Use It |
|---|---|---|
| `encode_walkable()` | MAP encoding: Σ(role ⊗ filler) | Packet → 4096-dim bipolar vector |
| `similarity()` | Cosine similarity | Drift detection: recent vs baseline |
| `similarity_profile()` | Per-dimension agreement | Anomalous dimension identification |
| `invert()` | Resonator / nearest-neighbor in codebook | Pattern attribution |
| `segment()` | Sequential similarity analysis | Phase change detection |
| `analogy()` | Algebraic analogy: A⊗B⊗C → D | Zero-shot attack variant detection |
| Accumulator bundling | Superposition: A + B + C + ... | Baseline learning, window aggregation |
| Magnitude ratio | L2 norm ratio of accumulators | Volume estimation, rate derivation |
| `OnlineSubspace` (CCIPCA) | Incremental PCA on encoded vectors | Learn k-dimensional manifold of normal traffic; residual = anomaly score |
| `EngramLibrary` | Subspace snapshot memory with two-tier matching | Store attack manifolds; instant re-detection via eigenvalue pre-filter → full residual |
| `anomalous_component()` | Reconstruction residual: x − reconstruct(x) | Isolate out-of-subspace signal for surprise fingerprinting |
| Surprise fingerprint | Unbind anomalous component with role vectors | Per-field attribution: which fields drove the anomaly |

## The Key Insight

Classical DDoS systems ask: **"Does this packet match a known bad pattern?"**

This system asks: **"Does recent traffic look different from normal traffic in vector space?"**

The first question requires knowing what "bad" looks like in advance. The second question only requires knowing what "normal" looks like — and the system learns that automatically during warmup.

When the answer is "yes, it's different," the system doesn't just raise an alert. It identifies *which fields* characterize the difference, *how much* to throttle based on volume ratio, compiles a compound rule from those fields, and enforces it at kernel line rate across a million-rule decision tree. Every step is derived, not configured.

That's what VSA/HDC buys you: a mathematical framework where similarity, composition, and decomposition are all cheap O(d) operations on fixed-size vectors. The algebra does the thinking.
