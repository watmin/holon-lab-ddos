# Quantum-Inspired Techniques for VSA/HDC

**Where the analogy between VSA superposition and quantum superposition
is real, where it breaks down, and what we can steal from quantum
information theory.**

---

## The Real Analogy

This isn't metaphorical. The mathematical parallels are specific:

| Quantum Mechanics | VSA/HDC (Holon) | Shared Math |
|---|---|---|
| Quantum state `|ψ⟩` | Vector (4096-dim bipolar) | High-dimensional state vectors |
| Superposition `α|0⟩ + β|1⟩` | Bundle `A + B + C` | Linear combination of states |
| Measurement → collapse | Normalize → threshold to bipolar | Continuous → discrete |
| Amplitude `|α|²` = probability | Magnitude `||acc||` = volume | Squared norm as observable |
| Entanglement | `bind(A, B)` | Joint state ≠ product of parts |
| Interference | Constructive/destructive bundling | Same sign = reinforce, opposite = cancel |
| Decoherence | Accumulator saturation | Noise drowns out signal |
| Born rule `P = |⟨ψ|φ⟩|²` | `similarity(a, b)²` ≈ pattern presence | Inner product squared |

The accumulator IS a quantum-like state. It holds continuous amplitudes
(f64 sums) that represent the superposition of all observed patterns. Each
pattern exists simultaneously in the same 4096-dimensional space, interfering
constructively (similar patterns reinforce) and destructively (different
patterns cancel).

---

## Technique 1: Weak Measurement (Already Doing This)

### Quantum Concept

In quantum mechanics, a "strong measurement" collapses the wave function —
you get a definite outcome but destroy the superposition. A "weak
measurement" extracts partial information while preserving the state.

### VSA Application

**We already do this and didn't name it.**

The accumulator (f64 sums) is the "quantum state." Normalizing to bipolar
is "strong measurement" — it collapses the continuous amplitudes to {+1, -1}.
After normalization, the amplitude information is gone.

But the magnitude-based rate derivation reads the amplitude BEFORE
normalizing. It's a weak measurement — it extracts the volume signal
(`||acc||`) without collapsing the state. The accumulator continues
accumulating.

**What else can we weakly measure?**

| Weak Measurement | What It Extracts | Quantum Analogue |
|---|---|---|
| `||acc||` (magnitude) | Volume / packet count | Amplitude |
| `||acc|| / count` (mag ratio) | Diversity / cardinality | Purity |
| `variance_per_dim(acc)` | Dimension stability | Coherence |
| `kurtosis(acc)` | Tail heaviness | Higher-order moments |
| `acc.sums.iter().map(|x| x*x).sum() / (||acc||²)` | Concentration ratio | Participation ratio |

All of these extract information from the continuous accumulator without
thresholding it. The rate derivation proved that one weak measurement
(magnitude) is operationally useful. There are more.

### Practical Addition: `participation_ratio(acc) → f64`

The participation ratio measures how many dimensions "participate" in the
accumulator's energy:

```rust
fn participation_ratio(sums: &[f64]) -> f64 {
    let sum_sq: f64 = sums.iter().map(|x| x * x).sum();
    let sum_4th: f64 = sums.iter().map(|x| x.powi(4)).sum();
    if sum_4th < 1e-10 { return 0.0; }
    (sum_sq * sum_sq) / (sums.len() as f64 * sum_4th)
}
```

- PR ≈ 1.0: energy spread across all dimensions (diverse traffic)
- PR ≈ 0.01: energy concentrated in few dimensions (dominated by one pattern)

This is a weak measurement that detects concentration WITHOUT requiring a
baseline. It works from packet 1.

---

## Technique 2: Error-Correcting Vector Design

### Quantum Concept

Quantum error correction (QEC) encodes logical qubits across multiple
physical qubits using codes (surface codes, stabilizer codes). A single
qubit error doesn't destroy the logical information because the code has
built-in redundancy.

### VSA Application

The 4096-dimensional vector is already a form of error correction — any
single dimension can be flipped (by noise, by interference from bundling)
and the vector is still recognizable by similarity. The "code distance"
is roughly `d/2` — you can corrupt half the dimensions and still have
positive similarity.

But the current vectors are RANDOM. Random codes are good on average but
not optimal. Coding theory has spent 70 years designing codes that are
better than random.

**Proposal:** Instead of random vectors for atoms, use vectors sampled
from known error-correcting codes:

| Code Family | Min Distance | Capacity Gain | Complexity |
|---|---|---|---|
| Random (current) | ~d/2 | Baseline | O(1) per vector |
| BCH codes | Configurable | ~20% improvement | O(d log d) |
| Reed-Solomon | Configurable | ~20% improvement | O(d log d) |
| LDPC codes | Near Shannon | ~40% improvement | O(d) |
| Polar codes | Capacity-achieving | ~50% improvement | O(d log d) |

"Capacity gain" means: for the same 4096 dimensions, you can bundle MORE
items before retrieval accuracy degrades. This directly translates to more
patterns in the baseline, more rules derivable, more robust accumulators.

### What to Try First

The simplest experiment: replace the ChaCha8-based random vector generation
with a **Hadamard matrix** row selection. Hadamard matrices have rows that
are exactly orthogonal (not just approximately orthogonal like random
vectors). For 4096 dimensions, a Hadamard matrix gives 4096 perfectly
orthogonal vectors.

```rust
fn hadamard_vector(index: usize, dimensions: usize) -> Vector {
    // Walsh-Hadamard: bit_i = popcount(index & i) % 2
    let data: Vec<i8> = (0..dimensions)
        .map(|i| if (index & i).count_ones() % 2 == 0 { 1 } else { -1 })
        .collect();
    Vector::from_data(data)
}
```

Perfectly orthogonal base vectors mean zero cross-talk in binding. This
should improve accumulator capacity and similarity precision for free.

**Trade-off:** Hadamard rows are structured, not random. The Johnson-
Lindenstrauss property (random projection preserves distances) relies on
randomness. Need to verify experimentally that Hadamard-based encodings
still preserve structural similarity.

---

## Technique 3: Amplitude Amplification (Grover for VSA)

### Quantum Concept

Grover's algorithm finds a marked item in an unsorted database of N items
in O(√N) queries instead of O(N). The key operation is amplitude
amplification: iteratively boost the amplitude of the target state while
suppressing non-target states.

### VSA Application

We already have `attend(query, memory, strength, Amplify)` — this amplifies
dimensions of `memory` that match `query`. One application is a one-shot
operation.

But Grover's insight is that ITERATION matters. Applying amplitude
amplification once gives a small boost. Applying it `O(√N)` times gives
near-certainty. Over-applying it (more than `O(√N)` times) actually
REDUCES the signal — the amplitude "rotates past" the target.

**Iterative attention for weak signal detection:**

```rust
fn grover_amplify(
    signal: &Vector,
    accumulator: &Vector,
    iterations: usize,
) -> Vector {
    let mut amplified = accumulator.clone();

    for _ in 0..iterations {
        // Amplify dimensions matching the signal
        amplified = Primitives::attend(&signal, &amplified, 1.5, AttendMode::Amplify);
        // Reflect about the mean (Grover's diffusion operator)
        amplified = reflect_about_mean(&amplified);
    }

    amplified
}

fn reflect_about_mean(vec: &Vector) -> Vector {
    let mean: f64 = vec.data().iter().map(|&x| x as f64).sum::<f64>()
        / vec.dimensions() as f64;
    let data: Vec<i8> = vec.data().iter()
        .map(|&x| {
            let reflected = 2.0 * mean - (x as f64);
            if reflected > 0.0 { 1 } else if reflected < 0.0 { -1 } else { 0 }
        })
        .collect();
    Vector::from_data(data)
}
```

**Use case:** Detecting a weak attack signal buried in normal traffic. A
single similarity check might show drift=0.82 (below threshold). But 3
iterations of Grover amplification could boost the attack signal above
threshold.

**The over-rotation risk is real.** Too many iterations inverts the signal.
The optimal number of iterations depends on the signal-to-noise ratio.
For VSA with ~N items bundled, optimal iterations ≈ `π/4 * √(N)`.

### Worth Trying?

**Yes, with caution.** The discrete bipolar vectors don't have the
continuous phase that makes quantum Grover work perfectly. But the
principle — iterative amplification with reflection — should still boost
weak signals. Experiments needed to find the practical iteration count.

---

## Technique 4: Purity as a Detection Signal

### Quantum Concept

The purity of a quantum state `Tr(ρ²)` measures how "pure" vs "mixed" it
is. A pure state (single vector) has purity 1. A maximally mixed state
(uniform distribution over all states) has purity `1/d`.

### VSA Application

The accumulator's purity measures how dominated it is by a single pattern:

```rust
fn purity(sums: &[f64]) -> f64 {
    let sum_sq: f64 = sums.iter().map(|x| x * x).sum();
    let sum_4th: f64 = sums.iter().map(|x| x.powi(4)).sum();
    let d = sums.len() as f64;

    // Normalize: 1/d for maximally mixed, 1.0 for pure
    (d * sum_4th) / (sum_sq * sum_sq)
}
```

| Traffic State | Purity | Interpretation |
|---|---|---|
| Single attack pattern | ~1.0 | Pure — one dominant pattern |
| Normal (diverse) | ~0.1 | Mixed — many patterns superimposed |
| Two concurrent attacks | ~0.5 | Partially pure — few dominant patterns |
| Accumulator saturated | ~1/d ≈ 0 | Maximally mixed — no structure |

**This is different from drift.** Drift measures HOW MUCH traffic changed.
Purity measures HOW CONCENTRATED the current traffic is. You can have high
purity with low drift (traffic is concentrated but matches baseline) or
low purity with high drift (traffic is diverse but shifted).

**Purity × drift gives a 2D detection space:**

```
                    High Purity
                        |
         Attack         |      Targeted normal
        (detect!)       |      (focused service)
                        |
  Low Drift ————————————+———————————— High Drift
                        |
        Normal          |      Diverse shift
        (ignore)        |      (investigate)
                        |
                    Low Purity
```

### Implementation

Add to the detection loop alongside drift:
```rust
let purity = purity(&self.recent_acc.raw_sums());
let drift = self.holon.similarity(&recent_vec, &baseline_vec);

match (drift < 0.85, purity > 0.5) {
    (true, true)  => "ATTACK: concentrated anomalous traffic",
    (true, false) => "SHIFT: diverse anomalous traffic (investigate)",
    (false, true) => "FOCUSED: concentrated but normal (known service)",
    (false, false) => "NORMAL: diverse normal traffic",
}
```

---

## Technique 5: Partial Trace (Field Marginalization)

### Quantum Concept

Given a composite quantum system AB, the partial trace over B gives the
reduced state of A — what you know about A when you ignore B.

### VSA Application

The accumulator contains ALL fields superimposed. Unbinding extracts one
field but leaves noise from the others. A partial trace would EXACTLY
marginalize over unwanted fields, giving a clean per-field distribution.

For VSA, the "partial trace" over field F is:

```rust
fn partial_trace(accumulator: &Accumulator, role_vectors: &[&Vector], keep_field: &Vector) -> Vector {
    // Unbind with the field we want to keep
    let unbound = Primitives::bind(&accumulator.normalize(), keep_field);

    // The result contains the distribution of values for keep_field,
    // plus noise from cross-terms of other fields.
    // To reduce noise: project OUT the known cross-term directions.
    let noise_directions: Vec<&Vector> = role_vectors.iter()
        .filter(|r| !std::ptr::eq(**r, keep_field))
        .map(|r| *r)
        .collect();

    // Gram-Schmidt orthogonalization removes known interference
    Primitives::project(&unbound, &noise_directions, true)  // orthogonalize = true removes these directions
}
```

**This gives a cleaner per-field extraction than plain unbinding.** The
`project` operation with orthogonalization removes the known cross-terms
from other fields, leaving only the target field's contribution.

### Worth Trying?

**Yes.** This should improve the accuracy of the per-field cardinality
estimation (unbinding as diversity measure). The current approach is noisy
because cross-terms from other fields contaminate the unbound signal.
Partial trace via projection removes that contamination.

The `project` primitive already exists in holon-rs. This is a composition
of existing operations, not a new primitive.

---

## Technique 6: No-Cloning and Secure Transmission

### Quantum Concept

The no-cloning theorem states you can't copy an unknown quantum state
perfectly. But you CAN teleport it using entanglement + classical bits.

### VSA Application

The no-cloning theorem doesn't hold for classical vectors (you can always
copy a `Vec<i8>`). But the COMMUNICATION pattern of quantum teleportation
is useful:

**Secure vector transmission:** Two nodes share a secret random vector S
(the "entanglement resource," derived from the shared seed). To transmit
a vector V:

1. Sender computes: `message = bind(V, S)` (entanglement)
2. Sender transmits `message` over insecure channel
3. Receiver computes: `V' = bind(message, S) = bind(bind(V, S), S) = V`

The transmitted `message` is indistinguishable from random to an
eavesdropper who doesn't know S. The original vector V is recoverable only
with knowledge of S. This is effectively a one-time-pad in vector space.

**Practical use:** Transmitting baseline vectors or accumulator snapshots
between nodes without revealing what traffic patterns they represent. An
attacker intercepting the message learns nothing about the traffic profile
without the seed.

**This is trivially simple but worth noting** — the binding operation IS
a symmetric cipher in VSA space. `bind(V, S)` encrypts. `bind(cipher, S)`
decrypts. The "key" is S. The security depends on S being unknown to the
adversary, same as any symmetric cipher.

---

## What's NOT Worth Stealing

| Quantum Concept | Why It Doesn't Apply |
|---|---|
| Quantum speedup (BQP) | We're classical. No exponential speedup. |
| Shor's algorithm | Factoring is irrelevant to VSA operations. |
| Quantum key distribution | We have classical deterministic seeds. |
| Quantum supremacy | VSA is already O(d) per operation. Can't beat that. |
| Qubits / gate model | Bipolar vectors aren't qubits. No unitarity constraint. |

The analogy is structural (superposition, interference, measurement) not
computational (no quantum speedup). We're stealing the THEORY not the
HARDWARE.

---

## Summary: What to Try

| Technique | Difficulty | Expected Impact | Novel? |
|---|---|---|---|
| Participation ratio (weak measurement) | Easy | Medium — baseline-free concentration signal | Somewhat |
| Purity as detection signal | Easy | High — 2D detection space (drift × purity) | Yes for VSA |
| Hadamard vector design | Medium | Potentially high — better capacity | Yes |
| Iterative amplitude amplification | Medium | Medium — weak signal boosting | Yes for VSA |
| Partial trace via projection | Easy | Medium — cleaner per-field extraction | Yes |
| Secure vector transmission | Easy | Low — niche use case, cool trick | No (obvious) |
| Error-correcting codes for vectors | Hard | Potentially transformative — 50% capacity | Research question |

**Recommended first experiments:**
1. Purity (5 lines, immediate value as detection signal)
2. Participation ratio (5 lines, baseline-free)
3. Partial trace via projection (10 lines, composition of existing primitives)
4. Hadamard vectors (15 lines, compare capacity vs random in tests)
5. Iterative amplification (20 lines, needs tuning experiments)
