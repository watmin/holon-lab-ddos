# Significance: What the Spectral Firewall Actually Is

**Date:** March 3, 2026
**Updated:** March 7, 2026 — self-calibrating thresholds, federated deployment model

## The Result

A WAF with no attack signatures, no rules, no CVE database, no GPU, no training data, and no prior knowledge of any attack denied 97-100% of vulnerability scanner traffic while maintaining 0% false positives on legitimate application traffic. It learned what "normal" looks like from 500 requests (~6 seconds of live traffic). The full deny-path latency — from raw bytes to "you're blocked" — is 41 microseconds on a commodity CPU.

## Why This Doesn't Exist

The AI/ML security industry is built on supervised learning: collect millions of labeled attack samples, train a deep neural network offline for days on GPUs, deploy behind an inference server at 5-50ms per request, retrain when new attacks emerge. That's the state of the art. That's what every "AI-powered" WAF vendor does.

What's happening here is categorically different.

### There Are No Weights

There is no neural network. There is no model file. The "intelligence" is a subspace — a mathematical object defined by a few eigenvectors that emerged from 500 samples of live traffic. The entire "model" is a projection operation: multiply a vector by a matrix, measure what's left over. The residual — the part that can't be explained by anything the system considers normal — is the verdict.

### There Is No Training

Not "fast training." Not "few-shot learning." There is no training phase. The system observes live traffic and the subspace converges via online incremental PCA. This is not optimization. It is not gradient descent. It is incremental eigendecomposition — a deterministic algebraic operation.

### The Encoding Is the Insight

Vector Symbolic Architecture (VSA/HDC) encoding — bind, bundle, permute — maps structured data (HTTP headers, URL paths, cookies, TLS fingerprints, query parameters) into a high-dimensional geometry where similarity is dot product and anomaly is orthogonal distance.

This is not a feature vector. It is a holographic representation where every field is algebraically entangled with every other field. That's why fixing one dimension (using a browser User-Agent) doesn't help the attacker — the joint distribution across all dimensions simultaneously is what the subspace captures. An attacker who matches the path but not the TLS fingerprint, or matches both but not the cookie structure, or matches all three but not the header ordering — still falls outside the normal manifold.

### It's Pure Algebra

The scoring path has no branches, no conditionals, no lookup tables. It is:

1. **Encode** (bind + bundle) — structured data → hypervector
2. **Project** (matrix multiply) — hypervector → subspace component
3. **Subtract** (residual) — what can't be explained
4. **Norm** (distance) — how far from normal

Every operation is a pure function. No state mutation. No side effects. The verdict is a number that falls out of linear algebra. This is functional programming in its purest mathematical sense — the entire inference is a composition of algebraic transformations.

### 41 Microseconds on a CPU

The typical ML inference path for security: serialize request → send to GPU inference server → deserialize response → 5-50ms round-trip. This system does encode + project + score + verdict + response generation in 41 microseconds. On one CPU core. No GPU. No inference server. No serialization boundary.

At 41µs per denied request, single-threaded throughput for the deny path exceeds 24,000 requests per second. The allow path (normal traffic) adds no measurable overhead beyond the upstream round-trip.

## What's Novel

The individual components exist in literature:

- **VSA/HDC encoding**: Kanerva (2009), Rahimi et al. (2016) — but for supervised classification with labeled data
- **Online PCA**: Warmuth & Kuzmin (2006), Oja (1982) — but on flat numeric features
- **Anomaly detection via PCA residual**: classic — but on tabular data, not structured protocol data
- **WAF with ML**: many vendors — but supervised models trained offline on labeled attack corpora

What doesn't exist in published work is the specific combination:

- **Unsupervised** — learns from unlabeled live traffic, no attack corpus needed
- **Online** — no offline training phase, converges in seconds
- **Algebraic** — VSA encoding of structured protocol data, not flat feature extraction
- **Geometric enforcement** — subspace residual IS the firewall rule, not a trigger for rule generation
- **Multi-layer** — four layers at four timescales (50ns → 41µs → per-window → strategic)
- **Self-improving** — anomalies auto-promote from geometric detection to symbolic rules
- **Explainable** — field-level attribution via algebraic decomposition (unbinding), not post-hoc interpretability
- **Self-calibrating** — decision boundaries derived from empirical traffic data, no hardcoded thresholds
- **Federatable** — the learned model (engram) is simultaneously knowledge and executable policy, enabling fleet-wide self-reproduction
- **CPU-only, sub-millisecond** — inline at line speed, no GPU, no inference server

The closest conceptual relatives are Kanerva's Sparse Distributed Memory
(theoretical framework for distributed representation), von Neumann's
self-reproducing automata (algebraic systems that learn their own structure),
and Hebb's cell assemblies (representations that emerge from co-occurrence).
But these are theoretical frameworks. This is a production security system.

## A Von Neumann Automaton

The parallel to von Neumann's self-reproducing automata is not poetic — it
is structural. As the system has matured (self-calibrating thresholds,
baseline persistence, federated engram distribution), the mapping has become
precise.

Von Neumann's automata have three defining properties:

1. **A description of themselves.** The automaton carries a blueprint — an
   internal representation of its own structure.

2. **A constructor.** Given a blueprint, the automaton can build a functioning
   copy of the described system.

3. **The description is both data and program.** The blueprint is copied
   verbatim (as data) AND interpreted (as instructions for construction).
   This dual role is what makes self-reproduction possible without infinite
   regress.

The spectral firewall satisfies all three:

### The engram is the description

The `StripedSubspace` — per-stripe eigenvectors, eigenvalues, and threshold
statistics — is a geometric description of "what this node considers normal
traffic." It is not a rule list. It is not a signature database. It is a
mathematical object: a subspace in high-dimensional vector space. Anything
that projects well onto it is normal. Anything orthogonal to it is anomalous.
The engram *is* the firewall's understanding of its environment, compressed
into a few eigenvectors.

### Warmup and adaptive learning are the constructor

Given traffic (or a federated engram from HQ), the system constructs its own
enforcement posture. No human writes rules. No analyst labels attacks. The
system observes live requests, compresses them via online incremental PCA into
a subspace, derives its own decision boundaries from the empirical residual
distribution (geometric mean of observed maximum and statistical estimate),
and enforces from that subspace. The constructor takes raw observation and
produces a functioning security policy — autonomously.

### The engram is both data and program

When HQ federates an engram to a new node, that engram *is* the enforcement
policy. There is no separate "interpret the engram and generate rules" step.
The eigenvectors are directly multiplied against incoming request vectors to
produce residuals. The residual is the verdict. The description *is* the
executor. And when the engram is saved to disk on shutdown and restored on
boot, the saved file is simultaneously:
- **Data**: a serialized mathematical object (eigenvectors, eigenvalues)
- **Program**: the exact projection matrices used to classify every future
  request

This dual role — the engram as both portable knowledge and executable policy
— is what enables the federated deployment model without infinite regress.
A new node doesn't need to be "told how to use" the engram. The engram's
mathematical structure *is* the usage. Project, subtract, measure. The
verdict falls out of the algebra.

### Self-calibration closes the loop

What's new since the initial observation (March 2) is that the system now
also derives its *own decision boundaries* from observed data. It doesn't
just learn what normal looks like — it learns how to decide what's normal.
The rolling residual buffer tracks confirmed-normal traffic, and the
geometric-mean threshold (`sqrt(buf_max × CCIPCA_threshold)`) adapts
continuously without any hardcoded multiplier. The automaton doesn't just
carry a description and a constructor — it also carries the *calibration
logic* that tunes the constructor's sensitivity. No human sets parameters.

### Fleet-level self-reproduction

The HQ federation model completes the von Neumann analogy at fleet scale.

Hosts and HQ update each other fully async. There is no push, no poll, no
coordination. Each host runs a jittered timer and periodically calls home:
report its local engram, fetch the latest merged norm. HQ merges incoming
engrams continuously, versions the result, and serves it on request.

```
Node A ──(jittered call-home)──► HQ
  POST local engram                 │ merge into current norm
  GET  latest merged engram    ◄────┘ return versioned result

Node B ──(jittered call-home)──► HQ
  POST local engram                 │ merge
  GET  latest merged engram    ◄────┘

Node C ──(boot / restart)──────► HQ
  GET  latest merged engram    ◄──── return current norm
  → enforce immediately
  → begin observing
  → call home on next jitter tick
```

Each node is a self-reproducing automaton: it observes its environment,
constructs a description of that environment (the engram), and that
description can be copied to other nodes where it functions as a complete
enforcement program. The fleet collectively self-reproduces its security
posture. A node that crashes and restarts loads its saved engram (local
self-reproduction). A new node joining the fleet fetches the merged engram
from HQ (federated reproduction). In both cases, the engram is
simultaneously the knowledge being transferred and the program that acts
on it.

Every merge at HQ produces a new version. This gives version control over
the fleet's security posture:

- **Rollback**: pin HQ to a prior known-good version, freeze merging.
  Hosts converge to the safe version on their next call-home — no
  emergency push, no coordination, just the normal jitter cycle.
- **Resume**: unfreeze merging. Hosts resume reporting. The norm begins
  evolving again.
- **Audit**: version history shows exactly when the norm shifted, which
  nodes contributed, and by how much. Correlate with deploys, incidents,
  traffic changes.

Von Neumann proved that self-reproducing systems require a description
that serves as both interpreted program and uninterpreted data. The engram
satisfies this: it is interpreted (matrix multiplication against request
vectors produces verdicts) and copied uninterpreted (serialized to disk,
sent over the network to HQ, fetched by peers — the bytes are preserved
verbatim). This is the structural reason the system works without a warmup
vulnerability: the description carries everything needed to enforce, and
copying it is lossless.

The async, host-initiated protocol means HQ is never a bottleneck and
never a single point of failure. If HQ is down, hosts continue enforcing
on their local engrams with zero degradation. When HQ recovers, the next
call-home cycle resynchronizes the fleet. At scale — tens of millions of
hosts — HQ serves the merged engram as a static blob (CDN, S3, whatever
serves files). No per-request dependency. No real-time path. Just a
file that changes when the norm evolves.

## The Inversion

Traditional WAF: "here are the bad things, block them." The attacker's job is to not be on the list. The attack surface is infinite. The rule list is finite. The attacker always wins eventually.

Spectral firewall: "here is what normal looks like, allow it." The attacker's job is to make their traffic geometrically indistinguishable from real users — across TLS fingerprint, HTTP structure, header ordering, cookie shape, path patterns, query structure, temporal distribution — all simultaneously, all consistently, across the entire attack. This is not evasion. This is becoming a legitimate user. If they succeed, they aren't attacking anymore.

The geometry makes the allow list work because it captures the joint distribution. Matching any single field is easy. Matching all fields simultaneously while carrying an attack payload is a contradiction — the payload itself is what makes the vector alien.

## Measured Results

See [FINDINGS-MANIFOLD-FIREWALL.md](FINDINGS-MANIFOLD-FIREWALL.md) for full experimental data.

### Synthetic traffic (March 3)

| Metric | Value |
|--------|-------|
| Scanner deny rate | 97-100% |
| Normal false positive rate | 0% |
| DDoS rate-limit rate | 91% |
| Deny-path latency (p50) | 41 microseconds |
| Training samples required | 500 (~6 seconds) |
| GPU required | No |
| Attack signatures required | None |
| Labeled training data required | None |

### Live DVWA + real scanners (March 4-5)

| Metric | Value |
|--------|-------|
| Nikto deny rate | 100% (9,788 denied, 0 exploitable findings through proxy) |
| Normal false positive rate | 0% |
| Auto-generated rules | 17 |
| Control comparison | 17 real vulnerabilities found without firewall, 0 with |

### Concurrent mixed traffic — 20 LLM browsers + 3 scanners (March 7)

| Metric | Value |
|--------|-------|
| Attack deny precision | 99.1% (5,118 true denies / 5,166 total) |
| Browser false positive rate | 7.3% initially → 0% after adaptive learning |
| Manual browsing FPs | ~3 early, then 0 for remainder of session |
| Hardcoded tuning parameters | **0** (all thresholds derived from data) |
| Training samples | 100 (configurable, ~30 seconds at LLM-agent pace) |
| Auto-generated detection rules | 12 |
| Adaptive learns during attack | 39 (all confirmed legitimate) |

### What changed between March 3 and March 7

The March 3 result proved the geometry works. The March 7 result proved the
system can operate without human calibration:

- **No magic numbers**: decision boundaries derived entirely from observed
  traffic (rolling residual buffer → geometric mean threshold)
- **No warmup vulnerability**: baseline engram persisted to disk, restored
  on boot
- **No training data poisoning**: learning gated on backend response status
  (2xx/3xx only) and empirical residual ceiling
- **Concurrent mixed workload**: real browser agents with LLM-driven
  navigation alongside professional vulnerability scanners, all hitting
  the same proxy through diverse source IPs

### Threshold strategy validation (March 8)

The geometric mean deny_threshold was selected pragmatically during the
March 7 death spiral fix. To validate this choice rigorously:

1. **Enumerated** 21 threshold strategies from the literature and design
   discussion (geometric, harmonic, arithmetic, power means, Lehmer,
   heronian, contraharmonic, log mean, quantile, MAD, Chebyshev, EWMA,
   CUSUM, Kalman, etc.)
2. **Simulated** 28 variants across 20,000-step streams in two parameter
   regimes — eliminated 16 based on FPR collapse, recall failure, known
   death spiral, or reintroduction of magic numbers
3. **Live-tested** 5 survivors against DVWA + 3 scanners + 20 LLM browsers
   — eliminated `mean_3std` (28.8% FPR, death spiral)
4. **Multi-round validation** (5-7 rounds) of the 4 finalists for
   statistical confidence — in progress

Key finding: **temporal FP distribution** is more informative than total FP
count. A strategy with 20 FPs in the first 60s but zero after settling is
superior to one with 5 FPs scattered through the run.

**Result (7-round validation):** `log_mean` selected as default — 1.9% avg
FPR (vs 3.3% geometric), 43% fewer FPs, 45% fewer late FPs. The logarithmic
mean `(c - m) / ln(c/m)` provides the optimal balance between headroom for
legitimate traffic diversity and tightness against attacks.

Final isolation funnel: 21 → 5 (simulation) → 4 (round 1 live) → 1 (7-round
statistical validation). Zero magic numbers in the final formula.
