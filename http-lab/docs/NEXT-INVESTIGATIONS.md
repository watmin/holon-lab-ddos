# Next Investigations

Open problems and findings for the spectral firewall.

---

## 1. Ground Truth: Leaf Binding Count and Distribution (MEASURED)

### Results — Phase 1 (pre-encoding changes)

Instrumented `param_sweep` with a leaf inventory pass over synthetic DVWA
(normal) and Nikto (attack) samples. Walked `RequestSample::walk_map_items()`
recursively, counted every leaf binding, and computed per-stripe distribution.

| Traffic type | min | p50 | mean  | max | unique paths |
|-------------|-----|-----|-------|-----|-------------|
| Normal (DVWA browse) | 104 | 108 | 107.8 | 117 | 117 |
| Attack (Nikto probe) | 83  | 90  | 91.8  | 111 | 115 |

~100 leaves per request. The striped encoder was flattening every list element
into a separate leaf binding, causing a "leaf explosion" — TLS cipher order
alone accounted for 10-33% of all leaves. This was identified as a regression.

### Results — Phase 2 (post-encoding changes, March 2026)

After introducing `WalkableValue::Spread` (fan-out) vs `List` (compose),
applying `char_list` encoding to string fields, and choosing per-field
List/Spread/char strategies:

| Traffic type | min | p50 | mean | max | unique paths |
|-------------|-----|-----|------|-----|-------------|
| Normal (DVWA browse) | 53 | 53 | 53.6 | 56 | 56 |
| Attack (Nikto probe) | 33 | 36 | 36.1 | 42 | 42 |

**~50% reduction in leaf count.** Lists (header_order, cipher_order, etc.) now
compose into single bindings. String fields (path, query, src_ip) use char-level
positional encoding via `char_list` — composed into one binding with fuzzy
matching properties.

#### Per-stripe distribution (32 stripes, post-encoding)

| Traffic type | min | mean | max | empty stripes |
|-------------|-----|------|-----|--------------|
| Normal | 0.0 | 1.7  | 4.0 | 2 |
| Attack | 0.0 | 1.1  | 4.0 | 7 |

With ~1.7 bindings per stripe on average (normal traffic), each stripe's input
vector is extremely sparse.

### K Sweep Results (RESOLVED — K=4 selected)

Ran targeted K sweep at production DIM=1024, STRIPES=32 with the new encoding:

| K | Separation | res_p50 | full_p50 | FPR | FNR |
|---|-----------|---------|----------|-----|-----|
| 1 | 2.3x | 31us | 345us | 0% | 0% |
| 2 | 2.6x | 39us | 359us | 0% | 0% |
| 3 | 3.0x | 46us | 368us | 0% | 0% |
| **4** | **3.2x** | **54us** | **377us** | **0%** | **0%** |
| 5 | 3.4x | 60us | 410us | 0% | 0% |
| 6 | 3.4x | 69us | 410us | 0% | 0% |
| 8 | 3.2x | 82us | 427us | 0% | 0% |
| 16 | 4.1x | 145us | 521us | 0% | 0% |
| 32 | 7.1x | 371us | 822us | 0% | 0% |

**Every K value achieves 0% FPR and 0% FNR** on synthetic DVWA/Nikto data.
The new encoding makes the normal/attack signal so structurally distinct that
even K=1 produces perfect classification. Separation plateau at K=5-6 (3.4x),
consistent with the ~1.7 binding/stripe rank.

Same pattern holds at DIM=2048: K=5-6 plateau at 3.0x, 0% FPR/FNR everywhere.

#### Live validation: K=4 FAILED (insufficient deny margin)

K=4 was deployed for live DVWA+Nikto validation. **Result: massive regression.**

| Metric | Synthetic (param_sweep) | Live (DVWA+Nikto) |
|--------|------------------------|-------------------|
| Normal score | ~35 | ~35 |
| Threshold (K=4) | 36.2 | **64.31** |
| Deny threshold (2x) | 72.4 | **128.62** |
| Attack score | ~116 (3.2x) | ~121-128 |
| Margin above deny | 43.6 (safe) | **~0 (razor thin)** |

Real DVWA traffic has more path/header variance than the 20 synthetic samples,
pushing the threshold ~1.8x higher. Nikto scores landed right at the deny
boundary — some denied (629), some rate-limited (310), but many got through
before streak-based enforcement triggered.

**Lesson:** 0% FPR/FNR in the synthetic sweep was misleading. It only shows
that normal and attack distributions don't overlap. It does NOT guarantee
sufficient margin between the deny boundary and attack scores. Higher K
produces a tighter normal fit → lower threshold → wider deny margin.

#### Fine-grained K sweep (K=8..32, step 2)

| K | Sep | Threshold | res_p50 | Est. live deny margin |
|---|-----|-----------|---------|----------------------|
| 8 | 3.2x | 36.1 | 82us | -8 (FAIL) |
| 12 | 3.5x | 33.7 | 106us | -1 (FAIL) |
| 14 | 3.7x | 31.5 | 127us | +9 (tight) |
| 16 | 4.1x | 28.4 | 138us | +20 (works) |
| 18 | 5.1x | 23.0 | 156us | +39 (good) |
| **20** | **6.7x** | **17.4** | **167us** | **+59 (strong)** |
| 24 | 6.9x | 16.9 | 187us | +61 (strong) |
| 28 | 7.0x | 16.6 | 216us | +63 (strong) |
| 32 | 7.1x | 16.4 | 240us | +63 (strong) |

**Dramatic knee at K=18→20.** Threshold drops from 23.0 to 17.4, separation
jumps from 5.1x to 6.7x. After K=20, it's a plateau — K=24 through K=32
barely move (17.4→16.4, 6% improvement for 60% more residual compute).

**Decision:** K=20 selected for production. Nearly identical deny margin to
K=32 (+59 vs +63), 30% less residual latency (167us vs 240us). The threshold
knee corresponds to where noise deflation becomes effective — below K=20 there
are still enough noisy dimensions to inflate the normal residual and widen the
threshold.

#### Live validation: K=20 PASSED

| Metric | K=4 (failed) | K=20 (production) |
|--------|-------------|-------------------|
| Score | 121-128 | 128.47 |
| Threshold | 64.31 | 38.35 |
| Score/threshold | ~1.9x (below deny) | **3.35x (strong deny)** |
| Denials | 629 | **9,971** |
| Rate limited | 310 | 0 |
| Nikto findings | Dozens of real vulns | **18 informational only** |

Nikto was completely stonewalled — spent 120s being denied, could not complete
any real vulnerability scanning. The 18 "findings" are SSL/header info visible
from the initial TLS handshake, not exploitable probes.

#### Eigenvalue observation

All eigenvalues report 0.0 with explained_ratio = 1.000 across every
configuration. With ~1.7 bindings per stripe, the signal is so low-rank that
PCA trivially captures 100% of variance. Despite this, higher K produces a
tighter fit in practice because it deflates more noise dimensions — the noise
floor is what determines the threshold, and the threshold determines the
deny margin.

---

## 2. Adaptive Learning: Handling "Slightly Different" Traffic

### The problem

The spectral firewall currently has a binary lifecycle: warmup → freeze → enforce.
After warmup, the manifold is static. Any traffic that differs structurally from
the warmup set — even legitimate traffic like mobile apps, new browser versions,
API clients, or seasonal traffic pattern shifts — is flagged as anomalous.

This is a deployment blocker. Real production environments have:
- Multiple client types (web browsers, mobile apps, API consumers)
- Client evolution (browser updates change TLS fingerprints and header ordering)
- Gradual traffic drift (new features, new endpoints, seasonal patterns)
- Deployment changes (new response headers, updated cookies)

### Proposed approaches

#### A. Gated continuous learning (simplest)

After warmup, keep calling `StripedSubspace::update()` but **only for requests
that score below the threshold.** The manifold gradually absorbs legitimate
drift without ever learning from attack traffic.

```
if residual < threshold:
    allow request
    subspace.update(stripe_vecs)   // learn from it
elif residual < deny_threshold:
    rate_limit request
    // do NOT update — anomalous but not clearly attack
else:
    deny request
    // do NOT update — structurally alien
```

**Pros:** Minimal code change. Leverages existing CCIPCA online learning. The
EMA threshold adapts automatically as the manifold shifts.

**Risks:**
- **Slow poisoning:** An attacker staying just under threshold on each request
  could gradually shift the manifold toward their attack pattern. Mitigation:
  cap the learning rate (e.g., only update every Nth sub-threshold sample),
  require N consistent sub-threshold samples before incorporating, or bound
  the maximum manifold drift per time window.
- **Concept drift:** If traffic changes rapidly (deploy, incident), the old
  baseline fades. The `amnesia` parameter controls this — higher amnesia forgets
  faster. May need to be tunable per deployment.

#### B. Multi-tier threshold with probation zone

Three zones instead of two:

| Zone | Residual range | Action | Learn? |
|------|---------------|--------|--------|
| Normal | < threshold | Allow | Yes |
| Probation | threshold to Nx threshold | Allow (or soft rate-limit) | No |
| Deny | > Nx threshold | Deny | No |

The probation zone lets "mildly different" traffic through (mobile app with
different headers) without corrupting the model. Operators can review probation
traffic and decide whether to promote those patterns (via engram import or
explicit "learn this" signal).

**N (probation ceiling)** becomes a tunability dial: low N = tight, rejects more
mild anomalies. High N = permissive, only hard denies clearly alien traffic.

#### C. Engram stacking (multi-population)

Train separate engrams for each client population:
- `baseline-browser.engram` — Chrome/Firefox/Safari web traffic
- `baseline-mobile.engram` — iOS/Android app traffic
- `baseline-api.engram` — API consumer traffic

Each engram is a separate `NormalSubspace` in `ManifoldState.normal_subspaces`.
A request is "normal" if it's close to ANY of the stacked engrams.

The `normal_subspaces: Vec<NormalSubspace>` field already exists in
`ManifoldState` — it was designed for this but only populated with one baseline.

**Pros:** Clean separation of concerns. Each population can have its own
threshold, K, and amnesia. New populations are added by training a new engram,
not by retraining everything.

**Cons:** Requires upfront knowledge of client populations. Each additional
engram adds compute (one residual calculation per engram per request).

#### D. Amnesia-gated learning

Use different amnesia rates based on context:
- **Low amnesia (slow adaptation)** during high-anomaly periods — don't let
  attack traffic corrupt the model
- **High amnesia (fast adaptation)** during stable periods — quickly absorb
  new legitimate patterns

The `anomaly_streak` counter already tracks consecutive anomalous ticks.
When streak > N, freeze learning. When streak returns to 0, resume learning
with elevated amnesia to catch up on any drift that occurred during the
freeze.

### Recommended starting point

**Approach A (gated continuous learning)** is the simplest to implement and test.
It requires changing ~5 lines in the sidecar tick loop: after evaluating a
request's residual, call `update()` if below threshold.

Test plan:
1. Warm up with browser traffic only
2. Introduce mobile-style traffic (different UA, different headers, no cookies)
3. Verify the mobile traffic initially triggers rate-limits
4. Observe whether the manifold adapts and starts allowing it
5. Then introduce Nikto — verify it's still denied despite the adaptation

If approach A works, it solves 80% of the deployment problem. Approaches B-D
are refinements for edge cases (slow poisoning, operator control, multi-tenant).

### Interaction with leaf binding count

These two investigations are connected. If real requests produce significantly
more leaves than estimated, the per-stripe rank increases, which means:
- The manifold has more structure to learn per stripe
- Continuous learning becomes more important (richer manifold = more drift surface)
- K may need to be larger to capture the richer structure
- The separation ratio from the parameter sweep may not hold — needs re-measurement
  with accurate leaf counts

Now that leaf counts are measured (~100, confirming estimates), the parameter
sweep results are validated and adaptive learning can proceed on solid ground.

---

## 3. Denial Token Size (Low Priority)

The denial context tokens are base64-encoded encrypted JSON. They're large
(~500+ characters) because they carry the full verdict, residual, threshold,
source IP, method, path, timestamp, and top attribution fields as JSON text.

Ideas to revisit when this becomes a bottleneck:
- **Compression before encryption:** zlib/zstd the JSON before encrypting.
  JSON compresses well (repeated keys, predictable structure).
- **Binary encoding:** msgpack, bincode, or protobuf instead of JSON. Drops
  key names and whitespace, typically 2-4x smaller.
- **Field trimming:** Only include top-N attribution fields instead of all.
  Most of the payload is attribution data.
- **Token reference:** Store the full context server-side (indexed by hash),
  put only the hash in the token. Trades token size for server-side state.

Not blocking anything currently — the tokens fit in HTTP headers and work.
Optimize when/if they cause problems (header size limits, bandwidth, storage).

---

## 4. Character-Level String Encoding (IMPLEMENTED)

### Summary

Implemented character-level positional encoding for string fields via the
`char_list` helper, which emits `WalkableValue::List` of single-character
scalars. The existing list/positional encoding machinery composes these into
a single vector per field — no leaf explosion, but with fuzzy matching
properties (similar strings → similar vectors, order-sensitive).

### What changed

Added `WalkableValue::Spread` variant to `holon-rs` to give `Walkable`
implementors control over encoding intent:
- **`List`** — composed into a single binding (used for char sequences,
  ordered lists like header_order, cipher_order, path_parts)
- **`Spread`** — fanned out into independent per-element bindings (used for
  headers, header_shapes, cookies — enables per-element attribution)
- **`Set`** — composed, unordered (unchanged)

Both the hierarchical and striped encoders now respect these semantics
uniformly. Previously the striped encoder flattened `List` into individual
leaf bindings (regression).

### Fields and their encoding strategy

| Field | Encoding | Rationale |
|-------|----------|-----------|
| method | `scalar_s` (atomic) | Small categorical set |
| path | `char_list` (fuzzy) | Partial path matching |
| path_parts | `List` (composed) | Positional directory structure |
| version | `scalar_s` (atomic) | Small categorical set |
| query | `char_list` (fuzzy) | Payload content matching |
| query_parts | `List` (composed) | Positional query structure |
| header_order | `List` (composed) | Header fingerprint as ordered sequence |
| headers | `Spread` (fan-out), values `char_list` | Per-header attribution + fuzzy value matching |
| header_shapes | `Spread` (fan-out) | Per-header structural attribution |
| cookies | `Spread` (fan-out) | Per-cookie attribution |
| src_ip | `char_list` (fuzzy) | Subnet prefix similarity |
| path_shape, query_shape | `List` (composed) | Structural fingerprint |
| TLS fields | unchanged | Sets/lists/scalars as defined by TlsContext |

### Impact on leaf count

Leaf count dropped from ~100 to ~53 (normal) / ~36 (attack). See section 1
for full measurements. The K sweep was run post-encoding-changes and confirmed
K=20 is optimal (see section 1 for the full K sweep analysis).

### What char_list materially captures (live observations)

Live DVWA+Nikto validation revealed the attribution gradient:

| Path type | `path` attribution score | Behavior |
|-----------|-------------------------|----------|
| `/` (seen in warmup) | not in top-5 | Projects well onto normal subspace |
| `/cgi-bin/` (real, unseen) | 0.6 | Partial char similarity to normal paths |
| `/CCsGfZ2r.eml` (random probe) | 0.7 | No character overlap with normal paths |

Char_list provides a **similarity gradient** instead of binary seen/unseen:
- Paths sharing character patterns with normal paths (e.g., `.php` suffix,
  `/` prefix, ASCII structure) get lower anomaly scores than random garbage
- Complementary to `path_parts` — path_parts captures directory structure,
  char_list captures intra-string character patterns
- Most valuable when TLS fingerprint is NOT the primary signal (attacker
  matching the TLS profile), making path/query patterns the main detection axis

Reconstruction for static rules is transparent: the `RequestSample` retains
the original raw strings (`path`, `query`, `src_ip`). The char_list encoding
only affects the spectral scoring layer — `DenialContext`, rule matching, and
logging all use the original values.

### Header value char_list encoding (IMPLEMENTED)

Header values within `headers` (Spread) now use `char_list` instead of atomic
scalars. Header names remain atomic (categorical identifiers).

Before: `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64)` and
`User-Agent: Mozilla/5.0 (X11; Linux x86_64)` were maximally orthogonal
despite sharing ~80% of their content.

After: character-level composition gives fuzzy similarity — the shared
`Mozilla/5.0 (` prefix and `) AppleWebKit/537.36` suffix create substantial
vector overlap, with divergence only in the OS/platform substring.

Implementation: within the `headers` Spread, each `[name, value]` pair changed
from `WalkableValue::List(vec![scalar_s(name), scalar_s(value)])` to
`WalkableValue::List(vec![scalar_s(name), char_list(value)])`.

**Verified:** leaf count unchanged (53 normal / 36 attack), detection quality
unchanged (K=20: sep=6.7x, thr=17.4, 0% FPR/FNR), encoding latency unchanged
(~430µs p50). Pure win — fuzzy header matching at zero cost.

### Next: body payload char_list encoding

The same technique generalizes directly to HTTP body content:
- **Text bodies** (HTML, JSON text, form data): `char_list(&body_string)`
- **JSON payloads**: walk JSON structure as Map/List, string values get char_list
- **Form-encoded bodies**: split into key=value pairs like query_parts, values
  get char_list
- **Binary bodies**: byte-level encoding (`body.iter().map(|b| scalar_s(format!("{:02x}", b)))`)

This is the natural next step once body capture is added to `RequestSample`.

---

## 5. Anomaly Breadth Metric

### The idea

The current system scores each request as a single aggregate residual and
attributes the top-N most anomalous fields. But it discards information about
**how many** fields are anomalous — the breadth of the anomaly.

Two requests with the same residual of 120:
- **Narrow anomaly**: 5 of 53 fields have high attribution scores — probably
  a different TLS client hitting normal pages. The HTTP layer is familiar.
- **Broad anomaly**: 40 of 53 fields have high attribution scores — every
  dimension of the request is wrong. Completely foreign client structure.

### Relationship with adaptive learning (Section 2)

Breadth and adaptive learning are **complementary, not substitutes.**

Adaptive learning is the *mechanism* (learn or don't learn from sub-threshold
traffic). Breadth is the *intelligence* that makes the mechanism safer.

Without breadth, adaptive learning has a poisoning vulnerability: an attacker
could craft requests that are "slightly off in many dimensions" to sneak under
the threshold while gradually rotating the manifold. Each individual field
looks almost normal, but the cumulative effect shifts the baseline.

The narrow/broad distinction doesn't map cleanly onto sub-threshold/above-threshold:

- **Narrow + high residual**: one extreme field (novel TLS extension set,
  everything else identical). Above threshold, but it's just a client update —
  adaptive learning can't absorb it even though it should.
- **Broad + low residual**: many fields slightly off, but none extreme enough
  to push the aggregate over threshold. Adaptive learning absorbs it — slowly
  poisoning the manifold. This is the dangerous quadrant.

The combined decision space:

```
  residual
     ▲
     │  DENY            │  DENY
     │  (narrow but     │  (broad, everything
     │   extreme)       │   wrong — scanner)
     ├──────────────────┤───────────────────
     │  LEARN           │  SUSPECT
     │  (minor drift,   │  (subtle but wide —
     │   absorb it)     │   possible poisoning)
     ▼                  │
     └──────────────────┴───────────────────► breadth
        narrow                        broad
```

The learning gate becomes: update manifold only if
`residual < threshold AND breadth < narrow_threshold`. This restricts learning
to requests that are *mostly familiar with minor variations* — exactly the
legitimate drift case.

### Metric candidates (threshold-free)

The original definition (`fraction of fields above breadth_threshold`) requires
calibrating `breadth_threshold`, which is fragile and application-specific.
Three threshold-free alternatives:

**1. Shannon entropy of attribution distribution.** Normalize per-field scores
into a probability distribution, compute entropy. High entropy = scores spread
evenly (broad). Low entropy = concentrated in few fields (narrow).
Self-calibrating, no tuning parameter. Can be computed at holon-rs level.

**2. Concentration ratio.** `max_field_score / mean_field_score`. High ratio =
one field dominates (narrow). Ratio near 1.0 = everything contributes equally
(broad). Simplest to compute, easy to reason about.

**3. Gini coefficient** of per-field scores. 0 = perfectly uniform (broadest).
1 = all energy in one field (narrowest). Standard inequality measure,
well-understood statistical properties.

All three compute a single scalar from the existing attribution scores. They
can be implemented generically in `holon-rs` as a property of any residual
decomposition — no application-specific knowledge needed.

**Recommendation:** start with concentration ratio (simplest), validate that
it distinguishes narrow vs broad in live traffic, then evaluate whether entropy
or Gini provides better separation if needed.

### Use cases

1. **Adaptive learning gate**: narrow anomalies (low breadth) are safe
   candidates for gated continuous learning (Section 2). Broad anomalies
   should never be learned — they represent fundamentally different client
   structures or slow-poisoning attempts
2. **Tiered enforcement**: broad anomaly → immediate deny with high confidence;
   narrow anomaly → rate-limit, possible legitimate client variant
3. **Rule generation confidence**: narrow anomaly concentrated in TLS fields →
   auto-generate TLS fingerprint rule. Broad anomaly → different threat class,
   needs manual review
4. **Alert prioritization**: breadth as a dimension for SOC triage — broad
   anomalies are more likely real attacks, narrow ones more likely false
   positives from client diversity

### Implementation plan

1. Add concentration ratio (and optionally entropy) computation to
   `drilldown_audit` in `manifold.rs` — computed from the full score list
   before truncation to top-N
2. Surface in `ManifoldVerdict` as `breadth: f64`
3. Include in log output and `DenialContext` for inspection
4. Wire into adaptive learning gate (Section 2) as a second condition
   alongside residual
5. Validate with live DVWA+Nikto: verify that Nikto probes show high breadth
   (broad) while legitimate browser variants show low breadth (narrow)

---

## 6. Centralized Engram Federation (HQ)

### The idea

Multiple edge nodes run independent spectral firewalls — each with its own
warmup, adaptive learning, and accumulated manifold state. A central **HQ**
periodically collects the learned state (engrams + rules) from all nodes,
merges them, and redistributes the merged result as the cold-boot starting
point for new or restarting nodes.

This solves several real deployment problems:
- **Cold start**: a new node comes up with zero learned state and must survive
  a full warmup period before it can enforce. With HQ, it boots from the
  fleet-wide merged engram and is immediately effective.
- **Node restart**: after a crash or deploy, the node loses its in-memory
  manifold. HQ provides continuity — the restarted node loads the last
  merged engram instead of starting from scratch.
- **Fleet consistency**: without federation, each node drifts independently.
  Node A sees mobile traffic, node B sees API traffic, node C sees browsers.
  Each develops a different normal baseline. HQ merges these perspectives
  into a unified view — every node benefits from the fleet's collective
  observation.
- **Attack intelligence sharing**: if node A learns to deny a new scanner
  pattern (via auto-generated rules), HQ propagates that rule to all nodes
  before the scanner reaches them.

### What gets federated

Two distinct artifacts:

**1. Engrams (spectral state)**
The `StripedSubspace` — per-stripe eigenvectors, eigenvalues, and threshold
statistics. This is the learned normal manifold. Merging engrams means
combining the subspace knowledge from multiple observation points.

**2. Rules (symbolic state)**
The auto-generated `RuleExpr` set — IP blocks, TLS fingerprint rules,
rate limits. These are already serializable (EDN format). Merging rules
means deduplicating, resolving conflicts, and propagating fleet-wide.

### Engram merge strategies

The core question: how to combine two `StripedSubspace` instances that
were trained on different (possibly overlapping) traffic populations.

**A. Subspace union (stack)**
Treat each node's engram as a separate `NormalSubspace` in the merged
`ManifoldState.normal_subspaces` vector. A request is "normal" if it's
close to ANY node's learned subspace. Simple, no information loss, but
compute scales linearly with number of contributing nodes.

**B. Eigenvector averaging**
Average the per-stripe eigenvectors across nodes (weighted by sample count
or confidence). Produces a single merged subspace that captures the
"average" normal. Loses outlier populations that only one node observed.
Compact — same size as a single engram.

**C. Concatenate-and-refit**
Concatenate the eigenvectors from all nodes into an enlarged basis, then
run a fresh PCA/CCIPCA pass to extract the top-K components. Captures the
full variance across all nodes in a compact representation. Most expensive
to compute but most principled.

**D. Federated CCIPCA**
CCIPCA is already an online algorithm — it processes one sample at a time.
HQ could replay "summary vectors" from each node through a central CCIPCA
instance. Each node periodically sends its current principal components
(not raw traffic) to HQ, which incorporates them into the global model.
Privacy-preserving: raw requests never leave the edge.

**Recommendation:** Start with **A (subspace union)** — it's trivial to
implement since `ManifoldState.normal_subspaces` already supports multiple
entries. Each collection cycle, HQ gathers engrams and builds a stacked
set. Nodes boot with the full stack. Graduate to C or D when the stack
grows too large for per-request compute budget.

### Rule merge strategy

Rules are simpler — they're symbolic and already have identity keys:

1. HQ collects `active_rule_specs()` from each node
2. Deduplicate by `identity_key()` (already implemented)
3. Union the rule sets — if any node thinks a pattern is anomalous, include it
4. Apply redundancy check (`is_redundant()`) to prune over-broad rules
5. Redistribute the merged set as preloaded rules for cold boot

Conflict resolution: if node A has `rate-limit 50` and node B has
`rate-limit 100` for the same constraint, take the more restrictive
(lower rps). For block vs rate-limit on the same pattern, prefer block.

### Collection protocol

```
  ┌──────┐     engram + rules      ┌──────┐
  │Node A├────────────────────────►│      │
  └──────┘                         │      │
  ┌──────┐     engram + rules      │  HQ  │──── merge ──► merged.engram
  │Node B├────────────────────────►│      │               merged.rules
  └──────┘                         │      │
  ┌──────┐     engram + rules      │      │
  │Node C├────────────────────────►│      │
  └──────┘                         └──┬───┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                  ▼
               ┌──────┐         ┌──────┐          ┌──────┐
               │Node A│         │Node B│          │Node D│ (new/restarted)
               └──────┘         └──────┘          └──────┘
```

- **Pull model**: HQ polls nodes on a schedule (e.g., every 5 minutes)
- **Push model**: nodes push to HQ after significant manifold changes
  (threshold shift > N%, new rules generated, warmup complete)
- **Distribution**: nodes fetch merged engram on boot, or HQ pushes after
  each merge cycle

### Interaction with other investigations

- **Adaptive learning (Section 2)**: federation amplifies adaptive learning.
  If one node adapts to mobile traffic, HQ propagates that adaptation to
  all nodes. Without federation, every node must independently discover
  and adapt to the same traffic patterns.
- **Anomaly breadth (Section 5)**: breadth could be aggregated at HQ level.
  If the same narrow anomaly appears across multiple nodes, it's likely
  legitimate drift (promote to normal). If the same broad anomaly appears
  across nodes, it's likely a distributed attack (escalate to block).
- **Engram stacking (Section 2C)**: federation naturally produces stacked
  engrams. Each node's contribution becomes a population in the stack.

### Open questions

1. **Staleness**: how old can a merged engram be before it hurts more than
   it helps? Traffic patterns change — a 24-hour-old engram may encode
   yesterday's deployment, not today's.
2. **Poisoning at scale**: if one compromised node sends a corrupted engram
   to HQ, it could poison the entire fleet. Mitigation: HQ validates
   incoming engrams (e.g., reject if threshold is anomalously low/high,
   or if eigenvectors are near-zero).
3. **Heterogeneous services**: if different nodes serve different
   applications (API vs web vs mobile), merging their engrams may produce
   an overly permissive baseline. May need per-service-class federation
   rather than fleet-wide.
4. **Transport**: engram serialization format and size. Current engram
   files are compact (eigenvectors + metadata). Rules are EDN text.
   Both fit comfortably in an HTTP POST body.
