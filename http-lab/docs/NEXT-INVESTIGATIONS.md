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

### Implementation: Approach A — Gated Continuous Learning (DONE)

Implemented in `process_req_sample()` with a two-gate safety mechanism:

**Gate 1: Residual** — only learn if `residual < threshold * ADAPTIVE_RESIDUAL_GATE`
(default 0.7). This ensures we only absorb requests well within the normal
regime, with a 30% safety margin from the threshold boundary.

**Gate 2: Stripe-level breadth** — only learn if `stripe_concentration() >=
ADAPTIVE_CONCENTRATION_GATE` (default 2.0). Uses the cheap per-stripe residual
distribution (O(N_STRIPES)) to verify the anomaly is narrow (concentrated in
few stripes). Broad anomalies (uniform across stripes) are rejected as potential
slow-poisoning attempts.

**Rate limiting** — only every `ADAPTIVE_LEARN_INTERVAL`th (default 10) eligible
sample is actually learned. This prevents rapid manifold drift even when all
traffic passes both gates.

**Manifold republishing** — after every `ADAPTIVE_REPUBLISH_INTERVAL` (default
50) adaptive learns, the manifold state is republished to the proxy via ArcSwap.
This keeps the proxy's scoring threshold in sync with the evolving baseline.

Configuration constants (sidecar `lib.rs`):
```
// ADAPTIVE_RESIDUAL_GATE — ELIMINATED. Replaced by residual < CCIPCA_threshold
//                          AND backend_ok gate. See Section 6.
ADAPTIVE_CONCENTRATION_GATE = 2.0  // min stripe concentration to learn
ADAPTIVE_LEARN_INTERVAL     = 10   // learn 1 in N eligible samples
ADAPTIVE_REPUBLISH_INTERVAL = 50   // republish manifold every N learns
```

Logging:
- `[ADAPTIVE] Learned sample #N (residual=X, concentration=Y)` — every 100th learn
- `[ADAPTIVE] Broad sample rejected (concentration=X, gate=Y)` — poisoning attempts
- `[ADAPTIVE] Republished manifold (total_learns=N, threshold=X)` — state sync
- Tick log includes `adaptive_learns=N` for continuous visibility

### Validation: Multi-Attack Experiment (March 7, 2026) — DONE

The gated continuous learning mechanism was exercised under real concurrent
mixed traffic (20 LLM browser agents + 3 vulnerability scanners).

**Poisoning discovered and fixed:** The original `ADAPTIVE_RESIDUAL_GATE=0.7`
was too permissive when combined with inflated thresholds from diverse training.
Attack residuals (26-43) fell below the absolute gate value (~74), causing
1,374 attack samples to be learned into the baseline. The manifold was actively
poisoned — threshold drifted upward, further admitting attack traffic.

**Fix:** Tightened gate from 0.7 to 0.5. With the corrected gate, only 22
samples were adaptively learned during the attack phase (all legitimate
browser traffic), and the manifold was never republished — the baseline
remained completely stable.

**Key insight:** The residual gate's absolute value matters more than its
ratio to threshold. When thresholds inflate (diverse training), a high
gate fraction admits too much. The gate should be derived from the
training data's residual distribution, not hardcoded. See Section 6.

### Validation (remaining TODO)

Test plan:
1. ~~Warm up with browser traffic only~~  ✓ (multi-attack warmup phase)
2. ~~Introduce diverse client traffic~~  ✓ (3 browser engines, 20 IPs)
3. Introduce mobile-style traffic (different UA, different headers, no cookies)
4. Verify the mobile traffic initially triggers rate-limits
5. Observe whether the manifold adapts and starts allowing it
6. ~~Then introduce attacks — verify still denied despite adaptation~~  ✓
7. ~~Monitor `[ADAPTIVE]` logs to verify attack traffic is never learned~~  ✓ (22 clean learns)

Items 3-5 remain untested — need a dedicated client-diversity test.

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

### Implementation (DONE)

**Two-tier breadth computation:**

#### Proxy-side: fine-grained per-field breadth (manifold.rs)

`drilldown_audit` now returns a `DrilldownResult` containing:
- `fields: Vec<DrilldownAttribution>` — sorted per-field attribution (unchanged)
- `concentration: f64` — `max_score / mean_score` (high = narrow, near 1.0 = broad)
- `breadth: f64` — fraction of fields scoring above mean (high = broad, low = narrow)

Computed from the FULL (untruncated) score list before top-N truncation. This
gives accurate breadth even when the result is truncated for logging/tokens.

Surfaced in:
- `DenialContext` — sealed in the X-Denial-Context token for forensics
- `DenyEventData` — streamed to the sidecar dashboard
- `DashboardEvent::Verdict` — visible in the live WAF dashboard SSE stream
- `log_attribution` — console logs show `breadth=0.65 (BROAD)` with labels:
  - `BROAD` (>0.5), `moderate` (>0.2), `narrow` (≤0.2)

#### Sidecar-side: coarse-grained per-stripe breadth (lib.rs)

`stripe_concentration()` computes concentration from per-stripe residual norms.
This is O(N_STRIPES) — much cheaper than the full leaf-level drilldown — and
leverages the striped architecture: different fields hash to different stripes,
so a narrow anomaly concentrates in few stripes while a broad one is uniform.

Used exclusively as the adaptive learning gate (Section 2).

### Validation (TODO)

Validate with live DVWA+Nikto:
- Nikto probes should show high breadth / low concentration (broad — many fields off)
- Legitimate browser variants should show low breadth / high concentration (narrow)
- The labels (`BROAD`/`moderate`/`narrow`) should match intuition in the logs

---

## 6. Deriving Decision Boundaries from Training Data (RESOLVED)

### The problem (original)

Three hardcoded constants controlled the spectral firewall's sensitivity:
`sigma_mult=3.0`, `deny_mult=1.5`, `ADAPTIVE_RESIDUAL_GATE=0.5`. These were
tuned by hand and failed to generalize across deployment scenarios.

### Resolution: Empirical self-calibration (March 7, 2026)

All three constants have been eliminated from the enforcement decision path.
The system now derives its thresholds from a rolling residual buffer that
tracks confirmed-normal traffic.

**Architecture:**

```
ResidualBuffer (VecDeque<f64>, capacity=500)
├── Admission gate: residual < CCIPCA_threshold AND backend_ok (2xx/3xx)
├── score_threshold = buf_max                    (empirical allow ceiling)
└── deny_threshold  = sqrt(buf_max × CCIPCA_thr) (geometric mean, no multiplier)
```

**Why the geometric mean works:**

The two data-derived boundaries — `buf_max` (tight, empirical) and
`CCIPCA_threshold` (loose, statistical) — bracket the true anomaly boundary.
Their geometric mean places the deny line proportionally between them without
a hardcoded multiplier:

- Early (sparse buffer): buf_max is small, CCIPCA is large → generous deny
  threshold, prevents death spiral where denied traffic can't feed learning
- Steady state: both converge → tight, proportional threshold
- Adapts automatically to traffic diversity, K, DIM, and population count

**Death spiral discovery and fix:**

Initial attempt used `buf_max * 2.0` for deny_threshold. With buf_max=8.39
from only 80 warmup samples, this produced deny_threshold=16.78. Normal
post-warmup browser traffic had residuals of 17-22 (visiting pages not seen
during warmup), causing:
1. Hard deny → no backend forwarding → no learning → buffer frozen
2. Threshold stays tight → more denies → repeat

The geometric mean (`sqrt(8.39 × 121) = 31.9`) broke this cycle — browsers
at 22 pass through as rate-limited (not denied), while attacks at 90 are
firmly denied. Rate-limited traffic still gets forwarded, feeding adaptive
learning and growing the buffer.

**Remaining operational constants** (not decision boundaries):
- `RESIDUAL_BUFFER_CAPACITY=500`, `RESIDUAL_BUFFER_MIN_SAMPLES=50` — buffer sizing
- `ADAPTIVE_LEARN_INTERVAL=10`, `ADAPTIVE_CONCENTRATION_GATE=2.0` — learning rate
- `sigma_mult=3.0` — still used inside CCIPCA for its internal estimate, but
  no longer drives proxy-side scoring. Serves as one input to the geometric mean.

**Validation:** 20 LLM browsers + 3 scanners, WARMUP_SAMPLES=100. 5,118 attack
denies, 48 browser FPs (27 early settling + 18 Firefox minority + 3 POSTs),
manual Chrome browsing had ~3 initial FPs then zero. 99.1% precision.

---

## 7. Centralized Engram Federation (HQ)

### The idea

Multiple edge nodes run independent spectral firewalls — each with its own
warmup, adaptive learning, and accumulated manifold state. A central **HQ**
periodically collects the learned engrams from all nodes, merges them, and
redistributes the merged result as the cold-boot starting point for new or
restarting nodes.

The engram is the core artifact: the `StripedSubspace` — per-stripe
eigenvectors, eigenvalues, and threshold statistics that geometrically
define "what normal traffic looks like." It's not an allow-list of values;
it's a subspace. Anything that projects well onto it has low residual
(normal). Anything orthogonal to it is anomalous. This is what HQ
federates — the learned shape of normal across the fleet.

(Auto-generated rules are a separate, DDoS-specific reactive mechanism.
They may optionally be shared via HQ but are not the primary value —
the engram is.)

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

### Collection protocol

```
  ┌──────┐       engram            ┌──────┐
  │Node A├────────────────────────►│      │
  └──────┘                         │      │
  ┌──────┐       engram            │  HQ  │──── merge ──► merged.engram
  │Node B├────────────────────────►│      │
  └──────┘                         │      │
  ┌──────┐       engram            │      │
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
  (threshold shift > N%, warmup complete)
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

### Deployment model: Passive → Federated → Enforcement

The self-calibrating thresholds (Section 6) enable a zero-tuning deployment:

**Phase 1: Passive observation (1-2 weeks per fleet)**
- Deploy spectral firewall in **monitor-only mode** across all app nodes
- Each node learns its normal baseline from live traffic
- Thresholds self-calibrate from the residual buffer — no human tuning
- Log verdicts but don't enforce — build confidence in the model
- Validates: false positive rate, coverage of client diversity, threshold
  stability under real traffic patterns

**Phase 2: Federated convergence (HQ merge cycle)**
- HQ collects engrams from all nodes (pull or push model)
- Merges via subspace union (start simple) or eigenvector averaging
- Redistributes the merged engram as the fleet-wide cold-boot baseline
- Every node now carries the collective intelligence of the fleet:
  - Node A saw mobile traffic → all nodes know mobile patterns
  - Node B saw API consumers → all nodes recognize API structure
  - Node C saw browser diversity → all nodes handle browser variance
- The merged engram's residual distribution reflects fleet-wide diversity,
  so the geometric-mean deny threshold is naturally calibrated for the
  full population

**Phase 3: Confident enforcement**
- Flip nodes to enforcement mode — deny/rate-limit anomalous traffic
- New/restarting nodes boot from the merged engram, enforce immediately
- No warmup vulnerability, no cold-start false positives
- Adaptive learning continues refining per-node baselines
- HQ continues merging and redistributing periodically

**Why this works:** The spectral firewall learns "what normal looks like"
from pure geometry — no attack signatures, no rules, no CVE databases.
The fleet collectively observes the full diversity of legitimate traffic.
Federation shares that collective observation. Self-calibrating thresholds
mean no per-deployment tuning. The result is a firewall that's never been
told about any attack but denies 99%+ of vulnerability scanners by
recognizing that attack traffic is geometrically alien to the learned
normal subspace.

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
   files are compact (eigenvectors + metadata). Fits comfortably in an
   HTTP POST body.
5. **Monitor-only mode**: needs implementation — log verdicts without
   applying deny/rate-limit actions. Could be a simple CLI flag or
   env var on the proxy.
6. **Convergence metrics**: how does HQ know when the fleet has converged
   enough to recommend enforcement? Possible signals: threshold stability
   (variance of deny_threshold across nodes), false positive rate in
   monitor logs, engram similarity between merge cycles.
