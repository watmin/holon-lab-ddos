# Next Investigations

Two open problems to address before the spectral firewall is production-viable.

---

## 1. Ground Truth: Actual Leaf Binding Count and Distribution

### The problem

All parameter tuning assumes ~100 leaf bindings per request. This number was
estimated, never measured. If real DVWA requests produce 40 or 300 leaves, the
optimal configuration shifts significantly:

- **Stripe load balance:** 100 leaves / 32 stripes = ~3 per stripe. If it's
  actually 40 leaves, some stripes get 0-1 bindings and K=32 is deflating
  empty dimensions. If it's 300, stripes are overloaded and we may need more.
- **Per-stripe rank:** With ~3 bindings per stripe, the data is rank-1 (one
  eigenvalue). The sweep confirmed this. But if real traffic produces 10+
  bindings per stripe, there's actual multi-dimensional structure to learn.
- **K sizing:** K=32 was chosen because it reaches the separation ceiling in
  the sweep. But the ceiling is an artifact of rank-1 data — with higher rank,
  K might need to be larger, or could be smaller.

### What to measure

1. **Total leaf count per request.** Instrument `encode_walkable_striped` or
   the `Walkable::walk_map_items` implementation on `RequestSample` to count
   leaves emitted per request. Log distribution during warmup.

2. **Full field inventory.** Dump every leaf path (FQDN) for a few requests.
   This reveals:
   - Fields we expect that aren't being walked
   - Fields being walked that shouldn't be (noise)
   - Whether variable-length fields (headers, cookies, query params) dominate

3. **Per-stripe distribution.** After FQDN hashing, how evenly are bindings
   spread? Plot a histogram of bindings-per-stripe. If the hash produces lumpy
   distribution, some stripes are learning rich structure while others see nothing.

4. **Normal vs attack leaf counts.** Do Nikto requests produce the same number
   of leaves as DVWA browsing? Different header sets, query strings, and cookie
   presence could shift the count significantly. If attack requests have fewer
   leaves (e.g., no cookies, minimal headers), that itself is a detection signal
   the encoding already captures implicitly.

### Approach

Add a `--dump-walk` debug flag to the proxy or a standalone script that:
- Creates an `Encoder` and `VectorManager`
- Constructs a few representative `RequestSample`s (from warmup traffic or
  captured samples)
- Calls `walk_map_items()` and prints every (path, value) pair
- Calls `encode_walkable_striped()` and reports per-stripe binding counts
- Outputs a summary: total leaves, min/max/mean per stripe, empty stripes

This is pure measurement — no production code changes needed. The results
inform whether the current 1024×32×32 config is well-sized or needs adjustment.

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

Measure the leaf counts first, then validate the parameter sweep results against
ground truth before implementing adaptive learning.
