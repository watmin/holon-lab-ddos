# Spectral Parameter Sweep — Results

**Date:** March 5, 2026
**Binary:** `cargo run -p http-proxy --release --example param_sweep`
**Machine:** Linux 6.17.9, release build with optimizations

## Summary

Swept the three parameter categories (geometry, eigenvalue, decision boundary)
with synthetic DVWA-normal and Nikto-attack traffic. Key findings:

1. **K is the most impactful parameter** — increasing from 8 to 16 nearly doubles
   separation (4.7x to 9.2x) with modest latency cost (+300us). K=32 reaches 13x
   separation. K=8 was undersized.
2. **DIM=2048 is the sweet spot** — half the latency of DIM=4096 with near-identical
   separation (5.0x vs 4.7x). DIM=512 still achieves 5.5x separation at 300us full path.
3. **More stripes improve separation monotonically** — 1 stripe = 3.1x, 64 stripes = 5.0x.
   Current 32 stripes is a good balance at 4.7x.
4. **Detection is robust across all configs** — 0% FPR and 0% FNR at every configuration
   tested, indicating the normal-vs-attack gap is large enough that parameter choice
   doesn't affect correctness, only the margin of safety.
5. **Warmup samples matter significantly** — 100 samples gives only 1.6x separation,
   500 gives 4.7x, 2000 gives 5.6x. The 500 default is adequate but not generous.
6. **Full hot path at current config (4096, 32, 8) is ~3ms**, not sub-millisecond.
   The 41us measurement from live testing was the deny-path only (no encoding).
   Sub-millisecond is achievable at DIM=512 (~300us) or DIM=1024 (~1.1ms).

## Raw Results

### Geometry Sweep: DIM (STRIPES=32, K=8)

| DIM  | enc_p50 | enc_p99 | res_p50 | res_p99 | full_p50 | full_p99 | sep   | FPR  | FNR  | thr   |
|------|---------|---------|---------|---------|----------|----------|-------|------|------|-------|
| 512  | 232us   | 483us   | 56us    | 71us    | 303us    | 477us    | 5.5x  | 0.0% | 0.0% | 22.1  |
| 1024 | 441us   | 1.2ms   | 212us   | 243us   | 1.1ms    | 1.7ms    | 5.1x  | 0.0% | 0.0% | 33.3  |
| 2048 | 792us   | 1.3ms   | 237us   | 367us   | 1.1ms    | 1.5ms    | 5.0x  | 0.0% | 0.0% | 48.7  |
| 4096 | 1.6ms   | 2.8ms   | 668us   | 1.5ms   | 3.2ms    | 5.6ms    | 4.7x  | 0.0% | 0.0% | 73.4  |
| 8192 | 5.5ms   | 11.1ms  | 1.5ms   | 2.0ms   | 7.4ms    | 15.9ms   | 4.8x  | 0.0% | 0.0% | 101.3 |

**Observation:** Encoding dominates the hot path (2-3x more than residual). Separation
is slightly *better* at lower DIM, likely because fewer dimensions concentrate the
signal. The full hot path scales roughly linearly with DIM.

### Geometry Sweep: STRIPES (DIM=4096, K=8)

| STRIPES | enc_p50 | res_p50 | full_p50 | sep   | FPR  | FNR  | thr   |
|---------|---------|---------|----------|-------|------|------|-------|
| 1       | 2.0ms   | 36us    | 1.8ms    | 3.1x  | 0.0% | 0.0% | 23.7  |
| 4       | 2.3ms   | 173us   | 1.7ms    | 3.7x  | 0.0% | 0.0% | 38.4  |
| 8       | 1.5ms   | 220us   | 2.1ms    | 3.9x  | 0.0% | 0.0% | 49.7  |
| 16      | 1.6ms   | 432us   | 2.3ms    | 4.3x  | 0.0% | 0.0% | 61.4  |
| 32      | 2.0ms   | 768us   | 4.2ms    | 4.7x  | 0.0% | 0.0% | 73.4  |
| 64      | 1.6ms   | 1.3ms   | 3.6ms    | 5.0x  | 0.0% | 0.0% | 77.5  |

**Observation:** Encoding cost is constant across stripes (as expected — same total
leaf bindings, just distributed differently). Residual cost scales linearly with
stripes. Separation improves monotonically — more stripes = less crosstalk = better
discrimination. Diminishing returns above 32.

### Geometry Sweep: K (DIM=4096, STRIPES=32)

| K  | enc_p50 | res_p50 | full_p50 | sep    | FPR  | FNR  | thr   |
|----|---------|---------|----------|--------|------|------|-------|
| 2  | 1.5ms   | 443us   | 2.3ms    | 2.7x   | 0.0% | 0.0% | 128.6 |
| 4  | 1.5ms   | 975us   | 2.5ms    | 3.3x   | 0.0% | 0.0% | 102.5 |
| 8  | 1.5ms   | 1.0ms   | 2.6ms    | 4.7x   | 0.0% | 0.0% | 73.4  |
| 16 | 1.4ms   | 1.3ms   | 2.9ms    | 9.2x   | 0.0% | 0.0% | 37.2  |
| 32 | 1.4ms   | 2.4ms   | 3.9ms    | 13.0x  | 0.0% | 0.0% | 26.3  |
| 64 | 1.5ms   | 4.6ms   | 6.1ms    | 13.1x  | 0.0% | 0.0% | 26.1  |

**Observation:** K has the strongest effect on separation of any parameter. K=2 gives
only 2.7x separation; K=32 gives 13.0x. The jump from K=8 to K=16 is dramatic (4.7x
to 9.2x). K=32 to K=64 shows no further improvement (13.0x to 13.1x) — the subspace
is fully learned by K=32. The threshold drops with higher K because more variance is
captured, leaving less residual for normal traffic.

**K=8 was the performance optimization from the previous session but it materially
degrades separation compared to the veth-lab's K=32.**

### Eigenvalue Sweep: amnesia

| amnesia | threshold | sep   | FPR  | FNR  | top eigenvalue |
|---------|-----------|-------|------|------|----------------|
| 0.5     | 69.4      | 4.9x  | 0.0% | 0.0% | 206.4          |
| 1.0     | 70.8      | 4.8x  | 0.0% | 0.0% | 206.4          |
| 2.0     | 73.4      | 4.7x  | 0.0% | 0.0% | 206.0          |
| 4.0     | 75.2      | 4.5x  | 0.0% | 0.0% | 204.8          |
| 8.0     | 73.7      | 4.6x  | 0.0% | 0.0% | 202.4          |

**Observation:** Amnesia has minimal impact. The range is only 4.5x to 4.9x across a
16x range of amnesia values. With 500 steady warmup samples, there's not much
distribution shift for amnesia to adapt to. The default of 2.0 is fine.

### Eigenvalue Sweep: sigma_mult

| sigma_mult | threshold | sep   | FPR  | FNR  |
|------------|-----------|-------|------|------|
| 1.5        | 44.1      | 7.8x  | 0.0% | 0.0% |
| 2.0        | 51.2      | 6.7x  | 0.0% | 0.0% |
| 2.5        | 58.6      | 5.8x  | 0.0% | 0.0% |
| 3.0        | 65.9      | 5.2x  | 0.0% | 0.0% |
| 3.5        | 73.4      | 4.7x  | 0.0% | 0.0% |
| 4.0        | 80.9      | 4.2x  | 0.0% | 0.0% |
| 5.0        | 96.1      | 3.6x  | 0.0% | 0.0% |

**Observation:** sigma_mult linearly scales the threshold. Lower sigma = tighter gate =
higher separation ratio. With the current traffic mix, even sigma_mult=1.5 produces 0%
FPR, suggesting the threshold is very conservative at 3.5. However, with real live
traffic (more variance), tighter thresholds risk false positives. The 3.5 default
provides ample safety margin.

### Eigenvalue Sweep: ema_alpha

| ema_alpha | threshold | sep   |
|-----------|-----------|-------|
| 0.001     | 113.8     | 3.0x  |
| 0.005     | 96.3      | 3.6x  |
| 0.010     | 73.4      | 4.7x  |
| 0.050     | 68.8      | 5.0x  |
| 0.100     | 71.6      | 4.8x  |

**Observation:** Very slow EMA (0.001) inflates the threshold because it hasn't
converged by 500 samples. 0.01 to 0.1 are all similar. The default 0.01 is fine.

### Eigenvalue Sweep: warmup_samples

| warmup | threshold | sep   | top eigenvalue |
|--------|-----------|-------|----------------|
| 100    | 209.2     | 1.6x  | 196.3          |
| 250    | 119.2     | 2.9x  | 203.5          |
| 500    | 73.4      | 4.7x  | 206.0          |
| 1000   | 63.8      | 5.4x  | 207.2          |
| 2000   | 61.2      | 5.6x  | 207.9          |

**Observation:** Strong effect. At 100 samples the threshold is 3x too high,
giving only 1.6x separation. 500 is adequate (4.7x). 1000-2000 gives marginal
improvement. At 80 rps, 500 samples = 6.3 seconds of warmup, which is acceptable.

### Decision Sweep: deny_mult

| deny_mult | deny_thr | mean_atk | deny% | ratelim% | FPR  | FNR  |
|-----------|----------|----------|-------|----------|------|------|
| 1.5       | 110.1    | 341.9    | 100%  | 0%       | 0.0% | 0.0% |
| 2.0       | 146.8    | 341.9    | 100%  | 0%       | 0.0% | 0.0% |
| 2.5       | 183.5    | 341.9    | 100%  | 0%       | 0.0% | 0.0% |
| 3.0       | 220.2    | 341.9    | 100%  | 0%       | 0.0% | 0.0% |
| 4.0       | 293.6    | 341.9    | 100%  | 0%       | 0.0% | 0.0% |

**Observation:** Mean attack residual (341.9) is so far above even the 4x deny
threshold (293.6) that the deny_mult doesn't matter for this traffic mix. The
deny/rate-limit boundary only becomes interesting for traffic that's anomalous
but close to the threshold — a mimicry attack scenario.

## Interaction Sweeps (March 5, 2026 — Round 2)

The single-variable sweeps above varied one parameter at a time. These interaction
sweeps explore how parameters combine.

### DIM × K Interaction (STRIPES=32)

| DIM  | K=8    | full_p50 | K=16   | full_p50 | K=32   | full_p50 |
|------|--------|----------|--------|----------|--------|----------|
| 512  | 5.5x   | 271us    | 10.1x  | 316us    | 13.1x  | 441us    |
| 1024 | 5.1x   | 535us    | 10.1x  | 653us    | 13.0x  | 1.0ms    |
| 2048 | 5.0x   | 936us    | 9.5x   | 1.7ms    | 13.0x  | 2.3ms    |
| 4096 | 4.7x   | 2.2ms    | 9.2x   | 3.5ms    | 13.0x  | 6.1ms    |

**Key finding:** K's effect on separation is consistent across all DIMs. The
separation ceiling at K=32 (~13x) is achievable at any DIM. Lower DIM actually
reaches it slightly faster (13.1x at 512 vs 13.0x at 4096).

DIM=512, K=32 gives **441us full path at 13.1x separation** — sub-millisecond
with the best separation we've measured.

### DIM × STRIPES Interaction (K=16)

| DIM  | S=8   | full_p50 | S=16  | full_p50 | S=32   | full_p50 | S=64   | full_p50 |
|------|-------|----------|-------|----------|--------|----------|--------|----------|
| 512  | 7.0x  | 386us    | 9.7x  | 440us    | 10.1x  | 378us    | 10.1x  | 845us    |
| 1024 | 6.9x  | 881us    | 8.7x  | 971us    | 10.1x  | 1.4ms    | 9.9x   | 1.0ms    |
| 2048 | 6.9x  | 688us    | 8.7x  | 895us    | 9.5x   | 1.3ms    | 9.3x   | 2.2ms    |
| 4096 | 6.8x  | 1.5ms    | 8.6x  | 1.9ms    | 9.2x   | 3.5ms    | 9.6x   | 7.3ms    |

**Key finding:** At K=16, stripes help up to ~32 then plateau. DIM=512 with 32
stripes (378us, 10.1x) is essentially identical to DIM=512 with 64 stripes
(845us, 10.1x) but at half the latency. Optimal stripe count is 16-32 regardless
of DIM.

### STRIPES × K Interaction (DIM=2048)

| STRIPES | K=4  | full_p50 | K=8   | full_p50 | K=16  | full_p50 | K=32   | full_p50 |
|---------|------|----------|-------|----------|-------|----------|--------|----------|
| 4       | 3.0x | 1.4ms    | 3.7x  | 850us    | 5.1x  | 845us    | 8.1x   | 1.5ms    |
| 8       | 2.9x | 1.4ms    | 4.2x  | 697us    | 6.9x  | 719us    | 9.4x   | 827us    |
| 16      | 3.1x | 709us    | 4.5x  | 733us    | 8.7x  | 1.2ms    | 12.6x  | 1.5ms    |
| 32      | 3.4x | 1.4ms    | 5.0x  | 839us    | 9.5x  | 1.3ms    | 13.0x  | 3.4ms    |
| 64      | 3.6x | 983us    | 5.3x  | 2.1ms    | 9.3x  | 3.9ms    | 12.6x  | 3.2ms    |

**Key finding:** K has a stronger effect than stripe count. The 8×32 config
(9.4x, 827us) beats 32×16 (9.5x, 1.3ms) at lower latency. The sweet spot at
DIM=2048 is 16 stripes × K=32 (12.6x, 1.5ms) — better than 32×16 and 64×16.

### Iso-Compute Budget Configs (DIM × K × STRIPES ≈ 1M)

Same compute budget as current config, different splits:

| Config (DIM×S×K) | Budget   | full_p50 | sep    | Verdict                          |
|------------------|----------|----------|--------|----------------------------------|
| 4096×32×8        | 1,048,576 | 2.1ms   | 4.7x   | **current baseline**             |
| 2048×32×16       | 1,048,576 | 1.3ms   | 9.5x   | 40% faster, 2x sep              |
| 2048×64×8        | 1,048,576 | 1.5ms   | 5.3x   | marginal improvement             |
| 1024×64×16       | 1,048,576 | 993us   | 9.9x   | sub-ms, 2x sep                   |
| **1024×32×32**   | 1,048,576 | **997us** | **13.0x** | **sub-ms, 2.8x sep — WINNER** |
| 512×64×32        | 1,048,576 | 800us   | 12.7x  | fastest, near-best               |
| 4096×16×16       | 1,048,576 | 2.0ms   | 8.6x   | high DIM, fewer stripes          |
| 8192×16×8        | 1,048,576 | 3.3ms   | 4.2x   | too much DIM, wastes budget      |
| 8192×8×16        | 1,048,576 | 7.9ms   | 6.8x   | huge DIM, fewest stripes, slow   |

Over/under budget comparison:

| Config (DIM×S×K) | Budget    | full_p50 | sep    | Notes                            |
|------------------|-----------|----------|--------|----------------------------------|
| 2048×32×32       | 2,097,152 | 2.5ms   | 13.0x  | 2x budget, same ceiling as 1024  |
| 2048×16×16       | 524,288   | 1.2ms   | 8.7x   | half budget, still 2x better     |
| 1024×16×16       | 262,144   | 534us   | 8.7x   | **quarter budget, 534us, 8.7x** |

## Analysis

### The FLOP allocation was wrong

We were spending compute in the wrong place. High DIM contributes almost nothing
to separation — it primarily adds latency. K (noise deflation steps) is the dominant
quality lever, and lower DIM is actually slightly *better* for separation because
signal concentrates more in fewer dimensions.

At the same 1M FLOP budget:
- **4096×32×8** (current): 2.1ms, 4.7x — large vectors, underpowered K
- **1024×32×32** (optimal): 997us, 13.0x — smaller vectors, fully-powered K

This is **2.1x faster AND 2.8x better separation** by redistributing compute from
DIM into K.

### K is king, DIM is noise

The separation ceiling (~13x) is determined entirely by K≥32. Once K captures all
noise directions, adding more dimensions doesn't help — it just makes the vectors
bigger. With ~3 bindings per stripe, the per-stripe data is roughly rank-1, and
K controls how many orthogonal noise dimensions are deflated.

### Stripes: diminishing returns above 16-32

More stripes reduces crosstalk but with diminishing returns. At K=16, going from
32 to 64 stripes often *hurts* (more compute, same or slightly lower separation).
The sweet spot is 16-32 stripes for the current leaf count (~100 leaves).

### Large DIM, few stripes: not recommended

8192×16×8 and 8192×8×16 are the worst iso-compute configs. Large DIM increases
encoding cost dramatically (O(DIM × leaves)) while providing no separation benefit.
The encoding cost dominates at high DIM.

### Sub-millisecond is now the *default*

Five configs achieve sub-millisecond full path at the same budget:
- 512×64×32: 800us, 12.7x
- 1024×64×16: 993us, 9.9x
- 1024×32×32: 997us, 13.0x

And at quarter budget: 1024×16×16 = 534us, 8.7x.

### Recommended configuration

| Parameter   | Current | Recommended  | Rationale                                                  |
|-------------|---------|--------------|-------------------------------------------------------------|
| `VSA_DIM`   | 4096    | **1024**     | 4x lower latency, higher concentration, same-budget 13x sep |
| `N_STRIPES` | 32      | **32** (keep) | Sweet spot for crosstalk reduction                         |
| `STRIPED_K` | 8       | **32**       | Captures all noise directions, reaches separation ceiling   |

Compute: 1024 × 32 × 32 = 1,048,576 (identical budget to current 4096 × 32 × 8).
Result: 997us full path (down from 2.1ms), 13.0x separation (up from 4.7x).

**Alternatively**, if latency is the primary concern:
- 1024×16×16 = 534us, 8.7x (quarter budget, still 2x better than current)
- 512×64×32 = 800us, 12.7x (same budget, fastest sub-ms option)

## Eigenvalue structure

All configurations show `explained_ratio = 1.0` and only 1 non-zero eigenvalue
(top3 = [~206, 0, 0]). This means:
- With only ~3 bindings per stripe (100 leaves / 32 stripes), the per-stripe
  data is rank-1 or near rank-1
- Higher K doesn't add more eigenvalues, it captures the residual structure better
  (the deflation projects away more noise)
- The subspace is essentially learning a single direction per stripe, and K
  controls how many orthogonal noise dimensions are removed

This explains why K=32 and K=64 have identical separation — once all the noise
directions are projected away (K > rank of the data), additional components
add nothing.
