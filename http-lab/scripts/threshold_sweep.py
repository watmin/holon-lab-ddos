#!/usr/bin/env python3
"""
Threshold strategy sweep — evaluates deny_threshold derivation strategies
against simulated traffic with varying buffer sizes and poisoning rates.

Usage:
  python threshold_sweep.py              # Grok's generic parameters
  python threshold_sweep.py --calibrated # Spectral firewall observed regime
"""

import numpy as np
from collections import deque
import sys
import time

CALIBRATED = "--calibrated" in sys.argv

if CALIBRATED:
    print("=== CALIBRATED MODE: spectral firewall observed regime ===\n")
    NORMAL_MU, NORMAL_SIGMA = 5.0, 2.0
    ATTACK_MU, ATTACK_SIGMA = 95.0, 15.0
    POISON_MU, POISON_SIGMA = 15.0, 3.0
    CCIPCA_START, CCIPCA_END = 120.0, 100.0
else:
    print("=== DEFAULT MODE: generic parameters ===\n")
    NORMAL_MU, NORMAL_SIGMA = 0.4, 0.3
    ATTACK_MU, ATTACK_SIGMA = 3.5, 1.2
    POISON_MU, POISON_SIGMA = 1.1, 0.3
    CCIPCA_START, CCIPCA_END = 2.5, 0.85

BUFFER_SIZES = [256, 512]
POISON_RATES = [0.0, 0.01, 0.05]
N_STEPS = 20_000
ATTACK_FRACTION = 0.15

np.random.seed(42)


def generate_stream(poison_rate):
    """Generate residual stream with attacks and optional poisoning."""
    is_attack = np.random.rand(N_STEPS) < ATTACK_FRACTION
    residuals = np.zeros(N_STEPS)
    clean_n = (~is_attack).sum()
    residuals[~is_attack] = np.abs(np.random.normal(NORMAL_MU, NORMAL_SIGMA, clean_n))
    residuals[is_attack] = np.abs(np.random.normal(ATTACK_MU, ATTACK_SIGMA, is_attack.sum()))
    if poison_rate > 0:
        n_poison = int(N_STEPS * poison_rate)
        poison_idx = np.random.choice(N_STEPS, n_poison, replace=False)
        residuals[poison_idx] = np.abs(np.random.normal(POISON_MU, POISON_SIGMA, n_poison))
    ccipca = np.linspace(CCIPCA_START, CCIPCA_END, N_STEPS) * (
        1 + 0.1 * np.sin(np.linspace(0, 20, N_STEPS))
    )
    return residuals, is_attack, ccipca


def run_strategy(name, thresh_fn, residuals, is_attack, ccipca, buf_size):
    """Run a single strategy through the stream. Returns metrics dict."""
    buf = deque(maxlen=buf_size)
    tp = fp = tn = fn = 0
    thresholds = []
    buf_arr = None
    buf_dirty = True

    for t in range(N_STEPS):
        r = residuals[t]
        c = ccipca[t]
        attack = is_attack[t]
        buf_max = max(buf) if buf else 0.0

        if buf_dirty and len(buf) > 10:
            buf_arr = np.array(buf)
            buf_dirty = False

        thresh = thresh_fn(buf_max, c, buf_arr, len(buf))
        thresholds.append(thresh)

        predicted = r > thresh
        if attack and predicted:   tp += 1
        elif attack:               fn += 1
        elif predicted:            fp += 1
        else:                      tn += 1

        if not attack and r < thresh * 0.9:
            buf.append(r)
            buf_dirty = True

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0
    th = np.array(thresholds[buf_size:])
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "thresh_mean": th.mean() if len(th) else 0,
        "thresh_std": th.std() if len(th) else 0,
    }


# ====================== STRATEGY DEFINITIONS ======================
# Each takes (buf_max, ccipca, buf_arr_or_None, buf_len) -> threshold

def s_geometric(bm, c, arr, n):
    return np.sqrt(max(bm, 1e-8) * max(c, 1e-8))

def s_harmonic(bm, c, arr, n):
    return 2.0 / (1.0 / max(bm, 1e-8) + 1.0 / max(c, 1e-8))

def s_arithmetic(bm, c, arr, n):
    return 0.5 * bm + 0.5 * c

def s_weighted_70_30(bm, c, arr, n):
    return 0.7 * bm + 0.3 * c

def s_weighted_30_70(bm, c, arr, n):
    return 0.3 * bm + 0.7 * c

def s_minimum(bm, c, arr, n):
    return min(bm, c)

def s_max_only(bm, c, arr, n):
    return max(bm, c)

def s_ccipca_only(bm, c, arr, n):
    return c

def s_buf_max_only(bm, c, arr, n):
    return bm if bm > 0 else c

def s_buf_max_2x(bm, c, arr, n):
    return bm * 2.0 if bm > 0 else c

def s_buf_max_3x(bm, c, arr, n):
    return bm * 3.0 if bm > 0 else c

def s_quantile_999(bm, c, arr, n):
    if arr is not None and n > 10:
        return np.quantile(arr, 0.999)
    return max(bm, c)

def s_quantile_99(bm, c, arr, n):
    if arr is not None and n > 10:
        return np.quantile(arr, 0.99)
    return max(bm, c)

def s_quantile_95(bm, c, arr, n):
    if arr is not None and n > 10:
        return np.quantile(arr, 0.95)
    return max(bm, c)

def s_mean_3std(bm, c, arr, n):
    if arr is not None and n > 10:
        return arr.mean() + 3 * arr.std(ddof=1)
    return max(bm, c)

def s_mean_2std(bm, c, arr, n):
    if arr is not None and n > 10:
        return arr.mean() + 2 * arr.std(ddof=1)
    return max(bm, c)

def s_mad(bm, c, arr, n):
    if arr is not None and n > 10:
        med = np.median(arr)
        mad = np.median(np.abs(arr - med))
        return med + 3.5 * mad if mad > 0 else med + 1.0
    return max(bm, c)

def s_chebyshev(bm, c, arr, n):
    if arr is not None and n > 10:
        mu = arr.mean()
        var = arr.var(ddof=1)
        eps = 0.001
        return mu + np.sqrt((1.0 / eps - 1.0) * var) if var > 0 else mu + 1.0
    return max(bm, c)

def s_power_neg1(bm, c, arr, n):
    a, d = max(bm, 1e-8), max(c, 1e-8)
    return ((a**-1 + d**-1) / 2) ** (-1)

def s_power_half(bm, c, arr, n):
    a, d = max(bm, 1e-8), max(c, 1e-8)
    return ((a**0.5 + d**0.5) / 2) ** 2

def s_power_2(bm, c, arr, n):
    a, d = max(bm, 1e-8), max(c, 1e-8)
    return ((a**2 + d**2) / 2) ** 0.5

def s_power_5(bm, c, arr, n):
    a, d = max(bm, 1e-8), max(c, 1e-8)
    return ((a**5 + d**5) / 2) ** 0.2

def s_lehmer_2(bm, c, arr, n):
    a, d = max(bm, 1e-8), max(c, 1e-8)
    return (a**2 + d**2) / (a + d)

def s_heronian(bm, c, arr, n):
    g = np.sqrt(max(bm, 1e-8) * max(c, 1e-8))
    return (bm + c + g) / 3

def s_contraharmonic(bm, c, arr, n):
    a, d = max(bm, 1e-8), max(c, 1e-8)
    return (a**2 + d**2) / (a + d)

def s_median_blend(bm, c, arr, n):
    if arr is not None and n > 10:
        q95 = np.quantile(arr, 0.95)
        return np.median([bm, c, q95])
    return max(bm, c)

def s_entropy_mod(bm, c, arr, n):
    base = np.sqrt(max(bm, 1e-8) * max(c, 1e-8))
    if arr is not None and n > 10:
        vals = arr / (arr.sum() + 1e-8)
        gini = 1.0 - 2.0 * np.sum(np.cumsum(np.sort(vals)) / vals.sum()) / len(vals)
        return base * (1.0 + 0.5 * gini)
    return base

def s_log_mean(bm, c, arr, n):
    a, d = max(bm, 1e-8), max(c, 1e-8)
    if abs(a - d) < 1e-10:
        return a
    return (a - d) / (np.log(a) - np.log(d))


STRATEGIES = {
    "geometric": s_geometric,
    "harmonic": s_harmonic,
    "arithmetic": s_arithmetic,
    "weighted_70_30": s_weighted_70_30,
    "weighted_30_70": s_weighted_30_70,
    "minimum": s_minimum,
    "max_only": s_max_only,
    "ccipca_only": s_ccipca_only,
    "buf_max_only": s_buf_max_only,
    "buf_max_2x": s_buf_max_2x,
    "buf_max_3x": s_buf_max_3x,
    "quantile_999": s_quantile_999,
    "quantile_99": s_quantile_99,
    "quantile_95": s_quantile_95,
    "mean_3std": s_mean_3std,
    "mean_2std": s_mean_2std,
    "mad": s_mad,
    "chebyshev": s_chebyshev,
    "power_p-1": s_power_neg1,
    "power_p0.5": s_power_half,
    "power_p2": s_power_2,
    "power_p5": s_power_5,
    "lehmer_p2": s_lehmer_2,
    "heronian": s_heronian,
    "contraharmonic": s_contraharmonic,
    "median_blend": s_median_blend,
    "entropy_mod": s_entropy_mod,
    "log_mean": s_log_mean,
}


def main():
    start = time.time()
    rows = []

    configs = list(
        (bs, pr) for bs, pr in
        ((bs, pr) for bs in BUFFER_SIZES for pr in POISON_RATES)
    )

    for buf_size, poison_rate in configs:
        residuals, is_attack, ccipca = generate_stream(poison_rate)

        for name, fn in STRATEGIES.items():
            m = run_strategy(name, fn, residuals, is_attack, ccipca, buf_size)
            rows.append({
                "strategy": name,
                "buf": buf_size,
                "poison": poison_rate,
                **{k: round(v, 5) for k, v in m.items()},
            })

    elapsed = time.time() - start
    print(f"Sweep completed in {elapsed:.1f}s ({len(STRATEGIES)} strategies × "
          f"{len(configs)} configs = {len(rows)} runs)\n")

    hdr = f"{'strategy':<18} {'buf':>4} {'poison':>6}  {'prec':>6} {'recall':>6} {'f1':>6} {'fpr':>8}  {'thr_mean':>8} {'thr_std':>8}"
    sep = "-" * len(hdr)

    # Print grouped by poison rate
    for pr in POISON_RATES:
        print(f"\n{'='*80}")
        print(f"  POISON RATE = {pr}")
        print(f"{'='*80}")
        print(hdr)
        print(sep)
        subset = [r for r in rows if r["poison"] == pr]
        subset.sort(key=lambda r: (r["buf"], r["fpr"], -r["recall"]))
        for r in subset:
            print(f"{r['strategy']:<18} {r['buf']:>4} {r['poison']:>6.2f}  "
                  f"{r['precision']:>6.4f} {r['recall']:>6.4f} {r['f1']:>6.4f} {r['fpr']:>8.5f}  "
                  f"{r['thresh_mean']:>8.2f} {r['thresh_std']:>8.4f}")

    # Summary: best strategies
    print(f"\n{'='*80}")
    print("  SUMMARY: Best strategies across all conditions (buf=512)")
    print(f"{'='*80}")
    print(f"\n{'strategy':<18} {'p=0 FPR':>10} {'p=0 recall':>10} {'p=.05 FPR':>10} {'p=.05 recall':>10} {'p=.05 F1':>10}")
    print("-" * 70)

    strat_names = list(STRATEGIES.keys())
    for name in strat_names:
        r0 = next((r for r in rows if r["strategy"] == name and r["buf"] == 512 and r["poison"] == 0.0), None)
        r5 = next((r for r in rows if r["strategy"] == name and r["buf"] == 512 and r["poison"] == 0.05), None)
        if r0 and r5:
            print(f"{name:<18} {r0['fpr']:>10.5f} {r0['recall']:>10.4f} {r5['fpr']:>10.5f} {r5['recall']:>10.4f} {r5['f1']:>10.4f}")

    # Geometric comparison
    print(f"\n{'='*80}")
    print("  STRATEGIES THAT BEAT GEOMETRIC MEAN (buf=512, poison=0.05)")
    print("  Criteria: F1 >= geometric AND FPR <= geometric")
    print(f"{'='*80}")
    geo = next((r for r in rows if r["strategy"] == "geometric" and r["buf"] == 512 and r["poison"] == 0.05), None)
    if geo:
        print(f"\n  Geometric baseline: F1={geo['f1']}, FPR={geo['fpr']}, recall={geo['recall']}")
        better = [r for r in rows
                  if r["buf"] == 512 and r["poison"] == 0.05
                  and r["f1"] >= geo["f1"] and r["fpr"] <= geo["fpr"]
                  and r["strategy"] != "geometric"]
        if better:
            better.sort(key=lambda r: (-r["f1"], r["fpr"]))
            for r in better:
                print(f"  {r['strategy']:<18} F1={r['f1']:.4f} FPR={r['fpr']:.5f} recall={r['recall']:.4f} "
                      f"thresh_mean={r['thresh_mean']:.2f}")
        else:
            print("  No strategies beat geometric on both F1 and FPR.")


if __name__ == "__main__":
    main()
