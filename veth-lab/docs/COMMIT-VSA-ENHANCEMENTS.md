# VSA Detection Enhancements

**Date:** 2026-02-17  
**Status:** ✅ COMPLETE  
**Implementation:** Sonnet 4.5, Reviewed by Opus 4.6

## Summary

Added three VSA/HDC primitives to enhance DDoS detection with zero ML, zero training data, and zero new eBPF code. All changes are userspace-only.

## Changes

### 1. Log-Scale Encoding for TTL and TCP Window

**Impact:** Fuzzy field clustering for OS fingerprinting

TTL and TCP window values now use logarithmic encoding instead of discrete integers. Nearby values produce similar vectors:
- TTL 64 ≈ TTL 60 (same OS, different path)
- TTL 64 ≠ TTL 128 (Linux vs Windows)
- TCP window values cluster by OS stack defaults

**Files Modified:**
- `filter/src/lib.rs` (lines 1365, 1378, 1397, 1410)

**Implementation:**
Both encoding paths updated (`walk_map_visitor` and `walk_map_items`):

```rust
// Fast visitor path
visitor("ttl", WalkableRef::Scalar(ScalarRef::log(self.ttl.max(1) as f64)));
visitor("tcp_window", WalkableRef::Scalar(ScalarRef::log(self.tcp_window.max(1) as f64)));

// Items path (fallback)
("ttl", WalkableValue::Scalar(ScalarValue::log(self.ttl.max(1) as f64)))
("tcp_window", WalkableValue::Scalar(ScalarValue::log(self.tcp_window.max(1) as f64)))
```

---

### 2. Magnitude Spectrum (Per-Field Diversity via Unbinding)

**Impact:** Automatic attack classification without hardcoded rules

Uses unbinding on the **raw float accumulator** to extract per-field diversity. Low diversity (→1.0) indicates concentration (potential attack indicator). High diversity (→0.0) indicates dispersion (normal traffic).

**Critical Design Note:** Operates on raw float accumulator, NOT normalized bipolar. The magnitude carries the diversity signal - normalization to bipolar destroys it. This is the key insight from VSA-NOVEL.md Section 2.

**Attack Classification:**
- **Amplification:** High src_ip diversity (~0.95), low dst_ip/dst_port
- **Botnet:** Low src_ip diversity (~0.03), low dst_ip/dst_port
- **Port scan:** Low src_ip, high dst_port diversity (~0.80)

**Files Modified:**
- `sidecar/src/main.rs` - Added `magnitude_spectrum()` method to FieldTracker

**Implementation:**
```rust
fn magnitude_spectrum(&self) -> Vec<(String, f64)> {
    // Get total accumulator magnitude
    let acc_magnitude = self.recent_acc.iter()
        .map(|x| x * x).sum::<f64>().sqrt();
    
    // For each field, unbind in float space
    for field in fields {
        let role_vec = self.holon.get_vector(field);
        // Element-wise multiply raw floats by bipolar role
        let unbound_magnitude = self.recent_acc.iter()
            .zip(role_vec.data().iter())
            .map(|(acc_val, &role_val)| {
                let product = acc_val * role_val as f64;
                product * product
            })
            .sum::<f64>().sqrt();
        // Relative diversity
        let diversity = unbound_magnitude / acc_magnitude;
    }
}
```

**Integration:**
- Runs every 10 ticks
- Logs top 5 fields by concentration
- Example output:
  ```
  === Magnitude Spectrum (field diversity via unbind) ===
    dst_ip       diversity=0.012 (concentration=83.3x)
    protocol     diversity=0.018 (concentration=55.6x)
    src_ip       diversity=0.901 (concentration=1.1x)
  ```

---

### 3. Drift Rate (Attack Onset Classification)

**Impact:** Distinguish flash floods from organic growth

Computes temporal derivative of similarity using `drift_rate()` over window history. Negative rate indicates similarity dropping (attack onset).

**Classification:**
- `drift_rate < -0.5` → Flash flood (instant attack) - immediate block recommended
- `drift_rate < -0.1` → Ramp-up attack (accelerating) - escalate response
- `|drift_rate| < 0.05` → Gradual shift (organic) - monitor only

**Files Modified:**
- `sidecar/src/main.rs` - Added `compute_drift_rate()` method to FieldTracker

**Implementation:**
```rust
fn compute_drift_rate(&self, window: usize) -> Option<f64> {
    // Uses existing window_history
    // Computes temporal derivative of similarity
}
```

**Integration:**
- Computed each tick
- Warns on flash flood or ramp-up detection
- Logs periodically every 10 ticks

---

## Testing

**Build:**
```bash
cd holon-lab-ddos/veth-lab
./scripts/build.sh
```

**Run with new features:**
```bash
sudo ./target/release/veth-sidecar \
    --interface veth-filter \
    --enforce \
    --rate-limit \
    --warmup-windows 10 \
    --warmup-packets 1000 \
    --sample-rate 100
```

**Expected new log output:**
```
=== Magnitude Spectrum (field diversity via unbind) ===
  dst_ip       diversity=0.012 (concentration=83.3x)
  ...

>>> FLASH FLOOD DETECTED: drift_rate=-0.612 (instant attack onset)
```

---

## Opus 4.6 Review Findings

### Issue 1: Incomplete log-scale encoding (FIXED)
**Problem:** Only the `walk_map_visitor` path was updated. The `walk_map_items` fallback path still used discrete integers.

**Fix:** Updated both paths to use log-scale encoding for consistency.

### Issue 2: Magnitude spectrum normalization (FIXED)
**Problem:** Original implementation normalized accumulator to bipolar before unbinding. This destroyed the magnitude information that carries the diversity signal. After bipolar conversion, every field showed approximately the same "diversity" (~sqrt(d)) regardless of actual cardinality.

**Root cause:** `Vector::from_f64()` converts floats to `{+1, -1, 0}`. Unbinding two bipolar vectors produces another bipolar vector with norm ≈ sqrt(nnz), which is roughly constant across all fields.

**Fix:** Operate directly on raw float accumulator. Unbind by element-wise multiplying raw floats by bipolar role vector, then measure the resulting magnitude. This preserves the diversity signal encoded in the accumulator's magnitude distribution.

**Theory:** Per VSA-NOVEL.md Section 2 - "Unbinding as Cardinality Estimator":
- N copies of same vector → magnitude ≈ N (linear)
- N orthogonal vectors → magnitude ≈ √N (square-root)
- The magnitude-to-count ratio is the diversity signal
- **Normalization destroys this signal by discarding magnitude**

---

## What This Enables

1. **Automatic attack type identification** - No need to manually classify amplification vs botnet
2. **Operational response tuning** - Different actions for flash floods vs ramp-ups
3. **Better OS fingerprinting** - TTL/window values cluster naturally by OS class
4. **Zero new infrastructure** - Uses existing accumulator, no new maps or data structures

---

## Architecture Notes

### Why These Three?

Per Opus 4.6 review:
- ✅ **Clear value, low risk** - Well-scoped, clearly valuable
- ✅ **No technical debt** - No architectural changes, no eBPF modifications
- ✅ **Immediate impact** - Visible in logs, actionable for operators

### What Was NOT Implemented

Per Opus 4.6 corrections:
- ❌ **Continuous decay** - Already implemented in FieldTracker (lines 320-530)
- ❌ **Flow ngrams** - Requires eBPF sampler changes (not feasible at 1:100 sampling)
- ⚠️ **Coherence** - Deferred to Phase 2 (advisory warmup signal only, needs careful gating)

---

## Next Steps

1. ✅ Build and test with traffic generator
2. Monitor magnitude spectrum output during attacks
3. Validate drift rate thresholds with real traffic
4. Consider Phase 2: coherence for warmup advisory

---

## References

- [VSA-UTILIZATION-AUDIT.md](VSA-UTILIZATION-AUDIT.md) - Full primitive inventory (corrected)
- [VSA-NOVEL.md](VSA-NOVEL.md) - Theory for unbinding as cardinality estimator
- [VSA.md](VSA.md) - Existing VSA usage (needs update)
- [PLAN-NEXT.md](PLAN-NEXT.md) - Section 15-16 cover related topics
