# VSA Enhancements Test - Expected Results

## Test Scenario: `scenarios/vsa-enhancements-test.json`

This scenario validates three new VSA features implemented in the sidecar:

1. **Log-scale encoding** for TTL and TCP window
2. **Magnitude spectrum** (per-field diversity via unbinding)
3. **Drift rate** (attack onset classification)

## Test Duration
~2 minutes 10 seconds (130 seconds total)

## Phase-by-Phase Expected Results

### Phase 1: Warmup (0-15s, normal)
**Purpose:** Establish baseline with diverse Linux clients

**Expected:**
- Magnitude spectrum shows **balanced diversity** across fields
- All fields have moderate diversity (~0.3-0.6)
- No concentration warnings
- Drift rate not computed yet (insufficient window history)

**Sample Output:**
```
=== Magnitude Spectrum (field diversity via unbind) ===
  tcp_flags    diversity=0.412 (concentration=2.4x)
  protocol     diversity=0.445 (concentration=2.2x)
  dst_port     diversity=0.498 (concentration=2.0x)
  src_ip       diversity=0.523 (concentration=1.9x)
  src_port     diversity=0.567 (concentration=1.8x)
```

---

### Phase 2: Normal Stable (15-23s, normal)
**Purpose:** Verify spectrum stability post-warmup

**Expected:**
- Spectrum unchanged from warmup
- Drift rate near zero (~0.0 ± 0.05) - gradual organic change
- No phase change detection

---

### Phase 3: Attack - Amplification (23-35s, attack)
**Purpose:** Test magnitude spectrum sensitivity to source concentration

**Attack Profile:**
- Single source IP (10.0.0.100)
- Single source port (53/UDP - DNS)
- 15k pps (5x baseline)

**Expected:**
- **Magnitude spectrum shows extreme concentration:**
  - `src_port` diversity ≈ 0.99 (concentration ≈ 100x+)
  - `src_ip` diversity ≈ 0.95 (concentration ≈ 20x+)
  - Other fields remain diverse
- **Drift rate < -0.5** → `FLASH FLOOD DETECTED` warning
- Phase change detection (similarity < 0.85)
- ANOMALY DETECTED log

**Sample Output:**
```
>>> FLASH FLOOD DETECTED: drift_rate=-0.743 (instant attack onset)
🔍 ANOMALY DETECTED! similarity=0.62 (threshold: 0.85, warmup_sim: 0.94)

=== Magnitude Spectrum (field diversity via unbind) ===
  src_port     diversity=0.992 (concentration=125.0x)
  src_ip       diversity=0.951 (concentration=20.4x)
  protocol     diversity=0.445 (concentration=2.2x)
  dst_port     diversity=0.387 (concentration=2.6x)
  tcp_flags    diversity=0.312 (concentration=3.2x)
```

---

### Phase 4: Calm 1 (35-43s, normal)
**Purpose:** Verify recovery and positive drift rate

**Expected:**
- Spectrum returns to baseline diversity
- **Drift rate positive** (similarity recovering, +0.2 to +0.5)
- Magnitude spectrum shows deconcentration

---

### Phase 5: Attack - SYN Flash Flood (43-53s, syn_flood)
**Purpose:** Test instant attack onset detection

**Attack Profile:**
- SYN flood at 15k pps
- Instant onset (zero ramp time)
- dst_port=443, TTL=128 (Windows-like)

**Expected:**
- **Drift rate < -0.5** → `FLASH FLOOD DETECTED` warning
- Phase change detection
- Spectrum shows concentrated `dst_port` and `tcp_flags` (SYN=0x02)
- **Log-scale TTL encoding** makes TTL shift (64→128) moderate, not extreme

**Sample Output:**
```
>>> FLASH FLOOD DETECTED: drift_rate=-0.812 (instant attack onset)
🔍 ANOMALY DETECTED! similarity=0.59

=== Magnitude Spectrum (field diversity via unbind) ===
  tcp_flags    diversity=0.978 (concentration=51.0x)
  dst_port     diversity=0.943 (concentration=17.5x)
  protocol     diversity=0.876 (concentration=8.1x)
  ttl          diversity=0.612 (concentration=1.6x)  <- Moderate due to log-scale
  src_ip       diversity=0.489 (concentration=2.0x)
```

---

### Phase 6: Calm 2 (53-61s, normal)
**Purpose:** Recovery verification

**Expected:**
- Return to baseline spectrum
- Positive drift rate

---

### Phases 7-9: Attack - Botnet Ramp (61-76s, attack)
**Purpose:** Test drift rate sensitivity to gradual onset

**Attack Profile:**
- 3 phases: 5k → 10k → 15k pps (5s each)
- Gradual ramp-up

**Expected:**
- Phase 1 (5k): Drift rate starting to decline (-0.05 to -0.1)
- Phase 2 (10k): Drift rate accelerating (-0.1 to -0.2)
- Phase 3 (15k): **Drift rate < -0.1** → `RAMP-UP ATTACK` warning
- Magnitude spectrum shows concentration building over time

**Sample Output (Phase 9):**
```
>>> RAMP-UP ATTACK: drift_rate=-0.134 (accelerating threat)
🔍 ANOMALY DETECTED! similarity=0.71

=== Magnitude Spectrum (field diversity via unbind) ===
  dst_port     diversity=0.887 (concentration=11.3x)
  protocol     diversity=0.823 (concentration=6.0x)
  src_ip       diversity=0.623 (concentration=1.6x)  <- Diverse botnet
```

---

### Phase 10: Calm 3 (76-84s, normal)
**Purpose:** Recovery

**Expected:**
- Return to baseline
- Positive drift rate

---

### Phase 11: Attack - OS Shift (84-96s, custom)
**Purpose:** Test log-scale encoding effectiveness

**Attack Profile:**
- Windows botnet (TTL=128, tcp_window=65535)
- 12k pps
- SYN flood (dst_port=443)

**Expected:**
- **Log-scale encoding dampens TTL shift:**
  - Linear: TTL 64→128 is 2x change (major signal)
  - Log-scale: log(64)→log(128) is 0.693 shift (moderate signal)
- Drift rate < -0.1 (ramp-up classification)
- Magnitude spectrum shows TTL concentration, but **not as extreme as src_port**

**Sample Output:**
```
>>> RAMP-UP ATTACK: drift_rate=-0.156 (accelerating threat)

=== Magnitude Spectrum (field diversity via unbind) ===
  tcp_flags    diversity=0.965 (concentration=28.6x)
  dst_port     diversity=0.912 (concentration=11.4x)
  ttl          diversity=0.743 (concentration=3.4x)  <- Log-scale keeps this moderate
  tcp_window   diversity=0.698 (concentration=3.0x)  <- Log-scale encoding
  protocol     diversity=0.634 (concentration=1.6x)
```

---

### Phase 12: Final Baseline (96-106s, normal)
**Purpose:** Final recovery

**Expected:**
- Return to baseline spectrum
- Drift rate positive then stabilizing near zero
- System returns to warm state

---

## Key Validation Points

### 1. Log-Scale Encoding (TTL/tcp_window)
**Validation:** Compare TTL diversity during Phase 11 (OS shift) vs Phase 3 (amplification)
- OS shift (TTL 64→128): diversity ~0.7-0.8 (moderate)
- If using linear encoding: would expect diversity ~0.9+ (extreme)

**Success Criteria:** TTL shift results in moderate, not extreme, diversity score

---

### 2. Magnitude Spectrum (Unbinding)
**Validation:** Phase 3 (amplification) should show:
- `src_port` diversity > 0.95 (concentration > 20x)
- `src_ip` diversity > 0.90 (concentration > 10x)
- Other fields < 0.70 (remain diverse)

**Success Criteria:** Spectrum correctly identifies most concentrated fields

---

### 3. Drift Rate (Attack Onset Classification)
**Validation:**
- Phase 3 (flash): drift_rate < -0.5 → "FLASH FLOOD DETECTED"
- Phase 5 (flash): drift_rate < -0.5 → "FLASH FLOOD DETECTED"
- Phase 9 (ramp): drift_rate < -0.1 → "RAMP-UP ATTACK"
- Phase 11 (ramp): drift_rate < -0.1 → "RAMP-UP ATTACK"

**Success Criteria:** Correct classification of attack onset dynamics

---

## Running the Test

```bash
cd holon-lab-ddos/veth-lab
./scripts/test-vsa-enhancements.sh
```

## Analyzing Results

```bash
# View magnitude spectrum evolution
grep 'Magnitude Spectrum' logs/vsa-test-sidecar.log | head -40

# View drift rate classifications
grep 'FLASH FLOOD\|RAMP-UP' logs/vsa-test-sidecar.log

# View phase changes
grep 'ANOMALY DETECTED' logs/vsa-test-sidecar.log

# View full sidecar output
less logs/vsa-test-sidecar.log
```

## Troubleshooting

### No drift rate output
- **Cause:** Window history too short (need 4+ windows for 3-window drift)
- **Fix:** Ensure warmup completes (15s = ~150 ticks at 10 ticks/sec)

### All fields have similar diversity
- **Cause:** Magnitude spectrum normalization bug (should be fixed)
- **Fix:** Verify `magnitude_spectrum()` uses raw float accumulator, not bipolar

### No flash flood detection
- **Cause:** Drift rate threshold too aggressive
- **Fix:** Review drift_rate computation window size (currently 3)

### Log-scale encoding not working
- **Cause:** Both `walk_map_visitor` and `walk_map_items` paths must be updated
- **Fix:** Verify lines 1321, 1336, 1365, 1378 in `filter/src/lib.rs`
