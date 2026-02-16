# Dynamic Payload Byte Match Derivation

**Date:** 2026-02-15
**Status:** ✅ COMPLETE AND VALIDATED

## Overview

The system autonomously learns what "normal" L4 payloads look like using VSA, then when attack traffic arrives with unfamiliar byte patterns, it drills down to the exact byte positions that differ, groups them into multi-byte signatures, and pushes sparse `l4-match` rules into the eBPF decision tree — all without signatures, training data, or human intervention.

![Payload byte match detection in action](https://github.com/user-attachments/assets/aad82715-3460-4036-8b48-de0e8e79c6c8)

## How It Works

### Phase 1: Warmup — Learn What's Familiar

During warmup (configurable, typically 15 seconds), the `PayloadTracker` observes legitimate traffic and builds a VSA baseline:

1. Each packet's L4 payload is truncated to 512 bytes and sliced into **8 windows of 64 bytes** each
2. Each window is encoded as a VSA vector using walkable encoding: byte positions (`p0`..`p63`) bound with hex values (`0xde`, `0x41`, etc.)
3. Vectors are accumulated across all warmup packets into per-window accumulators
4. On freeze: accumulators are normalized into **bipolar baseline vectors** (one per window)

**Threshold auto-calibration:** After freezing baselines, all stored warmup payloads are replayed. The system computes the mean and standard deviation of per-payload minimum similarities, then sets:

```
threshold = (mean - 3 × stddev).clamp(0.3, mean - 0.05)
```

A standard deviation floor of 0.1 prevents over-sensitivity when warmup traffic is uniform (e.g., all packets carry the same game protocol header).

### Phase 2: Detection — Score Every Packet

After warmup, each incoming packet is scored against the baseline:

1. Encode each active window into a VSA vector
2. Compute `similarity(window_vec, baseline_vec)` — the absolute cosine similarity
3. If **any** window scores below the threshold → the payload is **anomalous**
4. Anomalous and normal payloads are stored per-destination IP for rule derivation

### Phase 3: Rule Derivation — From Anomaly to Byte Pattern

When a destination accumulates enough anomalies (default: 3), the system derives concrete byte-match rules through a four-step pipeline:

#### Step 1: Drill-Down

For each anomalous payload and each anomalous window:
- Bind each byte position's field+value pair and score against the baseline
- Positions with similarity < 0.005 are marked **unfamiliar** — these are the attack's fingerprint bytes

#### Step 2: Gap Probing

Extend detected positions by checking ±4 neighbors:
- For each candidate, collect the byte values from attack vs. legitimate samples
- If any attack byte at that position never appears in legitimate traffic → include it

#### Step 3: Position Scoring

For each candidate position, compute a quality score:
- **Consensus byte**: the most common value at that position across attack samples
- **Consensus rate**: fraction of attack samples with that byte (must be ≥ 50%)
- **Penalties**: familiar bytes (appear in legitimate traffic) get 10× penalty; zero bytes (common padding) get 5× penalty

#### Step 4: Multi-Byte Pattern Assembly

Group nearby high-scoring positions (gap ≤ 8 bytes) into contiguous spans:

```
Position:   [4, 5, 6, 7,    12, 13, 14, 15]
Match:      [DE AD BE EF    CA FE F0 0D]
Mask:       [FF FF FF FF 00 00 00 00 FF FF FF FF FF]
            ^^^^^^^^^^^^^^^^                 ^^^^^^^^^^^^^^^^
            matched bytes    don't-care gap  matched bytes
```

The mask enables **sparse matching** — the eBPF filter checks only the positions that matter, skipping variable bytes in between.

Rules require ≥2 matched bytes per pattern (unless a single byte is highly distinctive). Up to 4 rules are derived per destination per cycle.

### Phase 4: Rule Insertion

Derived rules flow through the same pipeline as header-based rules:
- Deduplication via `rule_identity_key` (constraints + action type)
- `RuleEvent` broadcast to the metrics dashboard (SSE)
- Decision tree recompilation via `compile_and_flip_tree`
- `DagSnapshot` broadcast for live DAG visualization
- Global budget enforcement (max 64 payload rules total)

## Rule Format

Generated rules use the `l4-match` predicate with sparse byte masks:

```edn
{:constraints [(= dst-ip 167772162)
               (l4-match 8 "deadbeef00000000cafef00d" "ffffffff00000000ffffffff")]
 :actions [(rate-limit 500 :name ["system" "payload_l4match_192.168.1.2_off8_len12"])]
 :priority 100}
```

| Field | Meaning |
|-------|---------|
| `l4-match offset` | Byte offset from start of L4 payload |
| `match_bytes` | Hex string of expected byte values |
| `mask_bytes` | Hex string: `ff` = must match, `00` = don't care |
| `rate-limit pps` | Derived from FieldTracker's vector-based `rate_factor` |

## Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `PAYLOAD_WINDOW_SIZE` | 64 bytes | VSA encoding window granularity |
| `MAX_PAYLOAD_BYTES` | 512 bytes | Maximum L4 payload analyzed per packet |
| `NUM_PAYLOAD_WINDOWS` | 8 | Windows per payload (512 / 64) |
| `MAX_PAYLOAD_RULES_TOTAL` | 64 | Global budget across all destinations |

## Test Scenario

The `payload-anomaly-detection.json` scenario validates five distinct attack patterns against a game protocol baseline (`GME00001BEGI`):

| Phase | Pattern | What It Tests |
|-------|---------|--------------|
| **Constant signature** | `DEADBEEF` prefix | Fixed 4-byte signature at offset 0 |
| **Scattered bytes** | `FF`, `AC`, `FB`, `CA` at positions 2,5,8,12 | Sparse matching across non-contiguous positions |
| **Deep offset** | Shellcode at byte 32+ | Detection beyond the first 64-byte window |
| **Sandwich** | Unfamiliar prefix + familiar middle + unfamiliar suffix | Multiple spans in a single payload |
| **Long signature** | 16-byte constant `C0FEBABE1337...` | Extended contiguous byte match |

All five attacks are detected with multi-byte rules derived autonomously. Recovery phases between attacks verify the system doesn't flag returning legitimate traffic.

## What Makes This Novel

1. **Zero signatures** — the system has never seen these attacks before; it learns "normal" and derives byte-level rules from deviations
2. **VSA drill-down** — instead of pattern matching, the system uses vector similarity at progressively finer granularity (window → position → byte)
3. **Sparse masks** — generated rules match only the discriminative bytes, tolerating variation in padding or sequence numbers
4. **Vector-derived rate limits** — the allowed PPS comes from the FieldTracker's `rate_factor`, itself a VSA-derived compression ratio, not a hardcoded value
5. **Self-calibrating threshold** — the anomaly threshold adapts to the observed variance in baseline traffic, no tuning required
