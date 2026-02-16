# Decay-Based Per-Packet Processing

**Date:** 2026-02-16
**Status:** COMPLETE AND VALIDATED

https://github.com/user-attachments/assets/efdc15d5-c87a-41e1-b568-e5ff2fa96760

## Overview

The sidecar replaces fixed-time window processing with continuous, per-packet
exponential decay. Instead of accumulating traffic into 2-second windows and
resetting, each packet is processed inline with decay applied to the
accumulator before every addition. This eliminates boundary artifacts, enables
sub-second detection, and naturally emphasizes recent traffic.

## Two Accumulators, Two Decay Models

The system maintains two accumulators with fundamentally different decay
strategies, each optimized for its purpose:

### Direction Accumulator (`recent_acc`) — Per-Packet Decay

```
For each packet:
    recent_acc *= alpha          # decay by fixed factor per packet
    recent_acc += encode(packet) # add new packet at full weight
```

- **Decay factor:** `alpha = 0.5^(1/half_life)` where `half_life` is in packets
- **Rate-invariant:** at steady state, magnitude converges to the same value
  regardless of traffic rate (effective count = `1/(1-alpha)`)
- **Encodes:** traffic pattern direction only (which fields, which values)
- **Used for:** cosine similarity drift, anomaly detection, attribution

This is the correct behavior for detection: whether traffic is 1K or 10K pps,
the drift score reflects *what* the traffic looks like, not *how much* there is.

### Rate Accumulator (`rate_acc`) — Time-Based Decay

```
For each packet:
    dt = now - last_update
    rate_acc *= e^(-lambda * dt)  # decay by wall-clock time
    rate_acc += encode(packet)    # add same VSA vector
```

- **Decay constant:** `lambda = ln(2) / half_life_seconds`
- **Rate-proportional:** at steady state, magnitude is proportional to PPS
- **Encodes:** traffic pattern direction AND volume (PPS in magnitude)
- **Used for:** fleet-distributable rate profile

The time-based decay makes the magnitude directly proportional to packet rate.
At steady state with constant traffic at rate R:

```
||rate_acc|| ≈ ||v|| * R / (lambda * sample_rate)
```

Double the traffic, double the magnitude. This vector is a single artifact that
encodes everything a fleet scrubber needs: what the traffic looks like (direction)
and how much there is (magnitude).

## Analysis Trigger

Analysis no longer happens on window boundaries. A **hybrid trigger** fires when
either condition is met:

- `--analysis-interval` packets have been processed (default: 200), OR
- `--analysis-max-ms` milliseconds have elapsed (default: 200)

Whichever comes first. At baseline ~3000 pps with 1:100 sampling (~30
samples/sec), the packet trigger fires every ~6.7 seconds while the time
trigger fires every 200ms. The time trigger dominates, giving ~5 analysis
ticks per second.

Under heavy attack (e.g. 30K pps, 300 samples/sec), the packet trigger fires
every ~0.67 seconds — still responsive but not wasteful.

## Rate Limiting

Rate limits for derived rules use a scalar PPS baseline for instant response:

```
baseline_pps = warmup_samples * sample_rate / warmup_duration
rate_factor  = baseline_pps / estimated_current_pps
allowed_pps  = estimated_current_pps * rate_factor = baseline_pps
```

The scalar approach reacts within a single analysis tick because it uses the raw
per-tick sample count. The rate vector (time-decayed) also encodes PPS but
smooths over its half-life period — ideal for fleet coordination where noise
reduction across nodes matters, not for local rate limiting where speed matters.

## Warmup

Warmup is packet-count driven (`--warmup-packets`, default 200). During warmup:

- The direction accumulator runs WITHOUT decay (all packets weighted equally for
  a clean baseline)
- The rate accumulator runs WITH time-based decay (so it reaches steady state
  before freeze)
- Value counts accumulate without decay for concentration analysis

At freeze:
1. The direction accumulator is normalized into a bipolar baseline vector
2. The rate accumulator magnitude is snapshotted as `baseline_rate_magnitude`
3. The scalar `baseline_pps` is computed from sample count and elapsed time
   (measured from first sample arrival, not program init, to exclude startup
   dead time)
4. The direction accumulator is cleared; the rate accumulator is NOT cleared
   (it's already at steady state)

## CLI Arguments

| Argument | Default | Purpose |
|----------|---------|---------|
| `--decay-half-life` | 1000 packets | Per-packet decay half-life for direction accumulator |
| `--analysis-interval` | 200 packets | Packet threshold for hybrid analysis trigger |
| `--analysis-max-ms` | 200 ms | Time threshold for hybrid analysis trigger |
| `--rate-half-life-ms` | 2000 ms | Time-based decay half-life for rate accumulator |
| `--warmup-packets` | 200 | Packet count to complete warmup |

## Why Two Decay Models

Per-packet decay makes magnitude rate-invariant. This is exactly right for
anomaly detection — you want to know if the traffic *pattern* changed, not
whether the volume changed. A 10x traffic spike with the same distribution
should show drift ≈ 1.0 (normal), not trigger a false positive.

Time-based decay makes magnitude rate-proportional. This is exactly right for
rate estimation — you want the vector's magnitude to reflect how many packets
per second are arriving. A 10x spike means 10x magnitude, giving a rate factor
of 0.1 that throttles back to baseline levels.

Using one accumulator for both would require a compromise that serves neither
purpose well. Two accumulators, each with the right decay model, cleanly
separate detection (what) from rate estimation (how much).

## Performance

The per-packet cost of the decay model:

- **Direction accumulator:** one scalar multiply over the vector + one vector add
- **Rate accumulator:** one `exp()` call + one scalar multiply + one vector add
- **VSA encoding:** unchanged (one `encode_walkable` call, shared by both)

At 10,000 dimensions and ~30 samples/sec at baseline, this is negligible
compared to the eBPF packet processing path.
