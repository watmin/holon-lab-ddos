# Traffic Generator Jitter Feature

## Overview
The traffic generator now supports PPS jitter to create more realistic, variable traffic patterns instead of perfectly steady rates.

## Usage

### Default (5% jitter)
```bash
sudo ip netns exec veth-lab-gen ./target/release/veth-generator \
    --scenario-file veth-lab/scenarios/stress-test.json
```
By default, the generator applies ±5% jitter to the target PPS.

### Custom Jitter
```bash
# 10% jitter (more variance)
sudo ip netns exec veth-lab-gen ./target/release/veth-generator \
    --pps 2000 \
    --pattern mixed \
    --jitter-pct 10

# No jitter (perfectly steady)
sudo ip netns exec veth-lab-gen ./target/release/veth-generator \
    --pps 2000 \
    --pattern mixed \
    --jitter-pct 0
```

## How It Works

The jitter is applied per-packet by randomly varying the target PPS within the specified percentage range:

- **Target PPS**: 2000
- **Jitter**: 5%
- **Range**: 1900 - 2100 pps (randomly selected each packet)

This creates natural variance that makes the dashboard more interesting to watch:
- Timeline charts show realistic fluctuations
- More representative of real-world traffic
- Easier to spot anomalies against a noisy baseline

## Examples

| jitter_pct | 1000 pps range | 10000 pps range |
|------------|---------------|-----------------|
| 0          | 1000          | 10000           |
| 5 (default)| 950-1050      | 9500-10500      |
| 10         | 900-1100      | 9000-11000      |
| 20         | 800-1200      | 8000-12000      |

## Dashboard Impact

With jitter enabled (default), you'll see:
- **Timeline charts**: Natural waviness instead of flat lines
- **Packets/s stat**: Varies slightly each second
- **More engaging**: Easier to tell the dashboard is live
- **Realistic**: Matches actual network behavior

Without jitter (--jitter-pct 0):
- **Timeline charts**: Perfectly flat lines
- **Packets/s stat**: Constant value
- **Less realistic**: Networks never have perfectly steady rates

## Recommended Settings

- **Normal testing**: 5% (default) - good balance
- **Stress testing**: 0% - max predictability for benchmarks
- **Realistic demo**: 10% - more visual interest
- **Chaos testing**: 20% - high variance for robustness testing

The jitter is regenerated per-packet, so even within a 1-second window, the actual rate will vary naturally.
