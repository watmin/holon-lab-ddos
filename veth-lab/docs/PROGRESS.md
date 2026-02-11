# Veth Lab: Holon-Powered XDP DDoS Mitigation

**Status:** Proof-of-Concept Complete  
**Date:** February 2026  
**Latest Update:** February 11, 2026  
**Result:** Vector-derived XDP rate limiting with zero hardcoded values  
**Key Achievement:** Rate limits calculated purely from accumulator magnitude ratios

## Overview

This document describes the integration of **Holon-rs** (a Rust implementation of Vector Symbolic Architecture / Hyperdimensional Computing) with **eBPF/XDP** for real-time DDoS detection and mitigation.

The system demonstrates:
- Sub-second anomaly detection using VSA/HDC
- Dynamic rule injection into XDP for kernel-level blocking
- Reproducible local testing using network namespaces

## Motivation

Traditional DDoS mitigation relies on:
- Static rules that require manual tuning
- Signature-based detection that misses novel attacks
- Rate limiting that affects legitimate traffic

Holon offers a different approach:
- **Unsupervised learning**: No labeled training data required
- **Real-time adaptation**: Baseline evolves with traffic patterns
- **Semantic understanding**: Encodes packet structure, not just bytes
- **Efficient**: O(1) similarity computation via vector operations

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Host Namespace                              │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   Holon Sidecar                          │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐   │    │
│  │  │ Perf     │  │ Holon-rs │  │ Anomaly Detection    │   │    │
│  │  │ Reader   │──│ Encoder  │──│ - Drift Analysis     │   │    │
│  │  └──────────┘  └──────────┘  │ - Concentration      │   │    │
│  │       ▲                      └──────────┬───────────┘   │    │
│  │       │                                 │               │    │
│  │       │ samples                         │ rules         │    │
│  │       │                                 ▼               │    │
│  │  ┌────┴─────────────────────────────────────────────┐   │    │
│  │  │              XDP Program (veth-filter)            │   │    │
│  │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐           │   │    │
│  │  │  │ RULES   │  │ STATS   │  │ SAMPLES │           │   │    │
│  │  │  │ HashMap │  │ PerCPU  │  │ PerfBuf │           │   │    │
│  │  │  └─────────┘  └─────────┘  └─────────┘           │   │    │
│  │  └──────────────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│                        veth-filter                               │
│                              │                                   │
└──────────────────────────────┼───────────────────────────────────┘
                               │
                          veth pair
                               │
┌──────────────────────────────┼───────────────────────────────────┐
│                              │                                   │
│                          veth-gen                                │
│                              │                                   │
│  ┌───────────────────────────┴───────────────────────────────┐  │
│  │                  Traffic Generator                         │  │
│  │  - AF_PACKET raw socket                                    │  │
│  │  - Normal/Attack/Mixed/Ramp patterns                       │  │
│  │  - Configurable PPS and duration                           │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│                    veth-lab-gen Namespace                        │
└──────────────────────────────────────────────────────────────────┘
```

## Components

### 1. XDP Filter (`filter-ebpf/`)

A BPF program that runs at the network driver level:

```rust
// Rule types supported
enum RuleType {
    SrcIp = 0,
    DstIp = 1,
    SrcPort = 2,
    DstPort = 3,
    Protocol = 4,
}

// BPF Maps
static RULES: HashMap<RuleKey, RuleValue>   // Dynamic drop rules
static STATS: PerCpuArray<u64>              // Counters
static CONFIG: PerCpuArray<u32>             // Sample rate, enforce mode
static SAMPLES: PerfEventArray<PacketSample> // Packet samples to userspace
```

**Capabilities:**
- Parse Ethernet, IP, TCP/UDP headers
- Check packets against dynamic rules
- Sample packets to userspace via perf buffer
- Track per-CPU statistics

### 2. Filter Library (`filter/`)

Rust library for managing the XDP program:

```rust
// Key API
impl VethFilter {
    fn new(interface: &str) -> Result<Self>;
    async fn add_rule(&self, rule: &Rule) -> Result<()>;
    async fn remove_rule(&self, rule: &Rule) -> Result<()>;
    async fn stats(&self) -> Result<FilterStats>;
    async fn take_perf_array(&self) -> Result<AsyncPerfEventArray>;
}
```

### 3. Traffic Generator (`generator/`)

Generates test traffic using AF_PACKET raw sockets:

| Pattern | Description |
|---------|-------------|
| Normal | Random source IPs (192.168.x.x), port 5000 |
| Attack | Fixed source IP (10.0.0.100), port 9999 |
| Mixed | Alternates 5s attack / 5s normal |
| Ramp | Gradually increases attack ratio 0% → 100% |

### 4. Holon Sidecar (`sidecar/`)

The detection engine using Holon-rs:

```rust
// Packet encoding
fn encode_packet(holon: &Holon, sample: &PacketSample) -> Vec<f64> {
    let src_ip_vec = holon.encode_string(&format!("src_ip={}", sample.src_ip_addr()));
    let dst_ip_vec = holon.encode_string(&format!("dst_ip={}", sample.dst_ip_addr()));
    let protocol_vec = holon.encode_string(&format!("protocol={}", sample.protocol));
    let src_port_vec = holon.encode_string(&format!("src_port={}", sample.src_port));
    let dst_port_vec = holon.encode_string(&format!("dst_port={}", sample.dst_port));
    
    // Bundle all fields into single vector
    holon.bundle(&[src_ip_vec, dst_ip_vec, protocol_vec, src_port_vec, dst_port_vec])
}
```

**Detection Algorithm:**

1. **Accumulator Drift**: Compare current window's bundled vector to baseline
   - High similarity (>0.7) = Normal traffic
   - Low similarity (<0.7) = Anomalous traffic

2. **Concentration Analysis**: When anomaly detected, find fields with >50% concentration
   - These indicate the attack vector (e.g., all traffic from same source IP)

3. **Rule Generation**: Convert concentrated values to XDP drop rules

## Results

### Vector-Derived Rate Limiting (February 11, 2026)

A major breakthrough: **rate limiting where the allowed PPS is derived purely from vector operations**, with zero hardcoded thresholds.

#### Key Innovations

1. **Walkable Trait Integration**: `PacketSample` implements holon-rs `Walkable` trait for zero-serialization encoding
2. **Magnitude-Aware Encoding**: Packet sizes use `$log` (logarithmic) encoding where ratios matter
3. **Extended Primitives**: Full integration of Batch 014 primitives:
   - `similarity_profile()` - Per-dimension agreement/disagreement analysis
   - `segment()` - Phase change detection in traffic patterns
   - `invert()` - Pattern attribution to codebook entries
   - `analogy()` - Zero-shot attack variant detection
4. **Token Bucket in eBPF**: Rate limiting action (not just DROP) with 64-bit safe arithmetic
5. **Baseline Concentration Tracking**: Avoids blocking expected patterns (e.g., dst_port=8888)
6. **Magnitude-Based Rate Derivation**: From Batch 013 experiments

#### The Rate Derivation Algorithm

```
rate_factor = 1 / magnitude_ratio
magnitude_ratio = ||recent_window_accumulator|| / ||baseline_per_window_accumulator||

If attack has 25x traffic volume → magnitude_ratio ≈ 25 → rate_factor ≈ 0.04
allowed_pps = estimated_current_pps × rate_factor ≈ baseline_pps
```

This means:
- **No hardcoded "normal" rate** - derived from baseline vector magnitude
- **No hardcoded "attack" threshold** - derived from magnitude ratio
- **Automatic scaling** - works regardless of actual traffic volume

#### Test Results

| Metric | Value |
|--------|-------|
| **Baseline PPS** | ~2000 (from scenario) |
| **Attack PPS** | ~50,000 |
| **Derived Rate Limit** | 2042 pps (vector-derived!) |
| **Total Packets** | 1.6M |
| **Dropped (rate limited)** | 1.4M (87%) |
| **Normal Traffic Blocked** | ZERO |

#### Detection Output

```
Baseline magnitude: total=26770.29, per_window=2059.25 (13 windows)
Baseline concentrated values: {"dst_port:8888", "protocol:UDP", ...}

Window 17: 420 packets, drift=0.736, anom_ratio=4.7%
>>> ANOMALY DETECTED
    Concentrated: src_ip=10.0.0.100 (93.8%)
    ADDED RATE_LIMIT RULE: SrcIp=10.0.0.100 (rate: Some(2042))
    Concentrated: dst_port=9999 (93.8%)
    ADDED RATE_LIMIT RULE: DstPort=9999 (rate: Some(2042))

Window 18: 1028 packets | XDP total: 202412, dropped: 96932
Window 25: 43 packets, drift=0.962 | Status: NORMAL (attack ended)
```

#### Key Findings

1. **Zero Hardcoded Values**: Rate limit derived entirely from vector magnitude comparison
2. **Baseline Preserved**: Normal traffic (dst_port=8888) correctly identified as "expected concentration"
3. **Token Bucket Works**: XDP rate limiting allows baseline-equivalent traffic through
4. **Phase Detection**: `segment()` correctly identified attack phase transitions
5. **Calm Periods Clean**: Dropped counter stays flat during normal traffic

---

### Stress Test: 1.3M PPS (February 9, 2026)

An unintentional stress test occurred when a rate-limiting bug caused the generator to run at maximum speed (~1.3M PPS) instead of the intended 50K PPS. The system handled it flawlessly.

#### Test Configuration

- **Traffic Pattern**: Multi-phase scenario (5m warmup, attacks, calm periods)
- **Actual Attack Rate**: ~1.3M PPS (25x intended!)
- **Normal Traffic**: 2000 PPS (baseline)
- **Detection Window**: 2 seconds
- **Sample Rate**: 1:100 (reduced from 1:1 to handle load)
- **Thresholds**: Drift < 0.7, Concentration > 50%

#### Performance Metrics

| Metric | Value |
|--------|-------|
| **Peak attack rate** | ~1.3M PPS |
| **Detection latency** | 52ms from attack start to rule insertion |
| **Drop rate during attack** | 98.3% - 99.5% |
| **Total packets processed** | 318 million |
| **Total dropped** | 316.6 million |
| **False positives after attack** | ZERO |
| **Sidecar stability** | No hangs, consistent 2s window processing |

#### Timeline (Stress Test)

| Time | Event |
|------|-------|
| 04:19:26 | Sidecar starts, warmup begins |
| 04:21:30 | Warmup complete (60 windows), **baseline FROZEN** |
| 04:24:31.149 | Attack Phase 2 starts (~1.3M PPS) |
| 04:24:31.201 | **ANOMALY DETECTED** (52ms latency!) |
| 04:24:31.201 | Rules added: SrcIp=10.0.0.100, DstPort=9999 |
| 04:24:33 | First window with drops: 2.6M packets dropped |
| 04:25:01 | Attack phase ends, 37.8M packets dropped |
| 04:25:03 | **Normal traffic resumes, drift=0.991 (NORMAL)** |
| 04:36:41 | Test ends, 316.6M total packets dropped |

#### Detection Output (Stress Test)

```
Window 147: 1164 packets, drift=0.589 | XDP total: 650554, dropped: 0
>>> ANOMALY DETECTED: drift=0.589 (threshold=0.7)
    Concentrated: src_ip=10.0.0.100 (93.3%)
    ADDED DROP RULE: SrcIp=10.0.0.100
    Concentrated: dst_port=9999 (93.3%)
    ADDED DROP RULE: DstPort=9999

Window 148: 51682 packets, drift=0.549 | XDP total: 3244795, dropped: 2594157
>>> ANOMALY DETECTED: drift=0.549 (continues detecting attack traffic in samples)

Window 163: 82 packets, drift=0.991 | XDP total: 38502832, dropped: 37847076
    Status: NORMAL (attack ended, baseline intact)
```

#### Key Findings

1. **XDP handles 1.3M PPS** - Pure kernel performance, no userspace bottleneck
2. **52ms detection latency** - Attack identified and rules applied in first window
3. **Baseline freezing works** - Normal traffic correctly identified after attack (drift=0.991)
4. **Rule TTL refresh works** - Sampled dropped packets keep rules active
5. **No false positives** - All calm periods correctly identified as NORMAL

---

### Original Test (Lower PPS)

- **Traffic**: 1000 packets/sec for 20 seconds (pure attack pattern)
- **Result**: 99.4% dropped, detection in first window

```
Generator sent:     19,697 packets
XDP total seen:     19,697 packets (100%)
XDP dropped:        19,574 packets (99.4%)
Packets passed:         123 packets (only before rules)
```

## Key Insights

### What Worked Well

1. **Extreme Scale Performance**: Handled 1.3M PPS attack without any degradation
2. **Fast Detection**: 52ms from attack start to rule insertion
3. **Accurate Identification**: Correctly identified attack source IP and port
4. **Effective Blocking**: 99.5% of attack traffic dropped at XDP layer
5. **Low Overhead**: Holon encoding runs in userspace, XDP handles line-rate filtering
6. **No False Positives**: Baseline protection prevents post-attack misdetection

### Architecture Improvements (Feb 9, 2026)

1. **Baseline Freezing**: After warmup, baseline accumulator is frozen to prevent attack pollution
2. **Configurable Sampling**: XDP samples 1:N packets (default 1:100) to reduce userspace load
3. **Non-blocking Sample Processing**: MPSC channels use `try_send` to drop samples under load
4. **Bounded Batch Processing**: Detection loop processes max 200 samples before checking timers
5. **Rule TTL Refresh**: Sampled dropped packets refresh rule expiration timestamps
6. **Scenario-based Traffic Generation**: JSON files define complex multi-phase attack scenarios
7. **Dual Logging**: Both stdout and timestamped log files for post-run analysis
8. **Time-based Rate Limiting**: Generator achieves 100% accuracy from 1k-200k PPS using elapsed-time tracking
9. **Per-phase PPS Override**: Scenario files support custom PPS per phase for flexible testing

### Challenges Encountered

1. **BPF Verifier**: Required careful coding patterns for packet access
2. **Byte Order**: Network vs host byte order for IP addresses
3. **Perf Buffer**: Had to switch from RingBuf to PerfEventArray for compatibility
4. **Baseline Training**: First window always shows drift=0.000 (no prior baseline)
5. **High-PPS Sample Flood**: Initially sampled 100% of packets, overwhelmed userspace at high PPS
6. **Baseline Pollution**: EMA updates during attack caused false positives after attack ended
7. **Rate Limiting Bug**: Generator's sleep calculation failed for PPS > 20K → fixed with time-based approach (100% accuracy 1k-200k PPS)

### Limitations of Current Implementation

1. **Single Field Rules**: Only generates rules for individual fields, not combinations
2. ~~**No Rate Limiting**: Only DROP action, no graduated response~~ ✓ FIXED Feb 11
3. **Manual Thresholds**: Drift and concentration thresholds are static (though rate limits are vector-derived)
4. **Rule TTL Not CLI-configurable**: Currently hardcoded at 5 minutes

## Scenario Files

Scenario files define multi-phase traffic patterns in JSON:

```json
{
  "name": "Realistic DDoS Scenario",
  "description": "Long baseline learning, varied attack patterns",
  "baseline_pps": 2000,
  "attack_pps": 50000,
  "phases": [
    {"name": "learning",  "duration_secs": 300, "type": "normal", "description": "5 min baseline"},
    {"name": "probe",     "duration_secs": 30,  "type": "attack", "description": "Initial probe"},
    {"name": "calm1",     "duration_secs": 240, "type": "normal", "description": "Recon period"},
    {"name": "sustained", "duration_secs": 180, "type": "attack", "description": "Main attack"},
    {"name": "recovery",  "duration_secs": 180, "type": "normal", "description": "Final calm"}
  ]
}
```

Available scenarios in `veth-lab/scenarios/`:
- `quick-test.json` - 2 minute test with 30s attack
- `realistic.json` - 17 minute multi-phase scenario
- `stress-test.json` - High-PPS rapid attack cycles

## Code Statistics

| Component | Lines of Rust |
|-----------|--------------|
| filter-ebpf | ~530 |
| filter lib | ~640 |
| generator | ~620 |
| sidecar | ~900 |
| **Total** | ~2,690 |

## Future Work

### Short Term
- [x] ~~Add rate limiting rules (not just DROP)~~ ✓ Token bucket in XDP + vector-derived rates
- [x] ~~Implement rule expiry/cleanup~~ ✓ TTL-based expiration with refresh
- [x] ~~Add baseline training period~~ ✓ Configurable warmup windows/packets + baseline freezing
- [ ] Support combination rules (e.g., src_ip AND dst_port)
- [ ] Make rule TTL configurable via CLI
- [ ] Expose extended primitives via CLI flags

### Medium Term
- [ ] Integrate with real network interfaces (not just veth)
- [ ] Add AF_XDP for zero-copy packet processing
- [ ] Implement multi-field encoding strategies
- [ ] Add metrics/Prometheus export
- [ ] Adaptive thresholds based on traffic patterns

### Long Term
- [ ] Distributed detection across multiple nodes
- [ ] ML-enhanced threshold tuning
- [ ] Integration with existing DDoS mitigation platforms
- [ ] Support for more protocols (ICMP, DNS, etc.)
- [ ] Hardware offload investigation (SmartNIC integration)

## Running the Demo

### Quick Test

```bash
# Setup network namespace and veth pair
sudo ./veth-lab/scripts/setup.sh

# Build all components
./veth-lab/scripts/build.sh

# Terminal 1: Start sidecar with enforcement
sudo ./target/release/veth-sidecar --interface veth-filter --enforce \
    --warmup-windows 60 --warmup-packets 6000 \
    --sample-rate 100 --log-dir logs

# Terminal 2: Generate attack traffic (scenario file)
sudo ip netns exec veth-lab-gen ./target/release/veth-generator \
    --interface veth-gen \
    --scenario-file veth-lab/scenarios/quick-test.json \
    --log-dir logs

# Cleanup
sudo ./veth-lab/scripts/teardown.sh
```

### Realistic Scenario (17 minutes)

```bash
# Terminal 1: Sidecar
sudo ./target/release/veth-sidecar --interface veth-filter --enforce \
    --warmup-windows 60 --warmup-packets 6000 \
    --sample-rate 100 --log-dir logs

# Terminal 2: Realistic attack pattern
sudo ip netns exec veth-lab-gen ./target/release/veth-generator \
    --interface veth-gen \
    --scenario-file veth-lab/scenarios/realistic.json \
    --log-dir logs
```

### CLI Options

**Sidecar (`veth-sidecar`):**
| Option | Default | Description |
|--------|---------|-------------|
| `--interface` | required | Network interface to attach XDP |
| `--enforce` | false | Actually drop packets (vs dry-run) |
| `--rate-limit` | false | Use rate limiting instead of DROP (vector-derived rates) |
| `--window` | 2 | Detection window in seconds |
| `--warmup-windows` | 10 | Windows before detection activates |
| `--warmup-packets` | 1000 | Packets before detection activates |
| `--sample-rate` | 100 | Sample 1 in N packets |
| `--drift` | 0.85 | Drift threshold for anomaly |
| `--concentration` | 0.5 | Field concentration threshold |
| `--log-dir` | logs | Directory for log files |

**Generator (`veth-generator`):**
| Option | Default | Description |
|--------|---------|-------------|
| `--interface` | veth-gen | Interface to send on |
| `--scenario-file` | none | JSON scenario file |
| `--pattern` | mixed | Traffic pattern (if no scenario) |
| `--pps` | 1000 | Packets per second |
| `--attack-pps` | 10000 | Attack PPS for scenario mode |
| `--log-dir` | logs | Directory for log files |

## References

- [Holon Project](https://github.com/watmin/holon) - VSA/HDC implementation
- [Aya](https://aya-rs.dev/) - Rust eBPF toolkit
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial) - XDP programming guide
- [Batch 013 Challenges](../../../scripts/challenges/013-batch/) - Python prototypes of rate limiting detection
