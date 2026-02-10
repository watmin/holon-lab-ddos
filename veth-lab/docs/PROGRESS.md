# Veth Lab: Holon-Powered XDP DDoS Mitigation

**Status:** Proof-of-Concept Complete  
**Date:** February 2026  
**Result:** 99.4% attack traffic blocked at XDP layer

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

### Test Configuration

- **Traffic**: 1000 packets/sec for 20 seconds (pure attack pattern)
- **Attack**: UDP packets from 10.0.0.100 to port 9999
- **Detection Window**: 2 seconds
- **Thresholds**: Drift < 0.7, Concentration > 50%

### Timeline

| Time (s) | Event |
|----------|-------|
| 0.0 | Sidecar starts, XDP attached |
| 0.5 | First attack packets arrive |
| 1.0 | Window 3: 123 packets, drift=0.000 |
| 1.0 | **ANOMALY DETECTED** |
| 1.0 | Rules added: DstPort=9999, SrcIp=10.0.0.100 |
| 1.0+ | All subsequent packets dropped by XDP |
| 20.0 | Generator stops |

### Final Statistics

```
Generator sent:     19,697 packets
XDP total seen:     19,697 packets (100%)
XDP dropped:        19,574 packets (99.4%)
Packets passed:         123 packets (only before rules)
```

### Detection Output

```
Window 3: 123 packets, drift=0.000 | XDP total: 123, dropped: 0
>>> ANOMALY DETECTED: drift=0.000 (threshold=0.7)
    Concentrated: dst_port=9999 (100.0%)
    ADDED DROP RULE: DstPort=9999
    Concentrated: src_ip=10.0.0.100 (100.0%)
    ADDED DROP RULE: SrcIp=10.0.0.100

Window 4: 2055 packets, drift=0.997 | XDP total: 2178, dropped: 2055
    Status: NORMAL (drift above threshold)
```

## Key Insights

### What Worked Well

1. **Fast Detection**: Anomaly detected in first window with sufficient packets (~500ms)
2. **Accurate Identification**: Correctly identified attack source IP and port
3. **Effective Blocking**: 99.4% of attack traffic dropped at XDP layer
4. **Low Overhead**: Holon encoding runs in userspace, XDP handles line-rate filtering

### Challenges Encountered

1. **BPF Verifier**: Required careful coding patterns for packet access
2. **Byte Order**: Network vs host byte order for IP addresses
3. **Perf Buffer**: Had to switch from RingBuf to PerfEventArray for compatibility
4. **Baseline Training**: First window always shows drift=0.000 (no prior baseline)

### Limitations of Current Implementation

1. **Pure Attacks Only**: Mixed traffic dilutes concentration below threshold
2. **Single Field Rules**: Only generates rules for individual fields, not combinations
3. **No Rate Limiting**: Only DROP action, no graduated response
4. **Manual Thresholds**: Drift and concentration thresholds are static

## Code Statistics

| Component | Lines of Rust |
|-----------|--------------|
| filter-ebpf | ~320 |
| filter lib | ~500 |
| generator | ~410 |
| sidecar | ~500 |
| **Total** | ~1,730 |

## Future Work

### Short Term
- [ ] Add rate limiting rules (not just DROP)
- [ ] Implement rule expiry/cleanup
- [ ] Add baseline training period
- [ ] Support combination rules (e.g., src_ip AND dst_port)

### Medium Term
- [ ] Integrate with real network interfaces (not just veth)
- [ ] Add AF_XDP for zero-copy packet processing
- [ ] Implement multi-field encoding strategies
- [ ] Add metrics/Prometheus export

### Long Term
- [ ] Distributed detection across multiple nodes
- [ ] ML-enhanced threshold tuning
- [ ] Integration with existing DDoS mitigation platforms
- [ ] Support for more protocols (ICMP, DNS, etc.)

## Running the Demo

```bash
# Setup network namespace and veth pair
sudo ./veth-lab/scripts/setup.sh

# Build all components
./veth-lab/scripts/build.sh

# Terminal 1: Start sidecar with enforcement
sudo ./target/release/veth-sidecar --interface veth-filter --enforce

# Terminal 2: Generate attack traffic
sudo ip netns exec veth-lab-gen ./target/release/veth-generator \
    --interface veth-gen --pattern attack --pps 1000 --duration 20

# Cleanup
sudo ./veth-lab/scripts/teardown.sh
```

## References

- [Holon Project](https://github.com/watmin/holon) - VSA/HDC implementation
- [Aya](https://aya-rs.dev/) - Rust eBPF toolkit
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial) - XDP programming guide
- [Batch 013 Challenges](../../../scripts/challenges/013-batch/) - Python prototypes of rate limiting detection
