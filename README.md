# Holon Lab - DDoS

[![Powered by Holon-rs](https://img.shields.io/badge/Powered%20by-Holon--rs-blue)](https://github.com/watmin/holon-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

XDP/eBPF-based DDoS detection and mitigation powered by [Holon-rs](https://github.com/watmin/holon-rs) — a Rust implementation of Vector Symbolic Architecture (VSA/HDC).

This lab demonstrates real-time anomaly detection at kernel level: **1.3M PPS handled with 99.5% drop rate and 52ms detection latency**.

## Status

**Stress-tested (Feb 2026):**
- ✅ **1.3M PPS** attack traffic handled without degradation
- ✅ **52ms** detection latency (attack start → rule insertion)
- ✅ **99.5%** drop rate during attacks
- ✅ **Zero false positives** after attack ends (baseline freezing)
- ✅ **100% rate accuracy** for traffic generation (1k-200k PPS)

**Components:**
- XDP/eBPF filter in Rust using [aya](https://aya-rs.dev/)
- [Holon-rs](https://github.com/watmin/holon-rs) for VSA-based anomaly detection
- Configurable packet sampling (1:N)
- Dynamic rule injection from userspace
- Scenario-based traffic generation with per-phase PPS control

**Veth Lab** (`veth-lab/`): Reproducible local testing using network namespaces - no special hardware required.

**Limitations:**
- Macvlan interfaces don't support AF_XDP (veth lab uses veth pairs instead)
- Currently DROP-only rules (rate limiting planned)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Host                                                           │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Packet Generator (test_sendmmsg)                        │   │
│  │ AF_PACKET + sendmmsg() batching                         │   │
│  │ ~45k pps, 100x fewer syscalls than sendto()             │   │
│  └─────────────────────────────────────────────────────────┘   │
│                    │                                            │
│                    ▼                                            │
│              macv1 (host macvlan)                               │
│                    │                                            │
│                    ▼ (hairpin via macvlan driver)               │
│              eth1 (container macvlan)                           │
│                    │                                            │
│  ┌─────────────────┴───────────────────────────────────────┐   │
│  │ XDP Filter (xdp-filter-ebpf)                            │   │
│  │ - Classifies packets by source IP                       │   │
│  │ - 10.0.0.0/8 = attack traffic                           │   │
│  │ - Samples packets to perf buffer (256 bytes each)       │   │
│  │ - Detect mode: count & pass | Enforce mode: drop        │   │
│  └─────────────────────────────────────────────────────────┘   │
│                    │                                            │
│                    ▼                                            │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ Userspace (pcap_capture / test_xdp)                     │   │
│  │ - Reads samples from perf buffer                        │   │
│  │ - Writes pcap files for analysis                        │   │
│  │ - Future: VSA/HDC classification pipeline               │   │
│  └─────────────────────────────────────────────────────────┘   │
│                    │                                            │
│                    ▼                                            │
│              Nginx container (192.168.1.200)                    │
└─────────────────────────────────────────────────────────────────┘
```

## Build

```bash
# Build eBPF program (requires nightly Rust)
CARGO_CFG_BPF_TARGET_ARCH=x86_64 cargo build -p xdp-filter-ebpf \
  --target bpfel-unknown-none -Z build-std=core --release

# Build userspace tools
cargo build --release -p xdp-filter -p xdp-generator
```

## Usage

### Packet Capture (for analysis)

```bash
# Get nginx container PID
NGINX_PID=$(docker inspect -f '{{.State.Pid}}' wordpress_nginx)

# Run pcap capture inside container's network namespace
# Sample rate: 1 = every packet, 100 = 1 in 100
sudo nsenter -t $NGINX_PID -n ./target/release/pcap_capture eth1 /tmp/capture.pcap 1

# View captured packets
tcpdump -r /tmp/capture.pcap -n | head -20
```

### Attack Simulation

```bash
# Generate SYN flood with spoofed 10.x.x.x sources
# Args: interface, target_ip, packets_per_second
sudo ./target/release/test_sendmmsg macv1 192.168.1.200 50000
```

### XDP Filter Stats

```bash
# Monitor filter statistics (detect or enforce mode)
sudo nsenter -t $NGINX_PID -n ./target/release/test_xdp eth1 detect

# Switch to enforce mode (actually drop attack packets)
sudo nsenter -t $NGINX_PID -n ./target/release/test_xdp eth1 enforce
```

## Test Results

**Attack Traffic (10s test):**
- 456k packets generated at ~45k pps
- 380k+ packets captured and classified as attack
- XDP filter correctly identified 10.x.x.x sources

**Legitimate Traffic:**
- WordPress traffic generator requests captured
- Full TCP handshakes and HTTP/TLS flows visible
- 0% false positive attack classification

## Components

| Crate | Description |
|-------|-------------|
| `xdp-filter-ebpf` | eBPF/XDP program (runs in kernel) |
| `xdp-filter` | Userspace loader, stats, pcap capture |
| `xdp-generator` | Packet generator (sendmmsg + AF_XDP stub) |
| `control-plane` | HTTP API for management (WIP) |

## Future Improvements

1. **Second NIC** - Enable AF_XDP zero-copy for 10x+ throughput
2. **VSA/HDC Integration** - Replace simple IP classification with learned embeddings
3. **Ring buffer** - Use BPF ring buffer instead of perf buffer (newer kernels)
4. **Native XDP mode** - Requires physical NIC, not macvlan

## Dependencies

```bash
# Rust nightly + BPF linker
rustup install nightly
cargo install bpf-linker

# Linux headers
sudo apt install linux-headers-$(uname -r) clang llvm libelf-dev
```

## Pinned Versions

Due to aya-ebpf toolchain issues, specific versions are pinned in `xdp-filter-ebpf/Cargo.toml`:
- `aya-ebpf = "=0.1.0"`
- `aya-ebpf-bindings = "=0.1.0"`  
- `aya-ebpf-cty = "=0.2.1"`

## Holon Integration

This lab integrates [holon-rs](https://github.com/watmin/holon-rs) for VSA/HDC-based packet classification:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  XDP Filter     │────▶│  Perf Buffer    │────▶│  Holon-rs       │
│  (kernel)       │     │  (sampled pkts) │     │  (VSA encoding) │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
        ▲                                                │
        │                                                ▼
        │                                       ┌─────────────────┐
        └───────────────────────────────────────│  Anomaly Detect │
                   Dynamic rule injection       │  (drift + conc) │
                                                └─────────────────┘
```

**Key concept:** Instead of hard-coded rules, Holon learns traffic patterns:
- Encode packet headers as hypervectors (src_ip, dst_port, protocol, etc.)
- Build baseline accumulator during warmup, then freeze
- Detect anomalies via accumulator drift (current vs baseline similarity)
- Identify attack vectors via field concentration analysis
- Inject DROP rules dynamically into XDP

**Results:** 100% attack recall with zero domain knowledge hardcoded.

## See Also

- [holon-rs](https://github.com/watmin/holon-rs) — Rust VSA library (12x faster than Python)
- [holon](https://github.com/watmin/holon) — Python reference implementation with extensive documentation
- [veth-lab/docs/PROGRESS.md](veth-lab/docs/PROGRESS.md) — Detailed stress test results and architecture
