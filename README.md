# Holon Lab - DDoS

XDP/eBPF-based DDoS traffic generator and filter for proving [Holon](https://github.com/YOUR_ORG/holon) VSA/HDC packet classification.

This lab demonstrates using Holon's vector symbolic architecture for real-time DDoS detection and mitigation at kernel level.

## Status

**Proven working (Feb 2026):**
- XDP/eBPF filter in Rust using aya-ebpf
- High-speed packet filtering (~45k pps in SKB mode)
- Full packet sampling to userspace via perf buffer
- Pcap capture for traffic analysis
- Detect mode (log but pass) and Enforce mode (drop attacks)
- Attack traffic identification (10.0.0.0/8 spoofed sources)

**Limitations (current setup):**
- Macvlan interfaces don't support AF_XDP (need physical NIC for zero-copy)
- SKB mode (not native XDP) due to macvlan
- 256-byte packet samples (BPF stack limit)

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

## Holon Integration (Planned)

This lab will integrate with [holon-rs](https://github.com/YOUR_ORG/holon-rs) to demonstrate VSA/HDC-based packet classification:

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  XDP Filter     │────▶│  Perf Buffer    │────▶│  Holon-rs       │
│  (kernel)       │     │  (256b samples) │     │  (VSA encoding) │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
        ▲                                                │
        │                                                ▼
        │                                       ┌─────────────────┐
        └───────────────────────────────────────│  HDC Classifier │
                   Update filter rules          │  (similarity)   │
                                                └─────────────────┘
```

**Key concept:** Instead of hard-coded rules (10.0.0.0/8 = attack), Holon learns traffic patterns:
- Encode packet headers as hypervectors
- Build prototype vectors for "normal" and "attack" traffic
- Classify new packets by similarity to prototypes
- Adapt to new attack patterns without rule updates

See [holon](https://github.com/YOUR_ORG/holon) for the Python reference implementation.
