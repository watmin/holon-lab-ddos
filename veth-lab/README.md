# Veth Lab - AF_XDP + Holon Sidecar

Local development environment for XDP packet filtering with Holon-based detection.

## Architecture

```
┌──────────────────────────┐              ┌───────────────────────────────────┐
│  netns: veth-lab-gen     │              │  Host (default netns)             │
│                          │              │                                    │
│  ┌────────────────────┐  │              │  ┌──────────────────────────────┐ │
│  │ Generator          │  │              │  │ XDP Filter (native)          │ │
│  │ - AF_PACKET/AF_XDP │  │              │  │ - RULES map (drop rules)     │ │
│  │ - Spoofed sources  │  │    veth      │  │ - STATS map (counters)       │ │
│  │ - Attack patterns  │  │◄────────────►│  │ - Ring buffer (samples)      │ │
│  └────────────────────┘  │    pair      │  └──────────────────────────────┘ │
│                          │              │                 │                  │
│  veth-gen: 10.100.0.1/24 │              │  veth-filter: 10.100.0.2/24      │
│                          │              │                 │                  │
└──────────────────────────┘              │                 ▼                  │
                                          │  ┌──────────────────────────────┐ │
                                          │  │ Sidecar                      │ │
                                          │  │ - Reads ring buffer samples  │ │
                                          │  │ - Holon-rs encoding          │ │
                                          │  │ - Anomaly detection          │ │
                                          │  │ - Updates RULES map          │ │
                                          │  └──────────────────────────────┘ │
                                          └───────────────────────────────────┘
```

## Quick Start

```bash
# 1. Setup veth pair + namespace (requires sudo)
sudo ./scripts/setup.sh

# 2. Build everything
./scripts/build.sh

# 3. Run the demo
sudo ./scripts/demo.sh

# 4. Cleanup when done
sudo ./scripts/teardown.sh
```

## Components

| Component | Description |
|-----------|-------------|
| `scripts/` | Setup, teardown, and orchestration scripts |
| `filter-ebpf/` | XDP eBPF program with dynamic rules |
| `filter/` | Userspace loader and rule management |
| `generator/` | Traffic generator (AF_PACKET, AF_XDP) |
| `sidecar/` | Holon detection and rule updates |

## Network Setup

- **veth-gen** (10.100.0.1/24): Generator side, in `veth-lab-gen` namespace
- **veth-filter** (10.100.0.2/24): Filter side, in host namespace

The veth pair acts like a virtual cable. Packets sent on veth-gen appear on veth-filter.

## Rule Format

Rules are stored in a BPF HashMap with this structure:

```rust
// Key: what to match
struct RuleKey {
    rule_type: u8,    // 0=src_ip, 1=dst_ip, 2=src_port, 3=dst_port, 4=protocol
    _pad: [u8; 3],
    value: u32,       // IP address or port (in network order)
}

// Value: what to do
struct RuleValue {
    action: u8,       // 0=pass, 1=drop, 2=rate_limit
    _pad: [u8; 3],
    rate_pps: u32,    // For rate_limit action
    tokens: u32,      // Token bucket state
    last_update: u64, // Timestamp for token refill
}
```

## Safety

This lab uses network namespaces to isolate traffic. Your laptop's networking is not affected:
- veth-gen is in a separate namespace
- veth-filter is attached to host but only receives traffic from veth-gen
- No routing changes are made to your default routes

## Requirements

- Linux kernel 5.4+ (for ring buffer, AF_XDP improvements)
- Rust nightly (for eBPF)
- bpf-linker
- Root access (for XDP attachment)
