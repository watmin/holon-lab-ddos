# DDoS Lab

XDP/eBPF-based DDoS traffic generator and scrubber for testing VSA/HDC packet classification.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Host                                                           │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ control-plane (HTTP API :8080)                          │   │
│  │ curl localhost:8080/stats                               │   │
│  │ curl -X POST localhost:8080/attack/start                │   │
│  └─────────────────────────────────────────────────────────┘   │
│                    │                       │                    │
│  ┌─────────────────┴───────┐   ┌───────────┴─────────────────┐ │
│  │ xdp-filter              │   │ xdp-generator               │ │
│  │ Inspect & drop bad pkts │   │ AF_XDP SYN/UDP flood        │ │
│  │ Stats via eBPF maps     │   │ Spoofed src: 10.0.0.0/8     │ │
│  └─────────────────────────┘   └─────────────────────────────┘ │
│             │                              │                    │
│             ▼                              ▼                    │
│      eth0/veth (container)            eno1 (host NIC)          │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
                   ┌───────────────┐
                   │  LAN / Switch │
                   └───────┬───────┘
                           │
                           ▼
                ┌─────────────────────┐
                │ Nginx container     │
                │ 192.168.1.200       │
                │ (WordPress target)  │
                └─────────────────────┘
```

## Components

### xdp-filter
- eBPF/XDP program that inspects incoming packets
- Drops traffic from 10.0.0.0/8 (DDoS simulation range)
- Passes legitimate traffic (192.168.1.x)
- Future: VSA/HDC integration for learned classification

### xdp-generator  
- AF_XDP-based packet generator
- Crafts SYN floods, UDP floods with spoofed source IPs
- Configurable burst patterns (30s-300s bursts)
- High PPS capability via kernel bypass

### control-plane
- Axum HTTP server for management
- Start/stop attacks, view stats, configure parameters
- Coordinates filter and generator

## API Endpoints

```bash
# Stats
curl localhost:8080/stats
curl localhost:8080/filter/stats
curl localhost:8080/attack/status

# Control
curl -X POST localhost:8080/attack/start
curl -X POST localhost:8080/attack/stop
curl -X POST localhost:8080/attack/config -d '{"type":"syn","pps":100000}'
curl -X POST localhost:8080/filter/mode -d '{"mode":"enforce"}'
```

## Prerequisites

```bash
# Rust + cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# bpf-linker (for compiling eBPF)
cargo install bpf-linker

# Linux headers and tools
sudo apt install linux-headers-$(uname -r) clang llvm libelf-dev
```

## Build

```bash
cargo xtask build-ebpf    # Build eBPF programs
cargo build --release      # Build userspace
```

## Run

```bash
# Start the control plane (generator only for now, XDP filter pending)
# IMPORTANT: Use a macvlan interface (-i macv1) for proper hairpin to work
sudo ./target/release/ddos-lab --no-filter --target 192.168.1.200 -i macv1

# In another terminal, start an attack
curl -X POST localhost:8080/attack/start

# Watch stats
watch -n1 'curl -s localhost:8080/attack/status | jq'

# Stop attack
curl -X POST localhost:8080/attack/stop
```

### Why macv1 instead of eno1?

The attack traffic needs to hairpin back to the Nginx container (192.168.1.200) which 
is on a Docker macvlan network. When sending from a host macvlan interface (macv1), 
the kernel's macvlan driver handles the internal routing between macvlan peers on 
the same parent interface. Sending from eno1 directly doesn't work because the 
physical switch won't hairpin traffic back to the same port.

## Testing with WordPress traffic generator

Run the legitimate traffic generator alongside:
```bash
cd ../
python3 wordpress_traffic_generator.py
```

The filter should:
- DROP packets from 10.0.0.0/8 (attack traffic)
- PASS packets from 192.168.1.x (legitimate via macvlan)
