# Holon Lab - DDoS

[![Powered by Holon-rs](https://img.shields.io/badge/Powered%20by-Holon--rs-blue)](https://github.com/watmin/holon-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Autonomous DDoS detection and mitigation at kernel level, powered by [Holon-rs](https://github.com/watmin/holon-rs) (Vector Symbolic Architecture / Hyperdimensional Computing) and an eBPF tree Rete engine.

**No signatures. No thresholds to configure. No domain knowledge hardcoded.** Holon learns what normal traffic looks like, detects when it changes, figures out what changed, and writes filter rules — all autonomously.

## Key Results (Feb 2026)

- **1,000,000 rules** compiled into a decision tree and enforced at line rate
- **~5 BPF tail calls per packet** regardless of rule count (O(depth), not O(rules))
- **Zero-config detection** — anomaly detection and rule derivation from vector algebra alone
- **Atomic rule updates** — blue/green tree deployment with zero-downtime flips
- **Sub-second detection** — anomaly flagged within one 2-second window of attack onset

## Architecture

```
Packets ──► XDP (veth_filter) ──► BPF Tail-Call DFS ──► DROP / RATE-LIMIT / PASS
                │                     │
                │ perf sample         │ reads TREE_NODES, TREE_EDGES
                ▼                     │
            Sidecar                   │
            ├─ Holon-rs encode        │
            ├─ Drift detection        │
            ├─ Pattern attribution    │
            ├─ Rule generation        │
            ├─ DAG compiler ──────────┘
            └─ Blue/green flip         (atomic TREE_ROOT swap)
```

The eBPF program evaluates a million-rule decision tree via depth-first search using BPF tail calls. Each tail call processes one DFS step (~4K instructions, trivially verified). The userspace sidecar uses Holon's VSA/HDC to detect anomalies and compile new rules into the tree without stopping packet processing.

## Veth Lab

**[`veth-lab/`](veth-lab/)** — the primary development and testing environment. Reproducible local testing using veth pairs and network namespaces. No special hardware required.

```bash
cd veth-lab
./scripts/build.sh
sudo ./scripts/setup.sh
sudo ./target/release/veth-sidecar --interface veth-filter --enforce --rate-limit
```

See the [Veth Lab README](veth-lab/README.md) for full setup and usage instructions.

## Documentation

The `veth-lab/docs/` directory contains comprehensive documentation:

| Document | Description |
|---|---|
| [PROGRESS.md](veth-lab/docs/PROGRESS.md) | Timeline, architecture overview, test results |
| [RETE.md](veth-lab/docs/RETE.md) | How we implement Rete in spirit (Clara comparison) |
| [VSA.md](veth-lab/docs/VSA.md) | Holon/HDC theory — encoding, detection, rule derivation |
| [EBPF.md](veth-lab/docs/EBPF.md) | The eBPF engineering story — 6 chapters of verifier battles |
| [DECISIONS.md](veth-lab/docs/DECISIONS.md) | 10 architecture decision records with rationale |
| [SCALING.md](veth-lab/docs/SCALING.md) | Performance data from 50K to 1M rules, projections to 5M+ |
| [RULES.md](veth-lab/docs/RULES.md) | Rule language reference — s-expressions, predicates, extensions |
| [OPERATIONS.md](veth-lab/docs/OPERATIONS.md) | Build, run, tune, monitor, and debug runbook |

## Components

| Crate | Description |
|---|---|
| `veth-lab/filter-ebpf` | XDP eBPF programs — `veth_filter` (entry) + `tree_walk_step` (DFS) |
| `veth-lab/filter` | Userspace library — DAG compiler, tree flattener, blue/green deployment |
| `veth-lab/sidecar` | Holon detection engine — anomaly detection, rule generation, CLI |
| `veth-lab/generator` | Traffic generator — normal + multi-phase attack traffic |

## Dependencies

```bash
# Rust nightly + BPF linker
rustup install nightly
cargo install bpf-linker

# Linux headers and tools
sudo apt install linux-headers-$(uname -r) clang llvm libelf-dev
sudo apt install linux-tools-common linux-tools-$(uname -r)  # bpftool
```

## See Also

- [holon-rs](https://github.com/watmin/holon-rs) — Rust VSA/HDC library
- [holon](https://github.com/watmin/holon) — Python reference implementation with extensive documentation
