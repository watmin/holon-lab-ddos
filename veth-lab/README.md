# Veth Lab

Local development and testing environment for the Holon-powered eBPF DDoS mitigation system. Uses veth pairs and network namespaces — no special hardware required.

## Architecture

```
┌──────────────────────────┐              ┌───────────────────────────────────┐
│  netns: veth-lab-gen     │              │  Host (default netns)             │
│                          │              │                                    │
│  ┌────────────────────┐  │              │  ┌──────────────────────────────┐ │
│  │ Generator          │  │              │  │ veth_filter (XDP entry)      │ │
│  │ - Normal traffic   │  │              │  │ - Parse + extract fields     │ │
│  │ - UDP amplification│  │    veth      │  │ - Sample to perf buffer     │ │
│  │ - TCP SYN flood    │  │◄────────────►│  │ - Init DFS, tail call ──┐   │ │
│  └────────────────────┘  │    pair      │  │                         │   │ │
│                          │              │  │ tree_walk_step (DFS)  ◄──┘   │ │
│  veth-gen                │              │  │ - Pop stack, check node     │ │
│                          │              │  │ - Push wildcard + specific  │ │
│                          │              │  │ - Tail call self            │ │
└──────────────────────────┘              │  │ - Apply: DROP/RATE/PASS    │ │
                                          │  └──────────────────────────────┘ │
                                          │                 │                  │
                                          │  veth-filter    │ perf samples    │
                                          │                 ▼                  │
                                          │  ┌──────────────────────────────┐ │
                                          │  │ Sidecar                      │ │
                                          │  │ - Holon-rs VSA encoding     │ │
                                          │  │ - Anomaly detection (drift) │ │
                                          │  │ - Pattern attribution       │ │
                                          │  │ - Rule generation (s-expr)  │ │
                                          │  │ - DAG compiler              │ │
                                          │  │ - Blue/green tree flip      │ │
                                          │  └──────────────────────────────┘ │
                                          └───────────────────────────────────┘
```

## Quick Start

```bash
# 1. Build everything (eBPF + userspace)
./scripts/build.sh

# 2. Setup veth pair + namespace
sudo ./scripts/setup.sh

# 3. Run with enforcement and rate limiting
sudo ./target/release/veth-sidecar \
    --interface veth-filter \
    --enforce \
    --rate-limit \
    --warmup-windows 10 \
    --warmup-packets 1000 \
    --sample-rate 100

# 4. (Separate terminal) Generate traffic
sudo ./target/release/veth-generator --interface veth-inside

# 5. Cleanup when done
sudo ./scripts/teardown.sh
```

### With Pre-Loaded Rules (Stress Test)

```bash
# Generate 1M rules in EDN format (recommended)
python3 scripts/generate_ruleset_edn.py --count 1000000 --output scenarios/rules-1m.edn

# Or generate JSON (legacy format)
python3 scripts/generate_ruleset.py --count 1000000 --output scenarios/rules-1m.json

# Run with pre-loaded rules (auto-detects format)
sudo ./target/release/veth-sidecar \
    --interface veth-filter \
    --enforce \
    --rate-limit \
    --rules-file scenarios/rules-1m.edn \
    --warmup-windows 15 \
    --warmup-packets 1500 \
    --sample-rate 100
```

**Performance:** EDN format parses 1M rules in ~2.7 seconds (40% smaller files than JSON).

## Components

| Component | Description |
|---|---|
| `filter-ebpf/` | XDP eBPF programs — `veth_filter` (entry point) + `tree_walk_step` (DFS walker) |
| `filter/` | Userspace library — `VethFilter`, DAG compiler, tree flattener, blue/green deployment |
| `sidecar/` | Detection engine — Holon analysis, rule generation, JSON parsing, CLI |
| `generator/` | Traffic generator — normal traffic + multi-phase attacks (UDP amp, SYN flood) |
| `scripts/` | Build, setup, teardown, demo, rule generation |

## How It Works

1. **eBPF parses packets** and samples 1-in-N to userspace via perf buffer
2. **Holon encodes samples** as 4096-dimensional hypervectors using VSA binding and bundling
3. **Drift detection** compares the current window's accumulator against the frozen baseline
4. **Pattern attribution** identifies which fields (proto, src-ip, dst-port, etc.) are concentrated in anomalous traffic
5. **Rules are generated** as EDN maps: `{:constraints [(= proto 17) (= src-port 53)] :actions [(rate-limit 1906)]}`
6. **DAG compiler** builds a decision tree with memoization and structural sharing (`Rc<ShadowNode>`)
7. **Blue/green flip** writes the new tree to the inactive slot and atomically swaps `TREE_ROOT`
8. **BPF tail-call DFS** walks the tree — ~5 tail calls per packet, regardless of rule count

## Rule Language

Rules use EDN (Extensible Data Notation) format with s-expression predicates:

```edn
{:constraints [(= proto 17)
               (= src-port 53)
               (= src-addr "10.0.0.200")]
 :actions     [(rate-limit 1906)]
 :priority    200}
```

**File Format:** Rules can span multiple lines for readability:
```edn
;; Single-line (compact)
{:constraints [(= proto 17) (= src-port 53)] :actions [(rate-limit 500)] :priority 200}

;; Multi-line (readable)
{:constraints [(= proto 17)
               (= src-port 53)]
 :actions [(rate-limit 500)]
 :priority 200}
```

**Fields:** `proto`, `src-addr`, `dst-addr`, `src-port`, `dst-port`, `tcp-flags`, `ttl`, `df`, `tcp-window`

**Actions:** `(drop)`, `(pass)`, `(rate-limit <pps>)`, `(rate-limit <pps> :name "label")`, `(count :name "label")`

See [docs/EDN-RULES.md](docs/EDN-RULES.md) for the complete EDN format reference.
See [docs/RULES.md](docs/RULES.md) for the legacy s-expression format and language theory.

## Documentation

| Document | Description |
|---|---|
| [PROGRESS.md](docs/PROGRESS.md) | Timeline, results, architecture overview |
| [RETE.md](docs/RETE.md) | Rete theory — how this implements a discrimination network |
| [VSA.md](docs/VSA.md) | Holon/HDC theory — encoding, detection, rule derivation |
| [EBPF.md](docs/EBPF.md) | eBPF engineering — 6 chapters of verifier battles |
| [DECISIONS.md](docs/DECISIONS.md) | 10 architecture decision records |
| [SCALING.md](docs/SCALING.md) | Performance from 50K to 1M rules, projections to 5M+ |
| [EDN-RULES.md](docs/EDN-RULES.md) | **EDN rule format reference (current format)** |
| [RULES.md](docs/RULES.md) | Legacy s-expression format and language theory |
| [OPERATIONS.md](docs/OPERATIONS.md) | Build, run, tune, monitor, debug runbook |

## Safety

This lab uses network namespaces to isolate traffic. Your host networking is not affected:
- Traffic generator runs in a separate namespace
- veth-filter only receives traffic from the veth pair
- No routing changes are made to default routes

## Requirements

- Linux kernel 5.15+ (BPF tail calls, BTF)
- Rust nightly (for eBPF compilation)
- `bpf-linker` (`cargo install bpf-linker`)
- Root access (XDP requires `CAP_NET_ADMIN`)
- Optional: `bpftool` for debugging (`sudo apt install linux-tools-common`)
