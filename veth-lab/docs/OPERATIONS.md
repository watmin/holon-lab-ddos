# Operations Guide

**How to build, run, tune, monitor, and debug the system.**

## Prerequisites

- Linux kernel 5.15+ (BPF tail call support, BTF)
- Rust nightly toolchain (for eBPF compilation)
- `bpf-linker` (`cargo install bpf-linker`)
- Root/sudo access (XDP requires `CAP_NET_ADMIN`)
- `bpftool` for debugging (`sudo apt install linux-tools-common linux-tools-$(uname -r)` or `sudo apt install bpftool`)

## Building

From the `holon-lab-ddos/` directory:

```bash
cd veth-lab
./scripts/build.sh
```

This builds:
1. **eBPF program** (`filter-ebpf/target/bpfel-unknown-none/release/veth-filter`) — compiled with `cargo +nightly` targeting `bpfel-unknown-none`
2. **Userspace components** — `veth-filter` (library), `veth-sidecar` (detection engine), `veth-generator` (traffic gen)

Binaries land in `target/release/`:
- `veth-sidecar` — the main program (detection + enforcement)
- `veth-generator` — synthetic traffic generator for testing
- `veth-loader` — standalone XDP loader (for testing without detection)

## Network Setup

The test environment uses a veth pair:

```bash
sudo ./veth-lab/scripts/setup.sh
```

This creates:
- `veth-filter` — the "outside" interface (XDP attaches here)
- `veth-inside` — the "inside" interface (traffic generator sends here)

## Running

### Basic Detection (No Enforcement)

```bash
sudo ./target/release/veth-sidecar --interface veth-filter
```

Observes traffic, detects anomalies, logs rules it *would* apply. No packets are dropped.

### Full Enforcement with Rate Limiting

```bash
sudo ./target/release/veth-sidecar \
    --interface veth-filter \
    --enforce \
    --rate-limit \
    --warmup-windows 10 \
    --warmup-packets 1000 \
    --sample-rate 100 \
    --min-packets 30 \
    --log-dir logs
```

### With Pre-Loaded Rules

```bash
sudo ./target/release/veth-sidecar \
    --interface veth-filter \
    --enforce \
    --rate-limit \
    --rules-file veth-lab/scenarios/rules-50k.json \
    --warmup-windows 15 \
    --warmup-packets 1500 \
    --sample-rate 100 \
    --min-packets 30 \
    --log-dir logs
```

### Traffic Generator (Separate Terminal)

```bash
sudo ./target/release/veth-generator --interface veth-inside
```

The generator sends a mix of normal traffic and attack phases (UDP amplification, TCP SYN flood).

## CLI Reference

### `veth-sidecar`

| Flag | Default | Description |
|---|---|---|
| `--interface` | `veth-filter` | Interface to attach XDP program to |
| `--window` | `2` | Detection window duration in seconds |
| `--threshold` | `0.85` | Drift threshold (0.0–1.0). Lower = more sensitive |
| `--min-packets` | `50` | Minimum packets per window for detection to run |
| `--concentration` | `0.5` | Field concentration threshold (0.0–1.0). Higher = stricter |
| `--enforce` | off | Enable enforcement (actually drop/rate-limit packets) |
| `--rate-limit` | off | Use rate limiting instead of binary DROP |
| `--dimensions` | `4096` | Holon vector dimensions |
| `--warmup-windows` | `5` | Windows to learn baseline before detecting |
| `--warmup-packets` | `500` | Minimum packets during warmup to establish baseline |
| `--sample-rate` | `100` | Sample 1-in-N packets (100 = 1%) |
| `--perf-pages` | `4` | Perf buffer pages per CPU (4 = 16KB) |
| `--rules-file` | none | Path to JSON rules file to pre-load |
| `--log-dir` | `logs` | Directory for log files |

### Tuning Guidelines

**Detection sensitivity:**
- `--threshold 0.85` — default, good for clear attacks
- `--threshold 0.75` — more sensitive, may flag minor traffic shifts
- `--threshold 0.90` — less sensitive, only flags major anomalies

**Warmup period:**
- Short warmup (`--warmup-windows 5 --warmup-packets 500`) — faster start, less stable baseline
- Long warmup (`--warmup-windows 15 --warmup-packets 1500`) — stable baseline, slower to first detection
- With pre-loaded rules, longer warmup is recommended (rules are compiled after warmup completes)

**Sample rate:**
- `--sample-rate 100` — 1% of packets, good for 10Kpps+
- `--sample-rate 10` — 10% of packets, good for low-traffic testing
- `--sample-rate 1000` — 0.1% of packets, for very high PPS

**Concentration threshold:**
- `--concentration 0.5` — flags fields where one value appears >50% of the time
- `--concentration 0.7` — only flags highly concentrated fields
- Lower values generate broader rules; higher values generate more specific rules

## Reading the Logs

### Warmup Window

```
Window 3 [WARMUP]: 42 packets, drift=0.000 | XDP total: 12847, dropped: 0 (hard:0 rate:0) | DFS tc:0 comp:0 | DIAG eval2:0 root:0 state:0 tc_try:0 tc_fail:0 | warmup 3/10 windows, 126/1000 packets
```

| Field | Meaning |
|---|---|
| `Window 3 [WARMUP]` | Third window, still in warmup phase |
| `42 packets` | Packets sampled to userspace this window |
| `drift=0.000` | Cosine distance from baseline (0 = identical) |
| `XDP total: 12847` | Total packets seen by XDP since start |
| `dropped: 0 (hard:0 rate:0)` | Drops: hard (DROP action) + rate-limited |
| `DFS tc:0 comp:0` | Tail call entries and DFS completions (0 = no tree loaded yet) |
| `DIAG eval2:... tc_fail:...` | Internal diagnostic counters (see Debugging) |
| `warmup 3/10 windows, 126/1000 packets` | Warmup progress |

### Normal Window (No Anomaly)

```
Window 15: 38 packets, drift=0.142, anom_ratio=0.0%, phase=0 | XDP total: 58291, dropped: 0 (hard:0 rate:0) | DFS tc:48095 comp:48095 | DIAG eval2:48095 root:48095 state:48095 tc_try:48095 tc_fail:0
```

| Field | Meaning |
|---|---|
| `drift=0.142` | Low drift — traffic looks normal |
| `anom_ratio=0.0%` | No individual anomalous packets |
| `phase=0` | Phase 0 = stable state |
| `DFS tc:48095 comp:48095` | All tail calls completed successfully (`tc == comp` is healthy) |
| `tc_fail:0` | No tail call failures (healthy) |

### Anomaly Detection

```
ANOMALY: drift=0.743, 92.1% anomalous (42/47 packets), phase changed to 1
  Concentrated: proto=17 (85.1%), src-port=53 (71.2%), src-addr=10.0.0.200 (89.3%)
  Tree compiled: 50004 rules → 100008 nodes, 100004 edges in 92ms
  Added rule: ((and (= proto 17) (= src-port 53) (= src-addr 10.0.0.200)) => (rate-limit 1906))
```

| Field | Meaning |
|---|---|
| `drift=0.743` | High drift — traffic has shifted significantly from baseline |
| `92.1% anomalous` | Most packets in this window are anomalous |
| `phase changed to 1` | Detected a phase transition (new attack) |
| `Concentrated: proto=17 (85.1%)` | Protocol 17 (UDP) appears in 85% of anomalous packets |
| `100008 nodes` | Compiled tree size (including pre-loaded rules) |
| `rate-limit 1906` | Derived rate from vector magnitude ratio |

### Healthy Counters (What "Good" Looks Like)

```
DFS tc:48095 comp:48095    ← tc == comp: all DFS walks complete
tc_fail:0                  ← zero failures: tail calls working
hard:1972036 rate:1972036  ← drops happening: rules enforced
```

### Unhealthy Counters (What "Bad" Looks Like)

```
DFS tc:48095 comp:0        ← completions zero: DFS never finishing
tc_fail:48095              ← all tail calls failing
tc_try:48095 tc_fail:48095 ← tc_try == tc_fail: ProgramArray empty
```

## Generating Rule Files

```bash
# 10K rules
python3 veth-lab/scripts/generate_ruleset.py --count 10000 --output veth-lab/scenarios/rules-10k.json

# 50K rules
python3 veth-lab/scripts/generate_ruleset.py --count 50000 --output veth-lab/scenarios/rules-50k.json

# 1M rules
python3 veth-lab/scripts/generate_ruleset.py --count 1000000 --output veth-lab/scenarios/rules-1m.json
```

Generated files contain:
- 4 **sentinel rules** matching test traffic patterns (UDP amplification, SYN flood)
- N-4 **background rules** with unique (proto, src-addr, dst-port) triples

The `.gitignore` excludes `rules-*.json` — regenerate locally as needed.

## Debugging with bpftool

### List loaded eBPF programs

```bash
sudo bpftool prog list | tail -20
```

You should see two XDP programs:
```
862: xdp  name veth_filter     tag 36e5c1f452d52b06  gpl
    loaded_at 2026-02-12T22:14:08-0800  uid 0
    xlated 16360B  jited 10277B  memlock 20480B
    map_ids 1432,1426,1446,...
863: xdp  name tree_walk_step  tag 2b9ce22e42620efc  gpl
    loaded_at 2026-02-12T22:14:09-0800  uid 0
    xlated 4232B  jited 2630B  memlock 8192B
    map_ids 1432,1428,1427,...
```

### Check ProgramArray (tail call target)

```bash
# Find the prog_array map
sudo bpftool map list | grep -A2 prog_array

# Dump it — should have 1 element
sudo bpftool map dump id <MAP_ID>
```

**Critical:** If this shows `Found 0 elements`, the tail call target has been dropped. The `ProgramArray` fd was closed. This is the "silent killer" — the program runs, processes packets, but the DFS never executes. See `EBPF.md` for the full story.

### Inspect tree maps

```bash
# Find TREE_NODES (array, 16B entries, 5M max)
sudo bpftool map list | grep -B1 "max_entries 5000000"

# Check how many edges are populated
sudo bpftool map list | grep -B1 "TREE_EDGES"

# Dump a specific node
sudo bpftool map lookup id <TREE_NODES_ID> key 0 0 0 0
```

### Check stats counters

```bash
# STATS is a PerCpuArray — dump shows per-CPU values
sudo bpftool map dump id <STATS_ID>
```

Stats indices:
| Index | Counter |
|---|---|
| 0 | total_packets |
| 1 | passed_packets |
| 2 | dropped_packets (hard DROP) |
| 3 | sampled_packets |
| 5 | rate_limited_packets |
| 6 | dfs_completions |
| 7 | tail_call_entries |
| 8 | diag: eval_mode==2 entered |
| 9 | diag: root non-zero |
| 10 | diag: got DFS state pointer |
| 11 | diag: tail call attempted |
| 12 | diag: tail call failed (returned) |

### Detach XDP program

```bash
sudo ip link set dev veth-filter xdp off
```

## Troubleshooting

### "BPF program is too large"

The eBPF verifier hit the 1M instruction limit. This shouldn't happen with the current tail-call architecture. If it does:
1. Check that `filter-ebpf` was rebuilt (`./scripts/build.sh`)
2. Verify the eBPF binary is the tail-call version, not an older single-program version
3. Check `bpftool prog list` — `tree_walk_step` should be ~4K instructions, not 16K+

### Zero drops with rules loaded

1. Check `tc_fail` in the logs — if `tc_fail == tc_try`, the ProgramArray is empty
2. Run `sudo bpftool map dump id <PROG_ARRAY_ID>` — should show 1 element
3. If 0 elements: the `ProgramArray` fd was closed. Rebuild and restart
4. Check `DFS comp` — if `comp > 0` but `drops == 0`, rules may not match the traffic
5. Check that `--enforce` flag is set

### "Failed to compile tree: bpf_map_update_elem failed"

Map is full. Either:
- Too many rules for the current `TREE_SLOT_SIZE` (default 2.5M nodes per slot)
- Edge map is full (5M entries)
- Increase map sizes in `filter-ebpf/src/main.rs` and `filter/src/lib.rs`, then rebuild

### Detection too sensitive / too many rules

- Increase `--threshold` (e.g., 0.90)
- Increase `--concentration` (e.g., 0.7)
- Increase `--warmup-windows` for more stable baseline
- Increase `--min-packets` to require more evidence per window

### Detection not triggering

- Decrease `--threshold` (e.g., 0.75)
- Decrease `--sample-rate` (e.g., 10) to sample more packets
- Check that `sampled_packets` counter is increasing — if zero, perf buffer may be full
- Increase `--perf-pages` (e.g., 16) for more perf buffer space

### High `tc_fail` but not 100%

Occasional tail call failures can happen under extreme load (kernel stack depth limit). If `tc_fail / tc_try < 1%`, this is normal and doesn't significantly affect enforcement. If higher:
- Check system load — other eBPF programs consuming tail call budget?
- Check `bpftool prog list` for other XDP/TC programs on the same interface

## File Layout

```
holon-lab-ddos/
├── veth-lab/
│   ├── filter-ebpf/         # eBPF program (kernel space)
│   │   └── src/main.rs      #   XDP entry + tree_walk_step
│   ├── filter/               # Userspace filter library
│   │   └── src/
│   │       ├── lib.rs        #   VethFilter, RuleSpec, Predicate, FieldDim
│   │       └── tree.rs       #   DAG compiler, flattener, userspace simulator
│   ├── sidecar/              # Detection engine
│   │   └── src/main.rs       #   Holon analysis, rule generation, CLI
│   ├── generator/            # Traffic generator
│   │   └── src/main.rs       #   Synthetic normal + attack traffic
│   ├── scripts/
│   │   ├── build.sh          #   Build everything
│   │   ├── setup.sh          #   Create veth pair
│   │   ├── demo.sh           #   Run full demo
│   │   └── generate_ruleset.py  # Generate large JSON rule files
│   ├── scenarios/            # Rule files (generated, git-ignored)
│   │   └── rules-*.json
│   ├── docs/                 # Documentation
│   │   ├── PROGRESS.md       #   Timeline and results
│   │   ├── RETE.md           #   Rete theory mapping
│   │   ├── VSA.md            #   Holon/HDC theory
│   │   ├── EBPF.md           #   Verifier engineering story
│   │   ├── DECISIONS.md      #   Architecture decision records
│   │   ├── SCALING.md        #   Performance analysis
│   │   ├── RULES.md          #   Rule language reference
│   │   └── OPERATIONS.md     #   This file
│   └── logs/                 # Runtime logs (git-ignored)
└── target/release/           # Built binaries
    ├── veth-sidecar
    ├── veth-generator
    └── veth-loader
```
