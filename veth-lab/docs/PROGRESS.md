# Veth Lab: Holon-Powered XDP DDoS Mitigation

**Status:** Tree Rete Engine Live — 1M Rules Proven  
**Date:** February 2026  
**Latest Update:** February 14, 2026  
**Result:** Scalable decision-tree rule engine with BPF tail-call DFS, blue/green atomic deployment, and s-expression rule representation  
**Key Achievement:** 1,000,000 rules loaded and dropping packets, BPF tail-call architecture, stack-based DFS trie traversal, ~5 tail calls per packet regardless of rule count

## Overview

This document describes the integration of **Holon-rs** (a Rust implementation of Vector Symbolic Architecture / Hyperdimensional Computing) with **eBPF/XDP** for real-time DDoS detection and mitigation.

The system demonstrates:
- Sub-second anomaly detection using VSA/HDC
- Dynamic rule injection into XDP for kernel-level filtering
- Decision-tree rule discrimination (Tree Rete) with O(depth) packet evaluation
- Blue/green atomic deployment for zero-downtime rule updates
- S-expression rule representation for human-readable rule visibility
- Reproducible local testing using network namespaces

## Motivation

Traditional DDoS mitigation relies on:
- Static rules that require manual tuning
- Signature-based detection that misses novel attacks
- Rate limiting that affects legitimate traffic
- Linear rule iteration that caps at ~10k rules per prefix list

Holon offers a different approach:
- **Unsupervised learning**: No labeled training data required
- **Real-time adaptation**: Baseline evolves with traffic patterns
- **Semantic understanding**: Encodes packet structure, not just bytes
- **Efficient**: O(1) similarity computation via vector operations
- **Scalable rule engine**: Tree-based discrimination, not linear iteration

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Host Namespace                              │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                   Holon Sidecar                              ││
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐      ││
│  │  │ Perf     │  │ Holon-rs │  │ Anomaly Detection    │      ││
│  │  │ Reader   │──│ Encoder  │──│ - Drift Analysis     │      ││
│  │  └──────────┘  └──────────┘  │ - Concentration      │      ││
│  │       ▲                      └──────────┬───────────┘      ││
│  │       │                                 │                   ││
│  │       │ samples              ┌──────────▼───────────┐      ││
│  │       │                      │ Tree Compiler        │      ││
│  │       │                      │ - RuleSpec → Tree    │      ││
│  │       │                      │ - Blue/Green Flip    │      ││
│  │       │                      │ - S-expr Logging     │      ││
│  │       │                      └──────────┬───────────┘      ││
│  │       │                                 │ compile_and_flip  ││
│  │       │                                 ▼                   ││
│  │  ┌────┴─────────────────────────────────────────────┐      ││
│  │  │              XDP Program (veth-filter)            │      ││
│  │  │                                                   │      ││
│  │  │  ┌──────────────────────────────────────────┐    │      ││
│  │  │  │ Tree Rete Engine (eval_mode=2)           │    │      ││
│  │  │  │  TREE_NODES: Array<TreeNode> [5M]        │    │      ││
│  │  │  │  TREE_EDGES: HashMap<EdgeKey,u32> [5M]   │    │      ││
│  │  │  │  TREE_ROOT: Array<u32> [1] (atomic ptr)  │    │      ││
│  │  │  │  TREE_RATE_STATE: HashMap<u32,Bucket>    │    │      ││
│  │  │  │  TREE_DFS_STATE: PerCpuArray<DfsState>   │    │      ││
│  │  │  │  TREE_WALK_PROG: ProgramArray [1]        │    │      ││
│  │  │  └──────────────────────────────────────────┘    │      ││
│  │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐          │      ││
│  │  │  │ STATS   │  │ CONFIG  │  │ SAMPLES │          │      ││
│  │  │  │ PerCPU  │  │ Array   │  │ PerfBuf │          │      ││
│  │  │  └─────────┘  └─────────┘  └─────────┘          │      ││
│  │  └──────────────────────────────────────────────────┘      ││
│  └─────────────────────────────────────────────────────────────┘│
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

## Tree Rete Engine

### Why Tree Rete?

The original bitmask Rete engine used a 64-bit bitmask to track which rules matched a packet. This fundamentally capped the system at **64 rules** -- a non-starter for the goal of hosting **100k–1M rules** while probabilistically evaluating only **10–30 per packet**.

The Tree Rete replaces linear rule iteration with a **decision tree** where packet field values drive traversal. A packet enters at the root and a **stack-based DFS** explores all matching paths — both specific-value edges and wildcard branches — collecting every terminating node. The highest-priority match wins. The DFS is implemented via **BPF tail calls**, where each iteration is a separate ~100-instruction XDP program that tail-calls itself. This avoids BPF verifier instruction limits while keeping per-packet cost at ~5 tail calls regardless of tree size.

### Dimensions (Traversal Order)

```
Proto → SrcIp → DstIp → L4Word0 (src-port) → L4Word1 (dst-port) →
  TcpFlags → Ttl → DfBit → TcpWindow
```

The compiler skips dimensions that no rule constrains, so a typical rule touching 2–3 fields only produces a 2–3 level tree.

### Rule Representation: S-expressions

Rules are represented as s-expressions in Clara-style LHS ⇒ RHS form. All values are raw numbers (same as wireshark), IPs in dotted notation:

```
((and (= proto 17)
      (= src-port 53))
 =>
 (rate-limit 1234))
```

A 6-constraint SYN flood rule (live output):

```
((and (= tcp-flags 2)
      (= tcp-window 65535)
      (= proto 6)
      (= src-addr 10.0.0.100)
      (= dst-port 9999)
      (= ttl 128))
 =>
 (rate-limit 2048))
```

The compact one-liner form is also available:

```
((and (= tcp-flags 2) (= tcp-window 65535) (= proto 6) (= src-addr 10.0.0.100) (= dst-port 9999) (= ttl 128)) => (rate-limit 2048))
```

#### Available Field Dimensions

| S-expr Name | Field | Values |
|-------------|-------|--------|
| `proto` | Protocol | 6=TCP, 17=UDP, 1=ICMP |
| `src-addr` | Source IP | IPv4 dotted notation |
| `dst-addr` | Destination IP | IPv4 dotted notation |
| `src-port` | Source Port | 0–65535 |
| `dst-port` | Destination Port | 0–65535 |
| `tcp-flags` | TCP Flags | 2=SYN, 18=SYN+ACK, 16=ACK, etc. |
| `ttl` | TTL | 64=Linux, 128=Windows, 255=network gear |
| `df` | DF Bit | 0=clear, 1=set |
| `tcp-window` | TCP Window | 0–65535 |

### Tree Compilation (DAG Compiler)

The userspace compiler (`filter/src/tree.rs`) builds a DAG (Directed Acyclic Graph) with memoization and structural deduplication:

1. **Partition** rules by the current dimension into specific-value and wildcard groups
2. **Replicate** wildcard rules into every specific-value subtree via `Rc<ShadowNode>` sharing
3. **Memoize** recursive calls — identical `(rule_set, dimension)` pairs produce shared subtrees
4. **Skip** dimensions not constrained by any rule in the current subtree
5. **Recurse** until all dimensions are exhausted or only one rule remains
6. **Flatten** the DAG into `(node_id → TreeNode)` and `(EdgeKey → child_id)` with content-hash deduplication

The DFS trie walker in eBPF explores both specific-value and wildcard branches at each node, so the compiler doesn't need to fully replicate wildcards — the DAG structure is preserved in the flat tree, dramatically reducing node count.

Priority resolution: when multiple paths terminate at matching nodes, the DFS collects all matches and the highest-priority (lowest numeric value) rule wins.

### Blue/Green Atomic Deployment

Rule updates are zero-downtime via double buffering:

```
TREE_NODES array (5M entries):
  ┌──────────────────────┬──────────────────────┐
  │ Slot 0: 1–2,500,000  │ Slot 1: 2,500,001+   │
  └──────────┬───────────┴──────────┬───────────┘
             │                      │
       TREE_ROOT ──────► active slot root node ID
```

**Update sequence:**
1. Sidecar collects all active `RuleSpec`s
2. Compiler builds new tree in the **inactive** slot
3. Nodes and edges written to eBPF maps
4. `TREE_ROOT` atomically updated to point to new slot's root
5. eBPF program immediately starts traversing the new tree
6. Old slot cleaned up lazily

Packets in-flight during the flip see either the old or new tree -- never a partial state.

### eBPF Tree Walker — BPF Tail-Call DFS

The eBPF walker uses a **two-program tail-call architecture** to implement a stack-based DFS that explores all matching paths through the decision tree:

```
veth_filter (XDP entry point)
  │
  ├── Parse packet, extract fields into DfsState
  ├── Sample packet (before tail call — packet data only accessible here)
  ├── Initialize DFS stack with root node
  │
  └── tail_call → tree_walk_step (index 0 in TREE_WALK_PROG)
                    │
                    ├── Pop node from stack
                    ├── Check for action (update best if higher priority)
                    ├── Look up specific-value edge → push child
                    ├── Look up wildcard child → push child
                    │
                    └── tail_call → tree_walk_step (self, loop)
                          │
                          └── ... until stack empty or 33 tail calls exhausted
                                │
                                └── apply_dfs_result()
                                      ├── Rate limit check (token bucket)
                                      ├── Update STATS counters
                                      └── Return XDP_DROP or XDP_PASS
```

**Key design decisions:**

- **Per-CPU DfsState** (`PerCpuArray<DfsState>`): Carries the 16-entry DFS stack, pre-extracted packet fields, and best-match state between tail calls. BPF programs don't migrate CPUs between tail calls, so this is safe without locks.
- **Field pre-extraction**: All 9 packet field values are extracted once in `veth_filter` and stored in `DfsState.fields[]`. The tail-called program never touches raw packet data — this avoids verifier issues with packet pointer invalidation across tail calls.
- **Sampling before tail call**: `sample_packet()` runs in `veth_filter` where packet bounds checks are established. The tail-called `tree_walk_step` operates purely on map data.
- **Field-by-field initialization**: `DfsState` fields are written individually (not via bulk array assignment) to avoid Rust generating `memset` operations that blow up the verifier's instruction count.

**Performance characteristics:**

| Metric | Value |
|--------|-------|
| Instructions per `tree_walk_step` | ~100 (2-3 map lookups) |
| Tail calls per packet (normal traffic) | ~5 |
| Tail calls per packet (attack, more wildcards) | ~7-10 |
| Maximum tail calls (kernel limit) | 33 |
| DFS stack depth | 16 entries |
| Verifier compliance | Each program independently verified |

### Idempotent Rule Insertion

Each `RuleSpec` produces a **canonical hash** from its sorted constraints, action, and rate. This hash serves as:
- The stable `rule_id` for rate-limiting state in `TREE_RATE_STATE` (persists across tree rebuilds)
- The deduplication key in the sidecar's active rule set

Inserting the same logical rule twice is a no-op.

## Components

### 1. XDP Filter (`filter-ebpf/`)

eBPF program running at the network driver level with three evaluation modes:

| Mode | Engine | Description |
|------|--------|-------------|
| 0 | Legacy | Original per-rule HashMap lookup |
| 1 | Bitmask Rete | 64-bit bitmask discrimination (deprecated, 64-rule cap) |
| 2 | **Tree Rete** | Decision tree traversal (current, 100k+ rules) |

**BPF Maps:**

```rust
// Tree Rete maps
static TREE_NODES: Array<TreeNode>              // 5M entries (2 slots × 2.5M)
static TREE_EDGES: HashMap<EdgeKey, u32>        // 5M entries
static TREE_ROOT: Array<u32>                    // Atomic pointer to active root
static TREE_RATE_STATE: HashMap<u32, TokenBucket> // 2M entries, keyed by rule hash
static TREE_DFS_STATE: PerCpuArray<DfsState>    // Per-CPU DFS scratch (stack, fields, match state)
static TREE_WALK_PROG: ProgramArray             // Tail-call target (index 0 = tree_walk_step)

// Shared maps
static STATS: PerCpuArray<u64>                  // Counters (16 slots)
static CONFIG: Array<u32>                       // Sample rate, enforce mode, eval mode
static SAMPLES: PerfEventArray<PacketSample>    // Packet samples to userspace
```

### 2. Filter Library (`filter/`)

Rust library for managing the XDP program and tree compilation:

```rust
impl VethFilter {
    fn new(interface: &str) -> Result<Self>;
    async fn compile_and_flip_tree(&self, rules: &[RuleSpec]) -> Result<()>;
    async fn clear_tree(&self) -> Result<()>;
    fn set_eval_mode(&self, mode: u32);
    async fn stats(&self) -> Result<FilterStats>;
    async fn take_perf_array(&self) -> Result<AsyncPerfEventArray>;
}

impl RuleSpec {
    fn to_sexpr(&self) -> String;        // Compact one-liner
    fn to_sexpr_pretty(&self) -> String;  // Multi-line Clara style
    fn canonical_hash(&self) -> u32;      // Stable rule ID
}
```

**Submodules:**
- `tree.rs` — Tree compiler, `ShadowNode` IR, `FlatTree` serializer, `TreeManager` (blue/green orchestrator)

### 3. Traffic Generator (`generator/`)

Generates test traffic using AF_PACKET raw sockets with distinct p0f fingerprints per attack type:

| Phase Type | Protocol | TTL | DF | TCP Flags | Window | Description |
|-----------|----------|-----|-----|-----------|--------|-------------|
| `normal` | UDP (17) | 64 | 1 | — | — | Baseline: random src IPs, port 5000 |
| `attack` | UDP (17) | **255** | **0** | — | — | UDP amplification reflector fingerprint |
| `syn_flood` | **TCP (6)** | **128** | 1 | **2 (SYN)** | **65535** | Windows botnet SYN flood fingerprint |

### 4. Holon Sidecar (`sidecar/`)

The detection engine using Holon-rs. Now drives the Tree Rete engine:

1. Samples packets from XDP via perf buffer
2. Encodes packets into hyperdimensional vectors using Holon-rs
3. Detects anomalies via accumulator drift and field concentration
4. Compiles `RuleSpec`s with vector-derived rate limits
5. Calls `compile_and_flip_tree()` to atomically deploy new rule set
6. Logs rules as pretty-printed s-expressions

**Rule Lifecycle:**
```
Anomaly Detected → RuleSpec created → Added to active set →
  Tree recompiled → Atomic flip → Rule active in eBPF
  
Rule Expired (TTL) → Removed from active set →
  Tree recompiled → Atomic flip → Rule gone from eBPF
```

## Results

### 1,000,000 Rules — BPF Tail-Call DFS (February 13, 2026)

The culmination of the scalable rule engine work: **one million pre-loaded rules** with live anomaly detection and packet drops, powered by a BPF tail-call DFS architecture.

#### The Journey

The path to 1M rules required solving several fundamental eBPF constraints:

1. **64-rule bitmask limit** (Feb 10) → Tree Rete decision tree
2. **Verifier instruction limit** (1M insn) → Unrolled macro walker, then stack-based DFS
3. **DFS loop blew verifier** → Pre-extracted fields, bounded loops
4. **Still too many instructions** → **BPF tail calls** — each DFS step is a separate ~100-insn program
5. **Verifier crash with tail calls** → Field-by-field DfsState init (no memset), sampling moved before tail call
6. **Tail calls silently failing** → `bpftool map dump` revealed empty prog_array — `take_map()` + drop closed the fd, clearing entries. Fixed by keeping `ProgramArray` alive in the struct.

#### 1M Rule Test Results

| Metric | Value |
|--------|-------|
| **Rules loaded** | 1,000,000 |
| **JSON parse time** | 677ms (149 MB file) |
| **Tree compile time** | 3.8 seconds |
| **Tree nodes** | 2,000,004 (80% of 2.5M slot capacity) |
| **Tree edges** | 2,000,000 |
| **Blue/green flip time** | ~1.6s (writing 2M nodes + 2M edges to BPF maps) |
| **Headroom** | ~500K nodes for Holon dynamic additions |
| **Tail calls per packet** | ~5 (normal), ~7-10 (attack) — **same as 50K rules** |
| **Tail call failures** | **0** |
| **Total drops** | 3,944,072 (hard:1,972,036 + rate:1,972,036) |
| **Detection latency** | First anomaly window 18, drops by window 19 |
| **Post-mitigation** | Normal by window 34 (97%+ confidence) |

#### Scaling Properties

The decision tree gets **wider** with more rules, not deeper. The 9-dimension depth is fixed. Per-packet traversal cost is bounded by the number of dimensions (~5 tail calls for normal traffic), not the number of rules. This means:

- 50K rules: ~5 tail calls/packet
- 1M rules: ~5 tail calls/packet
- Theoretical ceiling: ~5M rules before compile time and hash map cache pressure become concerns

#### Map Capacity (scaled for 1M+)

| Map | Entries | Value Size | Total Memory |
|-----|---------|-----------|-------------|
| `TREE_NODES` | 5,000,000 | 16B | ~80 MB |
| `TREE_EDGES` | 5,000,000 | 12B (+hash) | ~300 MB |
| `TREE_RATE_STATE` | 2,000,000 | 16B (+hash) | ~150 MB |
| `TREE_DFS_STATE` | 1 × nCPU | 164B | ~2 KB |
| **Total** | | | **~530 MB** |

### p0f-Level Field Detection (February 12, 2026)

The system autonomously identifies distinct attack fingerprints using p0f-level fields (TCP flags, TTL, DF bit, TCP window) and compiles rich compound rules.

#### UDP Amplification Detection

Concentrated fields: `ttl=255` (100%), `df_bit=0` (100%), `src_ip=10.0.0.100` (100%), `dst_port=9999` (100%)

```
RULE:
((and (= ttl 255)
      (= dst-port 9999)
      (= src-addr 10.0.0.100)
      (= df 0))
 =>
 (rate-limit 2091))
```

Tree: 5 nodes, 4 edges, 1 rate bucket — the reflector's TTL=255 and DF=0 fingerprint distinguishes it from normal UDP traffic (TTL=64, DF=1).

#### TCP SYN Flood Detection

Concentrated fields: `tcp_flags=2` (100%), `tcp_window=65535` (100%), `protocol=6` (100%), `ttl=128` (100%), `src_ip=10.0.0.100` (100%), `dst_port=9999` (100%)

```
RULE:
((and (= tcp-flags 2)
      (= tcp-window 65535)
      (= proto 6)
      (= src-addr 10.0.0.100)
      (= dst-port 9999)
      (= ttl 128))
 =>
 (rate-limit 2048))
```

Tree: 17 nodes, 14 edges, 2 rate buckets — both the UDP amplification rule and the SYN flood rule coexist in the same tree, with distinct rate-limiting buckets.

#### Multi-Phase Timeline (Quick Test Scenario)

```
[  0s] warmup    — normal UDP, TTL=64, DF=1 (baseline)
[ 30s] udp_amp   — ANOMALY: ttl=255, df_bit=0 → 4-constraint rule compiled
[ 45s] calm1     — NORMAL (drift=0.97)
[ 65s] syn_flood — ANOMALY: tcp_flags=2, tcp_window=65535, proto=6, ttl=128 → 6-constraint rule compiled
[ 80s] calm2     — NORMAL (drift=0.97)
[100s] udp_amp2  — ANOMALY: same reflector fingerprint → existing rule refreshed
[115s] final     — NORMAL
```

Key: the system distinguished two fundamentally different attack types without any signatures or training data — purely from vector space concentration analysis.

### Vector-Derived Rate Limiting (February 11, 2026)

A major breakthrough: **rate limiting where the allowed PPS is derived purely from vector operations**, with zero hardcoded thresholds.

#### Key Innovations

1. **Walkable Trait Integration**: `PacketSample` implements holon-rs `Walkable` trait for zero-serialization encoding
2. **Magnitude-Aware Encoding**: Packet sizes use `$log` (logarithmic) encoding where ratios matter
3. **Extended Primitives**: Full integration of Batch 014 primitives:
   - `similarity_profile()` — Per-dimension agreement/disagreement analysis
   - `segment()` — Phase change detection in traffic patterns
   - `invert()` — Pattern attribution to codebook entries
   - `analogy()` — Zero-shot attack variant detection
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
- **No hardcoded "normal" rate** — derived from baseline vector magnitude
- **No hardcoded "attack" threshold** — derived from magnitude ratio
- **Automatic scaling** — works regardless of actual traffic volume

#### Test Results

| Metric | Value |
|--------|-------|
| **Baseline PPS** | ~2000 (from scenario) |
| **Attack PPS** | ~50,000 |
| **Derived Rate Limit** | 2042 pps (vector-derived!) |
| **Total Packets** | 1.6M |
| **Dropped (rate limited)** | 1.4M (87%) |
| **Normal Traffic Blocked** | ZERO |

### Stress Test: 1.3M PPS (February 9, 2026)

An unintentional stress test occurred when a rate-limiting bug caused the generator to run at maximum speed (~1.3M PPS) instead of the intended 50K PPS. The system handled it flawlessly.

| Metric | Value |
|--------|-------|
| **Peak attack rate** | ~1.3M PPS |
| **Detection latency** | 52ms from attack start to rule insertion |
| **Drop rate during attack** | 98.3% – 99.5% |
| **Total packets processed** | 318 million |
| **Total dropped** | 316.6 million |
| **False positives after attack** | ZERO |

## Evolution

| Date | Milestone |
|------|-----------|
| Feb 7 | Initial XDP filter with per-rule HashMap lookup |
| Feb 8 | Perf buffer sampling + sidecar detection loop |
| Feb 9 | Stress test at 1.3M PPS, baseline freezing, 52ms detection |
| Feb 10 | Bitmask Rete engine (eval_mode=1), 64-rule discrimination network |
| Feb 11 | Vector-derived rate limiting, token bucket in eBPF, Walkable trait |
| Feb 12 | **Tree Rete engine** — decision tree, blue/green flip, s-expressions |
| Feb 12 | **p0f-level fields** — TCP flags, TTL, DF bit, TCP window in sampling, encoding, and rule compilation. Multi-attack-type detection (UDP amplification + TCP SYN flood) with 6-constraint compound rules |
| Feb 12 | **Extended rule language** — ranges, OR, negation, bitmask, byte-at-offset design. 50K rule stress test. DAG compiler with structural deduplication and memoization |
| Feb 13 | **BPF tail-call DFS** — stack-based trie traversal via `tree_walk_step` self-tail-call. Per-CPU `DfsState` for cross-call state. Explores all matching paths (specific + wildcard), picks highest priority |
| Feb 13 | **1,000,000 rules** — 2M nodes, 3.8s compile, ~5 tail calls/packet, 3.9M drops. Maps scaled to 5M nodes / 5M edges. Proved per-packet cost is independent of rule count |
| Feb 14 | **Range predicates** — `>`, `<`, `>=`, `<=` via guard edges with runtime evaluation. No tree expansion needed |
| Feb 14 | **MaskEq + byte matching** — `(mask-eq)`, `(protocol-match)`, `(tcp-flags-match)` for bitmask fields. `(l4-match)` for arbitrary transport-offset byte matching (1-64 bytes). Three-tiered system: MaskEq guard edges, custom dimension fan-out (1-4B), pattern guards (5-64B) |
| Feb 14 | **Per-rule metrics manifest** — All actions support `:name`. Compiler returns `RuleManifestEntry` manifest. Deterministic custom dim assignment for stable `rule_id`s. Comprehensive 9-rule integration test verified all predicates and action types |

## Future Work

### Completed
- [x] Rate limiting rules (not just DROP) — Token bucket in XDP + vector-derived rates
- [x] Rule expiry/cleanup — TTL-based expiration with refresh
- [x] Baseline training period — Configurable warmup windows/packets + baseline freezing
- [x] Combination rules (e.g., src_ip AND dst_port) — Tree Rete handles arbitrary conjunctions
- [x] Scalable rule engine (100k+ rules) — Tree Rete replaces 64-rule bitmask
- [x] Zero-downtime rule updates — Blue/green atomic flip
- [x] Human-readable rule format — S-expression (Clara-style LHS ⇒ RHS), all-numeric values
- [x] **p0f field integration** — TCP flags, TTL, DF bit, TCP window in PacketSample, Walkable encoding, concentration analysis, and rule compilation
- [x] **Multi-attack-type detection** — Distinct fingerprints for UDP amplification (TTL=255, DF=0) and TCP SYN flood (flags=2, window=65535, TTL=128)
- [x] **TCP SYN packet generation** — `craft_tcp_syn_packet` + `syn_flood` phase type in scenarios
- [x] **BPF tail-call DFS architecture** — Stack-based DFS trie traversal via self-tail-calling `tree_walk_step`, per-CPU `DfsState`, explores all matching paths
- [x] **1,000,000 rule scale** — Proven with live traffic: 2M nodes, 3.8s compile, ~5 tail calls/packet, full detection and mitigation
- [x] **DAG compiler with memoization** — Structural deduplication, content-hash sharing, `Rc<ShadowNode>` for memory efficiency
- [x] **Extended rule language design** — Ranges, OR, negation, bitmask, byte-at-offset (extensibility proven, implementation deferred)
- [x] **Range predicates** — `>`, `<`, `>=`, `<=` via guard edges with `RANGE_OP_GT/LT/GTE/LTE` constants
- [x] **MaskEq predicates** — `(mask-eq field mask expected)` with `(value & mask) == expected` semantics. Guard edge `RANGE_OP_MASK_EQ = 5`
- [x] **Protocol/TCP-flags match** — `(protocol-match)`, `(tcp-flags-match)` sugar forms for MaskEq
- [x] **L4 byte matching** — `(l4-match offset "hex-match" "hex-mask")` for 1-64 byte patterns at transport-relative offsets. Custom dimensions (1-4B), pattern guards (5-64B)
- [x] **Per-rule drop/pass metrics** — DROP and PASS actions increment `TREE_COUNTERS` for per-rule attribution in logs
- [x] **Rule manifest** — Compiler returns `RuleManifestEntry` for authoritative action-type and label mapping
- [x] **Named actions on all types** — `:name ["ns" "metric"]` supported on pass, drop, rate-limit, and count

### Short Term
- [ ] Make rule TTL configurable via CLI
- [ ] Expose extended primitives via CLI flags

### Medium Term
- [ ] Integrate with real network interfaces (not just veth)
- [ ] Add AF_XDP for zero-copy packet processing
- [ ] Adaptive thresholds based on traffic patterns
- [ ] Add metrics/Prometheus export
- [ ] Tree compaction / garbage collection for long-running deployments

### Long Term
- [ ] Distributed detection across multiple nodes
- [ ] Hardware offload investigation (SmartNIC integration)
- [ ] Support for more protocols (ICMP, DNS amplification, etc.)
- [ ] Integration with existing DDoS mitigation platforms

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

## References

- [Holon Project](https://github.com/watmin/holon) — VSA/HDC implementation
- [Aya](https://aya-rs.dev/) — Rust eBPF toolkit
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial) — XDP programming guide
- [Batch 013 Challenges](../../../scripts/challenges/013-batch/) — Python prototypes of rate limiting detection
- [Batch 014 Challenges](../../../scripts/challenges/014-batch/) — Extended primitives for explainable VSA
