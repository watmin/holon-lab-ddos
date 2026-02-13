# Scaling Analysis: From 50K to 1M Rules and Beyond

**Measured data from live runs proving that per-packet cost is independent of rule count, with analysis of where the actual ceilings are.**

## Measured Results

### Compile-Time Scaling

| Rules | Parse (JSON) | Compile (DAG) | Nodes | Edges | Flip (BPF maps) | Total |
|---|---|---|---|---|---|---|
| 10,000 | ~30ms | ~40ms | ~20K | ~20K | ~30ms | ~100ms |
| 50,000 | ~36ms | ~90ms | 100,004 | 100,000 | ~70ms | ~200ms |
| 1,000,000 | 677ms | 2,867ms | 2,000,004 | 2,000,000 | ~1,600ms | ~5,100ms |

**Observations:**
- Parse time scales linearly with file size (149 MB for 1M rules)
- Compile time scales approximately linearly (0.04ms/rule at 50K, 0.003ms/rule at 1M — better at scale due to DAG sharing)
- Node count is consistently ~2x rule count (each rule adds ~2 nodes on average)
- Flip time scales linearly with node+edge count (writing to BPF maps via syscall)

### Per-Packet Cost (The Key Metric)

| Rules | Tail Calls / Packet (normal) | Tail Calls / Packet (attack) | tc_fail |
|---|---|---|---|
| 50,000 | ~5 | ~7–10 | 0 |
| 1,000,000 | ~5 | ~7–10 | 0 |

**Per-packet cost is identical at 50K and 1M rules.** The tree gets wider, not deeper. The 9-dimension depth is fixed. Normal traffic follows one specific-value path through the tree (~5 tail calls for ~5 active dimensions). Attack traffic may explore additional wildcard branches (~7–10 tail calls).

### Slot Utilization

| Rules | Nodes | Slot Capacity | Utilization | Headroom |
|---|---|---|---|---|
| 50,000 | 100,004 | 2,500,000 | 4.0% | ~2,400,000 |
| 1,000,000 | 2,000,004 | 2,500,000 | 80.0% | ~500,000 |

At 1M rules, 80% slot utilization leaves ~500K nodes for Holon-generated dynamic rules.

### Detection Performance

| Rules | Detection Latency | First Drops | Post-Mitigation Normal |
|---|---|---|---|
| 50,000 | Window 17 (~4s after attack) | Window 18 | Window 34 (~30s) |
| 1,000,000 | Window 18 (~4s after attack) | Window 19 | Window 34 (~30s) |

Detection latency is unchanged by rule count — the detection loop runs at the same cadence regardless of how many pre-loaded rules exist. The extra ~1s at 1M rules is from the longer tree recompile (3.8s vs 0.1s).

### Total Drops

| Rules | Total Drops | Hard Drops | Rate-Limited Drops |
|---|---|---|---|
| 50,000 | 4,299,076 | 2,149,538 | 2,149,538 |
| 1,000,000 | 3,944,072 | 1,972,036 | 1,972,036 |

Comparable drop counts — the difference is within noise of different attack traffic volumes.

## Memory Scaling

### BPF Map Memory (Kernel)

| Map | Type | Entry Size | Max Entries | Total Memory |
|---|---|---|---|---|
| `TREE_NODES` | Array | 16B | 5,000,000 | 80 MB |
| `TREE_EDGES` | HashMap | 12B key+val (+~50B overhead) | 5,000,000 | ~310 MB |
| `TREE_RATE_STATE` | HashMap | 20B key+val (+~50B overhead) | 2,000,000 | ~140 MB |
| `TREE_DFS_STATE` | PerCpuArray | 164B × nCPU | 1 | ~2 KB |
| `TREE_WALK_PROG` | ProgramArray | 8B | 1 | ~272B |
| Legacy maps | Various | Various | Various | ~50 MB |
| **Total** | | | | **~580 MB** |

BPF HashMap memory is pre-allocated at map creation. The 580 MB is reserved when the XDP program loads, regardless of how many entries are actually used.

### Userspace Memory (Sidecar)

| Component | At 50K Rules | At 1M Rules |
|---|---|---|
| Rule specs in memory | ~10 MB | ~200 MB |
| JSON parsing peak | ~15 MB | ~300 MB |
| DAG compilation peak | ~50 MB | ~800 MB |
| Holon vectors (4096 dims × i8) | ~4 KB | ~4 KB |
| Accumulators (4096 dims × f64) | ~32 KB | ~32 KB |
| **Peak RSS** | ~100 MB | ~1.5 GB |

The DAG compiler is the peak memory consumer. Memoization (`HashMap<CacheKey, Rc<ShadowNode>>`) caches intermediate results. At 1M rules, this cache grows large but is bounded by the number of unique `(rule_set, dimension)` pairs.

On a system with 54 GB RAM, this is comfortable.

## Scaling Projections

### Node Count vs Rule Count

The relationship is approximately `nodes ≈ 2 × rules` for rules with 3 constraints each (proto + src_ip + dst_port). Rules with more or fewer constraints will shift this ratio:

| Rule Structure | Constraints | Nodes/Rule | 1M Rules → Nodes |
|---|---|---|---|
| Simple (proto + src_ip) | 2 | ~1.5 | ~1.5M |
| Typical (proto + src_ip + dst_port) | 3 | ~2.0 | ~2.0M |
| Rich (proto + src_ip + dst_port + ttl + df) | 5 | ~2.5 | ~2.5M |
| Full (all 9 dimensions) | 9 | ~3.0 | ~3.0M |

DAG sharing reduces node count when rules share common prefix paths. The more rules share values at early dimensions (like proto), the better the sharing ratio.

### Capacity by Slot Size

| TREE_SLOT_SIZE | Max Rules (typical) | TREE_NODES Max | Memory |
|---|---|---|---|
| 500,000 | ~250K | 1,000,000 | ~16 MB |
| 2,500,000 | **~1.25M** | 5,000,000 | **~80 MB** |
| 5,000,000 | ~2.5M | 10,000,000 | ~160 MB |
| 10,000,000 | ~5M | 20,000,000 | ~320 MB |

Edge map must scale proportionally. At 5M rules, `TREE_EDGES` would need ~10M entries (~620 MB).

### Compile Time Projection

Compile time scales approximately linearly with rule count (with good memoization):

| Rules | Estimated Compile | Estimated Flip | Total |
|---|---|---|---|
| 100,000 | ~0.3s | ~0.2s | ~0.5s |
| 500,000 | ~1.5s | ~0.8s | ~2.3s |
| 1,000,000 | ~2.9s | ~1.6s | ~4.5s |
| 2,000,000 | ~6s | ~3s | ~9s |
| 5,000,000 | ~15s | ~8s | ~23s |

At 5M rules, a ~23-second compile is acceptable for rule updates that happen at detection cadence (~2s windows). The blue/green architecture means packets continue using the old tree during compilation.

## Bottleneck Analysis

### What's NOT the Bottleneck

**Per-packet evaluation.** The DFS tail-call cost is O(tree_depth), not O(rule_count). With 9 dimensions, the maximum path length is 9 steps. In practice, ~5 tail calls per packet. This doesn't change with more rules.

**Map lookup latency.** BPF HashMap lookups are O(1) average. At 5M entries, the hash table is ~310 MB — too large for L3 cache on most systems, but individual lookups only touch one bucket chain (one or two cache lines).

### What IS the Bottleneck (at Scale)

**1. Compile time (>5M rules)**

The DAG compiler's memoization cache grows with the number of unique `(rule_set, dimension)` pairs. At very large rule counts, the cache itself becomes a bottleneck — both in memory and in hash lookup time. Mitigations:
- Streaming compilation (process rules in batches)
- Incremental tree updates (modify only the changed subtree)
- Parallel compilation (partition rules by first dimension)

**2. Map write time during flip (>5M rules)**

Writing 5M nodes and 5M edges via `bpf_map_update_elem` syscalls takes ~8 seconds. Each syscall has kernel overhead. Mitigations:
- Batch map updates (`BPF_MAP_UPDATE_BATCH` syscall)
- Pre-serialize to mmap'd region and swap
- Reduce writes by only updating changed entries (incremental flip)

**3. Edge HashMap cache pressure (>5M entries)**

At 5M+ entries, the `TREE_EDGES` HashMap spans hundreds of MB. Random lookups (different packets hit different edges) cause cache misses. On a system with 32MB L3 cache, effective lookup time increases from ~50ns to ~200ns per cache miss. With 5 lookups per packet, this adds ~1μs per packet.

At 10Gbps with 64-byte packets (~15M PPS), the edge lookup budget is ~67ns per packet. Five lookups at 200ns each = 1μs = too slow. Mitigations:
- Array-based edge storage (contiguous memory, better prefetching)
- Reduce edge count via denser node encoding
- Partition hot edges (frequently accessed) into a smaller fast-path map

**4. DFS tail call budget for pathological rule sets**

The 33-call kernel limit means at most 32 DFS steps per packet. For well-structured rule sets (rules share prefixes, wildcards are sparse), this is ample — typical traffic uses ~5 steps. But pathological cases exist:

```
Rule 1: (= proto 6)                      ← wildcard on everything else
Rule 2: (= proto 17)                     ← wildcard on everything else
Rule 3: (= src-port 53)                  ← wildcard on proto (!) and everything else
```

Rule 3 has wildcards at the proto dimension, which means the DFS must explore both the proto=6 subtree and the proto=17 subtree (and any other proto subtrees). If wildcards appear at multiple dimensions, exploration branches multiply.

Worst case: a rule with wildcards at every dimension is `(match anything) → action`. The DFS would need to explore every root-to-leaf path. With 9 dimensions and multiple values per dimension, this could exceed 33 steps.

Mitigation: rules with many wildcards should have high priority so the DFS can prune early (once a high-priority match is found, lower-priority paths can be skipped — a future optimization).

## Theoretical Ceiling

| Factor | Limit | At Limit |
|---|---|---|
| TREE_SLOT_SIZE | ~10M nodes/slot | ~5M rules |
| TREE_EDGES max_entries | ~20M entries | ~10M rules |
| Kernel BPF map memory | System RAM dependent | ~50M rules at 54GB |
| Compile time | ~30s acceptable | ~7M rules |
| Edge lookup cache pressure | ~10Gbps line rate | ~5M rules |
| Tail call budget | 33 per packet | Depends on wildcard density |

**Practical ceiling: ~5M rules** before cache pressure affects line-rate performance.

**Theoretical ceiling: ~10M rules** with batch map updates and incremental compilation.

Beyond 10M rules, the architecture would benefit from partitioning (per-prefix subtrees with separate prog_array entries) or hardware offload (SmartNIC with larger memory hierarchy).

## The Remarkable Property

The system scales on two independent axes:

```
Rule count:  compile-time cost (seconds, amortized)
Packet rate: per-packet cost (tail calls, constant)
```

Adding rules costs compiler time. Adding packets costs tail calls. The two don't interact. A million rules and a million packets per second cost the same per-packet work as ten rules and a million packets per second.

This is the fundamental property of a discrimination network: the structure absorbs the complexity at build time so that evaluation time depends only on the query (packet), not the knowledge base (rules).
