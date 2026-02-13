# Architecture Decision Records

**Every major decision in this system had alternatives we considered and rejected. This document captures the reasoning so future-us understands not just what we built, but why.**

---

## ADR-001: Tree Discrimination vs Linear Rule Scan

**Date:** February 12, 2026  
**Status:** Accepted

### Context

The previous system (DPDK-based) iterated a flat rule array, scoped per destination prefix. It supported ~10K rules per prefix list. The user wanted 100K–1M rules without prefix scoping.

### Options

| Option | Per-Packet Cost | Rule Capacity | Compound Rules |
|---|---|---|---|
| **A. Linear scan** | O(n) | Unlimited | Yes |
| **B. Hash dispatch (bitmask)** | O(fields) | 64 rules | Yes |
| **C. Decision tree** | O(depth) | Unlimited | Yes |
| **D. Bloom filter pre-screen** | O(1) + O(n) worst | Unlimited | Limited |

### Decision

**Option C: Decision tree (Tree Rete).** The per-packet cost is bounded by tree depth (9 dimensions), not rule count. A packet touching 1M rules does the same ~5 lookups as one touching 50 rules.

### Rationale

- Linear scan was what the user had before and explicitly wanted to replace
- Bitmask Rete proved the shared-evaluation principle works in eBPF but caps at 64 rules
- Bloom filters give fast rejection but don't help with compound rules or priority resolution
- Tree depth is fixed by dimension count (9), not rule count — this is the key scaling property

### Consequences

- Compiler complexity increases (tree construction, DAG deduplication)
- Blue/green deployment needed for atomic updates (can't modify tree in-place)
- Wildcard rules require either replication or multi-path traversal

---

## ADR-002: BPF Tail Calls vs Loop Unrolling

**Date:** February 13, 2026  
**Status:** Accepted (replaced single-program DFS)

### Context

The stack-based DFS required a loop inside eBPF. The BPF verifier's path exploration is exponential in the number of iterations × branches per iteration. Every approach to a single-program DFS hit the 1M instruction verification limit.

### Options

| Option | Verifier | Max Iterations | Complexity |
|---|---|---|---|
| **A. Macro unrolling (9 levels)** | Passes | 9 | Single-path only, no wildcards |
| **B. Bounded `for` loop (20 iters)** | Fails at 1M insns | 20 | Multi-path, correct |
| **C. BPF tail calls** | Each program trivial | 33 | Multi-path, modular |
| **D. BPF-to-BPF function calls** | Shared verification | Limited | Still hits instruction limit |

### Decision

**Option C: BPF tail calls.** Each DFS step is an independent XDP program that tail-calls itself. The verifier sees ~100 instructions per program. The kernel enforces a 33-call limit.

### Rationale

- Tail calls make the verifier problem trivial — each program is verified independently
- 33 tail calls × 1 DFS step per call = 33 DFS steps, far more than needed for 9 dimensions
- Per-CPU state (`DfsState` in `PerCpuArray`) is safe because BPF programs don't migrate CPUs between tail calls
- The architecture is modular — `veth_filter` handles parsing/sampling, `tree_walk_step` handles traversal, separation is clean

### Consequences

- State must be passed via per-CPU map (not stack or registers)
- Packet data is only accessible in the entry program (bounds don't carry across tail calls)
- `ProgramArray` fd must remain open for the program lifetime (the `bpftool` lesson)
- Slightly higher per-step overhead (map read/write for DfsState) vs register-only

### What We Tried First

1. Macro unrolling (9 levels) — worked but couldn't handle wildcards or multi-path
2. Bounded `for` loop (20 iterations) — correct algorithm, verifier rejected it
3. Reduced loop (10 iterations) with pre-extracted fields — still too many instructions
4. Multi-cursor approach (2–3 cursors in lockstep) — verifier path explosion worse than the loop

---

## ADR-003: DAG Compiler vs Full Wildcard Replication

**Date:** February 12–13, 2026  
**Status:** Accepted

### Context

When a rule doesn't constrain a dimension (e.g., "match any protocol"), the single-path walker required that rule to be replicated into every possible value's subtree at that dimension. For 50K rules with wildcards, this caused node count explosion and OOM.

### Options

| Option | Node Count | Memory | Compiler Complexity |
|---|---|---|---|
| **A. Full replication** | O(rules × values^wildcards) | Explosion | Simple |
| **B. DAG with Rc sharing** | O(rules × dims) | Bounded | Moderate |
| **C. DAG + multi-path walker** | O(unique subtrees) | Minimal | Walker must handle wildcards |

### Decision

**Option C: DAG compiler with multi-path DFS walker.** The compiler builds a pure DAG with `Rc<ShadowNode>` sharing and content-hash deduplication. The eBPF walker explores both specific-value and wildcard branches at each node.

### Rationale

- Full replication OOM'd at 50K rules. 1M rules would be impossible
- DAG-only (option B) still required single-path walker to follow replicated paths
- Multi-path DFS naturally handles wildcards — no replication needed at all
- Memoization cache keyed by `(rule_set_hash, dimension)` ensures identical subtrees are built once
- 50K rules → 100K nodes (2:1 ratio). 1M rules → 2M nodes (same ratio). Linear scaling.

### Consequences

- The walker is more complex (DFS stack, wildcard exploration)
- This is what pushed us to tail calls (the DFS loop was too complex for single-program verification)
- Content-hash deduplication during flattening ensures no duplicate nodes in the BPF maps
- The tree structure is a true DAG — multiple parents can share the same child subtree

---

## ADR-004: Blue/Green Deployment vs In-Place Update

**Date:** February 12, 2026  
**Status:** Accepted

### Context

Rule updates happen every ~2 seconds when anomalies are detected. The tree has 2M nodes and 2M edges. Updating in-place risks packets seeing a partially updated tree.

### Options

| Option | Downtime | Consistency | Memory |
|---|---|---|---|
| **A. In-place update** | None | Inconsistent during update | 1x |
| **B. Blue/green (double buffer)** | Zero | Always consistent | 2x |
| **C. RCU-style** | Zero | Consistent | 1x + GC complexity |
| **D. Map-in-map** | Zero | Consistent | Complex setup |

### Decision

**Option B: Blue/green double buffering.** The `TREE_NODES` array is split into two slots (2.5M each). The compiler writes the new tree to the inactive slot while the active slot continues serving packets. `TREE_ROOT` is atomically updated to point to the new slot's root.

### Rationale

- Simplest correctness model — a packet sees either the old tree or the new tree, never a mix
- Memory overhead is acceptable (2x nodes, but BPF maps are pre-allocated anyway)
- `TREE_ROOT` update is a single atomic u32 write — the cheapest possible flip
- Old slot cleanup is lazy (edges from previous tree cleaned before next write)
- RCU would be more memory-efficient but adds garbage collection complexity in eBPF

### Consequences

- `TREE_SLOT_SIZE` must be large enough for the largest tree (currently 2.5M per slot)
- Rate-limiting state (`TREE_RATE_STATE`) is keyed by rule canonical hash, independent of slot — persists across flips
- Edge cleanup between flips adds ~100ms to compile time (tracking and deleting old edges)

---

## ADR-005: Per-CPU DfsState vs Stack Variables

**Date:** February 13, 2026  
**Status:** Accepted

### Context

BPF tail calls replace the current program entirely — no shared stack, no shared registers. State must be explicitly passed between tail-called programs.

### Options

| Option | Access Cost | Size Limit | Safety |
|---|---|---|---|
| **A. Per-CPU array** | 1 map lookup | Map value limit (~32KB) | CPU-local, no locks |
| **B. Per-CPU hash** | 1 hash lookup | Same | Slightly slower |
| **C. Packet metadata (XDP)** | Direct access | ~256 bytes | Too small |
| **D. Map-in-map** | 2 lookups | Flexible | Over-engineered |

### Decision

**Option A: `PerCpuArray<DfsState>` with 1 entry.** Single map read/write per tail call. ~164 bytes per CPU.

### Rationale

- `PerCpuArray` with index 0 is the cheapest possible map access
- 164 bytes is well within limits (16-entry stack + 9 fields + match state + metadata)
- BPF programs don't migrate CPUs between tail calls (kernel guarantee), so per-CPU state is race-free without locks
- No hash computation overhead (unlike HashMap)

### Consequences

- Must initialize DfsState field-by-field in `veth_filter` (memset causes verifier issues)
- DfsState struct layout matters — padding must be explicit for eBPF alignment
- One entry per CPU means one concurrent DFS per CPU — but XDP is already per-CPU

---

## ADR-006: Vector Magnitude for Rate Derivation vs Hardcoded Thresholds

**Date:** February 11, 2026  
**Status:** Accepted

### Context

Rate limiting requires knowing "how many packets per second should be allowed." Traditional systems use hardcoded values or operator-configured thresholds.

### Options

| Option | Requires Configuration | Adapts to Traffic | Accuracy |
|---|---|---|---|
| **A. Hardcoded PPS** | Yes | No | Static |
| **B. Percentile-based** | Threshold config | Partially | Depends on window |
| **C. Vector magnitude ratio** | None | Yes | Emergent from algebra |
| **D. ML regression** | Training data | After training | Model-dependent |

### Decision

**Option C: Vector magnitude ratio.** The rate limit is `estimated_pps / magnitude_ratio` where `magnitude_ratio = ||recent_window|| / ||baseline_per_window||`.

### Rationale

- Zero configuration — the rate emerges from the relationship between two vector magnitudes
- Automatically scales with traffic volume — 10x attack → 10x magnitude → 1/10 rate factor
- The allowed rate converges to approximately the baseline PPS without ever measuring or storing baseline PPS
- Works from the first detection window — no training period beyond the baseline warmup
- Grounded in VSA theory: accumulator magnitude correlates with observation count

### Consequences

- The rate limit is approximate (magnitude correlation isn't perfect for correlated traffic)
- Flooring at 100 PPS prevents over-aggressive limiting
- The magnitude ratio is computed from the raw float accumulator, not the normalized bipolar vector

---

## ADR-007: S-Expressions vs JSON vs DSL

**Date:** February 12, 2026  
**Status:** Accepted

### Context

Rules need a human-readable representation for logging, debugging, and eventual external API.

### Options

| Option | Readability | Parsability | Inspiration |
|---|---|---|---|
| **A. JSON** | Verbose | Easy | Industry standard |
| **B. Custom DSL** | Variable | Custom parser needed | Flexible |
| **C. S-expressions (Clara-style)** | Excellent | Trivial (s-expr parser) | Clara/Clojure Rete |
| **D. YAML** | Good | Library needed | DevOps-friendly |

### Decision

**Option C: S-expressions** in Clara's LHS ⇒ RHS style:

```
((and (= proto 17)
      (= src-port 53))
 =>
 (rate-limit 1234))
```

### Rationale

- Clara is the spiritual ancestor — s-expressions make the Rete connection explicit
- Compact but readable — one rule is one expression
- All values are raw numbers (same as wireshark/eBPF sees): `proto 17` not `proto tcp`
- Pretty-print and compact forms are trivial to generate
- Nested structure naturally represents compound rules
- The user specifically requested Clara-style syntax

### Consequences

- Field names are kebab-case (`src-addr`, `dst-port`, `tcp-flags`) for readability
- IPs are dotted notation despite being stored as u32 internally
- No parser needed yet (rules are generated, not user-authored) but the format is parseable

---

## ADR-008: Bipolar Vectors (+1/-1) vs Binary (0/1)

**Date:** February 11, 2026  
**Status:** Accepted (inherited from Holon-rs design)

### Context

VSA/HDC implementations use either bipolar ({+1, -1}) or binary ({0, 1}) vector elements.

### Decision

**Bipolar (+1, -1, 0) using i8 storage.** The zero value represents "don't know" / "not active."

### Rationale

- Bipolar arithmetic: XOR binding is element-wise multiply, bundling is element-wise sum + sign
- Cosine similarity is a natural similarity measure on bipolar vectors
- The three-valued system (+1, -1, 0) captures "agrees," "disagrees," and "no information" — useful for sparse encodings where not every dimension is activated
- i8 storage (1 byte per dimension) is cache-friendly: 4096 dimensions = 4KB per vector
- Bundling via accumulation (f64) → normalization to bipolar preserves the "majority vote" property

---

## ADR-009: 9 Fixed Dimensions vs Dynamic Dimension Set

**Date:** February 12, 2026  
**Status:** Accepted

### Context

The tree traversal order must be known at compile time (both userspace and eBPF). Which packet fields become tree dimensions, and in what order?

### Decision

**9 fixed dimensions in protocol-semantic order:**

```
Proto → SrcIp → DstIp → L4Word0 (src-port) → L4Word1 (dst-port) →
  TcpFlags → Ttl → DfBit → TcpWindow
```

### Rationale

- Proto first provides the strongest initial discrimination (TCP vs UDP vs ICMP are fundamentally different traffic)
- IP addresses next for source/destination scoping
- L4 ports for service identification
- TCP-specific fields last (only meaningful when proto=6) — contextual binding
- Fixed order means eBPF field extraction is a static array index, not a branch
- The compiler skips dimensions that no rule in the current subtree constrains, so unused dimensions cost nothing
- Extensible: adding a new dimension is a new enum variant, a new extraction in eBPF, and a new field in the s-expression language

### What We Rejected

- **Dynamic ordering based on cardinality** — would require the eBPF program to know the ordering at runtime, adding branches
- **TCP flags first** — the user explicitly rejected this: "checking TCP flags up front is undesirable... indexing on proto is good, contextually binding TCP flags if and only if proto is 6"
- **Data-driven ordering** — the demo traffic was TCP-heavy but the user noted "just because our demo pool of packets is TCP heavy doesn't mean it's a good data ref for the real world"

---

## ADR-010: Pre-Extract Fields vs Lazy Extraction

**Date:** February 13, 2026  
**Status:** Accepted

### Context

The DFS loop needs to read the packet's value for whatever dimension the current tree node branches on. This could be done lazily (extract on demand) or eagerly (extract all up front).

### Decision

**Eager pre-extraction.** All 9 field values are extracted once in `veth_filter` and stored in `DfsState.fields[]`.

### Rationale

- Eliminates a 9-way branch inside the DFS loop (the verifier's worst enemy)
- Field access in `tree_walk_step` is `fields[node.dimension & 0xF]` — one bounded array index
- Packet data is only accessible in `veth_filter` (bounds don't carry across tail calls) so lazy extraction is impossible with tail calls anyway
- 9 × 4 bytes = 36 bytes of storage — trivial
- The extraction function compiles to straight-line code in `veth_filter` where instruction budget is ample

### Consequences

- Fields for irrelevant protocols are extracted but unused (e.g., TCP window extracted for UDP packets, set to 0)
- This is fine — the tree simply has no edges for those values, so they're never looked up

---

## Decision Map

```
Linear scan (rejected: O(n))
  └─► Bitmask Rete (proved principle, capped at 64)
       └─► Tree Rete
            ├── Single-path walker (no wildcards in eBPF)
            │    └─► Full replication (OOM)
            │         └─► DAG compiler (memory solved)
            │              └─► Multi-cursor walker (verifier explosion)
            │                   └─► Stack-based DFS (verifier explosion)
            │                        └─► BPF tail calls ✓
            ├── Rate derivation
            │    └─► Hardcoded (rejected: requires config)
            │         └─► Magnitude ratio ✓ (zero config)
            ├── Update strategy
            │    └─► In-place (inconsistent)
            │         └─► Blue/green ✓ (atomic flip)
            └── Rule syntax
                 └─► JSON (verbose)
                      └─► S-expressions ✓ (Clara heritage)
```
