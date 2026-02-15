# System Capacity & Limits

**Ground truth document for the byte matching and tree Rete engine.**

**Last verified:** 2026-02-14, with live 10-tenant test (750K packets, all tenants matched including offsets 108 and 208).

---

## Current Architecture

The system processes packets in XDP (earliest possible hook in the Linux network stack) using a tree-based Rete discrimination network. Rules are compiled into a flat tree stored in BPF maps, walked via tail-call DFS. Each packet is classified against all active rules in a single pass.

### Three-Tier Byte Matching

1. **Custom Dimensions (O(1) fan-out):** 1-4 byte matches at any packet offset. Read directly from the XDP packet context. Assigned at compile time to the 7 most frequently used `(offset, length)` combos. HashMap edge lookup — O(1) per dimension.

2. **PatternGuard (linear scan):** 5-64 byte matches at L4 offsets 0-63. Pre-copied into a 64-byte `pattern_data` buffer. Byte-by-byte masked comparison. Also handles overflow 1-4 byte matches when more than 7 unique offsets exist.

3. **Tree edges (structural):** All standard packet fields (proto, src/dst IP, ports, TCP flags, TTL, DF, TCP window) are tree dimensions with HashMap fan-out. Rules sharing common constraints share tree subtrees via Rc.

---

## Hard Limits (Current Configuration)

| Resource | Capacity | Per-Entry Size | Total Memory | Governed By |
|---|---|---|---|---|
| Tree nodes | 2,500,000 per slot (5M total) | 36 bytes | ~172 MB | `TREE_NODES` array |
| Tree edges | 5,000,000 (shared) | 12 bytes | ~143 MB | `TREE_EDGES` HashMap |
| Tree counters | 100,000 | 12 bytes | ~3 MB | `TREE_COUNTERS` HashMap |
| Rate limiter buckets | 2,000,000 | 28 bytes | ~134 MB | `TREE_RATE_STATE` HashMap |
| Byte patterns | 65,536 | 132 bytes | ~8.5 MB | `BYTE_PATTERNS` array |
| Custom dim slots | 7 | 4 bytes config | negligible | `CUSTOM_DIM_CONFIG` array |
| DFS state | 1 per CPU | 232 bytes | ~3 KB | `TREE_DFS_STATE` PerCpuArray |
| **Total BPF map memory** | | | **~460 MB** | |

### Per-Packet Fixed Cost

| Operation | Cost | Notes |
|---|---|---|
| Field extraction (9 dims) | ~free | Single pass over IP/L4 headers |
| Custom dim extraction (7 slots) | ~free | 7 direct packet reads, bounded offset |
| pattern_data memcpy | ~free | 64 bytes from transport header |
| DFS state init | ~free | Field-by-field writes (no memset) |

### Per-Packet Variable Cost (Scoped by Tree Walk)

| Operation | Cost | When |
|---|---|---|
| HashMap edge lookup | O(1) | Per dimension in visited subtree |
| Range edge comparison | O(1) | Up to 2 per node in visited path |
| PatternGuard comparison | O(64 bytes) | Per guard edge in visited subtree |
| Tail calls | O(depth) | ~5-16 per packet depending on tree depth |

---

## Tenant Capacity Analysis

### What Is a "Tenant"?

A tenant is a logical scope, typically a destination address. Each tenant has rules that only apply to their traffic. The tree naturally isolates tenants — a packet to tenant X only traverses X's subtree. Other tenants' rules are never evaluated.

### Binding Constraints

For a typical tenant with 1 destination address and 1 byte-match rule:

| Resource | Usage per Tenant | Capacity | Max Tenants |
|---|---|---|---|
| Tree nodes | ~3 (with subtree sharing) | 2,500,000 | ~833,000 |
| Tree edges | ~3 | 2,500,000 | ~833,000 |
| Counters | 1 per rule | 100,000 | **100,000** |
| Byte patterns | 0-1 (only for PatternGuard) | 65,536 | 65,536 |

**Binding constraint: TREE_COUNTERS at 100,000 rules.** This is the practical ceiling for total rules across all tenants. Increasing it is a one-line constant change.

### Scaling Scenarios

**Scenario A: 100K tenants, each with 1 simple rule (same offset)**
```
Custom dims:    1 slot used (all tenants share the same offset)
Tree nodes:     ~300K (shared proto, per-tenant dst-addr + leaf)
Tree edges:     ~300K
Counters:       100K (1 per rule — at the limit)
Byte patterns:  0 (all matches via custom dim fan-out)
Verdict:        FITS. Increase TREE_COUNTERS for headroom.
```

**Scenario B: 10K tenants, each with 10 rules at different offsets**
```
Custom dims:    7 slots (top 7 offsets by frequency)
Tree nodes:     ~200K (heavy subtree sharing)
Tree edges:     ~300K
Counters:       100K (10K tenants × 10 rules — at the limit)
Byte patterns:  depends on overflow (if >7 unique offsets, overflow rules here)
Verdict:        FITS. Counter map is the constraint.
```

**Scenario C: 1K tenants, each with 100 byte-match rules**
```
Custom dims:    7 slots
Tree nodes:     ~500K
Tree edges:     ~500K
Counters:       100K (at the limit)
Byte patterns:  up to ~93K overflow rules (well within 65K? NO — might exceed)
Verdict:        TIGHT. May need to increase BYTE_PATTERNS and TREE_COUNTERS.
```

**Scenario D: 500 tenants, each with different deep offsets (1-4 bytes)**
```
Custom dims:    7 slots (top 7 offsets by frequency, O(1))
Tree nodes:     ~2K
Tree edges:     ~2K
Counters:       500
Byte patterns:  493 (500 - 7 custom dims = 493 PatternGuard entries)
Verdict:        TRIVIAL. System is barely loaded.
```

---

## Offset Capabilities

### Custom Dimensions (1-4 byte matches)

| Property | Value |
|---|---|
| Offset range | 0 to packet length (MTU-dependent: 1500 Ethernet, 9000 jumbo) |
| Match length | 1, 2, or 4 bytes |
| Match type | Exact (`Eq`) or masked (`MaskEq`) |
| Fan-out | O(1) via HashMap — unlimited rules per offset |
| Slots | 7 (frequency-based allocation) |
| Deep offset support | **Yes — verified at offsets 108 and 208** |

### PatternGuard (5-64 byte matches)

| Property | Value |
|---|---|
| Offset range | 0 to 63 (limited by `pattern_data` buffer) |
| Match length | 1 to 64 bytes |
| Match type | Masked byte-by-byte comparison |
| Entries | 65,536 |
| Deep offset support | No (would need larger `pattern_data` buffer) |

### Standard Dimensions (always extracted)

| Dimension | Index | Fan-out |
|---|---|---|
| Protocol | 0 | O(1) HashMap |
| Source IP | 1 | O(1) HashMap |
| Destination IP | 2 | O(1) HashMap |
| Source Port (L4 word 0) | 3 | O(1) HashMap |
| Destination Port (L4 word 1) | 4 | O(1) HashMap |
| TCP Flags | 5 | O(1) HashMap |
| TTL | 6 | O(1) HashMap |
| DF Bit | 7 | O(1) HashMap |
| TCP Window | 8 | O(1) HashMap |

---

## What Would It Take to Scale Further

### One-Line Changes (constant only, rebuild and deploy)

| Limit | Current | Could Set To | Memory Impact | Risk |
|---|---|---|---|---|
| TREE_COUNTERS | 100K | 1M | +24 MB | None |
| BYTE_PATTERNS | 65K | 1M | +124 MB | None |
| TREE_NODES | 5M | 20M | +540 MB | None |
| TREE_EDGES | 5M | 20M | +860 MB | None |
| TREE_RATE_STATE | 2M | 10M | +535 MB | None |

Total for maximum configuration: ~2.5 GB of BPF map memory. Comfortable on any scrubbing appliance.

### Small Refactors (bounded engineering, no architectural changes)

| Limit | Current | Target | Work Required |
|---|---|---|---|
| Custom dim slots | 7 | 16 | Enlarge `DfsState.fields` to `[u32; 32]`, extend `FieldDim` enum, add extraction calls. ~half day. |
| PatternGuard offset | 0-63 | 0-255 | Change `MAX_PATTERN_LEN` to 256, accept 4x memcpy cost per packet. Verifier may need loop unrolling. ~1 day. |
| Range edges per node | 2 | 4+ | Enlarge `TreeNode` struct, update DFS walker. ~half day. |
| DFS stack depth | 16 | 32 | Enlarge `DfsState.stack`, accept larger per-CPU map entry. ~trivial. |

### Not Needed (architecture already handles it)

| Concern | Why It's Already Solved |
|---|---|
| Tenant isolation | Tree structure naturally scopes by dst-addr — no cross-tenant evaluation |
| Compilation speed | Subtree sharing via Rc prevents O(N^2) node explosion |
| Hot-path efficiency | Blue/green double buffering — zero-downtime rule updates |
| Counter attribution | Manifest-based reporting — stable `rule_id`s survive recompilation |
| Dynamic rule generation | Compiler accepts `Vec<RuleSpec>` — Holon detection loop can generate rules programmatically |

---

## Verified Capabilities (Live Test Results)

**Test: 10 tenants, 13 rules, 750K packets, 14 traffic phases**

| Capability | Status | Evidence |
|---|---|---|
| Custom dim fan-out (7 offsets) | Verified | All 7 custom dim tenants matched 50,000 packets exactly |
| Frequency-based allocation | Verified | Offsets with 2 rules got priority slots over 1-rule offsets |
| PatternGuard fallback | Verified | Overflow offsets (108, 208) correctly fell to PatternGuard |
| Deep offset via direct packet read | Verified | Offset 108 and 208 matched 50,000 packets each |
| Long pattern (13 bytes) | Verified | "VETH-LAB-TEST" at offset 16 matched via PatternGuard |
| Tenant isolation | Verified | No cross-tenant counter contamination |
| Negative test | Verified | Wrong payload to correct dst-addr produced no false matches |
| Zero packet loss | Verified | 750,000 packets processed, 0 drops, 0 tail call failures |

---

## Tenant Limit Enforcement

The `--max-byte-matches-per-scope N` CLI argument (default: 32) prevents any single destination address from consuming excessive byte-match resources. Rules are grouped by their `dst-addr` constraint, and l4-match predicates are counted per group.

```
Byte match density: 11 total across 9 scopes (limit: 32/scope)
  Densest scope: 1.0.0.10 (2 byte matches)
```

This enforcement runs at rule load time (before compilation), providing a fast-fail boundary for multi-tenant resource governance.

---

## Summary

The system currently supports **up to 100,000 concurrent rules** (bound by `TREE_COUNTERS`), with **arbitrary-offset byte matching** for 1-4 byte patterns and **deep payload inspection** verified at L4 offsets up to 208 bytes. Scaling to 1M+ rules requires only constant changes. The architecture — tree-based tenant isolation, frequency-based dimension allocation, blue/green deployment, and manifest-based metrics — is designed for the Holon detection loop to generate and update rules dynamically at runtime.
