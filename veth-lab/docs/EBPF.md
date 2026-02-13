# Building a Rete Network Inside eBPF

**The engineering story of making complex rule evaluation work within the most constrained execution environment in modern computing.**

## The Constraints

eBPF programs run inside the Linux kernel with restrictions that exist for good reason — a bug in kernel code means a kernel panic, not a segfault. The BPF verifier enforces these constraints statically before any code executes:

| Constraint | Limit | Impact |
|---|---|---|
| Total instructions | 1,000,000 verified paths | Complex loops explode combinatorially |
| Loop iterations | Must be provably bounded | No `while` loops, no dynamic termination |
| Stack size | 512 bytes | No recursive function calls |
| Memory access | Must be bounds-checked | Every array index, every pointer deref |
| Tail call depth | 33 calls | Hard kernel limit, not configurable |
| Map value size | ~32KB | Structs can't be arbitrarily large |
| No dynamic allocation | Zero heap | Everything is fixed-size, pre-allocated |
| No floating point | Integer only | All arithmetic in fixed-point or integer |

The verifier doesn't just check that your program *probably* works. It explores every possible execution path and proves that none of them can crash the kernel. This means a program with 20 iterations of a loop and 3 branches per iteration has `3^20 ≈ 3.5 billion` potential paths to verify. The verifier gives up at 1 million.

## Chapter 1: HashMap Lookup (Feb 7)

**The simplest possible thing.**

```rust
// One rule = one map lookup
let key = RuleKey { rule_type: SRC_IP, value: src_ip };
if let Some(rule) = RULES.get(&key) {
    if rule.action == DROP { return XDP_DROP; }
}
```

Per-rule HashMap lookups. Each rule gets its own entry. To check a packet, you do N lookups for N rules. Simple, correct, fast enough for small rule sets.

**Problem:** Linear in rule count. 10 rules = 10 lookups. 10,000 rules = 10,000 lookups. And each rule only matches one field — no compound rules like "src_ip=X AND dst_port=Y."

**What we learned:** The eBPF verifier has no problem with simple programs. Map lookups are first-class operations. The challenge isn't getting code to run — it's getting *complex* code to run.

## Chapter 2: Bitmask Rete (Feb 10)

**First attempt at a discrimination network.**

Instead of checking each rule independently, build dispatch maps that return bitmasks:

```rust
let mut mask: u64 = ACTIVE_RULES.get(0);  // start with all active rules

// Narrow by protocol
if let Some(m) = DISPATCH_PROTO.get(&proto) { mask &= m; }
// Narrow by source IP
if let Some(m) = DISPATCH_SRC_IP.get(&src_ip) { mask &= m; }
// Narrow by destination port
if let Some(m) = DISPATCH_DST_IP.get(&dst_port) { mask &= m; }

// mask now contains only rules that match ALL checked fields
```

Each bit position represents a rule. The AND operations narrow the candidate set. After all fields are checked, the surviving bits identify matching rules.

**Result:** O(fields) instead of O(rules). Six map lookups regardless of rule count. Compound rules work naturally — a rule is the conjunction of its dispatch entries.

**Problem:** 64-bit bitmask = 64 rules maximum. The user's goal was 100K–1M rules. This was a dead end for scale, but it validated the discrimination network approach.

**What we learned:** The *principle* of shared evaluation works brilliantly in eBPF. Map lookups are cheap. The challenge is representing a large rule set, not evaluating it.

## Chapter 3: Tree Rete — Single-Path Walker (Feb 12)

**Decision tree traversal with macro-unrolled levels.**

Replace the bitmask with a tree structure. Each internal node represents a field dimension (proto, src_ip, dst_port, etc.). Edges connect parent nodes to child nodes based on field values. A packet walks from root to leaf, following edges that match its field values.

```rust
macro_rules! tree_walk_level {
    ($node_id:expr, $field_value:expr) => {
        if let Some(node) = TREE_NODES.get($node_id) {
            if node.has_action && node.priority > best_prio {
                best_action = node.action;
                best_prio = node.priority;
            }
            let edge_key = EdgeKey { parent: $node_id, value: $field_value };
            if let Some(child) = TREE_EDGES.get(&edge_key) {
                $node_id = *child;
            } else if node.wildcard_child != 0 {
                $node_id = node.wildcard_child;
            }
        }
    };
}

// Unroll 9 levels (one per field dimension)
tree_walk_level!(node_id, proto);
tree_walk_level!(node_id, src_ip);
tree_walk_level!(node_id, dst_ip);
tree_walk_level!(node_id, src_port);
tree_walk_level!(node_id, dst_port);
tree_walk_level!(node_id, tcp_flags);
tree_walk_level!(node_id, ttl);
tree_walk_level!(node_id, df_bit);
tree_walk_level!(node_id, tcp_window);
```

Each level: load node from `TREE_NODES`, check for action, look up edge in `TREE_EDGES`, follow it. Nine macro expansions = nine levels = nine dimensions. No loops, so the verifier sees straight-line code.

**Result:** ~270 instructions total. Verifier happy. Evaluates any number of rules in exactly 9 map lookups (one per dimension). First successful tree traversal with 10K rules.

**Problem:** Single-path traversal. If a rule has a wildcard on one dimension (e.g., "any protocol"), the compiler must replicate that rule into every possible value's subtree. This worked but meant the compiler had to expand wildcards, which exploded node count for rules with many wildcards.

**What we learned:** The eBPF verifier loves unrolled code. Nine identical blocks with no branches is trivially verified. But single-path traversal forces expensive wildcard replication at compile time.

## Chapter 4: DAG Compiler + Multi-Cursor (Feb 12)

**Attempt to solve the replication problem in the walker.**

Instead of single-path traversal, maintain multiple "cursors" that track both the specific-value path and the wildcard path simultaneously:

```rust
let mut cursors = [0u32; MAX_CURSORS];  // MAX_CURSORS = 3 or 4
cursors[0] = root;
let mut num_cursors = 1u32;

// For each dimension, each cursor spawns up to 2 children
// (specific match + wildcard)
```

This meant the tree didn't need wildcard replication — the walker would explore both branches.

**Problem:** The verifier exploded. Multiple cursors mean multiple paths through the code. With 3 cursors and 9 levels, the verifier saw `2^(3×9) = 134 billion` potential paths. Even reduced to `MAX_CURSORS=2`, it hit the 1M instruction limit.

**What we learned:** The verifier's path explosion is multiplicative. Every branch doubles the verification cost. Multiple independent state variables (cursors) multiply that further. The verifier doesn't know that most paths are impossible — it checks them all.

## Chapter 5: Stack-Based DFS (Feb 12–13)

**New approach: depth-first search with explicit stack.**

Instead of multiple cursors evaluated in lockstep, use a single stack and process one node at a time. For each node, push both the specific-value child and the wildcard child onto the stack. Pop the next node. Repeat until stack is empty.

```rust
let mut stack = [0u32; 16];
let mut top: u32 = 1;
stack[0] = root;

let mut best_action = ACT_PASS;
let mut best_prio = 0u8;

for _iter in 0..20 {  // bounded loop
    if top == 0 { break; }
    top -= 1;
    let node_id = stack[top & 0xF];  // masked index for verifier

    let node = TREE_NODES.get(node_id)?;

    // Check for terminal action
    if node.has_action && node.priority > best_prio {
        best_action = node.action;
        best_prio = node.priority;
    }

    // Push wildcard child
    if node.wildcard_child != 0 && top < 15 {
        stack[top & 0xF] = node.wildcard_child;
        top += 1;
    }

    // Push specific-value child
    let field_val = fields[node.dimension];
    let edge = EdgeKey { parent: node_id, value: field_val };
    if let Some(child) = TREE_EDGES.get(&edge) {
        if top < 15 {
            stack[top & 0xF] = *child;
            top += 1;
        }
    }
}
```

This explores ALL matching paths through the tree — every combination of specific matches and wildcards — and collects the highest-priority terminal node. Exactly the trie traversal the user envisioned.

### Verifier Battle #1: `while` loops

```
Error: last insn is not an exit or jmp, processed 0 insns
```

The first attempt used `while top > 0`. The BPF verifier (on this kernel) couldn't prove termination. A `while` loop needs the verifier to infer a loop bound from the condition, which it couldn't do for a stack-based loop.

**Fix:** Replace with `for _iter in 0..20` — an explicitly bounded loop. The verifier knows it runs at most 20 times.

### Verifier Battle #2: Array bounds

```
Error: invalid access to map value
```

`stack[top]` where `top` is a variable. The verifier couldn't prove `top < 16`. Even though we checked `top < 15` before pushing, the verifier lost track of the bound after the map lookup.

**Fix:** Masked indexing: `stack[top & 0xF]`. Since `0xF = 15`, the result is always 0–15, which is within the 16-element array. The verifier can prove this statically from the bitmask.

### Verifier Battle #3: Instruction explosion

```
Error: BPF program is too large. Processed 1000001 insn
```

Even with 20 iterations, the verifier explored too many paths. The problem: inside the loop, `get_field(dimension)` was a match statement with 9 arms, and each arm accessed different packet data. With 20 iterations, the verifier saw `9^20` potential field access patterns.

**Fix:** Pre-extract ALL field values before the loop:

```rust
let fields: [u32; 9] = extract_all_fields(ip_hdr, ihl, &facts);
```

Inside the loop, field access becomes `fields[node.dimension & 0xF]` — a single bounded array index instead of a 9-way branch. This eliminated the branch explosion inside the loop.

**Still too many instructions.** Even with pre-extraction, 20 iterations with 2 map lookups each generated ~400K verified paths. The verifier needed to check every combination of "map lookup returns Some" vs "map lookup returns None" at each iteration.

**Dead end.** The stack-based DFS was correct and elegant, but the BPF verifier fundamentally cannot handle it in a single program. No amount of optimization would fix the combinatorial path explosion of a loop with conditional map lookups.

## Chapter 6: BPF Tail Calls (Feb 13)

**The breakthrough: split the DFS across multiple programs.**

BPF tail calls allow one eBPF program to jump to another. The critical properties:
- The new program takes over completely (the old program's stack is gone)
- The kernel enforces a maximum of 33 tail calls per packet
- Each program is **verified independently** — the verifier only sees ~100 instructions, not the whole DFS
- Programs don't migrate CPUs between tail calls — per-CPU state is safe

Architecture:

```
veth_filter (XDP entry point, ~16K instructions)
  ├── Parse packet headers
  ├── Extract all field values
  ├── Sample packet to userspace
  ├── Initialize DfsState in per-CPU map
  │     - stack[0] = root
  │     - fields[0..8] = extracted values
  │     - matched = 0, best_action = PASS
  └── tail_call(TREE_WALK_PROG, 0)
              ↓
tree_walk_step (~4K instructions, verified independently)
  ├── Read DfsState from per-CPU map
  ├── Pop node from stack
  ├── Check for terminal action (update best match)
  ├── Push wildcard child
  ├── Push specific-value child
  ├── Write DfsState back
  ├── If stack not empty: tail_call(TREE_WALK_PROG, 0)  ← SELF
  └── If stack empty: apply_dfs_result() → XDP_DROP/XDP_PASS
```

`tree_walk_step` processes ONE DFS step and tail-calls ITSELF for the next step. The verifier sees a tiny program with 2–3 map lookups and no loops. Trivially verified.

The DFS state lives in `TREE_DFS_STATE`, a `PerCpuArray<DfsState>`:

```rust
pub struct DfsState {
    pub stack: [u32; 16],       // DFS node stack
    pub top: u32,               // stack pointer
    pub fields: [u32; 16],      // pre-extracted packet field values
    pub matched: u8,            // any rule matched?
    pub best_action: u8,        // highest-priority action
    pub best_prio: u8,          // highest priority seen
    pub best_rule_id: u32,      // for rate-limiting state lookup
    pub pkt_len: u32,           // packet metadata for stats
    pub enforce: u8,            // enforcement mode
    // ... other metadata
}
```

### Verifier Battle #4: `memset` explosion

```
Error: BPF program is too large (veth_filter)
```

Initializing `DfsState` with Rust array literals:
```rust
state.stack = [0u32; 16];
state.fields = [0u32; 16];
```

The Rust compiler generated `memset` calls for these. In BPF, `memset` is a compiler-generated subprogram. The verifier treated each `memset` as a function call, saving and restoring all registers. With two `memset` calls plus the rest of `veth_filter`, the register save/restore overhead pushed past the instruction limit.

**Fix:** Initialize every field individually:
```rust
state.stack[0] = root;
state.top = 1;
state.fields[0] = fields[0];
state.fields[1] = fields[1];
state.fields[2] = fields[2];
// ... all 9 fields
state.matched = 0;
state.best_action = ACT_PASS;
state.best_prio = 0;
// ... every single field
```

Verbose, but each line compiles to a single BPF store instruction. No subprogram calls, no register save/restore overhead.

### Verifier Battle #5: Packet pointer invalidation

```
Error: R4 offset is outside of the packet
```

`tree_walk_step` tried to call `sample_packet()`, which accesses raw packet data (`ctx.data()` to `ctx.data_end()`). But the verifier couldn't verify packet bounds across the tail call boundary — the packet pointer established in `veth_filter` doesn't carry over to `tree_walk_step`'s verification context.

**Fix:** Move ALL packet data access to `veth_filter`, before the tail call. The tail-called `tree_walk_step` never touches raw packet data — it only reads from maps (`TREE_DFS_STATE`, `TREE_NODES`, `TREE_EDGES`). Sampling happens in `veth_filter` where bounds checks are established.

### Verifier Battle #6: Tail call fallthrough

```
Error: R7 invalid mem access 'scalar'
```

When `tail_call()` fails (returns instead of jumping), the verifier merged the register state from the tail call path with the fallthrough path. The tail call clobbered registers that the fallthrough code needed.

**Fix:** Explicit early return after the tail call block:
```rust
unsafe { let _ = TREE_WALK_PROG.tail_call(&ctx, 0); }
// If we get here, tail call failed
return pass_packet();  // explicit return, don't fall through
```

### The Silent Killer: Empty ProgramArray

After all verifier battles were won, the program loaded and ran. No crashes. No errors.

**No drops.**

Every diagnostic counter showed the tail call was being attempted and failing silently. `bpf_tail_call` doesn't return an error code — it either jumps to the target (never returns) or falls through (returns 0, same as "success" in some ABIs).

Added STATS counters at every decision point in `veth_filter`:
```
DIAG eval2:48095 root:48095 state:48095 tc_try:48095 tc_fail:48095
```

Every single tail call attempted. Every single one failed. 100% failure rate.

Installed `bpftool`:
```bash
$ sudo bpftool map dump id 1449
Found 0 elements
```

**The ProgramArray was empty.** Despite `prog_array.set(0, &tree_walk_fd, 0)` succeeding without error during initialization.

Root cause: aya's `take_map("TREE_WALK_PROG")` removes the map from aya's registry and returns an owned `Map`. We created a `ProgramArray` from it, set the entry, and then **dropped the `ProgramArray` at the end of the block**. Dropping it closed the userspace file descriptor to the map. When the last userspace fd to a BPF prog_array is closed, the kernel clears all entries.

The map itself stayed alive (because the loaded BPF programs reference it), but its contents were wiped.

**Fix:** Store the `ProgramArray` in the `VethFilter` struct so it lives for the entire program lifetime:

```rust
pub struct VethFilter {
    bpf: Arc<RwLock<Ebpf>>,
    // ...
    /// Keep the prog_array alive so the tail-call entry persists.
    /// Dropping this closes the map fd, which clears the prog_array entries.
    _prog_array: Option<ProgramArray<MapData>>,
}
```

One field addition. Hours of debugging. `bpftool` saved us.

## Summary: What The Verifier Taught Us

| Battle | Symptom | Root Cause | Fix |
|---|---|---|---|
| `while` loop | 0 insns processed | Unprovable termination | `for` loop with explicit bound |
| Array bounds | Invalid map access | Unproven index range | Bitmask indexing (`& 0xF`) |
| Path explosion | 1M+ insns | Branches inside loops compound | Pre-extract all fields before loop |
| Still too many | 1M+ insns | Map lookups in loops branch | **Tail calls** — split into separate programs |
| `memset` | Too many insns | Array literal → memset subprogram | Field-by-field assignment |
| Packet pointers | Outside packet | Bounds don't carry across tail calls | All packet access before tail call |
| Register merge | Invalid mem access | Tail call fallthrough clobbers regs | Explicit `return` after tail call |
| Empty prog_array | 0 drops, silent | `take_map` + drop closes fd | Store `ProgramArray` in struct |

Every constraint we hit forced a better design:
- "Can't loop" → pre-extract fields (faster: no branching per iteration)
- "Can't have complex programs" → tail calls (better: independently verified modules)
- "Can't access packet data in tail call" → sample before tail call (cleaner: separation of concerns)
- "Can't bulk-initialize" → field-by-field init (explicit: no hidden compiler codegen)

The BPF verifier isn't an obstacle. It's a design pressure that produces better code — if you listen to what it's telling you.

## The Final Architecture

```
veth_filter          tree_walk_step          tree_walk_step
(~16K insns)         (~4K insns)             (~4K insns)
                     (verified separately)    (verified separately)
     │                     │                       │
  Parse packet        Pop stack[top]          Pop stack[top]
  Extract fields      Check node action       Check node action
  Sample packet       Push wildcard child     Push wildcard child
  Init DfsState       Push specific child     Push specific child
  Set stack[0]=root   ─────────────┐          ─────────────┐
     │                 tail_call   │           tail_call   │
     │  tail_call      to self ◄───┘           to self ◄───┘
     └────────►             │                       │
                            │ (stack empty)         │
                            ▼                       │
                    apply_dfs_result()              │
                    Rate limit check                │
                    XDP_DROP / XDP_PASS             │
                                                    │
              ◄─────── 33 tail calls max ──────────►
              ◄─────── ~5 calls typical ───────────►
```

Each `tree_walk_step` invocation: ~100 instructions, 2–3 map lookups, zero loops. The verifier sees a straight-line program. The kernel sees a DFS trie traversal across a million-rule decision tree. Five tail calls per packet, whether you have 50 rules or 5 million.
