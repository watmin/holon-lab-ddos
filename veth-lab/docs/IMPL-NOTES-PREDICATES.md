# Implementation Notes: Remaining Predicate Extensions

**Context for the implementing model.** The range predicate implementation
established a pattern for extending the tree Rete engine with new predicate
types. This document explains that pattern and specifies the next two predicates.

---

## Architecture Recap: How Range Predicates Were Implemented

The tree Rete engine has three types of children at each node:

1. **Specific edges** — exact value match via `TREE_EDGES` HashMap
2. **Wildcard child** — matches any value (rules with no constraint on this dim)
3. **Range edges** — up to 2 per node, runtime comparison in eBPF (NEW)

### Key files and their roles:

- **`filter/src/lib.rs`** — Core types: `Predicate` enum, `TreeNode` struct (must match eBPF),
  action/range constants, helper methods on `Predicate`
- **`filter/src/tree.rs`** — Tree compiler: `compile_recursive` (3-way partition),
  `flatten_recursive` (emit to flat TreeNode), `ShadowNode` (compile-time tree)
- **`filter-ebpf/src/main.rs`** — eBPF program: `TreeNode` struct (must match userspace),
  `try_tree_walk_step` (DFS walker), constants
- **`sidecar/src/main.rs`** — Rule parser: `parse_edn_predicate` (EDN → Predicate)

### The pattern for adding a new predicate type:

1. **Add variant(s) to `Predicate` enum** in `lib.rs`
2. **Add helper methods**: `constrains_dim()`, `field_dim()`, `as_range_on_dim()` etc.
3. **Update exhaustive matches**: `to_sexpr_clause()`, `canonical_hash()`,
   `constraints_to_edn()`, `as_eq_dim()` (return None for non-Eq)
4. **Decide compilation strategy**:
   - Expansion (In → multiple Eq rules) — no eBPF changes
   - Node annotation (Range → runtime check) — extend TreeNode + eBPF walker
5. **Update `compile_recursive`** — how to partition rules with this predicate
6. **Update `flatten_recursive`** — emit the annotation into TreeNode fields
7. **Update eBPF walker** — add the runtime check
8. **Update test simulators** — `simulate_single_walk_inner`, `simulate_walk_inner`,
   and the brute-force test matchers all need the new predicate in their match arms
9. **Add EDN parser support** — `parse_edn_predicate` in sidecar
10. **Add unit tests** — test the predicate alone and in competition with other types

### Critical detail: TreeNode must match between userspace and eBPF

`TreeNode` is defined in BOTH `filter/src/lib.rs` AND `filter-ebpf/src/main.rs`.
They are `#[repr(C)]` and must have identical layout. Any field added to one
must be added to the other in the same position.

Current `TreeNode` layout (36 bytes):
```rust
pub struct TreeNode {
    pub dimension: u8,        // offset 0
    pub has_action: u8,       // offset 1
    pub action: u8,           // offset 2
    pub priority: u8,         // offset 3
    pub rate_pps: u32,        // offset 4
    pub wildcard_child: u32,  // offset 8
    pub rule_id: u32,         // offset 12
    // Range edges
    pub range_count: u8,      // offset 16
    pub range_op_0: u8,       // offset 17
    pub range_op_1: u8,       // offset 18
    pub _range_pad: u8,       // offset 19
    pub range_val_0: u32,     // offset 20
    pub range_child_0: u32,   // offset 24
    pub range_val_1: u32,     // offset 28
    pub range_child_1: u32,   // offset 32
}
```

### ShadowNode (compile-time only, not in eBPF):
```rust
struct ShadowNode {
    dim_index: usize,
    action: Option<ShadowAction>,
    children: StdHashMap<u32, Rc<ShadowNode>>,         // specific edges
    wildcard: Option<Rc<ShadowNode>>,                   // wildcard child
    range_children: Vec<(RangeEdge, Rc<ShadowNode>)>,   // range edges
}
```

---

## Next: 4b. Bitmask Predicate

**Syntax:** `(mask tcp-flags 0x02)` — match if `(field_value & mask) != 0`

**Use case:** TCP flags are a bitmask field. `(mask tcp-flags 0x02)` matches any
packet with the SYN bit set, regardless of other flag bits. Currently you'd need
`(in tcp-flags 2 3 6 7 10 ...)` to enumerate all values with SYN set — ugly.

### Strategy: Node annotation (like range predicates)

Bitmask predicates should follow the SAME pattern as range predicates:
- They get their own edge type on tree nodes
- The eBPF walker evaluates `(packet_value & mask) != 0` at runtime
- Rules with bitmask predicates get separate subtrees (not merged with wildcards)

### Implementation Plan

#### 1. Add to `Predicate` enum in `filter/src/lib.rs`:
```rust
pub enum Predicate {
    // ... existing ...
    /// Bitmask: (field_value & mask) != 0
    Mask(FieldRef, u32),
}
```

#### 2. Add constants in both `lib.rs` and `filter-ebpf/main.rs`:

The bitmask edge can reuse the range edge infrastructure. A mask check is
conceptually similar to a range check — it's a runtime predicate on the
packet value at a tree node. Two options:

**Option A: Reuse range edge slots with a new op code.**
Add `RANGE_OP_MASK = 5`. The eBPF walker already checks `range_op_0/1` and
dispatches. Just add a new case: `5 => (fv & range_val_0) != 0`. This
requires NO new fields on TreeNode. The mask value goes in `range_val_N`.

This is the recommended approach — it's minimal change and the range edge
slots are general-purpose "runtime predicate checks."

**Option B: Separate mask fields on TreeNode.**
Add `mask_value: u32`, `mask_child: u32`. This is cleaner semantically but
wastes bytes on every node for a rarely-used feature.

**Go with Option A.** Rename the concept from "range edges" to "guard edges"
mentally — they're general-purpose runtime checks.

#### 3. Add helper methods to `Predicate`:

```rust
pub fn as_mask_on_dim(&self, dim: FieldDim) -> Option<u32> {
    match self {
        Predicate::Mask(FieldRef::Dim(d), mask) if *d == dim => Some(*mask),
        _ => None,
    }
}
```

Also update `as_range_on_dim` to also detect masks, OR add `as_guard_on_dim`
that returns an enum covering both range and mask types.

Actually, simpler: just add `RANGE_OP_MASK = 5` and have `as_range_on_dim`
also match masks. The function name is slightly misleading but the semantics
are "predicate that needs runtime evaluation at this dimension."

Better yet: rename `as_range_on_dim` → `as_guard_on_dim` to reflect that it
covers both ranges and masks. This is a small rename, touches:
- `lib.rs` (method definition)
- `tree.rs` (call site in `compile_recursive`)

#### 4. Update `compile_recursive` in `tree.rs`:

The existing 3-way partition already handles this. Mask predicates will flow
through the same path as range predicates — `as_range_on_dim` (or the renamed
`as_guard_on_dim`) will return `Some((RANGE_OP_MASK, mask_value))` for mask
predicates. They'll create a `RangeEdge { op: RANGE_OP_MASK, value: mask }`
and get their own subtree.

No changes needed to `compile_recursive` logic if the helper method returns
the right op code.

#### 5. Update eBPF walker in `filter-ebpf/src/main.rs`:

Add one match arm in each range check block:

```rust
let passes = match node.range_op_0 {
    RANGE_OP_GT  => fv > node.range_val_0,
    RANGE_OP_LT  => fv < node.range_val_0,
    RANGE_OP_GTE => fv >= node.range_val_0,
    RANGE_OP_LTE => fv <= node.range_val_0,
    RANGE_OP_MASK => (fv & node.range_val_0) != 0,  // NEW
    _ => false,
};
```

Same for `range_op_1`. That's it for the eBPF side.

#### 6. Update `to_sexpr_clause` and friends:

```rust
Predicate::Mask(FieldRef::Dim(dim), mask) => {
    format!("(mask {} 0x{:x})", dim.sexpr_name(), mask)
}
```

#### 7. Update EDN parser:

In `parse_edn_predicate`, add a case for "mask":
```rust
"mask" => {
    if list.len() != 3 {
        anyhow::bail!("mask predicate requires exactly 3 elements");
    }
    let value = parse_field_value(&list[2], dim)?;
    Ok(Some(Predicate::Mask(veth_filter::FieldRef::Dim(dim), value)))
}
```

#### 8. Update test simulators:

In all the brute-force test matchers in `tree.rs`, add:
```rust
Predicate::Mask(crate::FieldRef::Dim(dim), mask) => {
    pkt_map.get(dim).map_or(false, |v| (v & mask) != 0)
}
```

And in `simulate_single_walk_inner` and `simulate_walk_inner`, the range
check dispatchers already handle this if `RANGE_OP_MASK` is added.

#### 9. Tests:

- Basic mask: `(mask tcp-flags 0x02)` matches packets with SYN bit set
- Mask with Eq: `(= proto 6) (mask tcp-flags 0x02)` — TCP SYN packets
- Mask vs wildcard priority: mask rule at prio 100, wildcard at prio 50,
  packet without SYN → only wildcard matches
- Two masks same dim: `(mask tcp-flags 0x02)` and `(mask tcp-flags 0x10)` —
  SYN and ACK as separate rules

---

## After Bitmask: 4d. Negation (Not)

**Syntax:** `(not (= dst-port 9999))` — match if dst-port is NOT 9999.

**Strategy:** Negation is different from range/mask because it's a **modifier**
on another predicate, not a standalone predicate type.

### Two approaches:

**Approach A: Wildcard with exclusion field on TreeNode.**
A negated-Eq rule goes into the wildcard path (it matches "any value except X").
The tree node gets an exclusion check: if the packet value equals the excluded
value, skip this action.

Add to `TreeNode`:
```rust
pub exclude_value: u32,  // 0 = no exclusion
pub exclude_dim: u8,     // which dimension the exclusion applies to
```

In eBPF, after matching an action at a node:
```rust
if node.exclude_dim != 0xFF && state.fields[node.exclude_dim & 0xF] == node.exclude_value {
    // Exclusion matches — skip this action
    continue;
}
```

This is simple but limited: only supports negating a single Eq value.

**Approach B: Reuse guard edges with a "not-equal" op.**
Add `RANGE_OP_NEQ = 6`. A `(not (= dst-port 9999))` becomes a guard edge
with `op=NEQ, val=9999`. The eBPF check: `fv != node.range_val_0`.

This reuses the existing infrastructure perfectly. The subtree for the negated
rule contains rules that apply when `dst-port != 9999`.

BUT: there's a subtlety. Negation means the rule should match for ALL values
EXCEPT the excluded one. In the tree structure:
- At the dst-port dimension, the rule should go to the wildcard path
  (it matches most values)
- But if the packet has dst-port=9999, the rule should NOT match

If we use a guard edge: `(NEQ, 9999, child)` — the guard fires when
`fv != 9999`, and the DFS follows the child subtree. When `fv == 9999`,
the guard doesn't fire, so the child subtree is not explored. This is correct!

The difference from range predicates: range predicates create a RESTRICTED
path (only some values enter). Negation creates a BROADLY PERMISSIVE path
(most values enter, one excluded). The guard edge mechanism handles both.

**Go with Approach B.** It's consistent with the established pattern.

### Implementation Plan

1. Add `Not(Box<Predicate>)` to `Predicate` enum (wraps any predicate)
2. For now, only support `Not(Eq(...))` — error on `Not(In(...))` etc.
3. Add `RANGE_OP_NEQ = 6`
4. `as_guard_on_dim` returns `Some((RANGE_OP_NEQ, val))` for `Not(Eq(dim, val))`
5. eBPF: add `RANGE_OP_NEQ => fv != node.range_val_0`
6. EDN parser: `(not (= field value))` — parse the inner predicate, wrap in Not
7. Tests: negation alone, negation vs specific, negation with other constraints

---

## Summary: Implementation Order

1. **Bitmask** — Easiest. One new `RANGE_OP_MASK` constant, one match arm in eBPF,
   follows existing range edge infrastructure exactly.

2. **Negation** — Slightly more complex (wrapping predicate), but same guard edge
   mechanism. `RANGE_OP_NEQ` op code.

Both reuse the existing "guard edge" slots on TreeNode (the `range_op/val/child`
fields). No new fields needed on TreeNode. No TreeNode layout changes. The eBPF
verifier already accepts the range check code, and adding match arms doesn't
affect verification.

The guard edge approach generalizes: the 2 slots per node can hold any combination
of range checks, mask checks, or negation checks. If a node needs more than 2,
the compiler should log a warning (as it does today for range edges).
