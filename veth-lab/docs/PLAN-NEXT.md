# Next Phase: Design Notes

**Planning document for implementation. Each section is a self-contained spec
that can be handed to a capable model for implementation.**

---

## 1. RHS Syntax Redesign

### Problem

The current s-expression RHS feels noisy and the `:priority` tacked on after
the action is awkward:

```
((and (= proto 17) (= src-port 53)) => (rate-limit 1906) :priority 210)
```

Priority isn't part of the action — it's metadata about the rule itself. And as
we add more metadata (named limiters, tags, counters), the flat keyword args
after `=>` will become a mess.

### Proposed: EDN-Style RHS

Move to a map-like RHS where actions and metadata are clearly separated:

```clojure
((and (= proto 17) (= src-port 53))
 =>
 {:action  (rate-limit 1906)
  :priority 210})
```

Or with named rate limiter:

```clojure
((and (= proto 17) (= src-port 53))
 =>
 {:action   (rate-limit 1906 :name "amplification")
  :priority 210})
```

Or with multiple actions (rate-limit + count):

```clojure
((and (= proto 6) (= tcp-flags 2))
 =>
 {:actions  [(rate-limit 500 :name "syn-flood") (count :name "syn-attempts")]
  :priority 200})
```

### Key Design Decisions

1. **Single action vs action list:** Go with `:actions [...]` (plural, list).
   Even if most rules have one action, the list form is forward-compatible.
   If only one action, allow the shorthand `:action (rate-limit ...)` (singular).

2. **Priority lives in the map**, not as a trailing keyword. Default 100 if omitted.

3. **The map is the RHS.** The `=>` always points to a `{...}` map. No bare
   `(drop)` after `=>` anymore. Migration: `(drop)` becomes `{:action (drop)}`.

### Implementation

**Files to change:**

- `filter/src/lib.rs` — `RuleSpec::to_sexpr()`, `to_sexpr_pretty()`, `sexpr_parts()`
- `sidecar/src/main.rs` — Anywhere rules are logged or formatted
- `sidecar/src/main.rs` — `parse_rules_file()` JSON parsing (add optional `name` field)

**Struct changes:**

```rust
pub struct RuleSpec {
    pub constraints: Vec<Predicate>,
    pub actions: Vec<RuleAction>,    // was: pub action: RuleAction
    pub priority: u8,
}

pub enum RuleAction {
    Pass,
    Drop,
    RateLimit { pps: u32, name: Option<String> },
    Count { name: Option<String> },            // NEW
}
```

**Canonical hash:** Must include ALL actions (sorted) + priority. Named rate
limiters share the same bucket key derived from the name, not the rule hash.

**JSON format update:**

```json
{
  "constraints": [{"field": "proto", "value": 17}],
  "actions": [
    {"type": "rate-limit", "pps": 500, "name": "amplification"}
  ],
  "priority": 200
}
```

Backward compat: still accept `"action": "drop"` (singular) as shorthand.

---

## 2. Named Rate Limiters

### Problem

Currently, each rule has its own token bucket keyed by the rule's canonical
hash. If a SYN flood and a DNS reflection happen simultaneously, their rate
limiters are independent — each gets its own PPS budget. The operator may want
a single shared budget: "total inbound attack traffic shall not exceed X PPS."

### Design

**Named buckets.** A rate-limit action can include a `:name` string. All rules
sharing the same name share the same token bucket.

```clojure
;; Both rules deplete from the same "inbound-attack" bucket
((and (= proto 6) (= tcp-flags 2))
 =>
 {:action (rate-limit 1000 :name "inbound-attack"), :priority 200})

((and (= proto 17) (= src-port 53))
 =>
 {:action (rate-limit 1000 :name "inbound-attack"), :priority 190})
```

If a packet matches the SYN rule and consumes a token, fewer tokens remain for
the DNS rule's packets. Combined attack rate is capped at 1000 PPS total.

**Unnamed buckets** (current behavior) use the rule's canonical hash as the
bucket key. Nothing changes for existing rules.

### Implementation

**Bucket key derivation:**

```rust
fn bucket_key(action: &RuleAction) -> u32 {
    match action {
        RuleAction::RateLimit { name: Some(name), .. } => {
            // Named: hash the name string to get a stable u32 key
            let mut hasher = DefaultHasher::new();
            name.hash(&mut hasher);
            (hasher.finish() & 0xFFFFFFFF) as u32
        }
        RuleAction::RateLimit { name: None, pps } => {
            // Unnamed: use rule canonical hash (existing behavior)
            rule.canonical_hash() as u32
        }
        _ => 0, // non-rate-limit actions don't have buckets
    }
}
```

**eBPF side:** No changes needed. The eBPF `TreeNode` already stores
`rule_id: u32` which is used as the `TREE_RATE_STATE` key. The compiler just
needs to set `rule_id` to the named bucket key instead of the rule hash.

**Compiler changes (`tree.rs`):**

- When flattening a `TreeNode` with a rate-limit action, set
  `flat_node.rule_id = bucket_key(action)` instead of `canonical_hash`
- When inserting into `rate_buckets`, key by `bucket_key` and use the PPS
  from the action (all rules sharing a name should specify the same PPS — warn
  if they disagree, use the max)

**Files to change:**

- `filter/src/lib.rs` — `RuleAction` enum, `RuleSpec` struct, bucket key fn
- `filter/src/tree.rs` — `flatten_tree()` to use bucket key
- `sidecar/src/main.rs` — JSON parsing for `name` field

### Edge Cases

- **Conflicting PPS:** Two rules name the same bucket but specify different PPS.
  Resolution: use the maximum PPS and log a warning. The operator likely wants
  the more generous limit to apply.

- **Holon-generated rules:** Auto-generated rules should NOT use named buckets
  (they don't know about operator naming conventions). They continue to use
  per-rule buckets keyed by canonical hash.

---

## 3. Count Action (Non-Terminating)

### Problem

Currently all actions are terminating — a matched rule produces PASS, DROP, or
RATE_LIMIT. There's no way to say "count how many packets match this pattern"
without affecting forwarding.

### Design

**`(count)` is a non-terminating action.** It increments a counter but does NOT
stop the DFS walk. The packet continues being evaluated against other rules.

```clojure
;; Count SYN packets without dropping them
((and (= proto 6) (= tcp-flags 2))
 =>
 {:action (count :name "syn-packets")})

;; Separately, rate-limit actual attacks
((and (= proto 6) (= tcp-flags 2) (= dst-port 9999))
 =>
 {:action (rate-limit 100), :priority 200})
```

### Implementation Approach

**eBPF side:**

New action type `ACT_COUNT = 3`. In `tree_walk_step`, when a terminal node has
`action == ACT_COUNT`:
1. Increment the counter in a new `TREE_COUNTERS` map (HashMap<u32, u64>,
   keyed by counter name hash)
2. Do NOT set `best_action` or update priority — the count doesn't compete
   with terminating actions
3. Continue the DFS (don't stop walking)

**New BPF map:**

```rust
static TREE_COUNTERS: HashMap<u32, u64> = HashMap::with_max_entries(100_000, 0);
```

**Userspace reads:** Sidecar can read `TREE_COUNTERS` to report counts per
named counter. This is observability-only — no enforcement effect.

**DFS change:** Currently `tree_walk_step` updates `best_action` when
`node.has_action && node.priority > best_prio`. For count nodes, skip the
priority comparison and just increment the counter. The node should still be
"terminal" (has_action = true) so the DFS knows it found something, but the
count action should not participate in conflict resolution.

Simplest approach: add a flag `ACT_COUNT` that the DFS recognizes as
"increment and continue" rather than "record as candidate."

**Files to change:**

- `filter-ebpf/src/main.rs` — Add `ACT_COUNT`, `TREE_COUNTERS` map, handle in `tree_walk_step`
- `filter/src/lib.rs` — Add `RuleAction::Count`, update `ACT_*` constants
- `filter/src/tree.rs` — Compiler handles count nodes (same as other actions in tree structure)
- `sidecar/src/main.rs` — Read and log counter values

---

## 4. Predicate Extensions

### Status

The `Predicate` enum already has placeholder comments for all planned variants.
The tree architecture supports them — each is a new way to test a field value
at a tree node.

### 4a. Range Predicates (Gt, Lt, Gte, Lte)

**Example:** `(> ttl 200)` — match packets with TTL > 200.

**Tree compilation strategy:** Ranges can't be direct edge lookups (we'd need
an edge for every value in the range). Two approaches:

**Approach A — Expansion at compile time:**
Convert `(> ttl 200)` into 55 rules with `(= ttl 201)`, `(= ttl 202)`, ...,
`(= ttl 255)`. Simple, correct, but inflates rule count.

**Approach B — Range annotation on nodes (recommended):**
Add a `range_check` field to `TreeNode`:

```rust
struct TreeNode {
    // ... existing fields ...
    range_min: u32,   // 0 = no range check
    range_max: u32,   // 0 = no range check
}
```

When the DFS visits a node with `range_min > 0 || range_max > 0`, it checks
`field_value >= range_min && field_value <= range_max` instead of doing an
edge lookup. This handles `>`, `<`, `>=`, `<=` by setting min/max
appropriately (`> 200` → min=201, max=u32::MAX).

**eBPF impact:** Adds one or two comparisons per node that has a range. No
map lookup needed. Verifier should handle this easily.

**Recommendation:** Start with Approach A (expansion) for correctness, then
optimize to Approach B if expansion inflates node count unacceptably. For TTL
(256 values max), expansion is fine. For port ranges (0–65535), Approach B is
necessary.

### 4b. Bitmask Predicate

**Example:** `(mask tcp-flags 2)` — match if SYN bit is set.

**Compilation:** Cannot use edge lookup. Options:

1. **Expansion:** Enumerate all values where `value & mask != 0`. For
   `(mask tcp-flags 2)`, that's 128 values. Feasible for 8-bit fields.

2. **Node annotation:** Add `mask_check: u32` to TreeNode. If nonzero,
   the check is `(field_value & mask_check) != 0` instead of edge lookup.

**Recommendation:** Node annotation. Bitmask checks are a single AND + branch
in eBPF, much cheaper than 128 edge lookups.

### 4c. Set Membership (In)

**Example:** `(in src-port 53 123 5353)` — match if src-port is any of these.

**Compilation:** This naturally maps to multiple edges from the same parent to
the same child. At the current tree node, create edges for each value in the
set, all pointing to the same child subtree. The DAG's `Rc` sharing handles
this efficiently — one child subtree, N edges to it.

**eBPF impact:** Zero. The edge lookup `TREE_EDGES.get(parent, value)` already
handles this — each set member has its own edge entry. The DFS doesn't know
or care that they share a child.

**This is the easiest extension to implement.** It's purely a compiler change.

### 4d. Negation (Not)

**Example:** `(not (= proto 6))` — match anything that's NOT TCP.

**Compilation:** Tricky. The tree structure is built around "follow the edge
that matches." Negation means "follow all edges EXCEPT this one." Options:

1. **Expansion:** For `(not (= proto 6))`, expand to `(in proto 1 17 ...)` —
   all proto values except 6. Only works for small-domain fields.

2. **Wildcard with exclusion:** The DFS already follows wildcard branches.
   A negation could be compiled as "this rule lives in the wildcard subtree
   but has an exclusion list." The DFS would need to check exclusions.

3. **Inversion flag on edges:** An edge with `inverted: true` means "follow
   this edge for any value EXCEPT the one specified."

**Recommendation:** Defer negation. It's the most complex to get right and
the least common use case. When needed, expansion (option 1) works for
small-domain fields (proto, df_bit). For large-domain fields (ports, IPs),
negation is better handled by priority — have a specific-match rule at higher
priority and a wildcard catch-all at lower priority.

### 4e. Disjunction (Or)

**Example:** `(or (= proto 6) (= proto 17))` — match TCP or UDP.

**Compilation:** An OR of predicates on the same field is equivalent to set
membership: `(or (= proto 6) (= proto 17))` = `(in proto 6 17)`. Implement
`In` first.

An OR across different fields is harder: `(or (= proto 6) (= dst-port 80))`.
This would require the rule to appear in multiple tree positions (one under
proto=6, one under dst-port=80 wildcard path). The DAG compiler can handle
this by duplicating the rule spec.

**Recommendation:** Implement `In` (same-field OR) first. Cross-field OR is
a compiler challenge but doesn't require eBPF changes — it's rule duplication
at compile time.

### Implementation Order

1. **`In` (set membership)** — compiler only, zero eBPF changes, highest value
2. **Range (Gt/Lt/Gte/Lte)** — start with expansion, optimize to node annotation
3. **Mask** — node annotation, one AND instruction in eBPF
4. **Or (cross-field)** — compiler-side rule duplication
5. **Not** — defer, use priority-based workarounds

---

## 5. Sets and Prefix Sets

### Problem

A common operational need: "block these 500K source IPs" or "rate-limit
traffic from these 10K CIDRs." Currently each IP would be a separate rule.
500K rules each constraining src-addr works but is wasteful — they all share
the same action and priority.

### 5a. IP Sets

**Concept:** A named set of IPs that can be referenced in a rule:

```clojure
;; Define a set (userspace concept, not in s-expr)
(defset bad-sources ["10.0.0.200" "10.0.0.201" "10.1.0.0/16" ...])

;; Reference it in a rule
((in-set src-addr bad-sources)
 =>
 {:action (drop), :priority 200})
```

**Implementation options:**

**A. Compile-time expansion:** Expand `(in-set src-addr bad-sources)` into
N rules, one per IP/prefix. The DAG compiler deduplicates shared subtrees.
Simple, correct, works with existing eBPF.

**B. Separate BPF map for sets:** Create a `BPF_MAP_TYPE_HASH` or
`BPF_MAP_TYPE_LPM_TRIE` for IP sets. The tree node references the set by ID,
and the DFS checks membership via a map lookup instead of an edge lookup.

**Recommendation for near-term:** Compile-time expansion (option A). It
works today with zero eBPF changes. The DAG compiler's memoization handles
shared subtrees well. At 500K IPs, the tree grows by ~1M nodes — within
the 2.5M slot budget.

**Recommendation for scale (1M+ IPs):** Option B with `BPF_MAP_TYPE_LPM_TRIE`.
This is the kernel's native longest-prefix-match data structure, built for
exactly this use case. It would require:

1. A new BPF map: `static IP_SETS: HashMap<SetKey, u32>` or LPM trie
2. A new predicate: `InSet(FieldRef, SetId)`
3. A new check in `tree_walk_step`: if the node has a set check, do a map
   lookup instead of an edge lookup
4. Userspace management of set contents (add/remove IPs without recompiling tree)

The LPM trie approach is particularly interesting because it handles CIDRs
natively — `10.0.0.0/8` is a single entry, not 16M entries.

### 5b. Bloom Filters

**Concept:** For very large sets (millions of entries) where some false
positives are acceptable, a bloom filter in eBPF can answer "is this IP
possibly in the set?" in O(1).

```
BPF_MAP_TYPE_BLOOM_FILTER  (kernel 5.16+)
```

The kernel has native bloom filter support as a BPF map type. Usage:

1. Userspace inserts IPs into the bloom filter map
2. eBPF program checks `bloom_filter.contains(src_ip)`
3. If positive, apply the rule (with awareness of false positive rate)

**When to use:** Bloom filters make sense when:
- Set is very large (>1M entries)
- Some false positives are acceptable (e.g., rate-limiting, not hard DROP)
- The set changes frequently (bloom filter rebuild is cheaper than tree rebuild)

**Recommendation:** This is a later optimization. Start with LPM tries for
prefix sets. Bloom filters are the escape hatch for extreme scale.

---

## 6. Workflow: Planning vs Implementation

### The Handoff Pattern

1. **Deep planning (Opus):** Architectural decisions, eBPF verifier strategies,
   algorithm design, tradeoff analysis. Output: a design section in this doc
   with clear struct definitions, file lists, and implementation order.

2. **Implementation (Sonnet):** Given a specific section from this doc,
   implement it. Each section is designed to be self-contained: what structs
   to change, what files to touch, what the eBPF impact is, what tests to write.

3. **Review (Opus):** If Sonnet hits a wall (verifier issues, architectural
   questions), escalate back for analysis.

### Implementation Priority

| Feature | Complexity | eBPF Changes | Value |
|---|---|---|---|
| RHS syntax redesign | Low | None | High (cleaner foundation) |
| Named rate limiters | Low | None (bucket key change only) | High |
| Count action | Medium | New map + action type | Medium |
| `In` predicate (set membership) | Low | None (compiler only) | High |
| Range predicates | Medium | Node annotation or expansion | Medium |
| Bitmask predicate | Medium | Node annotation | Medium |
| LPM trie prefix sets | High | New map type + predicate | High |
| Negation | High | Compiler complexity | Low |
| Bloom filters | Medium | New map type | Low (niche) |

### Suggested Implementation Order

**Batch 1 — Foundation (no eBPF changes):**
1. RHS syntax redesign (struct changes, formatting, JSON parsing)
2. Named rate limiters (bucket key derivation)
3. `In` predicate (compiler-only, multi-edge to shared child)

**Batch 2 — eBPF extensions:**
4. Count action (new map, new action type in walker)
5. Range predicates (start with expansion, then node annotation)
6. Bitmask predicate (node annotation)

**Batch 3 — Scale features:**
7. LPM trie prefix sets
8. Cross-field OR (compiler rule duplication)
9. Bloom filters (if needed)

Each batch should be a commit or small PR. Tests first for each feature.
