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

---

## 7. Metrics Collection and Emission

### Problem

We have counters scattered across BPF maps (STATS, TREE_COUNTERS, rate limiter
state) but no systematic way to collect, aggregate, and export them. The sidecar
currently reads stats inline during the detection loop, but there's no dedicated
metrics pipeline.

### Design: Async Reactor Loop

A dedicated async task in the sidecar that periodically:

1. **Drains counters** from BPF maps (STATS, TREE_COUNTERS, rate state)
2. **Aggregates** per-CPU values into totals
3. **Computes deltas** (rate of change since last collection)
4. **Emits** to one or more sinks (log, file, socket, prometheus endpoint)

```rust
// Runs alongside the detection loop
async fn metrics_reactor(filter: Arc<VethFilter>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    let mut prev_stats = FilterStats::default();

    loop {
        ticker.tick().await;

        let stats = filter.stats().await?;
        let counters = filter.read_counters().await?;  // TREE_COUNTERS
        let rate_states = filter.read_rate_states().await?;  // TREE_RATE_STATE

        let delta = stats.delta(&prev_stats);
        prev_stats = stats.clone();

        // Emit to configured sinks
        emit_metrics(&delta, &counters, &rate_states).await;
    }
}
```

**Collection interval:** 1–5 seconds. Independent of detection window cadence.

### Emission Sinks (Pick One to Start)

| Sink | Complexity | Integration |
|---|---|---|
| **Structured JSON log file** | Low | grep/jq friendly |
| **Unix socket (line protocol)** | Low | Telegraf/Vector compatible |
| **Prometheus `/metrics` endpoint** | Medium | Industry standard |
| **StatsD UDP** | Low | Broad ecosystem |

**Recommendation:** Start with structured JSON log (one line per collection).
Add Prometheus endpoint later — it's the most useful but requires an HTTP
server dependency.

### Counter Draining

The `TREE_COUNTERS` map should be **read-and-reset** — atomically read the
value and set it to 0. This prevents counter overflow and gives clean deltas.
BPF has no atomic read-and-reset, but we can:

1. Read the value
2. Delete the key (or write 0)
3. Accept a small race window (packets between read and reset are lost from
   this collection cycle, counted in the next)

For high-fidelity: use a per-CPU counter map and sum across CPUs in userspace
(same as STATS today). Per-CPU maps avoid cross-CPU contention entirely.

---

## 8. Compound Naming (Namespaces)

### Problem

As the system grows multi-tenant or multi-concern, flat names like
`"syn-flood"` will collide. We need namespaced identifiers.

### Design: Compound Keys

Names become tuples: `[namespace, name]`.

```clojure
;; Tenant-scoped rate limiter
((and (= proto 6) (= tcp-flags 2) (= dst-addr 10.0.0.1))
 =>
 {:action (rate-limit 500 :name ["tenant-1" "syn-limit"])
  :priority 200})

;; Tenant-scoped counter
((and (= proto 17) (= src-port 53))
 =>
 {:action (count :name ["tenant-1" "dns-responses"])})
```

### Implementation

**Userspace:** The name is a `Vec<String>` or `(String, String)`. The hash
for the BPF map key is computed from the concatenation:

```rust
fn compound_key(namespace: &str, name: &str) -> u32 {
    let mut hasher = DefaultHasher::new();
    namespace.hash(&mut hasher);
    name.hash(&mut hasher);
    (hasher.finish() & 0xFFFFFFFF) as u32
}
```

**eBPF side:** No change. The map key is still a u32. The compound-ness is
a userspace abstraction over the hash.

**JSON format:**

```json
{
  "actions": [
    {"type": "rate-limit", "pps": 500, "name": ["tenant-1", "syn-limit"]}
  ]
}
```

**Backward compat:** A plain string `"syn-limit"` is treated as `["", "syn-limit"]`
(empty namespace).

### Metrics Integration

The metrics reactor uses compound names for grouping:

```json
{"ts": "2026-02-13T...", "namespace": "tenant-1", "counter": "dns-responses", "value": 4281, "delta": 127}
{"ts": "2026-02-13T...", "namespace": "tenant-1", "limiter": "syn-limit", "tokens": 342, "drops": 18}
```

This naturally supports per-tenant dashboards and alerting.

---

## 9. Dynamic Prefix Lists (Lazy Accumulation)

### Problem

Instead of expressing 10K individual `(= src-addr ...)` rules, accumulate
"bad" source addresses into a prefix list that rules reference by name. The
list grows lazily as the system detects new offenders, and entries expire
after a TTL.

### Design

```clojure
;; Rule references a dynamic prefix list by name
((in-prefix-list src-addr "bad-sources")
 =>
 {:action (rate-limit 100), :priority 200})
```

The prefix list `"bad-sources"` is populated by the detection engine:

```rust
// When Holon detects a concentrated src-addr in anomalous traffic:
prefix_lists.insert("bad-sources", src_addr, ttl: Duration::from_secs(3600));
```

### Implementation: LPM Trie with TTL

**BPF map:** `BPF_MAP_TYPE_LPM_TRIE` — the kernel's native longest-prefix-match
structure. Supports CIDR lookups natively.

```rust
// Key: prefix + address
struct LpmKey {
    prefix_len: u32,  // e.g., 32 for /32, 24 for /24
    addr: u32,        // IP address
}

static PREFIX_LISTS: HashMap<u32, LpmTrie<LpmKey, u8>> = ...;
// Outer key: hash of list name
// Inner: LPM trie of prefixes → action flags
```

**Actually, BPF doesn't support map-in-map with LPM tries directly.** Simpler
approach: one LPM trie per list, pre-created at startup:

```rust
static BAD_SOURCES: LpmTrie<LpmKey, u64> = LpmTrie::with_max_entries(1_000_000, 0);
// Value: expiry timestamp (or 0 for permanent)
```

**eBPF lookup:** In `tree_walk_step`, when a node has a prefix-list check:

```rust
let key = LpmKey { prefix_len: 32, addr: src_ip };
if let Some(entry) = BAD_SOURCES.get(&key) {
    if *entry == 0 || *entry > now_ns { /* match */ }
}
```

**Userspace management:**
- Insert: `lpm_trie.insert(LpmKey { prefix_len: 32, addr: ip }, expiry_ts)`
- Eviction: Periodic sweep deleting entries where `expiry_ts < now`
- No tree recompilation needed — the prefix list is checked at runtime

**This is powerful.** The tree says "check prefix list X for src-addr" and the
prefix list is managed independently. Adding 10K IPs to the list is 10K map
updates, not a tree recompile. Entries auto-expire.

### Interaction with Holon

When Holon detects anomalous traffic concentrated on a source address:
1. Instead of (or in addition to) generating a tree rule, insert the source
   IP into the `"bad-sources"` prefix list with a 1-hour TTL
2. A single tree rule `(in-prefix-list src-addr "bad-sources")` handles all
   current and future entries
3. As IPs expire, they stop matching without any tree recompilation

This is the **separation of policy (tree rule) from data (prefix list).**

---

## 10. Negation Syntax

### Clojure Precedent

In Clojure:
- `(not (= x y))` — composable, wraps any predicate
- `(not= x y)` — shorthand, common but only for equality

For a rule language where `not` should wrap ANY predicate (not just `=`), the
composable form is better:

```clojure
;; Negate equality
(not (= dst-port 9999))

;; Negate set membership (future)
(not (in src-port 53 123))

;; Negate range (future)
(not (> ttl 200))
```

`(not ...)` is the Clojure way. It's a higher-order form that wraps any
predicate. This is more composable than dedicated `!=`, `not-in`, etc.

### The SYN Counter Example

```clojure
;; Count SYN packets that AREN'T hitting the game server
((and (= proto 6)
      (= tcp-flags 2)
      (not (= dst-port 9999)))
 =>
 {:action (count :name ["monitoring" "non-game-syns"])})

;; Rate-limit SYNs TO the game server
((and (= proto 6)
      (= tcp-flags 2)
      (= dst-port 9999))
 =>
 {:action (rate-limit 100 :name ["game" "syn-limit"])
  :priority 200})
```

### Compilation Strategy for Negation

For `(not (= dst-port 9999))`:

**In the tree:** The rule needs to match when `dst-port != 9999`. At the
dst-port dimension in the tree:

1. The rule lives in the **wildcard branch** (matches any dst-port value)
2. But has an **exclusion**: if `dst-port == 9999`, skip this rule

Implementation: add an `exclusions: Vec<u32>` to the compiler's intermediate
representation. During flattening, a node with exclusions becomes a node that
the DFS visits via wildcard but skips if the field value matches an exclusion.

**eBPF impact:** Add an `exclude_value: u32` field to `TreeNode` (0 = no
exclusion). In `tree_walk_step`:

```rust
if node.exclude_value != 0 && fields[node.dimension] == node.exclude_value {
    // Skip this node — negation excludes it
    continue;  // don't push children, don't check action
}
```

One comparison per node. Minimal verifier impact. Supports single-value
negation. Multi-value negation (`(not (in ...))`) would need an exclusion
set, but single-value covers 90% of use cases.

---

## 11. HyperLogLog for Cardinality Estimation

### What You're Thinking Of

A **HyperLogLog (HLL)** estimates the number of **distinct** elements in a
stream. "How many unique source IPs are hitting port 443?" — HLL answers this
in ~1.2KB of memory with ~2% error, regardless of whether the answer is 50
or 50 million.

This isn't an anti-bloom filter (that would be a cuckoo filter or counting
bloom filter). HLL is specifically for **cardinality estimation** — counting
unique things without storing them.

### Why This Matters for DDoS

| Signal | What HLL Tells You |
|---|---|
| Source IP cardinality spike | Botnet activation (50 → 50,000 unique sources) |
| Destination port cardinality | Port scan detection |
| Low source cardinality + high PPS | Amplification attack (few sources, huge volume) |
| Source port cardinality | Randomized vs fixed source ports |

Holon already detects drift, but HLL gives a **specific, interpretable metric**:
"unique source count jumped 1000x." This feeds directly into rule generation.

### Implementation

**BPF doesn't have a native HLL map type.** But HLL is simple enough to
implement in a BPF array:

```rust
// HLL with 256 registers (m=256), ~5% error, 256 bytes
static HLL_SRC_IP: Array<u8> = Array::with_max_entries(256, 0);

fn hll_observe(value: u32) {
    let hash = bpf_hash(value);
    let register = (hash & 0xFF) as u32;       // first 8 bits → register index
    let remaining = hash >> 8;                   // remaining bits
    let leading_zeros = remaining.leading_zeros() + 1;  // ρ(remaining)

    if let Some(current) = HLL_SRC_IP.get_ptr_mut(register) {
        let cur = unsafe { *current };
        if leading_zeros as u8 > cur {
            unsafe { *current = leading_zeros as u8; }
        }
    }
}
```

**Userspace reads the 256 registers and computes the estimate:**

```rust
fn hll_count(registers: &[u8; 256]) -> f64 {
    let m = 256.0;
    let alpha = 0.7213 / (1.0 + 1.079 / m);  // bias correction
    let sum: f64 = registers.iter().map(|&r| 2.0_f64.powi(-(r as i32))).sum();
    let estimate = alpha * m * m / sum;
    // Small/large range corrections omitted for brevity
    estimate
}
```

**256 bytes per HLL counter.** We could have dozens of them:
- `HLL_SRC_IP` — unique source IPs
- `HLL_DST_PORT` — unique destination ports
- `HLL_SRC_PORT` — unique source ports
- Per-prefix HLLs (unique sources hitting a specific destination)

**Integration with metrics reactor:**
The metrics loop reads HLL registers every N seconds, computes cardinality
estimates, and emits them. Cardinality changes between cycles are a powerful
anomaly signal that complements Holon's drift detection.

**Integration with rules:**
HLL cardinality could feed into rule generation heuristics:

```
if hll_src_ip_cardinality > 10_000 && drift > 0.7 {
    // Botnet detected — generate broad rate-limit rule
}
if hll_src_ip_cardinality < 5 && pps > 100_000 {
    // Amplification — generate per-source drop rules
}
```

**Reset:** HLLs need periodic reset (or decay) to track *recent* cardinality.
The metrics reactor can zero the registers at configurable intervals.

### BPF Verifier Feasibility

The `hll_observe` function is ~10 instructions: one hash, one AND, one
shift, one leading_zeros (CLZ instruction), one array lookup, one compare,
one conditional store. Trivially verified. Can run in `veth_filter` alongside
sampling, before the tail call.

---

## 12. EDN as the Rule Language

### Why EDN Over JSON

[EDN (Extensible Data Notation)](https://github.com/edn-format/edn) is
Clojure's data format. JSON is a subset of what EDN can express, but EDN
adds:

| Feature | JSON | EDN |
|---|---|---|
| Keywords | No | `:action`, `:priority` |
| Sets | No (`[]` only) | `#{53 123 5353}` |
| Symbols | No | `rate-limit`, `drop` |
| Tagged literals | No | `#inst "2026-..."`, `#cidr "10.0.0.0/8"` |
| Comments | No | `; this is a comment` |
| Commas optional | Required | Whitespace-separated |

Sets are a native EDN type — perfect for `(in src-port #{53 123 5353})`.
Tagged literals let us define `#cidr "10.0.0.0/8"` as a first-class value.
Keywords make the RHS map natural: `{:action (drop) :priority 200}`.

### What Rules Look Like in EDN

```clojure
;; Current JSON (verbose, no comments)
[{"constraints": [{"field": "proto", "value": 17}], "action": "drop"}]

;; EDN equivalent (native, composable)
[{:constraints [(= proto 17)]
  :action      (drop)}]

;; Full rule with all features
{:constraints [(= proto 6)
               (= tcp-flags 2)
               (not (= dst-port 9999))]
 :actions     [(rate-limit 500 :name ["game" "syn-limit"])
               (count :name ["monitoring" "non-game-syns"])]
 :priority    200}

;; Prefix set reference with tagged literal
{:constraints [(in-prefix-list src-addr "bad-sources")
               (= proto 17)]
 :actions     [(rate-limit 100)]
 :priority    150}

;; Set membership with native EDN set
{:constraints [(in src-port #{53 123 5353})]
 :actions     [(rate-limit 300 :name "dns-ntp-amp")]}
```

### Rust EDN Libraries

Three options exist:

| Crate | Version | Notes |
|---|---|---|
| `edn-format` | 3.3.0 | Most mature, good docs, parse/emit |
| `edn-rs` | 0.18.0 | Serde-like macros (`map!`, `set!`), deser traits |
| `rsedn` | 0.2.0 | Two-stage lex+parse, lower-level |

**Recommendation:** `edn-rs` for its serde integration — we already use serde
for JSON parsing. Evaluating `edn-format` as a fallback if `edn-rs` doesn't
handle our nested s-expression predicates cleanly.

### Migration Path

1. Add `edn-rs` (or `edn-format`) dependency to sidecar
2. Write an EDN rule parser alongside the existing JSON parser
3. Auto-detect format: if file starts with `[{` → JSON, if `[{:` or `({` → EDN
4. Keep JSON support permanently (it's a subset, costs nothing)
5. Log emitted rules in EDN format (more readable than JSON s-exprs)
6. Eventually: rules API accepts EDN over the wire

**Files to change:**
- `sidecar/Cargo.toml` — add `edn-rs` or `edn-format`
- `sidecar/src/main.rs` — new `parse_rules_edn()` alongside `parse_rules_file()`
- `filter/src/lib.rs` — `to_edn()` emitter on `RuleSpec`

---

## 13. Blue/Green Prefix Lists

### Question

If prefix lists are loaded from external sources (compute cluster, user API,
threat intel feed), can we do atomic swaps on them too?

### Answer: Yes, Same Pattern as the Tree

**Double-buffered LPM tries.** Create two LPM trie maps per prefix list:

```rust
static PREFIX_LIST_A: LpmTrie<LpmKey, PrefixEntry> = LpmTrie::with_max_entries(1_000_000, 0);
static PREFIX_LIST_B: LpmTrie<LpmKey, PrefixEntry> = LpmTrie::with_max_entries(1_000_000, 0);
static PREFIX_LIST_ACTIVE: Array<u32> = Array::with_max_entries(1, 0);  // 0 = A, 1 = B
```

**Swap protocol (same as tree blue/green):**

1. Load new prefix data into the inactive list (B)
2. Atomic write to `PREFIX_LIST_ACTIVE`: 0 → 1
3. eBPF reads `PREFIX_LIST_ACTIVE` to choose which trie to query
4. Old list (A) is now available for the next update

**Alternatively: map-in-map.** BPF supports `BPF_MAP_TYPE_ARRAY_OF_MAPS` and
`BPF_MAP_TYPE_HASH_OF_MAPS`. Create an outer array map that holds references
to inner LPM tries. Swap by updating the outer map entry to point to the new
inner trie. This is cleaner than named A/B maps but more complex to set up
with aya.

**Recommendation:** Start with the simple A/B pattern (matches what we already
do for tree nodes). Graduate to map-in-map if we need many independent
prefix lists (the A/B approach requires 2 maps per list).

### Incremental Updates vs Full Swaps

For prefix lists fed by external sources, two update modes:

**Full swap (blue/green):** Replace the entire list atomically. Best for
batch updates from threat intel feeds that provide complete lists.

**Incremental updates:** Insert/delete individual entries in the active list.
Best for real-time feeds (e.g., Holon adding IPs as it detects them). No swap
needed — individual map updates are atomic at the entry level.

The two modes aren't mutually exclusive. Use incremental for Holon's live
detections, full swap for periodic bulk loads from external sources.

---

## 14. Prefix Lists: ipset Inspiration

### netfilter ipset Features Worth Emulating

Linux `ipset` is the gold standard for kernel-space IP set management. Key
features we should study and selectively adopt:

**Timeout/TTL (ipset has this):**
```bash
ipset create bad-sources hash:ip timeout 3600  # entries expire after 1 hour
ipset add bad-sources 10.0.0.200 timeout 600   # this one expires in 10 minutes
```

Our design already includes TTL on prefix list entries. The `PrefixEntry`
value in the LPM trie stores an expiry timestamp.

**Counters (ipset has this):**
```bash
ipset create tracked hash:ip counters
# Each entry tracks packets and bytes matched
```

We should store `{expiry_ts, packet_count, byte_count}` in prefix list
entries. The eBPF walker atomically increments counters when an entry matches.
This gives per-IP observability without separate counter rules.

**Comment/metadata (ipset has this):**
```bash
ipset add bad-sources 10.0.0.200 comment "detected by holon window 42"
```

Userspace-only metadata — store in a sidecar HashMap alongside the BPF entry.
Useful for audit trails ("why is this IP blocked?").

**Set types we should support:**

| ipset Type | Our Equivalent | Implementation |
|---|---|---|
| `hash:ip` | LPM trie with /32 prefixes | `BPF_MAP_TYPE_LPM_TRIE` |
| `hash:net` | LPM trie with variable prefixes | Same, native CIDR support |
| `hash:ip,port` | Compound key in HashMap | `BPF_MAP_TYPE_HASH` |
| `hash:net,port` | Two-stage: LPM trie + edge | LPM for net, then tree edge for port |
| `bitmap:port` | BPF array (65536 entries) | `BPF_MAP_TYPE_ARRAY` — O(1) lookup |

**Eviction strategies beyond TTL:**

| Strategy | ipset | Our Approach |
|---|---|---|
| Timeout (TTL) | Native | Store expiry_ts, periodic sweep |
| LRU | Not native | Touch timestamp on match, evict oldest |
| Max size | `maxelem` flag | Reject inserts beyond capacity |
| Forceadd | `forceadd` flag | On full, evict random entry to make room |

**Recommendation:** Implement TTL + max size first. LRU is a nice-to-have
but requires updating the entry on every match (write amplification in eBPF).
Forceadd is useful for Holon's live detection where we'd rather evict a stale
entry than fail to block a new attacker.

### PrefixEntry Struct

```rust
#[repr(C)]
struct PrefixEntry {
    expiry_ns: u64,      // 0 = permanent, else ktime_get_ns() deadline
    packets: u64,         // atomically incremented on match
    bytes: u64,           // atomically incremented on match
    action: u8,           // ACT_DROP, ACT_RATE_LIMIT, etc.
    flags: u8,            // reserved
    _pad: [u8; 6],
}
```

32 bytes per entry. At 1M entries in an LPM trie, ~32MB. Comfortable.

---

## 15. HyperLogLog: Placement Decision

### Question

Is HLL a firewall feature (eBPF) or a sidecar/Holon feature?

### Answer: Both, Different Roles

**eBPF-side HLL (in `veth_filter`):**
- Runs on EVERY packet (not just sampled ones)
- Gives ground-truth cardinality for the full traffic stream
- 256 bytes per counter, ~10 instructions per observe
- Best for: real-time cardinality tracking as a first-class XDP metric

**Sidecar-side HLL (in Holon analysis):**
- Runs on SAMPLED packets only
- Gives approximate cardinality (subject to sample rate)
- But can be combined with Holon's vector analysis for richer signals
- Best for: enriching anomaly detection with cardinality context

**Recommendation: eBPF-side for core metrics, sidecar-side for detection.**

The eBPF program maintains a few HLL counters (src_ip, dst_port, src_port)
updated on every packet. The metrics reactor reads these and reports exact*
cardinality. (* ~5% error, but over the full stream, not sampled.)

The sidecar uses the cardinality estimates as additional signals for rule
generation. "Unique source IPs jumped from 50 to 50,000" is a detection
trigger, not just a metric.

**What about Holon vectors?**

HLL and Holon vectors answer different questions:
- **Holon drift:** "Has the traffic distribution changed?" (distributional)
- **HLL cardinality:** "How many unique values exist?" (counting)

They're complementary. A DDoS with 50K unique IPs attacking one port will
show high drift AND high source cardinality. An amplification attack from
3 IPs will show high drift but LOW source cardinality. HLL disambiguates
attack types that Holon's drift score alone cannot.

HLL doesn't belong in the Holon primitive library itself — it's not a VSA
operation. It's a separate observability primitive that lives alongside Holon
in the sidecar's analysis pipeline.

---

## Updated Priority Table

| Feature | Complexity | eBPF Changes | Value |
|---|---|---|---|
| RHS syntax redesign | Low | None | High |
| EDN rule parser | Low | None | High |
| Named rate limiters | Low | None | High |
| Compound naming | Low | None | Medium |
| Count action | Medium | New map + action type | Medium |
| Metrics reactor | Medium | Read-only (new reads) | High |
| `In` predicate | Low | None (compiler only) | High |
| Negation (`not`) | Medium | Exclusion field on TreeNode | Medium |
| Range predicates | Medium | Node annotation or expansion | Medium |
| Bitmask predicate | Medium | Node annotation | Medium |
| Dynamic prefix lists (LPM) | High | New map type + predicate | High |
| Blue/green prefix lists | Medium | Double-buffered LPM tries | Medium |
| ipset-style counters/TTL | Medium | PrefixEntry struct in LPM | High |
| HyperLogLog (eBPF) | Medium | Small array + observe fn | High |
| HyperLogLog (sidecar) | Low | None (reads eBPF HLL) | Medium |
| Bloom filters | Medium | New map type | Low (niche) |

### Updated Implementation Order

**Batch 1 — Foundation (no eBPF changes):**
1. RHS syntax redesign (struct changes, formatting, JSON parsing)
2. EDN parser integration (`edn-rs` or `edn-format`)
3. Named rate limiters + compound naming
4. `In` predicate (compiler-only, multi-edge to shared child)

**Batch 2 — eBPF observability:**
5. Count action (new map, new action type in walker)
6. HyperLogLog in `veth_filter` (per-field cardinality)
7. Metrics reactor (async collection + emission loop)

**Batch 3 — eBPF predicates:**
8. Negation (exclusion field on TreeNode)
9. Range predicates (start with expansion, then node annotation)
10. Bitmask predicate (node annotation)

**Batch 4 — Scale features (prefix lists):**
11. Dynamic prefix lists (LPM tries with ipset-style TTL + counters)
12. Blue/green prefix list swaps
13. Holon integration (auto-populate prefix lists from detection)
14. Cross-field OR (compiler rule duplication)
15. Bloom filters (if needed)
