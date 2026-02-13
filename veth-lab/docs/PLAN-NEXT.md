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

## 15. Vector-Native Cardinality & Field Diversity

### Revision Note

The original version of this section dismissed cardinality estimation as
"not a VSA operation." That was wrong. The magnitude-based rate derivation
already proved that accumulator geometry encodes traffic properties beyond
what standard VSA/HDC literature describes. The same principles extend to
cardinality estimation and far richer signals.

### The Core Insight: Magnitude Encodes Diversity

In bipolar VSA, binding produces near-orthogonal vectors for different filler
values. When you accumulate (sum) bound vectors:

- **N copies of the SAME vector:** magnitude ≈ N (linear growth)
- **N ORTHOGONAL vectors:** magnitude ≈ √N (square-root growth)
- **Mix:** magnitude is between √N and N

The **magnitude-to-count ratio** of an accumulator is a cardinality signal:

| Scenario | Packets | Unique Sources | Magnitude | Ratio (mag/count) |
|---|---|---|---|---|
| Amplification | 1000 | 1 | ~1000 | ~1.0 |
| Mixed | 1000 | 10 | ~316 | ~0.316 |
| Botnet | 1000 | 1000 | ~31.6 | ~0.032 |

High ratio → low cardinality (amplification: few sources, high volume).
Low ratio → high cardinality (botnet: many unique sources).

**This falls out of the existing algebra.** No new data structure. No HLL.
The accumulator you already have IS a cardinality estimator.

### Per-Field Cardinality via Unbinding

The full packet accumulator contains ALL fields superimposed. Because binding
is its own inverse in bipolar VSA (`bind(A, bind(A, X)) ≈ X`), you can
**query the accumulator for field-specific information:**

```rust
// "What does the accumulator say about source IPs specifically?"
let src_ip_component = Primitives::bind(&accumulator_normalized, &role_src_ip);

// Magnitude of this component reflects src_ip diversity
let src_ip_diversity = src_ip_component.norm();
```

Unbinding with `role_src_ip` extracts the subspace contributed by source IP
bindings. Cross-terms from other fields (dst_port, proto, etc.) are
near-orthogonal to this subspace and contribute only noise.

**One accumulator. Any field. On demand.** No per-field counters, no per-field
HLLs, no per-field maps. Just unbind and measure.

### Magnitude Spectrum: Per-Field Diversity Profile

Unbind the accumulator with EVERY role vector to get a full diversity profile:

```rust
fn magnitude_spectrum(
    acc: &Vector,
    roles: &[(&str, &Vector)],
    count: usize,
) -> Vec<(String, f64)> {
    roles.iter().map(|(name, role)| {
        let component = Primitives::bind(acc, role);
        let diversity = component.norm() / count as f64;
        (name.to_string(), diversity)
    }).collect()
}

// Example output during a DNS amplification attack:
// [("src_ip",   0.95),    ← very few unique sources (amplification!)
//  ("dst_port", 0.97),    ← one destination port (targeted)
//  ("proto",    0.99),    ← one protocol (UDP)
//  ("src_port", 0.03),    ← many source ports (randomized by reflectors)
//  ("dst_ip",   0.98)]    ← one destination IP (victim)
```

**Flat spectrum** = diverse traffic across all fields (normal).
**Spiky spectrum** = concentration in specific fields (attack).

This is richer than the current binary concentration metric. It gives a
**continuous diversity measure per field** from a single vector operation.

### Accumulator Difference as Continuous Attribution

The current approach uses `similarity_profile(recent, baseline)` for
per-dimension agreement/disagreement. The **raw accumulator difference**
preserves more information:

```rust
// Difference accumulator (what changed?)
let delta: Vec<f64> = recent_acc.sums.iter()
    .zip(baseline_acc.sums.iter())
    .map(|(r, b)| r - b)
    .collect();

// Unbind delta with each role to get per-field change magnitude
let src_ip_change = bind_f64(&delta, &role_src_ip).norm();
let dst_port_change = bind_f64(&delta, &role_dst_port).norm();
let proto_change = bind_f64(&delta, &role_proto).norm();

// "Source IPs changed a lot, destination port barely changed"
// → New sources hitting the same service = botnet recruitment
```

Unbinding the DIFFERENCE gives "how much did this specific field change?" —
a continuous attribution metric instead of "concentrated or not."

### Interference Detection: Correlated Concurrent Attacks

When two independent attacks overlap in time, their vectors superimpose. If
the attacks are truly independent (different sources, different targets, no
shared fields), their contributions are orthogonal and magnitudes add in
quadrature:

```
||attack_A + attack_B|| ≈ √(||attack_A||² + ||attack_B||²)
```

If the observed magnitude EXCEEDS this (super-additive), the attacks share
structure — same botnet, same reflectors, correlated command-and-control.

```rust
fn detect_attack_correlation(
    combined_magnitude: f64,
    individual_estimates: &[f64],  // magnitudes of suspected independent attacks
) -> f64 {
    let independent_expected = individual_estimates.iter()
        .map(|m| m * m)
        .sum::<f64>()
        .sqrt();

    // correlation_signal > 1.0 means attacks share structure
    combined_magnitude / independent_expected
}
```

Two independent SYN flood + DNS amplification → correlation ~1.0.
Same botnet running both → correlation > 1.0 (shared source IPs reinforce).

This is a signal NO per-field counter can give you. It emerges from the
superposition properties of the vector space itself.

### Where eBPF HLL Still Fits

The vector-native approach operates on **sampled** packets (1-in-100). It
gives rich compositional signals but with sample-rate noise.

eBPF-side HLL operates on **every packet.** It gives ground-truth cardinality
as a crisp number: "42,187 unique source IPs this window."

**They serve different purposes:**

| Signal | Source | What It Gives |
|---|---|---|
| Exact unique count | eBPF HLL | Dashboard metric, alerting threshold |
| Per-field diversity profile | Vector unbinding | Rich forensic signal |
| Cross-field correlation | Vector interference | Attack relationship detection |
| Rate derivation | Accumulator magnitude | Already implemented |
| Phase detection | Window vector sequence | Already implemented |

**Recommendation:** Implement vector-native cardinality FIRST (zero new
infrastructure). Add eBPF HLL later as a metrics feature if you need exact
counts for dashboards or external alerting systems.

### Implementation: Vector-Native Cardinality

**New sidecar analysis (no eBPF changes, no new maps):**

```rust
/// Per-field diversity profile from accumulator unbinding.
fn analyze_field_diversity(&self) -> FieldDiversityProfile {
    let roles = self.holon.role_vectors();  // pre-computed role vectors
    let acc_vec = self.recent_acc_normalized();
    let count = self.window_packet_count;

    let mut profile = FieldDiversityProfile::new();

    for (field_name, role_vec) in roles {
        // Unbind to extract field-specific component
        let component = Primitives::bind(&acc_vec, role_vec);
        let diversity = component.norm();

        // Compare to baseline diversity for this field
        let baseline_div = self.baseline_field_diversity.get(field_name);
        let change = diversity / baseline_div.max(1e-10);

        profile.insert(field_name.clone(), FieldDiversity {
            diversity,
            baseline_ratio: change,
            cardinality_class: classify_cardinality(diversity, count),
        });
    }

    profile
}

fn classify_cardinality(diversity: f64, count: usize) -> CardinalityClass {
    let ratio = diversity / (count as f64).max(1.0);
    if ratio > 0.8      { CardinalityClass::VeryLow }   // 1-3 unique values
    else if ratio > 0.3 { CardinalityClass::Low }        // handful
    else if ratio > 0.05 { CardinalityClass::Medium }    // tens to hundreds
    else                 { CardinalityClass::High }       // thousands+
}
```

**Integration with rule generation:**

```rust
// During anomaly detection, after drift exceeds threshold:
let diversity = self.analyze_field_diversity();

if diversity["src_ip"].cardinality_class == CardinalityClass::VeryLow {
    // Few unique sources → per-IP drop rules
    // (amplification pattern)
} else if diversity["src_ip"].cardinality_class == CardinalityClass::High {
    // Many unique sources → rate-limit on dst_port or proto
    // (botnet pattern — can't enumerate sources)
}
```

**Files to change:**
- `sidecar/src/main.rs` — new `analyze_field_diversity()` in detection loop
- `holon-rs/src/primitives.rs` — possibly add `unbind_spectrum()` convenience

**No eBPF changes. No new maps. No new data structures.** Just new questions
asked of the accumulator that already exists.

### Novel VSA/HDC Contributions

These techniques appear to be novel in the VSA/HDC literature:

1. **Magnitude as volume proxy** — using accumulator norm for rate derivation
   (already implemented, already novel)

2. **Unbinding as cardinality estimator** — magnitude of unbound component as
   field-specific diversity signal

3. **Magnitude spectrum** — per-field diversity profile from systematic
   unbinding of a single accumulator

4. **Interference detection** — super-additive magnitude as a correlated
   attack signal

5. **Difference unbinding** — per-field attribution from accumulator delta

All are consequences of bipolar VSA algebra applied to network traffic
characterization. Worth documenting as contributions.

---

## 16. Holon Primitive Integration — Untapped Toolkit

These are holon-rs primitives we're not using that have direct, pragmatic
applications in the detection loop. No eBPF changes for any of them.

### 16a. Accumulator Decay (Continuous Detection)

**What it does:** `accumulator.decay(factor)` multiplies all sums by a
factor (e.g., 0.99). Old observations lose weight exponentially.

**Current approach:** Fixed 2-second windows. Accumulate, normalize, compare,
reset. Detection is discrete — drift is computed once per window.

**With decay:** No window resets. The accumulator runs continuously. Every
N packets (or every M milliseconds), decay by a factor and compute drift.
Detection becomes continuous — no 2-second blind spots.

```rust
// Instead of: accumulate for 2s, check, reset
// Do: continuously accumulate with exponential forgetting
loop {
    let sample = receive_sample().await;
    let vec = holon.encode_walkable(&sample);

    recent_acc.add(&vec);
    packet_count += 1;

    // Decay every 100 packets (tuneable)
    if packet_count % 100 == 0 {
        recent_acc.decay(0.95);  // 5% forgetting per cycle

        // Continuous drift check
        let recent_vec = recent_acc.normalize();
        let drift = holon.similarity(&recent_vec, &baseline_vec);

        if drift < threshold {
            // Anomaly detected — no window boundary needed
        }
    }
}
```

**Benefits:**
- No window duration to tune (the decay factor replaces it)
- No "missed" attacks that start in the middle of a window
- Drift signal is smoother (no discrete jumps at window boundaries)
- Naturally adapts: fast attacks show up fast, slow attacks show up slow

**Trade-off:** Harder to reason about "how many packets contributed to this
signal." The effective window is `1 / (1 - decay_factor)` packets (for
decay=0.95, the effective window is ~20 packets before 50% contribution).

**Implementation:**
- `sidecar/src/main.rs` — replace window-based loop with continuous loop
- Can coexist: keep window-based for logging/metrics, add continuous for detection
- The magnitude-based rate derivation still works: `||recent_acc||` still
  correlates with volume, just with exponential weighting

### 16b. Negate (Attack Peeling)

**What it does:** `Primitives::negate(superposition, component)` removes
a known component from a superposition.

**Application:** After detecting and mitigating attack A, check if there's
a hidden attack B underneath.

```rust
// Detected DNS amplification, generated rule for it
let dns_attack_profile = compute_attack_profile(&anomalous_packets);

// Remove the known attack from the recent accumulator
let cleaned = Primitives::negate(&recent_vec, &dns_attack_profile);

// Does the cleaned signal still drift from baseline?
let residual_drift = holon.similarity(&cleaned, &baseline_vec);

if residual_drift < threshold {
    // Second attack detected! The DNS amp was masking it.
    // Repeat: analyze `cleaned` for concentrated fields, generate rules
    let second_anomaly = analyze_concentrated_fields(&cleaned, &baseline_vec);
}
```

**This is iterative peeling.** Detect → mitigate → peel → detect again.
It can find N layered attacks, one at a time, by removing each detected
pattern and looking at what remains.

**Implementation:**
- `sidecar/src/main.rs` — add peeling loop after initial anomaly detection
- Store detected attack profiles for peeling
- Max peeling depth (e.g., 3 layers) to prevent infinite loops on noise

### 16c. Prototype (Robust Attack Profiling)

**What it does:** `Primitives::prototype(vectors, threshold)` extracts the
common pattern across multiple vectors using majority agreement.

**Current approach:** Each anomalous window generates rules independently.
If an attack spans 5 windows, you get 5 slightly different rule sets.

**With prototype:** Accumulate anomalous window vectors, then extract the
common pattern:

```rust
let mut anomalous_windows: Vec<Vector> = vec![];

// Collect several anomalous windows
if drift < threshold {
    anomalous_windows.push(recent_vec.clone());
}

// After 3+ anomalous windows, extract stable attack profile
if anomalous_windows.len() >= 3 {
    let refs: Vec<&Vector> = anomalous_windows.iter().collect();
    let attack_prototype = Primitives::prototype(&refs, 0.5);

    // Generate rules from prototype (more stable than any single window)
    let concentrated = analyze_concentrated_fields(&attack_prototype, &baseline_vec);
}
```

**Benefits:**
- Rules are more stable (based on consensus across windows, not one snapshot)
- Noisy single-window artifacts get filtered out
- The prototype is the "essence" of the attack

**Implementation:**
- `sidecar/src/main.rs` — buffer anomalous windows, apply prototype before rule gen
- Threshold parameter controls how much agreement is needed (0.5 = majority)

### 16d. Resonance (Anomaly Isolation)

**What it does:** `Primitives::resonance(vec, reference)` keeps only
dimensions where `vec` and `reference` agree. Everything else is zeroed.

**Application:** Separate the "normal part" of traffic from the "anomalous
part":

```rust
// Extract what's normal about the recent window
let normal_component = Primitives::resonance(&recent_vec, &baseline_vec);

// The anomaly is everything that DOESN'T agree with baseline
let anomaly_signal = Primitives::difference(&recent_vec, &normal_component);

// Analyze the pure anomaly signal (baseline noise removed)
let concentrated = analyze_concentrated_fields(&anomaly_signal, &zero_vec);
```

**Benefits:**
- Cleaner anomaly signal (baseline noise removed)
- More precise concentration analysis (only looks at what changed)
- Works even when the attack is a small fraction of total traffic

### 16e. Complexity (Baseline-Free Anomaly Signal)

**What it does:** `Primitives::complexity(vec)` returns a 0.0–1.0 measure
of how "mixed" a vector is (density × balance of active dimensions).

**Application:** A single-number anomaly signal that doesn't need a baseline:

```rust
let recent_vec = recent_acc.normalize();
let c = Primitives::complexity(&recent_vec);

// Low complexity = homogeneous traffic = likely attack
// High complexity = diverse traffic = likely normal
if c < 0.3 {
    warn!("Low complexity ({:.2}) — traffic is unusually homogeneous", c);
}
```

**Benefits:**
- Works from packet 1 (no warmup needed)
- Complementary to drift (drift needs a baseline, complexity doesn't)
- Good for the warmup period when baseline isn't established yet

**Implementation:**
- Add to detection loop as an auxiliary signal
- Could trigger early detection during warmup windows

### 16f. Sequence Encoding (Flow-Level Detection)

**What it does:** `encode_sequence(items, Ngram { n: 3 })` encodes
3-element windows of a sequence, capturing local ordering patterns.

**Application:** Encode packet *flows* instead of individual packets:

```rust
// Maintain a sliding window of recent packet vectors
let mut flow_window: VecDeque<Vector> = VecDeque::with_capacity(3);

for sample in samples {
    let vec = holon.encode_walkable(&sample);
    flow_window.push_back(vec);

    if flow_window.len() == 3 {
        // Encode the 3-packet motif
        let refs: Vec<&Vector> = flow_window.iter().collect();
        let trigram = holon.encode_sequence(&refs, SequenceMode::Ngram { n: 3 });

        flow_acc.add(&trigram);
        flow_window.pop_front();
    }
}

// Compare flow patterns to baseline flow patterns
let flow_drift = holon.similarity(&flow_acc.normalize(), &baseline_flow_vec);
```

**What this detects that per-packet can't:**
- SYN→RST→SYN→RST loops (individual SYNs and RSTs are normal)
- Slow scans (SYN to port A → SYN to port B → SYN to port C)
- Protocol anomalies (data before handshake completes)

**Implementation:**
- Add flow accumulator alongside packet accumulator in detection loop
- Separate drift threshold for flow-level anomalies
- Higher latency (needs 3 packets to form a trigram) but deeper signal

### 16g. Weighted Bundle (Confidence-Weighted Accumulation)

**What it does:** `accumulator.add_weighted(example, weight)` adds a
vector with a weight factor.

**Application:** Not all sampled packets are equally informative. Weight by:
- **Packet size:** Larger packets carry more information
- **Novelty:** Packets dissimilar to the accumulator get higher weight
- **Recency within window:** Later packets may be more relevant

```rust
// Weight by novelty: dissimilar packets get higher weight
let sim = holon.similarity(&vec, &recent_acc.normalize());
let novelty_weight = 1.0 - sim.abs();  // high when dissimilar
recent_acc.add_weighted(&vec, novelty_weight);
```

**Benefits:**
- Novel traffic patterns are amplified (detected faster)
- Redundant traffic is dampened (less noise)
- Attack onset shows up sooner (first anomalous packets get high weight)

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
| Vector-native cardinality | Low | None | **Very High** |
| Magnitude spectrum | Low | None | **Very High** |
| Accumulator decay | Low | None | **Very High** |
| Attack peeling (negate) | Low | None | High |
| Prototype (robust profiling) | Low | None | High |
| Resonance (anomaly isolation) | Low | None | Medium |
| Complexity (baseline-free) | Low | None | Medium |
| Weighted accumulation | Low | None | Medium |
| Sequence/n-gram detection | Medium | None | High |
| `In` predicate | Low | None (compiler only) | High |
| Negation (`not`) | Medium | Exclusion field on TreeNode | Medium |
| Range predicates | Medium | Node annotation or expansion | Medium |
| Bitmask predicate | Medium | Node annotation | Medium |
| Dynamic prefix lists (LPM) | High | New map type + predicate | High |
| Blue/green prefix lists | Medium | Double-buffered LPM tries | Medium |
| ipset-style counters/TTL | Medium | PrefixEntry struct in LPM | High |
| HyperLogLog (eBPF) | Medium | Small array + observe fn | Medium |
| Bloom filters | Medium | New map type | Low (niche) |

### Updated Implementation Order

**Batch 1 — Foundation (no eBPF changes):**
1. RHS syntax redesign (struct changes, formatting, JSON parsing)
2. EDN parser integration (`edn-rs` or `edn-format`)
3. Named rate limiters + compound naming
4. `In` predicate (compiler-only, multi-edge to shared child)

**Batch 2 — Holon detection enrichment (no eBPF changes):**
5. TTL + tcp_window log-scale encoding (fuzzy field clustering)
6. Accumulator decay (continuous detection, no window resets)
7. Complexity as auxiliary signal (baseline-free, works during warmup)
8. Attack peeling via negate (layered attack detection)
9. Prototype for robust attack profiling (consensus across windows)
10. Resonance for anomaly isolation (remove baseline noise)
11. Weighted accumulation (novelty-weighted packets)

**Batch 3 — Vector-native intelligence (no eBPF changes):**
12. Vector-native cardinality (unbinding as diversity estimator)
13. Magnitude spectrum (per-field diversity profile)
14. Interference detection (correlated attack signal)
15. Cardinality-aware rule generation (botnet vs amplification strategy)
16. Sequence/n-gram flow detection (packet motif anomalies)

**Batch 4 — eBPF observability:**
17. Count action (new map, new action type in walker)
18. Metrics reactor (async collection + emission loop)
19. HyperLogLog in `veth_filter` (ground-truth cardinality for dashboards)

**Batch 5 — eBPF predicates:**
20. Negation (exclusion field on TreeNode)
21. Range predicates (start with expansion, then node annotation)
22. Bitmask predicate (node annotation)

**Batch 6 — Scale features (prefix lists):**
23. Dynamic prefix lists (LPM tries with ipset-style TTL + counters)
24. Blue/green prefix list swaps
25. Holon integration (auto-populate prefix lists from detection)
26. Cross-field OR (compiler rule duplication)
27. Bloom filters (if needed)
