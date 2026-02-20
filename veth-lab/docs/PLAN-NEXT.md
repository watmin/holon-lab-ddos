# Next Phase: Design Notes

**Planning document for implementation. Each section is a self-contained spec
that can be handed to a capable model for implementation.**

**Last updated:** 2026-02-20

---

# Part I — Completed Work

## ✅ 1. EDN Rule Language & RHS Syntax [COMPLETED 2026-02-13]

**See:** `docs/COMMIT-EDN-IMPLEMENTATION.md` for full details.

### What Was Done

Migrated from JSON to EDN as the primary rule format, with a clean map-based
RHS syntax separating actions from metadata.

- **EDN parser** via `edn-rs` with auto-detection (JSON still supported)
- **Streaming parser**: 1M rules in 2.74s, constant memory
- **File size**: 40% smaller than JSON (887KB vs 1.5MB for 10K rules)
- **RHS as map**: `{:actions [(rate-limit 500)] :priority 200}`
- **Multiple actions per rule**: `{:actions [(rate-limit 500) (count)]}`
- **Pretty-print formatting** for logs

### Rule Syntax

```clojure
;; Full rule with all features
{:constraints [(= proto 6)
               (= tcp-flags 2)]
 :actions     [(rate-limit 500 :name ["game" "syn-limit"])
               (count :name ["monitoring" "syn-attempts"])]
 :priority    200}
```

**Files changed:** `sidecar/Cargo.toml`, `sidecar/src/main.rs`,
`filter/src/lib.rs`

---

## ✅ 2. Named Rate Limiters & Compound Naming [COMPLETED 2026-02-13]

### What Was Done

Implemented namespaced shared rate limiter buckets and extended compound
naming to all four action types (pass, drop, rate-limit, count).

- **Compound names**: `:name ["namespace" "name"]` tuple format
- **Shared buckets**: Rules with same name share one token bucket
- **Bucket key**: `hash(namespace + name)` for named, `canonical_hash()` for unnamed
- **PPS conflict handling**: Last-defined value wins, with warning
- **All actions support `:name`**: pass, drop, rate-limit, count

### Behavior

```edn
;; Three rules share the ["attack" "dns-amp"] bucket
{:constraints [(= proto 17) (= dst-port 53) (= src-addr "10.0.0.100")]
 :actions [(rate-limit 1000 :name ["attack" "dns-amp"])]}

{:constraints [(= proto 17) (= dst-port 53) (= src-addr "10.0.0.101")]
 :actions [(rate-limit 1000 :name ["attack" "dns-amp"])]}

;; Per-rule bucket (unnamed, backward compatible)
{:constraints [(= proto 17) (= src-addr "10.0.0.200")]
 :actions [(rate-limit 100)]}
```

**Suggested namespaces:** `"attack"`, `"monitor"`, `"test"`, `"manual"`

**Files changed:** `filter/src/lib.rs` (`bucket_key()`, `RuleAction` enum),
`filter/src/tree.rs`, `sidecar/src/main.rs`

---

## ✅ 3. Count Action (Non-Terminating) [COMPLETED 2026-02-13]

### What Was Done

Added non-terminating Count actions that increment a counter without
stopping the DFS walk. Packets continue to be evaluated against other rules.

- **`ACT_COUNT = 3`** in eBPF
- **`TREE_COUNTERS: HashMap<u32, u64>`** (100k max entries)
- **Non-terminating**: Increment counter, don't compete on priority, keep walking
- **Named counters**: `(count :name ["monitor" "syn-packets"])`

### eBPF Logic

```rust
if node.action == ACT_COUNT {
    // Non-terminating: increment and continue
    TREE_COUNTERS.increment(node.rule_id);
    // Don't update best_action — keep walking
} else if node.priority >= state.best_prio {
    // Terminating: compete on priority
    state.best_action = node.action;
    state.best_prio = node.priority;
}
```

**Files changed:** `filter-ebpf/src/main.rs`, `filter/src/lib.rs`,
`filter/src/tree.rs`, `sidecar/src/main.rs`

---

## ✅ 4. Predicate Extensions [COMPLETED 2026-02-14]

### ✅ 4a. Range Predicates (Gt, Lt, Gte, Lte)

Implemented with eBPF runtime evaluation (node annotation, not expansion).

- **Range edge slots**: Each `TreeNode` has up to 2 range edge slots
  (`range_op_0/1`, `range_val_0/1`, `range_child_0/1`)
- **3-way partitioning** at each dimension: Eq → specific edges, Range → range
  edges, unconstrained → wildcard child
- **No expansion**: `(> dst-port 1000)` is a single range edge, not 64K rules
- **Live tested** with ~27M packets, 42 tests pass

### ✅ 4b. Bitmask & Byte Matching Predicates

What started as a simple bitmask predicate evolved into a comprehensive
three-tiered matching system.

**Three tiers:**

1. **`MaskEq` guard edges** on pre-extracted fields (1-2 bytes).
   `(value & mask) == expected` semantics via `RANGE_OP_MASK_EQ = 5`.
   - `(mask-eq <field> <mask> <expected>)` — generic on any field
   - `(protocol-match <match> <mask>)` — sugar for protocol field
   - `(tcp-flags-match <match> <mask>)` — sugar for TCP flags field

2. **Custom dimension fan-out** (1-4 byte exact matches at L4 offsets).
   `FieldDim::Custom0-Custom6` (indices 9-15) dynamically assigned at compile
   time. Enables O(1) HashMap edge lookup for short L4 byte patterns.
   - `(l4-match <offset> "<hex-match>" "<hex-mask>")` where len 1-4

3. **`PatternGuard` edges** referencing `BYTE_PATTERNS` BPF map (5-64 bytes).
   Byte-by-byte comparison against pre-copied `DfsState.pattern_data`.
   Match/mask bytes are pre-shifted at compile time for verifier compliance.
   - `(l4-match <offset> "<hex-match>" "<hex-mask>")` where len 5-64

**Key eBPF innovations:**
- `DfsState.pattern_data: [u8; 64]` — pre-copies transport payload for PatternGuard
- Custom dimensions extracted directly from packet in `veth_filter` (arbitrary offset)
- Pre-shifted `BytePattern` eliminates runtime offset arithmetic
- Frequency-based custom dim allocation (most-used combos get O(1) fan-out slots)
- `BYTE_PATTERNS` map scaled to 65K entries (~8.5 MB) for massive multi-tenancy

**Multi-tenant byte matching:**
- **Arbitrary offset custom dims:** 1-4 byte matches at ANY packet offset (not
  limited to pattern_data's 64-byte window). `extract_custom_dim_from_packet`
  reads directly from the XDP packet context where pointers are verified.
- **Frequency-based slot allocation:** The 7 custom dim slots are assigned to
  the `(offset, length)` combos used by the most rules, maximizing O(1) fan-out
  benefit. Overflow combos fall back to PatternGuard (correct, just linear scan).
- **Tenant isolation:** Each tenant's rules occupy their own subtree in the DAG.
  Packets destined for tenant X only traverse X's subtree — other tenants' byte
  match guards are never evaluated.
- **Tenant limits:** `--max-byte-matches-per-scope N` enforces per-destination
  byte match density limits, preventing resource exhaustion.
- **Scale target:** 65K byte pattern entries, hundreds of concurrent tenants
  with different offsets and patterns.

### ✅ Per-Rule Metrics Manifest

All action types support `:name` and per-rule counter attribution.

- **DROP and PASS** actions increment `TREE_COUNTERS` for per-rule attribution
- Compiler returns authoritative `RuleManifestEntry` manifest mapping
  `rule_id` to action type and label
- Sidecar reports separate sections for Count, Rate-Limit, Drop, and Pass actions

**Comprehensive integration test:** 9 rules covering every predicate type
and every action variant, verified with live traffic across 3 traffic types.
See `veth-lab/scenarios/comprehensive-predicate-test.edn`.

---

## ✅ 5. IPv4 Header Fingerprinting [COMPLETED 2026-02-15]

**See:** `docs/IP-HEADER-FINGERPRINTING.md` for full details.

### What Was Done

Extended the packet extraction pipeline and rule language with 6 new IPv4
header dimensions for OS fingerprinting, fragment detection, and QoS abuse
identification. The Holon detection loop autonomously picks up these fields
and generates targeted mitigation rules.

- **6 new FieldDim variants:** `IpId`, `IpLen`, `Dscp`, `Ecn`, `MfBit`,
  `FragOffset` — expanding static dimensions from 9 to 15
- **DIM_ORDER redesign:** Dimensions ordered by discriminative power
  (Proto → SrcIp → DstIp → ... → Ttl → DfBit → ... → FragOffset).
  Justified by information-theoretic analysis, not byte order.
- **Dimension skipping:** Tree compiler skips unconstrained dimensions at
  zero runtime cost. A rule on only `FragOffset` (dim index 14) compiles
  to a tree that jumps directly to that dimension.
- **Expression language extensions:** `ip-id`, `ip-len`, `dscp`, `ecn`,
  `mf`, `frag-offset` as first-class dimension names in EDN rules
- **eBPF extraction:** All 6 fields extracted in the root XDP program
  alongside existing fields, stored in `DfsState.fields[]`
- **Autonomous detection validated:** Holon's `similarity_profile()` and
  `invert()` automatically surface the new fields in concentration analysis,
  generating rules like `(= ttl 64) (= df 0) (= dscp 46)` without any
  detection code changes

### Example Rules

```edn
;; OS fingerprinting: Linux botnet (sequential IP IDs in range)
{:constraints [(= proto 17) (= ttl 64) (>= ip-id 1000) (<= ip-id 2000)]
 :actions [(rate-limit 1000 :name ["fingerprint" "linux-botnet"])]
 :priority 180}

;; Fragment flood detection
{:constraints [(= proto 17) (> frag-offset 0)]
 :actions [(drop :name ["fingerprint" "fragmented"])]
 :priority 200}
```

**Files changed:** `filter-ebpf/src/main.rs` (extraction), `filter/src/lib.rs`
(FieldDim enum), `filter/src/tree.rs` (DIM_ORDER, compilation),
`sidecar/src/main.rs` (EDN parser)

---

## ✅ 6. BPF RingBuf Full-Packet Sampling [COMPLETED 2026-02-15]

### What Was Done

Replaced the per-CPU `PerfEventArray` sampling transport with a single shared
BPF `RingBuf`. Packets are now sampled in full (up to MTU) rather than just
header fields, enabling future payload-based detection.

- **BPF RingBuf (4MB shared):** Single ring buffer with overflow-drop
  semantics — when the sidecar can't consume fast enough, new samples are
  silently dropped rather than blocking the XDP fast path
- **Full packet copy:** `bpf_xdp_load_bytes()` copies the entire packet
  (up to 1500 bytes) into the ring buffer entry, not just extracted fields
- **Async consumption:** Sidecar uses `tokio::io::unix::AsyncFd` to
  poll the ring buffer FD without busy-waiting
- **Backward compatible:** `PacketSample` struct extended with packet
  payload bytes; existing Holon `Walkable` encoding continues to work
  on the header fields, ignoring extra payload bytes for now
- **XDP program untouched:** The XDP program still makes its own pass/drop
  decision independently — the ring buffer copy is fire-and-forget

### Architecture

```
XDP program (fast path)
  ├── Extract fields → DFS walk → pass/drop/rate-limit
  └── 1:N sample → bpf_ringbuf_reserve() → copy full packet → submit
                          ↓
Sidecar (async consumer)
  └── AsyncFd poll → read PacketSample → Holon encode → accumulate
```

**Key property:** The ring buffer is a "copy stream" — like an in-memory
pcap. The XDP program does its normal work and the sidecar gets a shadow
copy for analysis. No packet is delayed or lost due to sampling.

**Files changed:** `filter-ebpf/src/main.rs` (RingBuf map, sample logic),
`filter/src/lib.rs` (PacketSample struct), `sidecar/src/main.rs` (AsyncFd
consumer)

---

## ✅ 7. Real-Time Metrics Dashboard [COMPLETED 2026-02-15]

**See:** `docs/METRICS-DASHBOARD.md` for full details.

### What Was Done

Built an embedded web dashboard served directly by the sidecar, providing
real-time observability into XDP stats, rate limiter state, and rule DAG
structure.

- **SSE streaming:** Server-Sent Events at 500ms intervals push metrics
  to the browser with no polling overhead
- **Timeline visualization:** uPlot-based Grafana-like dark theme with
  passed/dropped/rate-limited rates and per-rule trendlines
- **DAG viewer:** Interactive tree visualization of the compiled Rete
  decision tree with node types, edge labels, and depth coloring
- **Monotonic counter tracking:** Correct delta computation across
  blue/green tree flips by tracking cumulative offsets
- **Zero dependencies:** Single `dashboard.html` file with inline CSS/JS,
  served by the sidecar's built-in HTTP server on `--metrics-port`

**Files changed:** `sidecar/src/main.rs` (SSE endpoint, metrics collector),
`sidecar/static/dashboard.html`

---

## ✅ 8. Token Bucket Precision & Compound Range Fix [COMPLETED 2026-02-15]

### What Was Done

Fixed two bugs that caused a sawtooth pattern in rate-limit enforcement
during live attack testing.

### 8a. Nanosecond-Precision Token Bucket

The millisecond-granularity refill logic discarded sub-millisecond remainders
on every packet, causing cumulative drift that significantly under-counted
tokens at high packet rates.

- **Credit accumulator:** `credit += elapsed_ns * rate_pps`. When credit
  reaches `NS_PER_SEC` (1 billion), one whole token is produced. The
  fractional remainder is preserved across packets.
- **No runtime division:** All arithmetic uses multiplication and constant
  division (`/ NS_PER_SEC`), which the LLVM BPF backend compiles to
  multiply-by-reciprocal. No runtime `div` instructions.
- **Overflow protection:** Elapsed time capped at 2 seconds to prevent
  `u64` overflow on the multiply (`2e9 * u32::MAX = 8.6e18 < u64::MAX`).

### 8b. Compound Range AND Semantics

The tree compiler's `compile_recursive_dynamic` extracted only the first
range predicate per dimension (via `find_map`) and advanced `dim_idx + 1`,
silently dropping subsequent predicates. A rule like
`(>= ip-id 1000) (<= ip-id 2000)` was compiled as just `(>= ip-id 1000)`,
matching ~98.5% of traffic instead of ~1.5%.

- **Fix:** Remove the matched predicate from the rule and recurse at the
  **same** `dim_idx`. Subsequent predicates on the same dimension are
  picked up in further recursive steps, chaining as AND guards.
- **Regression test:** `test_compound_range_and_semantics` covers
  in-range, boundary, and out-of-range cases across 8 packet profiles.

### 8c. Comprehensive Test Suite (15 new tests)

Added targeted tests for all edge cases identified after the fixes:

**Tree compiler (tree.rs):**
- Empty range `(>= 1000) (<= 999)` — never matches
- Single-point range `(>= 1000) (<= 1000)` — exact match
- 3+ predicates on same dimension (strict `>` and `<`)
- Cross-dimension compound ranges (TTL AND IpId)
- Range + exact match interaction with priority ladder
- Range predicates on new fingerprint dimensions (Dscp, IpLen, FragOffset)
- 7-rule realistic DDoS ruleset with 12 packet profiles
- Nested overlapping ranges across 5 value regions

**Token bucket (lib.rs):**
- Initial burst, drain/refill, fractional preservation
- 20K pps precision, overflow cap, zero rate, 1 pps exact
- Nano-token credit rollover verification

**Files changed:** `filter-ebpf/src/main.rs` (token bucket), `filter/src/lib.rs`
(TokenBucket struct + 8 tests), `filter/src/tree.rs` (compiler fix + 8 tests)

---

## Implementation Progress Summary

| Feature | Complexity | eBPF Changes | Status |
|---|---|---|---|
| EDN rule language | Medium | None | ✅ Done |
| RHS syntax redesign | Low | None | ✅ Done |
| Named rate limiters | Low | None (bucket key only) | ✅ Done |
| Compound naming | Low | None | ✅ Done |
| Count action | Medium | New map + action type | ✅ Done |
| Range predicates | Medium | Node annotation | ✅ Done |
| Bitmask & byte matching | High | Custom dims + pattern map | ✅ Done |
| Multi-tenant byte matching | Medium | Direct packet read + 65K patterns | ✅ Done |
| Per-rule metrics manifest | Medium | TREE_COUNTERS for all actions | ✅ Done |
| IPv4 header fingerprinting | High | 6 new fields, DIM_ORDER | ✅ Done |
| BPF RingBuf full-packet sampling | Medium | RingBuf map, bpf_xdp_load_bytes | ✅ Done |
| Real-time metrics dashboard | Medium | Read-only (SSE) | ✅ Done |
| Token bucket nanosecond precision | Medium | Credit accumulator | ✅ Done |
| Compound range AND semantics | Medium | None (compiler fix) | ✅ Done |
| Comprehensive test suite | Medium | None | ✅ Done (80 tests) |
| Thin LTO build optimization | Low | None (Cargo profile) | ✅ Done |
| OnlineSubspace (CCIPCA) | High | None | ✅ Done |
| Engram library + two-tier matching | High | None | ✅ Done |
| Surprise fingerprint (field attribution) | Medium | None | ✅ Done |
| Instant rule deploy on engram hit | Medium | None | ✅ Done |
| Payload-level engrams | Medium | None | ✅ Done |
| LPM trie prefix sets | High | New map type + predicate | Planned |
| Bloom filters | Medium | New map type | Planned |
| Metrics export pipeline | Low | None (SSE exists) | Planned |
| HyperLogLog (eBPF) | Medium | Small array | Planned |
| Vector-native cardinality | Low | None | Planned |
| Holon primitive integration | Low-Medium | None | Planned |

---

# Part II — Design Decision: Explicit Rules Over Meta-Predicates

**Decision (2026-02-14):** The `In` (set membership), `Not` (negation), and
`Or` (disjunction) predicates have been deliberately excluded from the rule
language. This is an opinionated design choice, not a limitation.

### Rationale

Each predicate must map 1:1 to a single DAG operation. "Helper" predicates
like `IN`, `NOT`, and `OR` create a representation gap — the user writes one
rule but the DAG gets multiple internally expanded rules with different
`rule_id`s. This makes debugging, metrics attribution, and reasoning about
rule behavior harder.

**What you lose:** Syntactic convenience for hand-authored rules.

**What you gain:**
- Every rule in the file maps to exactly one path in the DAG
- Every `rule_id` in metrics corresponds to exactly one user-visible rule
- No hidden expansion, no hidden duplication, no hidden exclusion logic
- Simpler compiler, fewer verifier edge cases

### How to Express These Patterns

**Instead of `(in src-port 53 123 5353)`:** Write 3 explicit rules. The DAG
compiler naturally shares the common subtree — same efficiency, full transparency.

**Instead of `(not (= proto 6))`:** Use priority-based conflict resolution.
A specific-match rule at higher priority with a wildcard catch-all at lower
priority achieves the same result with unambiguous intent.

**Instead of `(or (= proto 6) (= dst-port 80))`:** Write 2 rules. Each is
independently countable and debuggable.

### Shared Metric Aggregation

Users can still aggregate related rules into a single counter via shared
`:name` labels on actions:

```edn
;; Three explicit rules, one shared counter
{:constraints [(= proto 17) (= src-port 53)]
 :actions [(count :name ["monitor" "reflection-ports"])]}

{:constraints [(= proto 17) (= src-port 123)]
 :actions [(count :name ["monitor" "reflection-ports"])]}

{:constraints [(= proto 17) (= src-port 5353)]
 :actions [(count :name ["monitor" "reflection-ports"])]}
```

The "set" concept lives in the metrics/action layer via compound naming,
not in the predicate layer. This is a cleaner separation of concerns.

### Previously Implemented, Now Removed

The `In` predicate was previously implemented via compile-time expansion
into multiple Eq rules (DAG Rc sharing prevented subtree duplication). It
was removed because the expansion created a representation gap: one user
rule became N internal rules with different `rule_id`s, making metrics
attribution and debugging confusing. The `expand_in_predicates` function
and EDN parser support have been deleted.

---

# Part III — Planned: Prefix Lists

## 9. LPM Tries for IP Prefix Sets

### Problem

A common operational need: "block these 500K source IPs" or "rate-limit
traffic from these 10K CIDRs." Each IP is a separate rule in the DAG.
For very large IP sets, this is better served by a dedicated eBPF map.

### Design: LPM Trie

Use `BPF_MAP_TYPE_LPM_TRIE` — the kernel's native
longest-prefix-match data structure. Handles CIDRs natively
(`10.0.0.0/8` is a single entry, not 16M entries).

```rust
// Key: prefix + address
struct LpmKey {
    prefix_len: u32,  // e.g., 32 for /32, 24 for /24
    addr: u32,        // IP address
}

static BAD_SOURCES: LpmTrie<LpmKey, u64> = LpmTrie::with_max_entries(1_000_000, 0);
```

**eBPF lookup:** Tree node references a set by ID, DFS checks membership via
map lookup instead of edge lookup:

```rust
let key = LpmKey { prefix_len: 32, addr: src_ip };
if let Some(entry) = BAD_SOURCES.get(&key) {
    if *entry == 0 || *entry > now_ns { /* match */ }
}
```

**Requires:**
1. New BPF map (LPM trie)
2. New predicate: `InSet(FieldRef, SetId)`
3. New check in `tree_walk_step`: map lookup at set-check nodes
4. Userspace management of set contents (add/remove without recompiling tree)

### Bloom Filters (Extreme Scale)

For very large sets (>1M entries) where some false positives are acceptable:

```
BPF_MAP_TYPE_BLOOM_FILTER  (kernel 5.16+)
```

Usage: Userspace inserts IPs into bloom filter map. eBPF checks
`bloom_filter.contains(src_ip)`. Best for rate-limiting (not hard DROP)
where false positives are tolerable.

**Recommendation:** Start with LPM tries for prefix sets. Bloom filters
are the escape hatch for extreme scale if needed.

**Files to change:**
- `filter-ebpf/src/main.rs` — New LPM trie map, set-check logic in DFS
- `filter/src/lib.rs` — `Predicate::InSet`, set registry
- `filter/src/tree.rs` — Compiler handles set-check nodes
- `sidecar/src/main.rs` — Set management, parsing `(in-set ...)` syntax

---

## 10. Dynamic Prefix Lists (Lazy Accumulation)

### Problem

Instead of expressing 10K individual `(= src-addr ...)` rules, accumulate
"bad" source addresses into a prefix list that rules reference by name. The
list grows lazily as the system detects new offenders, and entries expire
after a TTL.

### Design

```clojure
;; Rule references a dynamic prefix list by name
{:constraints [(in-prefix-list src-addr "bad-sources")]
 :actions [(rate-limit 100)]
 :priority 200}
```

The prefix list is populated by the detection engine:

```rust
// When Holon detects a concentrated src-addr in anomalous traffic:
prefix_lists.insert("bad-sources", src_addr, ttl: Duration::from_secs(3600));
```

### Implementation: LPM Trie with TTL

One LPM trie per list, pre-created at startup. Value stores expiry timestamp:

```rust
static BAD_SOURCES: LpmTrie<LpmKey, u64> = LpmTrie::with_max_entries(1_000_000, 0);
// Value: expiry_ns (0 = permanent)
```

**Userspace management:**
- Insert: `lpm_trie.insert(LpmKey { prefix_len: 32, addr: ip }, expiry_ts)`
- Eviction: Periodic sweep deleting entries where `expiry_ts < now`
- No tree recompilation needed — the prefix list is checked at runtime

**This is powerful.** The tree says "check prefix list X for src-addr" and
the prefix list is managed independently. Adding 10K IPs is 10K map updates,
not a tree recompile. Entries auto-expire.

### Interaction with Holon

When Holon detects anomalous traffic concentrated on a source address:
1. Insert the source IP into `"bad-sources"` with a 1-hour TTL
2. A single tree rule `(in-prefix-list src-addr "bad-sources")` handles all
   current and future entries
3. As IPs expire, they stop matching without any tree recompilation

This is the **separation of policy (tree rule) from data (prefix list).**

---

## 11. Blue/Green Prefix Lists

### Design

**Double-buffered LPM tries** — same pattern as tree blue/green:

```rust
static PREFIX_LIST_A: LpmTrie<LpmKey, PrefixEntry> = LpmTrie::with_max_entries(1_000_000, 0);
static PREFIX_LIST_B: LpmTrie<LpmKey, PrefixEntry> = LpmTrie::with_max_entries(1_000_000, 0);
static PREFIX_LIST_ACTIVE: Array<u32> = Array::with_max_entries(1, 0);  // 0 = A, 1 = B
```

**Swap protocol:**
1. Load new prefix data into the inactive list (B)
2. Atomic write to `PREFIX_LIST_ACTIVE`: 0 → 1
3. eBPF reads `PREFIX_LIST_ACTIVE` to choose which trie to query
4. Old list (A) is now available for the next update

**Alternative:** `BPF_MAP_TYPE_ARRAY_OF_MAPS` — outer array holds references
to inner LPM tries. Cleaner but more complex to set up with aya.

### Update Modes

**Full swap (blue/green):** Replace entire list atomically. Best for batch
updates from threat intel feeds that provide complete lists.

**Incremental updates:** Insert/delete individual entries in the active list.
Best for real-time feeds (Holon adding IPs as it detects them). Individual
map updates are atomic at the entry level.

The two modes coexist: incremental for Holon's live detections, full swap
for periodic bulk loads from external sources.

---

## 12. ipset-Style Features

### netfilter ipset Features Worth Emulating

**Timeout/TTL:**
```bash
ipset create bad-sources hash:ip timeout 3600  # entries expire after 1 hour
ipset add bad-sources 10.0.0.200 timeout 600   # this one expires in 10 minutes
```
Our design includes TTL on prefix list entries via `PrefixEntry.expiry_ns`.

**Counters:** Store `{expiry_ts, packet_count, byte_count}` in prefix list
entries. eBPF atomically increments on match. Per-IP observability without
separate counter rules.

**Comment/metadata:** Userspace-only metadata stored in a sidecar HashMap
alongside the BPF entry. Useful for audit trails ("why is this IP blocked?").

### Set Types

| ipset Type | Our Equivalent | Implementation |
|---|---|---|
| `hash:ip` | LPM trie with /32 prefixes | `BPF_MAP_TYPE_LPM_TRIE` |
| `hash:net` | LPM trie with variable prefixes | Same, native CIDR support |
| `hash:ip,port` | Compound key in HashMap | `BPF_MAP_TYPE_HASH` |
| `hash:net,port` | Two-stage: LPM trie + edge | LPM for net, then tree edge for port |
| `bitmap:port` | BPF array (65536 entries) | `BPF_MAP_TYPE_ARRAY` — O(1) lookup |

### Eviction Strategies

| Strategy | Approach |
|---|---|
| Timeout (TTL) | Store `expiry_ts`, periodic sweep |
| LRU | Touch timestamp on match, evict oldest |
| Max size | Reject inserts beyond capacity |
| Forceadd | On full, evict random entry to make room |

**Recommendation:** TTL + max size first. Forceadd is useful for Holon's live
detection where we'd rather evict a stale entry than fail to block a new
attacker. LRU requires write amplification in eBPF (update entry on every match).

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

# Part IV — Planned: Observability

## 13. Metrics Collection & Emission Pipeline [PARTIALLY DONE]

### Current State

The real-time metrics dashboard (Section 7 above) implements the core of
this design. What exists:

- **Async metrics collector:** Dedicated `tokio::spawn` task at 500ms
  intervals, independent of the detection window
- **Per-CPU aggregation:** STATS map read with per-CPU summation
- **Delta computation:** Monotonic counter tracking with cumulative offsets
  across blue/green tree flips
- **Rate limiter state:** All `TREE_RATE_STATE` buckets read and reported
- **SSE emission:** Server-Sent Events push JSON metrics to the browser
- **Structured log emission:** `RATE_LIMIT` and `METRICS SANITY` lines
  in the sidecar log file

### What Remains

| Sink | Status | Notes |
|---|---|---|
| **Structured JSON log file** | ✅ Done | Via sidecar log + SSE JSON |
| **SSE to browser** | ✅ Done | Dashboard at `--metrics-port` |
| **Unix socket (line protocol)** | Planned | Telegraf/Vector compatible |
| **Prometheus `/metrics` endpoint** | Planned | Industry standard scrape |
| **StatsD UDP** | Planned | Broad ecosystem |

### Counter Draining

`TREE_COUNTERS` should be **read-and-reset**: read the value and write 0.
Accept a small race window (packets between read and reset counted in next
cycle). For high-fidelity: per-CPU counter map (same as STATS today).

---

## 14. HyperLogLog for Cardinality Estimation

### What It Does

A **HyperLogLog (HLL)** estimates distinct elements in a stream.
"How many unique source IPs are hitting port 443?" — HLL answers this
in ~256 bytes of memory with ~5% error.

### Why This Matters for DDoS

| Signal | What HLL Tells You |
|---|---|
| Source IP cardinality spike | Botnet activation (50 → 50,000 unique sources) |
| Destination port cardinality | Port scan detection |
| Low source cardinality + high PPS | Amplification attack (few sources, huge volume) |
| Source port cardinality | Randomized vs fixed source ports |

### Implementation in eBPF

BPF doesn't have a native HLL map type, but HLL is simple enough to
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

**Userspace reads 256 registers and computes the estimate:**

```rust
fn hll_count(registers: &[u8; 256]) -> f64 {
    let m = 256.0;
    let alpha = 0.7213 / (1.0 + 1.079 / m);
    let sum: f64 = registers.iter().map(|&r| 2.0_f64.powi(-(r as i32))).sum();
    alpha * m * m / sum
}
```

**256 bytes per HLL counter.** We could have dozens:
`HLL_SRC_IP`, `HLL_DST_PORT`, `HLL_SRC_PORT`, per-prefix HLLs.

### BPF Verifier Feasibility

The `hll_observe` function is ~10 instructions: one hash, one AND, one
shift, one leading_zeros, one array lookup, one compare, one conditional
store. Trivially verified. Can run in `veth_filter` alongside sampling.

**Reset:** HLLs need periodic reset (or decay) to track *recent*
cardinality. The metrics reactor can zero the registers at configurable
intervals.

**Integration:** Metrics reactor reads HLL registers, computes cardinality
estimates, and emits them. Cardinality changes between cycles are a
powerful anomaly signal that complements Holon's drift detection.

---

# Part V — Planned: Holon Primitive Integration

## 15. Vector-Native Cardinality & Field Diversity

### The Core Insight: Magnitude Encodes Diversity

In bipolar VSA, binding produces near-orthogonal vectors for different
filler values. When you accumulate (sum) bound vectors:

- **N copies of the SAME vector:** magnitude ≈ N (linear growth)
- **N ORTHOGONAL vectors:** magnitude ≈ √N (square-root growth)

The **magnitude-to-count ratio** is a cardinality signal:

| Scenario | Packets | Unique Sources | Magnitude | Ratio |
|---|---|---|---|---|
| Amplification | 1000 | 1 | ~1000 | ~1.0 |
| Mixed | 1000 | 10 | ~316 | ~0.316 |
| Botnet | 1000 | 1000 | ~31.6 | ~0.032 |

**No new data structure.** The accumulator you already have IS a cardinality
estimator.

### Per-Field Cardinality via Unbinding

Because binding is its own inverse in bipolar VSA, you can **query the
accumulator for field-specific information:**

```rust
// "What does the accumulator say about source IPs specifically?"
let src_ip_component = Primitives::bind(&accumulator_normalized, &role_src_ip);
let src_ip_diversity = src_ip_component.norm();
```

**One accumulator. Any field. On demand.** No per-field counters, no
per-field HLLs, no per-field maps. Just unbind and measure.

### Magnitude Spectrum: Per-Field Diversity Profile

Unbind with EVERY role vector to get a full diversity profile:

```rust
fn magnitude_spectrum(acc: &Vector, roles: &[(&str, &Vector)], count: usize)
    -> Vec<(String, f64)>
{
    roles.iter().map(|(name, role)| {
        let component = Primitives::bind(acc, role);
        let diversity = component.norm() / count as f64;
        (name.to_string(), diversity)
    }).collect()
}

// Example output during a DNS amplification attack:
// [("src_ip",   0.95),    ← very few unique sources
//  ("dst_port", 0.97),    ← one destination port
//  ("proto",    0.99),    ← one protocol (UDP)
//  ("src_port", 0.03),    ← many source ports (randomized)
//  ("dst_ip",   0.98)]    ← one destination IP (victim)
```

**Flat spectrum** = diverse traffic (normal).
**Spiky spectrum** = concentration in specific fields (attack).

### Accumulator Difference as Continuous Attribution

The raw accumulator difference preserves more information than similarity:

```rust
let delta: Vec<f64> = recent_acc.sums.iter()
    .zip(baseline_acc.sums.iter())
    .map(|(r, b)| r - b)
    .collect();

// Unbind delta with each role to get per-field change magnitude
let src_ip_change = bind_f64(&delta, &role_src_ip).norm();
// "Source IPs changed a lot, destination port barely changed"
// → New sources hitting same service = botnet recruitment
```

### Interference Detection: Correlated Concurrent Attacks

When two independent attacks overlap, their vectors superimpose. If
independent, magnitudes add in quadrature:

```
||attack_A + attack_B|| ≈ √(||attack_A||² + ||attack_B||²)
```

If observed magnitude EXCEEDS this (super-additive), the attacks share
structure — same botnet, same reflectors, correlated C2.

```rust
fn detect_attack_correlation(combined_magnitude: f64, individual: &[f64]) -> f64 {
    let independent = individual.iter().map(|m| m * m).sum::<f64>().sqrt();
    combined_magnitude / independent  // > 1.0 means correlated
}
```

### Where eBPF HLL Still Fits

| Signal | Source | What It Gives |
|---|---|---|
| Exact unique count | eBPF HLL | Dashboard metric, alerting threshold |
| Per-field diversity profile | Vector unbinding | Rich forensic signal |
| Cross-field correlation | Vector interference | Attack relationship detection |
| Rate derivation | Accumulator magnitude | Already implemented |
| Phase detection | Window vector sequence | Already implemented |

**Recommendation:** Vector-native cardinality FIRST (zero new infrastructure).
Add eBPF HLL later for exact counts.

### Novel VSA/HDC Contributions

These techniques appear novel in the VSA/HDC literature:

1. **Magnitude as volume proxy** — accumulator norm for rate derivation (implemented)
2. **Unbinding as cardinality estimator** — magnitude of unbound component
3. **Magnitude spectrum** — per-field diversity from systematic unbinding
4. **Interference detection** — super-additive magnitude as correlation signal
5. **Difference unbinding** — per-field attribution from accumulator delta

**Files to change:**
- `sidecar/src/main.rs` — new `analyze_field_diversity()` in detection loop
- `holon-rs/src/primitives.rs` — possibly add `unbind_spectrum()` convenience

**No eBPF changes. No new maps. No new data structures.**

---

## 16. Holon Primitive Applications

These are holon-rs primitives we're not using that have direct applications
in the detection loop. No eBPF changes for any of them.

### 16a. Accumulator Decay (Continuous Detection)

**What it does:** `accumulator.decay(factor)` multiplies all sums by a
factor (e.g., 0.99). Old observations lose weight exponentially.

**Current approach:** Fixed 2-second windows. Discrete detection.

**With decay:** No window resets. Continuous accumulation with exponential
forgetting. Detection becomes continuous — no blind spots at window
boundaries.

```rust
loop {
    let sample = receive_sample().await;
    let vec = holon.encode_walkable(&sample);
    recent_acc.add(&vec);
    packet_count += 1;

    if packet_count % 100 == 0 {
        recent_acc.decay(0.95);  // 5% forgetting per cycle
        let drift = holon.similarity(&recent_acc.normalize(), &baseline_vec);
        if drift < threshold { /* anomaly — no window boundary needed */ }
    }
}
```

**Benefits:** No window duration to tune. No missed attacks that start
mid-window. Smoother drift signal. Naturally adapts to attack speed.

**Trade-off:** Harder to reason about effective window size. The effective
window is `1 / (1 - decay_factor)` packets.

### 16b. Negate (Attack Peeling)

**What it does:** `Primitives::negate(superposition, component)` removes
a known component from a superposition.

**Application:** After detecting and mitigating attack A, check if there's
a hidden attack B underneath.

```rust
let cleaned = Primitives::negate(&recent_vec, &dns_attack_profile);
let residual_drift = holon.similarity(&cleaned, &baseline_vec);

if residual_drift < threshold {
    // Second attack detected! The DNS amp was masking it.
}
```

**Iterative peeling:** Detect → mitigate → peel → detect again. Finds N
layered attacks by removing each detected pattern.

### 16c. Prototype (Robust Attack Profiling)

**What it does:** `Primitives::prototype(vectors, threshold)` extracts the
common pattern across multiple vectors using majority agreement.

**Application:** Accumulate anomalous window vectors, then extract stable
attack profile:

```rust
if anomalous_windows.len() >= 3 {
    let attack_prototype = Primitives::prototype(&refs, 0.5);
    // Generate rules from prototype (more stable than any single window)
}
```

**Benefits:** Rules based on consensus across windows, not one snapshot.
Noisy single-window artifacts filtered out.

### 16d. Resonance (Anomaly Isolation)

**What it does:** `Primitives::resonance(vec, reference)` keeps only
dimensions where `vec` and `reference` agree.

**Application:** Separate normal traffic component from anomalous:

```rust
let normal_component = Primitives::resonance(&recent_vec, &baseline_vec);
let anomaly_signal = Primitives::difference(&recent_vec, &normal_component);
// Analyze pure anomaly signal with baseline noise removed
```

### 16e. Complexity (Baseline-Free Anomaly Signal)

**What it does:** `Primitives::complexity(vec)` returns 0.0–1.0 measure
of how "mixed" a vector is.

**Application:** Single-number anomaly signal without needing a baseline:

```rust
let c = Primitives::complexity(&recent_vec);
// Low complexity = homogeneous traffic = likely attack
// High complexity = diverse traffic = likely normal
```

Works from packet 1 (no warmup needed). Good for the warmup period when
baseline isn't established yet.

### 16f. Sequence Encoding (Flow-Level Detection)

**What it does:** `encode_sequence(items, Ngram { n: 3 })` encodes
3-element windows of a sequence, capturing local ordering patterns.

**Application:** Encode packet *flows* instead of individual packets:

```rust
// Encode 3-packet motifs
let trigram = holon.encode_sequence(&packet_window, SequenceMode::Ngram { n: 3 });
flow_acc.add(&trigram);

// Compare flow patterns to baseline
let flow_drift = holon.similarity(&flow_acc.normalize(), &baseline_flow_vec);
```

**Detects what per-packet can't:** SYN→RST→SYN→RST loops, slow scans,
protocol anomalies (data before handshake).

### 16g. Weighted Bundle (Confidence-Weighted Accumulation)

**What it does:** `accumulator.add_weighted(example, weight)` adds a
vector with a weight factor.

**Application:** Weight by novelty — dissimilar packets get higher weight:

```rust
let sim = holon.similarity(&vec, &recent_acc.normalize());
let novelty_weight = 1.0 - sim.abs();
recent_acc.add_weighted(&vec, novelty_weight);
```

Attack onset shows up sooner (first anomalous packets get high weight).

---

# Appendix — Workflow Notes

## Planning & Implementation Handoff

1. **Deep planning (Opus):** Architectural decisions, eBPF verifier strategies,
   algorithm design, tradeoff analysis. Output: a design section in this doc.

2. **Implementation (Sonnet):** Given a specific section, implement it. Each
   section is self-contained: structs to change, files to touch, eBPF impact.

3. **Review (Opus):** If Sonnet hits a wall (verifier issues, architectural
   questions), escalate back for analysis.

## Suggested Implementation Order

**Next batch — Detection enrichment (no eBPF changes, high impact):**
1. ~~Payload-based detection~~ → ✅ Done (payload subspace + payload engrams)
2. Vector-native cardinality (unbinding as diversity estimator)
3. Magnitude spectrum (per-field diversity profile)
4. Accumulator decay (continuous detection — eliminates window boundary blind spots)
5. Complexity as auxiliary signal (baseline-free, works during warmup)

**Scale features (eBPF map extensions):**
6. Dynamic prefix lists (LPM tries with TTL + counters)
7. Blue/green prefix list swaps
8. Holon integration (auto-populate prefix lists from detection)

**Advanced detection (no eBPF changes):**
9. Attack peeling via negate (layered attack detection)
10. Prototype for robust attack profiling
11. Sequence encoding for flow-level anomaly detection

**Observability extensions:**
12. Prometheus `/metrics` endpoint (industry-standard scrape target)
13. HyperLogLog in `veth_filter` (ground-truth cardinality for dashboards)

**Later:**
14. Bloom filters (if needed for extreme-scale prefix sets)
