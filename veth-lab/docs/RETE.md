# Tree Rete: Clara at Line Rate

**Objective:** Implement a Rete-style discrimination network that evaluates compound rules at XDP line rate — achieving what Clara (Clojure's Rete implementation) does for business rules, but for packet filtering at 1M+ rules in the kernel.

## How This Maps to Rete

### Classic Rete (Forgy, 1979)

The Rete algorithm has two core structures:

- **Alpha network** — Tests individual conditions against facts. Shares nodes when multiple rules test the same condition. Routes facts to the rules they might match.
- **Beta network** — Joins partial matches across conditions. "Fact X matched condition A" AND "fact Y matched condition B" → composite match. Stores intermediate join results in beta memories.
- **Conflict resolution** — When multiple rules fire, pick one (typically by priority or specificity).

The fundamental insight: **don't evaluate every rule against every fact.** Build a shared discrimination network and let the structure do the work.

### Our Implementation

We split Rete across two execution domains:

```
┌─────────────────────────────────────────────────────────┐
│                  USERSPACE (Sidecar)                     │
│                                                          │
│   RuleSpecs ──► DAG Compiler ──► FlatTree                │
│                                                          │
│   This IS the beta network:                              │
│   - Joins constraints across dimensions                  │
│   - Memoizes intermediate join results                   │
│   - Rc<ShadowNode> shares identical subtrees             │
│   - Content-hash deduplication = beta memory sharing     │
│   - Executed ONCE at compile time                        │
│                                                          │
│   Output: materialized join structure (the tree itself)  │
│                                                          │
├────────────────── blue/green flip ───────────────────────┤
│                                                          │
│                  KERNEL (XDP + BPF tail calls)           │
│                                                          │
│   Packet ──► extract fields ──► DFS trie traversal       │
│                                                          │
│   This IS the alpha network:                             │
│   - Tests one field per tree level                       │
│   - Shared nodes (proto=17 tested once, not per-rule)    │
│   - Multi-path activation (specific + wildcard edges)    │
│   - Collects ALL matching terminal nodes                 │
│   - Conflict resolution: highest priority wins           │
│   - Executed PER PACKET at line rate                     │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Alpha Network — eBPF Tree Walker

The alpha network is the per-packet discrimination network running in XDP:

| Rete Concept | Our Implementation |
|---|---|
| Alpha nodes (single-condition tests) | Tree levels — each tests one packet field dimension |
| Shared alpha nodes | DAG structure — 500K rules with `proto=17` share one node |
| Alpha memory | Not needed — packets are transient, not persistent facts |
| Multi-path activation | DFS explores ALL matching paths (specific + wildcard) |
| Working memory elements | Individual packets (single-fact matching) |

The DFS trie traversal is faithful to Rete's spirit: it doesn't follow ONE path to ONE rule. It explores ALL matching paths through the shared discrimination network and collects every terminal match. This is exactly what the alpha network does — activate all paths that a fact satisfies.

Each DFS step is a ~100-instruction BPF program (`tree_walk_step`) that tail-calls itself. The kernel enforces a maximum of 33 tail calls, giving us up to 32 DFS steps — plenty for a 9-dimension tree with wildcard exploration.

### Beta Network — Userspace DAG Compiler

The beta network is the compile-time join phase running in the sidecar:

| Rete Concept | Our Implementation |
|---|---|
| Beta nodes (join conditions) | `compile_recursive` — partitions rules by dimension, joins constraints |
| Beta memory (cached partial matches) | Memoization cache keyed by `(rule_set_hash, dimension_index)` |
| Shared beta memory | `Rc<ShadowNode>` — identical subtrees from different join paths share one node |
| Join ordering | Fixed dimension order: Proto → SrcIp → DstIp → Ports → TCP fields |
| Token propagation | Not needed — all rules are known upfront, joins are pre-computed |

The key insight: **the tree IS the materialized beta network.** Every path from root to leaf represents a fully joined production — all conditions combined into a single traversal structure. Classic Rete computes joins at runtime as facts arrive. We pre-compute all joins once and bake them into the tree. The eBPF walker then traverses the pre-joined result.

The memoization cache is literally caching intermediate join results: "for this set of rules at this point in the dimension order, here's the subtree that represents all their remaining constraints joined together." When two different join paths produce identical remaining constraint sets, `Rc<ShadowNode>` shares the result — exactly what beta memory does.

This is an optimization the Rete literature calls **compile-time join ordering**: since all rules are known upfront, you pre-compute the optimal join structure rather than discovering joins dynamically.

### Conflict Resolution

| Rete Concept | Our Implementation |
|---|---|
| Conflict set | All terminal nodes found by DFS |
| Resolution strategy | Highest priority (lowest numeric value) wins |
| Firing | Single action executed: DROP, RATE_LIMIT, or PASS |

The DFS collects every matching terminal node, then the highest-priority match determines the action. This is textbook Rete conflict resolution.

### What We Don't Need (And Why)

**Beta joins across fact types** — Classic Rete joins facts of different types ("person X" + "order Y" where X.id = Y.customer_id). Our working memory contains a single fact type (packets), and each packet is matched independently. There's nothing to join across. The beta join simplifies to conjunction of conditions on a single fact — which is exactly what the tree structure represents.

**Incremental update** — Rete incrementally propagates working memory changes through the network. Our "working memory" is ephemeral — packets are transient, not persistent facts. We do rebuild the entire tree on rule changes (via blue/green flip), but this is the right trade-off: rules change rarely (seconds), packets arrive constantly (millions/sec).

**Temporal memory** — Rete caches partial matches between evaluation cycles. We don't need this because each packet evaluation is independent.

## Clara at Line Rate

[Clara](https://github.com/cerner/clara-rules) is a Rete implementation for Clojure that makes production rule systems accessible with a clean API and s-expression rule syntax:

```clojure
(defrule high-ttl-amplification
  [Packet (= proto 17) (= ttl 255) (= df-bit 0)]
  =>
  (insert! (RateLimit. src-addr 2000)))
```

Our system achieves the same expressive power, but the evaluation runs at XDP line rate in the kernel:

```
((and (= proto 17)
      (= ttl 255)
      (= df 0)
      (= src-addr 10.0.0.100))
 =>
 (rate-limit 2091))
```

| Property | Clara | Tree Rete (Ours) |
|---|---|---|
| Rule syntax | Clojure s-expressions | S-expressions (Clara-style LHS ⇒ RHS) |
| Execution | JVM, userspace | XDP, kernel, line rate |
| Rule capacity | Bounded by JVM memory | **1,000,000 rules proven** |
| Per-fact cost | O(matched conditions) | **~5 BPF tail calls, independent of rule count** |
| Alpha sharing | Yes (Rete alpha network) | Yes (DAG tree structure) |
| Beta joins | Runtime | **Compile-time (pre-materialized in tree)** |
| Conflict resolution | Priority/specificity | Priority (highest wins) |
| Incremental updates | Yes (fact-by-fact) | Blue/green atomic flip (~4s for 1M rules) |
| Rule derivation | Manual | **Autonomous** (Holon VSA/HDC anomaly detection) |

The last row is what makes this different from any existing Rete implementation. Clara requires a human to write rules. Our system **derives rules from the math** — vector magnitude ratios determine rate limits, concentration analysis determines which fields to constrain, and the compound rule emerges automatically. The Rete network then enforces it at line rate.

## The Architecture in One Sentence

The sidecar's DAG compiler is a compile-time beta network that pre-joins rule conditions into a materialized discrimination tree; the eBPF tail-call DFS is a line-rate alpha network that evaluates all matching paths and resolves conflicts by priority — together implementing Rete split across userspace and kernel, with rules derived autonomously from hyperdimensional vector analysis.
