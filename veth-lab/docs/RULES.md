# Rule Language Reference

**The expression language for defining packet filter rules — what's supported now, how to extend it, and the design philosophy behind raw numbers.**

## Philosophy

Rules use **raw numeric values everywhere**. `proto 6`, not `proto tcp`. `tcp-flags 2`, not `tcp-flags SYN`. This matches what you see in wireshark, tcpdump, and eBPF. No translation layer, no ambiguity about which symbolic name maps to which value.

The one exception: **IP addresses use dotted notation** (`10.0.0.200`) because a bare u32 like `167772360` is unreadable. Internally they're stored as `u32` in network byte order.

The syntax is modeled after Clojure's [Clara Rules](https://www.clara-rules.org/) — s-expressions with an LHS (conditions) `=>` RHS (action) structure.

## S-Expression Syntax

### Simple rule (one constraint)

```
((= proto 17) => (rate-limit 500))
```

### Compound rule (multiple constraints joined with `and`)

```
((and (= proto 17) (= src-port 53)) => (rate-limit 500))
```

### With explicit priority (default is 100, omitted when 100)

```
((and (= proto 6) (= tcp-flags 2)) => (drop) :priority 210)
```

### Pretty-printed (Clara style)

```
((and (= proto 17)
      (= src-port 53))
 =>
 (rate-limit 500))
```

## Field Reference

Fields are the dimensions of the decision tree. Every rule constrains one or more fields. Unconstrained fields are wildcards — the rule matches any value for that dimension.

| S-expr Name | FieldDim | Type | Description | Example Values |
|---|---|---|---|---|
| `proto` | Proto | u8 | IP protocol number | 6 (TCP), 17 (UDP), 1 (ICMP) |
| `src-addr` | SrcIp | IPv4 | Source IP address | `10.0.0.200`, `192.168.1.1` |
| `dst-addr` | DstIp | IPv4 | Destination IP address | `10.0.0.1` |
| `src-port` | L4Word0 | u16 | Source port (TCP/UDP) or ICMP type/code | 53, 123, 80 |
| `dst-port` | L4Word1 | u16 | Destination port (TCP/UDP) or ICMP checksum | 9999, 443, 22 |
| `tcp-flags` | TcpFlags | u8 | TCP flags bitmask | 2 (SYN), 18 (SYN+ACK), 16 (ACK) |
| `ttl` | Ttl | u8 | IP Time-To-Live | 64, 128, 255 |
| `df` | DfBit | u1 | Don't Fragment bit | 0, 1 |
| `tcp-window` | TcpWindow | u16 | TCP window size | 65535, 8192 |

### TCP Flags Quick Reference

| Value | Flags | Common Name |
|---|---|---|
| 2 | SYN | SYN |
| 18 | SYN+ACK | SYN-ACK |
| 16 | ACK | ACK |
| 1 | FIN | FIN |
| 4 | RST | RST |
| 24 | PSH+ACK | Push |
| 41 | FIN+PSH+ACK | FIN-Push |

### Tree Traversal Order

Fields are evaluated in this fixed order during tree traversal:

```
Proto → SrcIp → DstIp → L4Word0 → L4Word1 → TcpFlags → Ttl → DfBit → TcpWindow
```

The compiler skips dimensions that no rule in the current subtree constrains. The order is fixed at compile time — both the userspace compiler and eBPF walker agree on it.

## Actions

| S-expr | RuleAction | Description |
|---|---|---|
| `(pass)` | Pass | Explicitly allow the packet |
| `(drop)` | Drop | Hard drop — packet is silently discarded |
| `(rate-limit N)` | RateLimit | Token-bucket rate limiter at N packets/sec |

Rate limiters are keyed by the rule's canonical hash, which means:
- The same rule always maps to the same rate limiter (idempotent)
- Rate limiter state persists across blue/green tree flips
- Multiple packets matching the same rule share a single token bucket

## Priority

Priority is a `u8` (0–255). Higher value = higher priority. Default is 100.

When multiple rules match a packet (via the DFS multi-path walker), the highest-priority rule wins. This is the conflict resolution strategy — analogous to Rete's conflict set resolution.

```
;; Priority 210 beats priority 100 — the SYN flood rule takes precedence
((and (= proto 6) (= tcp-flags 2)) => (drop) :priority 210)
((= proto 6) => (rate-limit 5000))     ;; implicit :priority 100
```

## Wildcards

**Wildcards are implicit.** Any field not mentioned in a rule's constraints matches any value. There is no explicit wildcard syntax.

```
;; Matches ALL UDP traffic regardless of src/dst/ports/flags
((= proto 17) => (rate-limit 1000))

;; Matches DNS responses from anywhere to anywhere
((and (= proto 17) (= src-port 53)) => (rate-limit 500))

;; Matches everything from a specific source
((= src-addr 10.0.0.200) => (drop))
```

The eBPF DFS walker handles wildcards by exploring both the specific-value branch and the wildcard branch at each tree node. No wildcard replication needed in the compiled tree.

## Predicates

### Currently Implemented

| Form | Name | Description |
|---|---|---|
| `(= field value)` | Eq | Exact equality match |

### Designed for Extension (Not Yet Implemented)

The `Predicate` enum is explicitly designed for these future variants:

| Form | Name | Description |
|---|---|---|
| `(> field value)` | Gt | Greater than |
| `(< field value)` | Lt | Less than |
| `(>= field value)` | Gte | Greater than or equal |
| `(<= field value)` | Lte | Less than or equal |
| `(mask field bitmask)` | Mask | Bitmask test: `(field & bitmask) != 0` |
| `(in field val1 val2 ...)` | In | Set membership / disjunction |
| `(not pred)` | Not | Negation of a predicate |
| `(or pred1 pred2 ...)` | Or | Disjunction of predicates |

#### Range Example (Future)

```
;; Match TTL > 200 (suspicious, near max)
((and (= proto 6)
      (> ttl 200))
 =>
 (rate-limit 100))
```

**Implementation note:** Ranges can be compiled into the decision tree by expanding into discrete value edges at the compiler level, or by adding range-check logic to the eBPF walker. The enum is ready for either approach.

#### Bitmask Example (Future)

```
;; Match packets with SYN flag set (regardless of other flags)
((and (= proto 6)
      (mask tcp-flags 2))
 =>
 (rate-limit 500))
```

This would match SYN (2), SYN+ACK (18), SYN+FIN (3), etc. — anything with the SYN bit set.

#### Disjunction Example (Future)

```
;; Match DNS or NTP amplification sources
((and (= proto 17)
      (in src-port 53 123))
 =>
 (rate-limit 300))
```

#### Negation Example (Future)

```
;; Match non-TCP traffic to a specific port
((and (not (= proto 6))
      (= dst-port 9999))
 =>
 (drop))
```

### Byte-at-Offset (Future Concept)

For deep packet inspection beyond fixed fields:

```
;; Match specific byte pattern at offset 40
((and (= proto 6)
      (byte-at 40 0xFF))
 =>
 (drop))
```

This would require a new `FieldDim` variant and corresponding eBPF extraction logic. The tree architecture supports it — it's just another dimension.

## JSON Format

Rules are loaded from JSON files. The format maps directly to the s-expression structure:

```json
[
  {
    "constraints": [
      {"field": "proto", "value": 17},
      {"field": "src-port", "value": 53}
    ],
    "action": "rate-limit",
    "rate_pps": 500,
    "priority": 200
  },
  {
    "constraints": [
      {"field": "src-addr", "value": "10.0.0.200"},
      {"field": "dst-port", "value": 9999}
    ],
    "action": "drop",
    "priority": 150
  }
]
```

### Field Names in JSON

Same as s-expression names: `proto`, `src-addr`, `dst-addr`, `src-port`, `dst-port`, `tcp-flags`, `ttl`, `df`, `tcp-window`.

### Value Types

- **Numbers:** Protocol, port, flags, TTL, DF, window → integer
- **Strings:** IP addresses → dotted notation string (`"10.0.0.200"`)

### Actions

- `"pass"` — allow
- `"drop"` — hard drop
- `"rate-limit"` — token bucket (requires `rate_pps` field)

## Idempotent Rule Identity

Each rule has a **canonical hash** computed from its constraints (sorted by field dimension), action, rate, and priority. This hash:

- Is stable across compilations (same rule → same hash every time)
- Drives deduplication (identical logical rules are never inserted twice)
- Keys rate-limiter state (token buckets survive tree recompilation)

```
Rule: ((and (= proto 17) (= src-port 53)) => (rate-limit 500) :priority 200)
Hash: SHA-256(sorted_constraints || action || rate || priority) → u64
```

Constraint order in the s-expression doesn't matter — `(and (= proto 17) (= src-port 53))` and `(and (= src-port 53) (= proto 17))` produce the same canonical hash.

## Autonomous Rule Generation

Rules aren't just authored by humans. The Holon detection engine generates rules automatically when anomalies are detected:

1. **Anomaly detected** — drift exceeds threshold
2. **Pattern attributed** — similarity profile identifies concentrated fields
3. **Rate derived** — vector magnitude ratio determines PPS limit
4. **Rule emitted** — constraints from concentrated fields, rate from magnitude
5. **Tree recompiled** — new rule merged with existing rules, blue/green flip

The generated rules use the same `RuleSpec` structure and s-expression format as human-authored rules. They're logged in both s-expression and JSON formats for observability.

```
;; Holon-generated rule (from anomaly detection)
((and (= proto 17)
      (= src-port 53)
      (= src-addr 10.0.0.200))
 =>
 (rate-limit 1906))
```

The priority of Holon-generated rules defaults to 100. Pre-loaded rules with higher priority take precedence, allowing operators to override automated decisions.
