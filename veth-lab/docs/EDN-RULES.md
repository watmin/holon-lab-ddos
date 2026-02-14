# EDN Rule Format

As of Feb 2026, the veth-lab uses **EDN (Extensible Data Notation)** for rule files instead of JSON arrays.

## Why EDN?

- **Streaming-friendly**: One rule per line, parse incrementally (handles 1M+ rules)
- **40% smaller**: EDN is more compact than JSON (887K vs 1.5M for 10K rules)
- **Comments**: Native support for `;; comment` lines
- **Clojure-idiomatic**: Matches the s-expression predicate syntax
- **Readable**: Keywords (`:actions`) and cleaner syntax

## Format

Each line is a complete EDN map:

```edn
{:constraints [(= proto 17) (= src-port 53)] :actions [(rate-limit 500)] :priority 200}
```

### Fields

- **`:constraints`** - Vector of s-expression predicates (must all match)
- **`:actions`** - Vector of actions to take (typically one, but supports multiple)
- **`:priority`** - Optional priority (0-255, higher wins). Default: 100
- **`:comment`** - Optional comment string (max 256 chars) for documentation
- **`:label`** - Optional 2-tuple `["namespace" "name"]` for metrics (each max 64 chars, unused for now)

### Predicates

**Equality:**
```edn
(= proto 17)              ;; UDP
(= src-addr 10.0.0.200)   ;; Source IP
(= dst-port 9999)         ;; Destination port
(= tcp-flags 2)           ;; SYN flag
```

**Range predicates:**
```edn
(> ttl 200)                ;; TTL greater than 200
(< ttl 100)                ;; TTL less than 100
(>= dst-port 1024)         ;; Destination port >= 1024
(<= ttl 64)                ;; TTL <= 64
```

**Bitmask matching (MaskEq):**
```edn
(mask-eq ttl 0xF0 0x40)                ;; (TTL & 0xF0) == 0x40 (upper nibble = 4)
(protocol-match 17 0xFF)               ;; (proto & 0xFF) == 17 (exact UDP match)
(tcp-flags-match 0x02 0x02)            ;; (flags & 0x02) == 0x02 (SYN bit set)
```

**L4 byte matching (arbitrary transport-relative offsets):**
```edn
;; Short match (1-4 bytes): uses custom dimension fan-out for O(1) lookup
(l4-match 2 "22B8" "FFFF")            ;; 2 bytes at L4 offset 2 (dst port 8888)

;; Long match (5-64 bytes): uses pattern guard with byte-by-byte comparison
(l4-match 8 "564554482D4C41422D54455354" "FFFFFFFFFFFFFFFFFFFFFFFFFF")
;; 13 bytes at L4 offset 8 matching "VETH-LAB-TEST"
```

Match and mask values are **hexadecimal strings**. The offset is relative to the
start of the transport (L4) header (byte 0 = first byte after IP header).

Multiple constraints use implicit AND:

```edn
{:constraints [(= proto 6) (= tcp-flags 2) (= dst-port 9999)] :actions [(drop)]}
```

### Actions

**Drop:**
```edn
{:actions [(drop)]}
{:actions [(drop :name ["security" "syn-block"])]}
```

**Pass:**
```edn
{:actions [(pass)]}
{:actions [(pass :name ["allow" "normal-udp"])]}
```

**Rate-limit (unnamed, per-rule bucket):**
```edn
{:actions [(rate-limit 500)]}
```

**Rate-limit (named, shared bucket):**
```edn
{:actions [(rate-limit 500 :name ["ddos-mitigation" "dns-amp"])]}
```
Multiple rules with the same `:name` share the same rate limiter bucket.

**Count (non-terminating observability):**
```edn
{:actions [(count :name ["observability" "syn-packets"])]}
```
Count actions increment a counter without affecting packet forwarding.

**Multiple actions:**
```edn
{:actions [(count :name ["metrics" "attacks"]) (rate-limit 500 :name ["mitigation" "dns"])]}
```

## Action Details

### Rate Limiting

**Unnamed (per-rule):**
Each rule gets its own independent token bucket identified by the rule's canonical hash.

```edn
{:constraints [(= proto 17) (= src-port 53)] :actions [(rate-limit 500)]}
{:constraints [(= proto 17) (= src-port 123)] :actions [(rate-limit 1000)]}
;; These have separate 500 PPS and 1000 PPS buckets
```

**Named (shared bucket):**
Multiple rules can share the same rate limiter by using the same `:name` tuple `["namespace" "name"]`.

```edn
{:constraints [(= src-addr "10.0.0.1")] :actions [(rate-limit 1000 :name ["ddos" "dns-amp"])]}
{:constraints [(= src-addr "10.0.0.2")] :actions [(rate-limit 1000 :name ["ddos" "dns-amp"])]}
;; Both rules share a single 1000 PPS bucket named "ddos/dns-amp"
```

If rules with the same bucket name specify different PPS values, the **last-defined wins** (with a warning logged).

**Observability:**
Rate limiter stats (allowed/dropped counts) are logged every 10 detection windows.

### Count Actions

Count actions are **non-terminating** - they increment a counter but don't affect packet forwarding. Other rules in the tree continue to be evaluated.

```edn
{:constraints [(= proto 6) (= tcp-flags 2)] :actions [(count :name ["metrics" "syn-packets"])]}
```

Count actions **require a name** (no unnamed counters).

**Use cases:**
- Observability without enforcement
- Tracking attack patterns
- Pre-mitigation monitoring

Counter values are logged every 10 detection windows, showing namespace, name, and packet count.

### Rule Labels

Rules can have an optional `:label` for metrics organization:

```edn
{:constraints [(= proto 17) (= src-port 53)] 
 :actions     [(rate-limit 500)] 
 :label       ["attack-type" "dns-amplification"]}
```

**Auto-generated labels:**
If no `:label` is specified, rules automatically get a label in the `"system"` namespace using their canonical constraint EDN:

```
[system [(= proto 17) (= dst-port 53)]]
```

This ensures every rule has a meaningful, human-readable identifier for observability and metrics.

## Examples

### Simple Drop Rule

```edn
;; Block all traffic from a specific IP
{:constraints [(= src-addr 10.0.0.200)] :actions [(drop)] :priority 150}
```

### DNS Amplification Mitigation

```edn
;; Rate-limit DNS responses
{:constraints [(= proto 17) (= src-port 53)] :actions [(rate-limit 500)] :priority 200}
```

### SYN Flood Protection

```edn
;; Rate-limit SYN packets to game server
{:constraints [(= proto 6) (= tcp-flags 2) (= dst-port 9999)] :actions [(rate-limit 100)] :priority 210}
```

### Multi-Constraint Rule

```edn
;; Specific attacker to specific service
{:constraints [(= proto 17) (= src-addr "10.0.0.200") (= dst-port 9999)] :actions [(rate-limit 1000)]}
```

### With Comment Field

```edn
{:constraints [(= src-addr "10.0.0.200")] :actions [(drop)] :comment "Known attacker, blocked 2026-02-13"}
```

Comments are optional but helpful for documenting rules, especially manually-created ones. The generator includes comments for sentinel rules (shown both as EDN comment lines `;; ...` and as `:comment` fields).

### With Label for Metrics (Future)

```edn
{:constraints [(= proto 17) (= src-port 53)] :actions [(rate-limit 500)] :label ["attack" "dns-amp"]}
{:constraints [(= proto 6) (= tcp-flags 2)] :actions [(drop)] :label ["attack" "syn-flood"]}
```

Labels are a 2-tuple `["namespace" "name"]` for organizing rules by category. Future: will be used for per-label metrics aggregation (e.g., "show me all 'attack' rules" or "total drops by label"). Currently unused but structure is in place.

## File Format

**One rule per line:**

```edn
;; Comment explaining rule group
{:constraints [(= proto 17) (= src-port 53)] :actions [(rate-limit 500)] :priority 200}
{:constraints [(= proto 6) (= tcp-flags 2)] :actions [(drop)] :priority 150}

;; Another comment
{:constraints [(= src-addr 10.1.0.5)] :actions [(drop)]}
```

**Blank lines and comments are ignored.**

## Generating Test Rules

Use the EDN generator script:

```bash
# Generate 100 rules
python3 scripts/generate_ruleset_edn.py --count 100 --output scenarios/rules-100.edn

# Generate 1M rules (streaming-friendly!)
python3 scripts/generate_ruleset_edn.py --count 1000000 --output scenarios/rules-1m.edn

# With comments
python3 scripts/generate_ruleset_edn.py --count 50 --output test.edn --with-comments
```

## Loading Rules

```bash
# Sidecar auto-detects EDN format (looks for {:constraints at start of line)
sudo ./target/release/veth-sidecar --interface veth-filter --rules-file scenarios/rules-10k.edn --enforce
```

## Pretty-Print Format (for logs)

When rules are logged, they use a multi-line format for readability:

```edn
{:constraints [(= proto 6)
               (= tcp-flags 2)
               (= dst-port 9999)]
 :actions     [(rate-limit 100)]
 :priority    210}
```

Single-constraint rules stay compact:

```edn
{:constraints [(= proto 17)]
 :actions     [(drop)]}
```

## Legacy JSON Support

Legacy JSON arrays are still supported (auto-detected):

```json
[
  {
    "constraints": [
      {"field": "proto", "value": 17}
    ],
    "action": "drop"
  }
]
```

But new rules should use EDN for better performance and readability.

## Benefits Over JSON

| Metric | JSON Array | EDN (line-delimited) |
|--------|------------|----------------------|
| 10K rules | 1.5 MB | 0.9 MB (40% smaller) |
| Memory usage | Load entire file | Streaming (line-by-line) |
| Parse time | Single parse call | Incremental |
| Max rules | Limited by memory | Unlimited (streaming) |
| Comments | No | Yes (`;;`) |
| Readability | Verbose | Clojure-idiomatic |

For 1M rules, JSON would require ~150MB memory allocation. EDN streams line-by-line with minimal memory footprint.
