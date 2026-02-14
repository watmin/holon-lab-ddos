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

Currently only `=` (equality) is implemented:

```edn
(= proto 17)              ;; UDP
(= src-addr 10.0.0.200)   ;; Source IP
(= dst-port 9999)         ;; Destination port
(= tcp-flags 2)           ;; SYN flag
```

Multiple constraints use implicit AND:

```edn
{:constraints [(= proto 6) (= tcp-flags 2) (= dst-port 9999)] :actions [(drop)]}
```

### Actions

**Drop:**
```edn
{:actions [(drop)]}
```

**Pass:**
```edn
{:actions [(pass)]}
```

**Rate-limit (unnamed):**
```edn
{:actions [(rate-limit 500)]}
```

**Rate-limit (named, for shared buckets - future):**
```edn
{:actions [(rate-limit 500 :name "dns-amp")]}
```

**Count (non-terminating - future):**
```edn
{:actions [(count :name "syn-packets")]}
```

**Multiple actions:**
```edn
{:actions [(rate-limit 500) (count :name "attacks")]}
```

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
