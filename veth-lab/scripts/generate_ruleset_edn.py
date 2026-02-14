#!/usr/bin/env python3
"""Generate a large ruleset EDN file for the tree rete engine.

Creates a mix of:
  - "sentinel" rules that match known test traffic patterns (UDP amplification,
    TCP SYN flood, etc.)
  - Background blocklist rules with unique (proto, src-addr, dst-port) triples
    that won't match test traffic but exercise the tree at scale.

All background rules constrain proto + src-addr + dst-port so they share the
same constraint structure — no wildcard replication across dimensions.  This
keeps node count ~3x rule count (e.g. 10K rules ≈ 30K nodes).

Output format: One EDN rule per line (streaming-friendly, no 150MB JSON array).

Usage:
    python3 generate_ruleset_edn.py --count 10000 --output rules-10k.edn
    python3 generate_ruleset_edn.py --count 50000 --output rules-50k.edn
    python3 generate_ruleset_edn.py --count 1000000 --output rules-1m.edn
"""

import argparse
import os
import sys


def make_ip(i: int) -> str:
    """Generate IP 10.a.b.c from a counter (avoids 10.0.0.X test range)."""
    # Start at 10.1.0.0 to avoid colliding with 10.0.0.X test IPs
    i += 256  # skip 10.0.0.0/24
    a = (i >> 16) & 0xFF
    b = (i >> 8) & 0xFF
    c = i & 0xFF
    return f"10.{a}.{b}.{c}"


def format_edn_rule(constraints, actions, priority=None, comment=None):
    """Format a rule as a single-line EDN map."""
    # Format constraints as s-expressions
    constraint_strs = []
    for c in constraints:
        field = c["field"]
        value = c["value"]
        # IP addresses need to be quoted strings in EDN
        if field in ["src-addr", "dst-addr"]:
            constraint_strs.append(f'(= {field} "{value}")')
        else:
            constraint_strs.append(f'(= {field} {value})')
    
    constraints_edn = f'[{" ".join(constraint_strs)}]'
    
    # Format actions as s-expressions
    action_strs = []
    for action in actions:
        if action["type"] == "drop":
            action_strs.append("(drop)")
        elif action["type"] == "pass":
            action_strs.append("(pass)")
        elif action["type"] == "rate-limit":
            pps = action.get("pps", 1000)
            name = action.get("name")
            if name:
                action_strs.append(f'(rate-limit {pps} :name "{name}")')
            else:
                action_strs.append(f'(rate-limit {pps})')
        elif action["type"] == "count":
            name = action.get("name")
            if name:
                action_strs.append(f'(count :name "{name}")')
            else:
                action_strs.append("(count)")
    
    actions_edn = f'[{" ".join(action_strs)}]'
    
    # Build the EDN map
    parts = [f'{{:constraints {constraints_edn} :actions {actions_edn}']
    
    if priority is not None and priority != 100:
        parts.append(f' :priority {priority}')
    
    if comment:
        # Truncate and escape
        if len(comment) > 256:
            comment = comment[:256]
        escaped = comment.replace('"', '\\"')
        parts.append(f' :comment "{escaped}"')
    
    parts.append('}')
    return ''.join(parts)


def main():
    parser = argparse.ArgumentParser(
        description="Generate EDN rules file for tree rete stress test"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=10000,
        help="Total number of rules (default: 10000)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "--with-comments",
        action="store_true",
        help="Include explanatory comments in output",
    )
    args = parser.parse_args()

    # Open output
    if args.output:
        out = open(args.output, "w")
    else:
        out = sys.stdout

    # ── Sentinel rules: match known test traffic ──
    # These will fire when the generator sends attack phases.
    sentinels = [
        {
            "comment": "DNS amplification (port 53)",
            "constraints": [
                {"field": "proto", "value": 17},
                {"field": "src-port", "value": 53},
            ],
            "actions": [{"type": "rate-limit", "pps": 500}],
            "priority": 200,
        },
        {
            "comment": "NTP amplification (port 123)",
            "constraints": [
                {"field": "proto", "value": 17},
                {"field": "src-port", "value": 123},
            ],
            "actions": [{"type": "rate-limit", "pps": 300}],
            "priority": 190,
        },
        {
            "comment": "TCP SYN flood to game server",
            "constraints": [
                {"field": "proto", "value": 6},
                {"field": "tcp-flags", "value": 2},
                {"field": "dst-port", "value": 9999},
            ],
            "actions": [{"type": "rate-limit", "pps": 100}],
            "priority": 210,
        },
        {
            "comment": "Rate limit known attacker to game server",
            "constraints": [
                {"field": "src-addr", "value": "10.0.0.200"},
                {"field": "dst-port", "value": 9999},
            ],
            "actions": [{"type": "rate-limit", "pps": 1000}],
            "priority": 150,
        },
    ]

    rule_count = 0
    
    # Write sentinels
    for s in sentinels:
        if args.with_comments:
            out.write(f';; {s["comment"]}\n')
        edn_line = format_edn_rule(s["constraints"], s["actions"], s.get("priority"), s.get("comment"))
        out.write(edn_line + "\n")
        rule_count += 1

    if args.with_comments and rule_count < args.count:
        out.write(f"\n;; Background blocklist rules (proto + src-addr + dst-port)\n")

    # ── Background rules: blocklist-style, unique per IP ──
    # All share the same constraint structure (proto + src-addr + dst-port)
    # to avoid wildcard replication explosion in the tree.
    remaining = args.count - rule_count
    for i in range(max(0, remaining)):
        ip = make_ip(i)
        port = 8000 + (i % 57000)  # ports 8000-64999
        proto = 17 if (i % 3 != 0) else 6  # 2/3 UDP, 1/3 TCP

        constraints = [
            {"field": "proto", "value": proto},
            {"field": "src-addr", "value": ip},
            {"field": "dst-port", "value": port},
        ]
        actions = [{"type": "drop"}]
        
        edn_line = format_edn_rule(constraints, actions, priority=100)
        out.write(edn_line + "\n")
        rule_count += 1

    # Close output
    if args.output:
        out.close()
        size_mb = os.path.getsize(args.output) / 1024 / 1024
        print(f"Generated {rule_count} rules -> {args.output} ({size_mb:.1f} MB)", file=sys.stderr)
    else:
        print(f"\nGenerated {rule_count} rules to stdout", file=sys.stderr)

    # Summary
    sentinel_count = min(len(sentinels), args.count)
    bg_count = rule_count - sentinel_count
    print(f"  Sentinel rules (match test traffic): {sentinel_count}", file=sys.stderr)
    print(f"  Background rules (blocklist):        {bg_count}", file=sys.stderr)
    print(f"  Format: EDN (one rule per line, streaming-friendly)", file=sys.stderr)


if __name__ == "__main__":
    main()
