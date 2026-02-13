#!/usr/bin/env python3
"""Generate a large ruleset JSON file for the tree rete engine.

Creates a mix of:
  - "sentinel" rules that match known test traffic patterns (UDP amplification,
    TCP SYN flood, etc.)
  - Background blocklist rules with unique (proto, src-addr, dst-port) triples
    that won't match test traffic but exercise the tree at scale.

All background rules constrain proto + src-addr + dst-port so they share the
same constraint structure — no wildcard replication across dimensions.  This
keeps node count ~3x rule count (e.g. 10K rules ≈ 30K nodes).

Usage:
    python3 generate_ruleset.py --count 10000 --output rules-10k.json
    python3 generate_ruleset.py --count 50000 --output rules-50k.json
"""

import argparse
import json
import os
import struct
import sys


def make_ip(i: int) -> str:
    """Generate IP 10.a.b.c from a counter (avoids 10.0.0.X test range)."""
    # Start at 10.1.0.0 to avoid colliding with 10.0.0.X test IPs
    i += 256  # skip 10.0.0.0/24
    a = (i >> 16) & 0xFF
    b = (i >> 8) & 0xFF
    c = i & 0xFF
    return f"10.{a}.{b}.{c}"


def main():
    parser = argparse.ArgumentParser(
        description="Generate rules JSON for tree rete stress test"
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
    args = parser.parse_args()

    rules = []

    # ── Sentinel rules: match known test traffic ──
    # These will fire when the generator sends attack phases.
    sentinels = [
        {
            "constraints": [
                {"field": "proto", "value": 17},
                {"field": "src-port", "value": 53},
            ],
            "action": "rate-limit",
            "rate_pps": 500,
            "priority": 200,
        },
        {
            "constraints": [
                {"field": "proto", "value": 17},
                {"field": "src-port", "value": 123},
            ],
            "action": "rate-limit",
            "rate_pps": 300,
            "priority": 190,
        },
        {
            "constraints": [
                {"field": "proto", "value": 6},
                {"field": "tcp-flags", "value": 2},
                {"field": "dst-port", "value": 9999},
            ],
            "action": "rate-limit",
            "rate_pps": 100,
            "priority": 210,
        },
        {
            "constraints": [
                {"field": "src-addr", "value": "10.0.0.200"},
                {"field": "dst-port", "value": 9999},
            ],
            "action": "rate-limit",
            "rate_pps": 1000,
            "priority": 150,
        },
    ]

    for s in sentinels:
        rules.append(s)

    # ── Background rules: blocklist-style, unique per IP ──
    # All share the same constraint structure (proto + src-addr + dst-port)
    # to avoid wildcard replication explosion in the tree.
    remaining = args.count - len(rules)
    for i in range(max(0, remaining)):
        ip = make_ip(i)
        port = 8000 + (i % 57000)  # ports 8000-64999
        proto = 17 if (i % 3 != 0) else 6  # 2/3 UDP, 1/3 TCP

        rules.append(
            {
                "constraints": [
                    {"field": "proto", "value": proto},
                    {"field": "src-addr", "value": ip},
                    {"field": "dst-port", "value": port},
                ],
                "action": "drop",
                "priority": 100,
            }
        )

    # ── Write output ──
    output_str = json.dumps(rules, separators=(",", ":"))

    if args.output:
        with open(args.output, "w") as f:
            f.write(output_str)
        size_mb = os.path.getsize(args.output) / 1024 / 1024
        print(f"Generated {len(rules)} rules -> {args.output} ({size_mb:.1f} MB)", file=sys.stderr)
    else:
        sys.stdout.write(output_str)
        print(f"\nGenerated {len(rules)} rules to stdout", file=sys.stderr)

    # Summary
    sentinel_count = min(len(sentinels), args.count)
    bg_count = len(rules) - sentinel_count
    print(f"  Sentinel rules (match test traffic): {sentinel_count}", file=sys.stderr)
    print(f"  Background rules (blocklist):        {bg_count}", file=sys.stderr)


if __name__ == "__main__":
    main()
