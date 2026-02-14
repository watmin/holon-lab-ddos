#!/usr/bin/env python3
"""Quick standalone EDN parser test."""

import subprocess
import sys

# Test with first N lines
N = int(sys.argv[1]) if len(sys.argv) > 1 else 20
EDN_FILE = sys.argv[2] if len(sys.argv) > 2 else "scenarios/rules-100.edn"

print(f"Testing first {N} rules from {EDN_FILE}...")
print()

# Just grep for WARN/error in sidecar output
result = subprocess.run(
    f"head -{N} {EDN_FILE} | grep -v '^;' | grep -v '^$' | wc -l",
    shell=True, capture_output=True, text=True, cwd="/home/watmin/work/holon/holon-lab-ddos/veth-lab"
)
non_comment_lines = int(result.stdout.strip())
print(f"Non-comment lines to parse: {non_comment_lines}")
print()

# Quick parse test with sidecar (it will fail to attach XDP but that's OK)
cmd = f"""
head -{N} {EDN_FILE} > /tmp/test_rules.edn
timeout 2 sudo ./target/release/veth-sidecar \\
    --interface lo \\
    --rules-file /tmp/test_rules.edn \\
    --warmup-windows 1 --min-packets 10 2>&1 | \\
    grep -E '(Parsed|Failed to parse|Line [0-9]+:)' | head -30
"""

subprocess.run(cmd, shell=True, cwd="/home/watmin/work/holon/holon-lab-ddos")
