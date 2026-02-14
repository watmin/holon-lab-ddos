#!/bin/bash
# Quick test of EDN rule parser
#
# Usage: ./test_edn_parser.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"

cd "$LAB_DIR"

echo "=== EDN Parser Test ==="
echo ""

# Test 1: Generate a small EDN ruleset
echo "[1/3] Generating test EDN ruleset (20 rules)..."
python3 scripts/generate_ruleset_edn.py --count 20 --output /tmp/test-rules.edn --with-comments
echo ""

# Test 2: Show first few rules
echo "[2/3] Sample rules:"
head -15 /tmp/test-rules.edn
echo ""

# Test 3: Dry-run parse (no enforcement, just parse and log)
echo "[3/3] Testing parser (dry-run, no enforcement)..."
echo ""

# We'll just check if it can load without crashing
# The sidecar will parse the rules and log them
timeout 3s sudo ./target/release/veth-sidecar \
    --interface lo \
    --rules-file /tmp/test-rules.edn \
    --warmup-windows 1 \
    --min-packets 10 2>&1 | grep -E "(Parsed|Detected EDN|rules|RULE:)" || true

echo ""
echo "=== Test Complete ==="
echo ""
echo "If you see 'Parsed 20 rules' or 'Detected EDN' above, the parser works!"
