#!/bin/bash
# Helper script to run the generator inside the namespace
#
# Usage: sudo ./scripts/run-generator.sh [args...]
# Example: sudo ./scripts/run-generator.sh --pattern attack --pps 1000

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(dirname "$LAB_DIR")"

NAMESPACE="veth-lab-gen"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (sudo)"
    exit 1
fi

# Check if namespace exists
if ! ip netns list 2>/dev/null | grep -q "^${NAMESPACE}"; then
    echo "Namespace ${NAMESPACE} not found. Run: sudo ./scripts/setup.sh"
    exit 1
fi

# Run generator in namespace
exec ip netns exec "$NAMESPACE" "$ROOT_DIR/target/release/veth-generator" "$@"
