#!/bin/bash
# Helper script to run the Holon sidecar
#
# Usage: sudo ./scripts/run-sidecar.sh [args...]
# Example: sudo ./scripts/run-sidecar.sh --enforce --threshold 0.6

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(dirname "$LAB_DIR")"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (sudo)"
    exit 1
fi

# Run sidecar
exec "$ROOT_DIR/target/release/veth-sidecar" "$@"
