#!/bin/bash
# Helper script to run the XDP loader
#
# Usage: sudo ./scripts/run-loader.sh [args...]
# Example: sudo ./scripts/run-loader.sh --interface veth-filter stats

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(dirname "$LAB_DIR")"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root (sudo)"
    exit 1
fi

# Run loader
exec "$ROOT_DIR/target/release/veth-loader" "$@"
