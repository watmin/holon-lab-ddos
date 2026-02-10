#!/bin/bash
# Demo: Run the full veth-lab pipeline
#
# 1. Start XDP filter with sidecar
# 2. Generate traffic with attack patterns
# 3. Watch detection and rule generation

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(dirname "$LAB_DIR")"

# Configuration
NAMESPACE="veth-lab-gen"
VETH_FILTER="veth-filter"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (sudo)"
    exit 1
fi

# Check if namespace exists
if ! ip netns list 2>/dev/null | grep -q "^${NAMESPACE}"; then
    log_error "Namespace ${NAMESPACE} not found. Run: sudo ./scripts/setup.sh"
    exit 1
fi

# Check if binaries exist
if [[ ! -f "$ROOT_DIR/target/release/veth-loader" ]]; then
    log_error "Binaries not found. Run: ./scripts/build.sh"
    exit 1
fi

cd "$ROOT_DIR"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║             Veth Lab Demo - Holon XDP Detection              ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    
    # Kill background processes
    if [[ -n "${SIDECAR_PID:-}" ]]; then
        kill "$SIDECAR_PID" 2>/dev/null || true
    fi
    if [[ -n "${GEN_PID:-}" ]]; then
        # Generator runs in namespace, need to kill properly
        ip netns pids "$NAMESPACE" 2>/dev/null | xargs -r kill 2>/dev/null || true
    fi
    
    # Detach XDP
    ip link set "$VETH_FILTER" xdp off 2>/dev/null || true
    
    log_info "Cleanup complete"
}

trap cleanup EXIT

# Step 1: Start the sidecar (which loads XDP)
log_info "Starting Holon sidecar on ${VETH_FILTER}..."
./target/release/veth-sidecar \
    --interface "$VETH_FILTER" \
    --window 3 \
    --threshold 0.7 \
    --concentration 0.4 \
    --enforce \
    &
SIDECAR_PID=$!

# Wait for XDP to attach
sleep 2

# Verify XDP is attached
if ip link show "$VETH_FILTER" | grep -q "xdp"; then
    log_info "XDP program attached successfully"
else
    log_warn "XDP program may not be attached"
fi

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Step 2: Start traffic generator
log_info "Starting traffic generator in namespace ${NAMESPACE}..."
echo ""
echo "Traffic pattern: MIXED (5s normal, 5s attack)"
echo "  Normal: Random sources (192.168.x.x) -> port 8888"
echo "  Attack: Fixed source (10.0.0.100) -> port 9999"
echo ""

ip netns exec "$NAMESPACE" \
    ./target/release/veth-generator \
    --pattern mixed \
    --pps 500 \
    --duration 60 \
    &
GEN_PID=$!

echo ""
log_info "Demo running for 60 seconds..."
echo ""
echo "Watch for:"
echo "  - Drift dropping below threshold during attack phases"
echo "  - Concentrated values detected (dst_port=9999, src_ip=10.0.0.100)"
echo "  - Drop rules being added and packets being blocked"
echo ""
echo "Press Ctrl+C to stop early"
echo ""

# Wait for generator to finish
wait $GEN_PID || true

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Show final stats
log_info "Demo complete!"
echo ""

# Let sidecar print final stats
sleep 2
