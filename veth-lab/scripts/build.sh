#!/bin/bash
# Build all veth-lab components
#
# eBPF requires special build command with BPF target

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(dirname "$LAB_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

cd "$ROOT_DIR"

echo -e "${BLUE}=== Building Veth Lab ===${NC}"
echo ""

# Step 1: Build eBPF program
log_step "Building eBPF program (veth-filter-ebpf)..."

# Check for bpf-linker
if ! command -v bpf-linker &> /dev/null; then
    log_error "bpf-linker not found. Install with: cargo install bpf-linker"
    exit 1
fi

# Build eBPF with nightly and BPF target
# Note: filter-ebpf has its own workspace, build from its directory
pushd "$LAB_DIR/filter-ebpf" > /dev/null
RUSTFLAGS="" CARGO_CFG_BPF_TARGET_ARCH="x86_64" \
    cargo +nightly build \
    --target bpfel-unknown-none \
    -Z build-std=core \
    --release
BUILD_RESULT=$?
popd > /dev/null

if [[ $BUILD_RESULT -eq 0 ]]; then
    log_info "eBPF program built successfully"
else
    log_error "eBPF build failed"
    exit 1
fi

# Step 2: Build userspace components
log_step "Building userspace components..."

cargo build --release \
    -p veth-filter \
    -p veth-generator \
    -p veth-sidecar

if [[ $? -eq 0 ]]; then
    log_info "Userspace components built successfully"
else
    log_error "Userspace build failed"
    exit 1
fi

echo ""
echo -e "${GREEN}=== Build Complete ===${NC}"
echo ""
echo "Binaries:"
echo "  target/release/veth-loader     - XDP loader and rule manager"
echo "  target/release/veth-generator  - Traffic generator"
echo "  target/release/veth-sidecar    - Holon detection sidecar"
echo ""
echo "eBPF:"
echo "  veth-lab/filter-ebpf/target/bpfel-unknown-none/release/veth-filter"
echo ""
echo "Next steps:"
echo "  1. Setup network:  sudo ./veth-lab/scripts/setup.sh"
echo "  2. Run demo:       sudo ./veth-lab/scripts/demo.sh"
