#!/bin/bash
# Setup veth pair and network namespace for XDP testing
# This creates an isolated environment that won't affect your laptop's networking

set -euo pipefail

# Configuration
NAMESPACE="veth-lab-gen"
VETH_GEN="veth-gen"
VETH_FILTER="veth-filter"
GEN_IP="10.100.0.1/24"
FILTER_IP="10.100.0.2/24"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (sudo)"
    exit 1
fi

# Check if already set up
if ip netns list 2>/dev/null | grep -q "^${NAMESPACE}"; then
    log_warn "Namespace ${NAMESPACE} already exists. Run teardown.sh first or use status.sh"
    exit 0
fi

log_info "Creating veth lab environment..."

# Create network namespace for the generator
log_info "Creating namespace: ${NAMESPACE}"
ip netns add "${NAMESPACE}"

# Create veth pair
log_info "Creating veth pair: ${VETH_GEN} <-> ${VETH_FILTER}"
ip link add "${VETH_GEN}" type veth peer name "${VETH_FILTER}"

# Move generator end into namespace
log_info "Moving ${VETH_GEN} into namespace ${NAMESPACE}"
ip link set "${VETH_GEN}" netns "${NAMESPACE}"

# Configure generator side (in namespace)
log_info "Configuring ${VETH_GEN} with IP ${GEN_IP}"
ip netns exec "${NAMESPACE}" ip addr add "${GEN_IP}" dev "${VETH_GEN}"
ip netns exec "${NAMESPACE}" ip link set "${VETH_GEN}" up
ip netns exec "${NAMESPACE}" ip link set lo up

# Configure filter side (in host namespace)
log_info "Configuring ${VETH_FILTER} with IP ${FILTER_IP}"
ip addr add "${FILTER_IP}" dev "${VETH_FILTER}"
ip link set "${VETH_FILTER}" up

# Disable reverse path filtering (allows spoofed source IPs)
log_info "Disabling rp_filter for veth interfaces"
sysctl -w "net.ipv4.conf.${VETH_FILTER}.rp_filter=0" >/dev/null
ip netns exec "${NAMESPACE}" sysctl -w "net.ipv4.conf.${VETH_GEN}.rp_filter=0" >/dev/null
ip netns exec "${NAMESPACE}" sysctl -w "net.ipv4.conf.all.rp_filter=0" >/dev/null

# Enable forwarding in namespace (for AF_PACKET to work properly)
ip netns exec "${NAMESPACE}" sysctl -w "net.ipv4.ip_forward=1" >/dev/null

# Verify setup
log_info "Verifying setup..."
echo ""
echo "=== Host interfaces ==="
ip addr show "${VETH_FILTER}"
echo ""
echo "=== Namespace interfaces ==="
ip netns exec "${NAMESPACE}" ip addr show "${VETH_GEN}"
echo ""

# Test connectivity
log_info "Testing connectivity..."
if ip netns exec "${NAMESPACE}" ping -c 1 -W 1 10.100.0.2 >/dev/null 2>&1; then
    log_info "Ping from namespace to host: SUCCESS"
else
    log_warn "Ping from namespace to host: FAILED (may be blocked by firewall, XDP will still work)"
fi

# Check XDP support
log_info "Checking XDP support on ${VETH_FILTER}..."
DRIVER=$(ethtool -i "${VETH_FILTER}" 2>/dev/null | grep "^driver:" | awk '{print $2}' || echo "unknown")
echo "  Driver: ${DRIVER}"

if [[ "${DRIVER}" == "veth" ]]; then
    log_info "veth driver supports native XDP and AF_XDP"
fi

echo ""
log_info "Setup complete!"
echo ""
echo "Usage:"
echo "  - Run generator in namespace:  sudo ip netns exec ${NAMESPACE} <command>"
echo "  - Attach XDP to filter:        (from host) attach to ${VETH_FILTER}"
echo "  - Teardown when done:          sudo ./scripts/teardown.sh"
echo ""
echo "Environment variables for other scripts:"
echo "  export VETH_LAB_NS=${NAMESPACE}"
echo "  export VETH_LAB_GEN=${VETH_GEN}"
echo "  export VETH_LAB_FILTER=${VETH_FILTER}"
