#!/bin/bash
# Teardown veth pair and network namespace
# Safe cleanup - won't affect other networking

set -euo pipefail

# Configuration (must match setup.sh)
NAMESPACE="veth-lab-gen"
VETH_GEN="veth-gen"
VETH_FILTER="veth-filter"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (sudo)"
    exit 1
fi

log_info "Tearing down veth lab environment..."

# Detach any XDP programs first
if ip link show "${VETH_FILTER}" >/dev/null 2>&1; then
    if ip link show "${VETH_FILTER}" | grep -q "xdp"; then
        log_info "Detaching XDP program from ${VETH_FILTER}"
        ip link set "${VETH_FILTER}" xdp off 2>/dev/null || true
    fi
fi

# Delete veth pair (deleting one end deletes both)
if ip link show "${VETH_FILTER}" >/dev/null 2>&1; then
    log_info "Deleting veth pair"
    ip link del "${VETH_FILTER}"
else
    log_warn "veth interface ${VETH_FILTER} not found (already deleted?)"
fi

# Delete namespace
if ip netns list 2>/dev/null | grep -q "^${NAMESPACE}"; then
    log_info "Deleting namespace ${NAMESPACE}"
    ip netns del "${NAMESPACE}"
else
    log_warn "Namespace ${NAMESPACE} not found (already deleted?)"
fi

log_info "Teardown complete!"
