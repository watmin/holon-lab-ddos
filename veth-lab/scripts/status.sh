#!/bin/bash
# Check status of veth lab environment

set -euo pipefail

# Configuration (must match setup.sh)
NAMESPACE="veth-lab-gen"
VETH_GEN="veth-gen"
VETH_FILTER="veth-filter"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

check_ok() { echo -e "  ${GREEN}✓${NC} $1"; }
check_fail() { echo -e "  ${RED}✗${NC} $1"; }
check_warn() { echo -e "  ${YELLOW}!${NC} $1"; }

echo -e "${BLUE}=== Veth Lab Status ===${NC}"
echo ""

# Check namespace
echo "Network Namespace:"
if ip netns list 2>/dev/null | grep -q "^${NAMESPACE}"; then
    check_ok "${NAMESPACE} exists"
    NAMESPACE_OK=true
else
    check_fail "${NAMESPACE} not found"
    NAMESPACE_OK=false
fi

# Check veth-filter (host side)
echo ""
echo "Filter Interface (${VETH_FILTER}):"
if ip link show "${VETH_FILTER}" >/dev/null 2>&1; then
    check_ok "Interface exists"
    
    # Check if up
    if ip link show "${VETH_FILTER}" | grep -q "state UP"; then
        check_ok "Interface is UP"
    else
        check_warn "Interface is DOWN"
    fi
    
    # Check IP
    IP=$(ip -4 addr show "${VETH_FILTER}" 2>/dev/null | grep -oP 'inet \K[\d.]+' || echo "none")
    if [[ "${IP}" != "none" ]]; then
        check_ok "IP address: ${IP}"
    else
        check_warn "No IP address assigned"
    fi
    
    # Check XDP
    if ip link show "${VETH_FILTER}" | grep -q "xdp"; then
        XDP_MODE=$(ip link show "${VETH_FILTER}" | grep -oP 'xdp[a-z]*' || echo "xdp")
        check_ok "XDP program attached (${XDP_MODE})"
    else
        check_warn "No XDP program attached"
    fi
    
    FILTER_OK=true
else
    check_fail "Interface not found"
    FILTER_OK=false
fi

# Check veth-gen (namespace side)
echo ""
echo "Generator Interface (${VETH_GEN} in ${NAMESPACE}):"
if [[ "${NAMESPACE_OK}" == "true" ]]; then
    if ip netns exec "${NAMESPACE}" ip link show "${VETH_GEN}" >/dev/null 2>&1; then
        check_ok "Interface exists"
        
        # Check if up
        if ip netns exec "${NAMESPACE}" ip link show "${VETH_GEN}" | grep -q "state UP"; then
            check_ok "Interface is UP"
        else
            check_warn "Interface is DOWN"
        fi
        
        # Check IP
        IP=$(ip netns exec "${NAMESPACE}" ip -4 addr show "${VETH_GEN}" 2>/dev/null | grep -oP 'inet \K[\d.]+' || echo "none")
        if [[ "${IP}" != "none" ]]; then
            check_ok "IP address: ${IP}"
        else
            check_warn "No IP address assigned"
        fi
        
        GEN_OK=true
    else
        check_fail "Interface not found in namespace"
        GEN_OK=false
    fi
else
    check_fail "Cannot check - namespace doesn't exist"
    GEN_OK=false
fi

# Connectivity test
echo ""
echo "Connectivity:"
if [[ "${NAMESPACE_OK}" == "true" ]] && [[ "${GEN_OK}" == "true" ]] && [[ "${FILTER_OK}" == "true" ]]; then
    if ip netns exec "${NAMESPACE}" ping -c 1 -W 1 10.100.0.2 >/dev/null 2>&1; then
        check_ok "Namespace -> Host ping works"
    else
        check_warn "Namespace -> Host ping blocked (XDP may still work)"
    fi
else
    check_fail "Cannot test - interfaces not ready"
fi

# Summary
echo ""
echo -e "${BLUE}=== Summary ===${NC}"
if [[ "${NAMESPACE_OK}" == "true" ]] && [[ "${GEN_OK}" == "true" ]] && [[ "${FILTER_OK}" == "true" ]]; then
    echo -e "${GREEN}Lab is ready!${NC}"
    echo ""
    echo "To run generator in namespace:"
    echo "  sudo ip netns exec ${NAMESPACE} ./target/release/veth-generator"
    echo ""
    echo "To attach XDP filter:"
    echo "  sudo ./target/release/veth-loader --interface ${VETH_FILTER}"
else
    echo -e "${RED}Lab not ready. Run: sudo ./scripts/setup.sh${NC}"
fi
