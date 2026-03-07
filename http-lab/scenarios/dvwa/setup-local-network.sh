#!/usr/bin/env bash
# setup-local-network.sh
# Creates a dummy network interface with multiple IPs for source address diversity.
# Run once after boot: sudo ./setup-local-network.sh
#
# This is fully local — no physical NIC, no DHCP, no router involvement.
# The dummy0 interface acts like a private loopback with multiple addresses.
#
# After this, start the TCP forwarders:
#   source .venv/bin/activate
#   python source_forwarder.py
#
# Then point the spectral proxy at 10.99.0.100:8443 and browser agents
# at https://127.0.0.1:50001, :50002, etc.

set -euo pipefail

COUNT="${1:-10}"
PROXY_IP="10.99.0.100"
SUBNET="10.99.0"

GREEN='\033[0;32m'
NC='\033[0m'
info() { echo -e "${GREEN}[+] $1${NC}"; }

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0 [count]"; exit 1; }

info "Creating dummy0 interface..."
ip link del dummy0 2>/dev/null || true
ip link add dummy0 type dummy
ip link set dummy0 up

info "Adding proxy listen address: ${PROXY_IP}/24"
ip addr add "${PROXY_IP}/24" dev dummy0 2>/dev/null || true

info "Adding ${COUNT} source addresses..."
for ((i=1; i<=COUNT; i++)); do
    ip addr add "${SUBNET}.${i}/24" dev dummy0 2>/dev/null || true
    echo "  ${SUBNET}.${i}"
done

info "Verifying..."
ip -4 addr show dummy0 | grep inet | head -$((COUNT+1))

echo ""
info "Done. dummy0 has ${COUNT} source IPs + proxy IP."
echo ""
echo "Next steps:"
echo "  1. Start proxy:  RUST_LOG=info ./http-proxy --listen 10.99.0.100:8443 ..."
echo "  2. Start forwarders: python source_forwarder.py --count ${COUNT}"
echo "  3. Start agents: python dvwa_browser_agent.py --proxy-url https://127.0.0.1:50001 ..."
echo ""
echo "To tear down: sudo ip link del dummy0"
