#!/usr/bin/env bash
# End-to-end manifold firewall test against DVWA with Nikto.
#
# Flow:
#   1. Start DVWA (Docker) on :8080
#   2. Build and start proxy on :8443 with manifold + denial tokens
#   3. Warm up the manifold with dvwa_browse traffic
#   4. Run Nikto against the proxy
#   5. Print manifold verdict summary
#
# Prerequisites:
#   - Docker (for DVWA and Nikto)
#   - Rust toolchain (for building proxy + generator)
#
# Usage:
#   ./run-nikto.sh               # full run
#   ./run-nikto.sh --skip-build  # skip cargo build (if already built)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
REPO_DIR="$(dirname "$LAB_DIR")"
CERTS_DIR="$LAB_DIR/certs"
LOGS_DIR="$LAB_DIR/logs"
ENGRAMS_DIR="$LAB_DIR/engrams"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

SKIP_BUILD=false
for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
    esac
done

mkdir -p "$LOGS_DIR" "$ENGRAMS_DIR"

cleanup() {
    echo ""
    echo "==> Cleaning up..."
    if [[ -f "$LOGS_DIR/proxy.pid" ]]; then
        kill "$(cat "$LOGS_DIR/proxy.pid")" 2>/dev/null || true
        rm -f "$LOGS_DIR/proxy.pid"
    fi
    cd "$SCRIPT_DIR" && docker compose down -v 2>/dev/null || true
    echo "==> Done."
}
trap cleanup EXIT

# --- 1. Start DVWA ---
echo "==> Starting DVWA on :8080"
cd "$SCRIPT_DIR"
docker compose up -d

echo "    Waiting for DVWA to be ready..."
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:8080/ > /dev/null 2>&1; then
        echo "    DVWA ready (took ${i}s)"
        break
    fi
    if [[ $i -eq 30 ]]; then
        echo "ERROR: DVWA did not become ready in 30s"
        exit 1
    fi
    sleep 1
done

# --- 2. Build ---
if [[ "$SKIP_BUILD" == "false" ]]; then
    echo "==> Building http-lab"
    "$LAB_DIR/scripts/build.sh"
fi

# --- 3. Setup certs ---
"$LAB_DIR/scripts/setup.sh"

# --- 4. Start proxy ---
PROXY_BIN="$REPO_DIR/target/release/http-proxy"
PROXY_LOG="$LOGS_DIR/nikto_proxy_${TIMESTAMP}.log"

if [[ -f "$LOGS_DIR/proxy.pid" ]] && kill -0 "$(cat "$LOGS_DIR/proxy.pid")" 2>/dev/null; then
    echo "==> Stopping existing proxy"
    kill "$(cat "$LOGS_DIR/proxy.pid")" 2>/dev/null || true
    sleep 1
fi

echo "==> Starting proxy on :8443 → :8080 (DVWA) with denial tokens"
RUST_LOG=info "$PROXY_BIN" \
    --listen 0.0.0.0:8443 \
    --upstream 127.0.0.1:8080 \
    --cert "$CERTS_DIR/cert.pem" \
    --key "$CERTS_DIR/key.pem" \
    --engram-path "$ENGRAMS_DIR/nikto" \
    --metrics-addr 127.0.0.1:9090 \
    --denial-tokens \
    > "$PROXY_LOG" 2>&1 &
echo $! > "$LOGS_DIR/proxy.pid"
sleep 2
echo "    Proxy running (pid=$(cat "$LOGS_DIR/proxy.pid"))"
echo "    Log: $PROXY_LOG"

# --- 5. Warmup with dvwa_browse ---
GENERATOR_BIN="$REPO_DIR/target/release/http-generator"
WARMUP_LOG="$LOGS_DIR/nikto_warmup_${TIMESTAMP}.log"

echo ""
echo "==> Warming up manifold (30s @ 80 rps dvwa_browse)"

# Inline warmup scenario
WARMUP_JSON=$(cat <<'EJSON'
{
  "phases": [
    {
      "name": "warmup",
      "duration_s": 30,
      "rps": 80,
      "pattern": "dvwa_browse",
      "tls_profiles": ["chrome_120", "firefox_121"]
    }
  ]
}
EJSON
)

WARMUP_FILE=$(mktemp /tmp/warmup_XXXXXX.json)
echo "$WARMUP_JSON" > "$WARMUP_FILE"

RUST_LOG=info "$GENERATOR_BIN" \
    --target 127.0.0.1:8443 \
    --host localhost \
    --insecure \
    --scenario "$WARMUP_FILE" \
    2>&1 | tee "$WARMUP_LOG"

rm -f "$WARMUP_FILE"
echo "    Warmup complete."

# --- 6. Run Nikto ---
NIKTO_LOG="$LOGS_DIR/nikto_scan_${TIMESTAMP}.log"

echo ""
echo "==> Running Nikto against proxy (https://127.0.0.1:8443)"
echo "    Nikto log: $NIKTO_LOG"

docker run --rm --net=host \
    docker.io/sullo/nikto \
    -h https://127.0.0.1:8443 \
    -ssl \
    -nointeractive \
    -Tuning x \
    -timeout 5 \
    -maxtime 120 \
    2>&1 | tee "$NIKTO_LOG"

echo ""
echo "==> Nikto scan complete."

# --- 7. Summary ---
echo ""
echo "=========================================="
echo " Manifold Firewall — Nikto Test Results"
echo "=========================================="
echo ""
echo "Proxy log: $PROXY_LOG"
echo "Nikto log: $NIKTO_LOG"
echo ""

echo "--- Proxy manifold verdicts ---"
curl -sf http://127.0.0.1:9090/metrics 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for k in ['manifold_allow','manifold_warmup','manifold_rate_limit','manifold_deny']:
        print(f'  {k}: {data.get(k, \"N/A\")}')
except:
    print('  (could not parse metrics)')
" || echo "  (metrics endpoint not available)"

echo ""
echo "--- Proxy rule tree rules ---"
grep -c 'Rule added' "$PROXY_LOG" 2>/dev/null && echo " rules added" || echo "  0 rules added"

echo ""
echo "--- Proxy deny attribution (top 5) ---"
grep 'surprise probe\|drilldown' "$PROXY_LOG" | tail -5 || echo "  (none logged)"

echo ""
echo "--- Nikto findings ---"
grep -cE '^\+' "$NIKTO_LOG" 2>/dev/null && echo " findings reported by Nikto" || echo "  0 findings"

echo ""
echo "To inspect denial tokens:"
echo "  grep 'X-Denial-Context' $PROXY_LOG | head -3"
echo ""
echo "To unseal a token:"
echo "  cargo run -p http-proxy --bin holon-engram -- unseal <token>"
echo ""
