#!/usr/bin/env bash
# End-to-end HTTP WAF demo:
#   1. Setup (cert + mock backend)
#   2. Start proxy (with sidecar in-process)
#   3. Run generator scenario
#   4. Watch metrics
#
# Usage:
#   ./demo.sh                                      # built-in single-wave scenario
#   ./demo.sh --scenario multi_attack              # multi-wave attack from scenarios/
#   ./demo.sh --scenario manifold_firewall --denial-tokens  # manifold test with tokens
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$(dirname "$LAB_DIR")"
CERTS_DIR="$LAB_DIR/certs"
LOGS_DIR="$LAB_DIR/logs"
ENGRAMS_DIR="$LAB_DIR/engrams"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

SCENARIO_ARG=""
DENIAL_TOKENS=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --scenario)       SCENARIO_ARG="$2"; shift 2 ;;
        --denial-tokens)  DENIAL_TOKENS="--denial-tokens"; shift ;;
        *)                shift ;;
    esac
done

mkdir -p "$LOGS_DIR" "$ENGRAMS_DIR"

# --- 1. Build ---
echo "==> Building http-lab"
"$SCRIPT_DIR/build.sh"

# --- 2. Setup ---
"$SCRIPT_DIR/setup.sh"

# --- 3. Start proxy ---
PROXY_BIN="$REPO_DIR/target/release/http-proxy"
PROXY_LOG="$LOGS_DIR/proxy_${TIMESTAMP}.log"
PROXY_PID_FILE="$LOGS_DIR/proxy.pid"

# Stop any existing proxy
if [[ -f "$PROXY_PID_FILE" ]] && kill -0 "$(cat "$PROXY_PID_FILE")" 2>/dev/null; then
    echo "==> Stopping existing proxy (pid=$(cat $PROXY_PID_FILE))"
    kill "$(cat "$PROXY_PID_FILE")" 2>/dev/null || true
    sleep 1
fi

TOKENS_MSG=""
if [[ -n "$DENIAL_TOKENS" ]]; then
    TOKENS_MSG=" + denial tokens"
fi
echo "==> Starting proxy on :8443 (metrics on :9090)${TOKENS_MSG}"
RUST_LOG=info "$PROXY_BIN" \
    --listen 0.0.0.0:8443 \
    --upstream 127.0.0.1:8080 \
    --cert "$CERTS_DIR/cert.pem" \
    --key "$CERTS_DIR/key.pem" \
    --engram-path "$ENGRAMS_DIR/http" \
    --metrics-addr 127.0.0.1:9090 \
    $DENIAL_TOKENS \
    > "$PROXY_LOG" 2>&1 &
echo $! > "$PROXY_PID_FILE"
sleep 2
echo "    Proxy running (pid=$(cat $PROXY_PID_FILE))"
echo "    Log: $PROXY_LOG"

# --- 4. Run generator ---
GENERATOR_BIN="$REPO_DIR/target/release/http-generator"
GENERATOR_LOG="$LOGS_DIR/generator_${TIMESTAMP}.log"

SCENARIO_FLAG=""
if [[ -n "$SCENARIO_ARG" ]]; then
    SCENARIO_FILE="$LAB_DIR/scenarios/${SCENARIO_ARG}.json"
    if [[ ! -f "$SCENARIO_FILE" ]]; then
        echo "ERROR: Scenario file not found: $SCENARIO_FILE"
        exit 1
    fi
    SCENARIO_FLAG="--scenario $SCENARIO_FILE"
    echo ""
    echo "==> Running scenario: $SCENARIO_ARG"
else
    echo ""
    echo "==> Running built-in demo scenario (warmup → flood → calm)"
fi
echo "    Metrics: http://127.0.0.1:9090/metrics"
echo "    Proxy log: $PROXY_LOG"
echo ""

RUST_LOG=info "$GENERATOR_BIN" \
    --target 127.0.0.1:8443 \
    --host localhost \
    --insecure \
    $SCENARIO_FLAG \
    2>&1 | tee "$GENERATOR_LOG"

echo ""
echo "=========================================="
echo " Demo Complete — Results"
echo "=========================================="
echo ""
echo "--- Generator per-phase results ---"
grep 'PHASE_RESULT' "$GENERATOR_LOG" || echo "  (no PHASE_RESULT lines found)"
echo ""
grep 'FINAL_SUMMARY' "$GENERATOR_LOG" || true
echo ""

echo "--- Manifold verdict counts ---"
curl -sf http://127.0.0.1:9090/metrics 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for k in ['manifold_allow','manifold_warmup','manifold_rate_limit','manifold_deny']:
        v = data.get(k, 'N/A')
        print(f'  {k}: {v}')
except:
    print('  (could not parse metrics)')
" || echo "  (metrics endpoint not available)"

echo ""
echo "--- Rule tree activity ---"
echo "  Rules added: $(grep -c 'Rule added' "$PROXY_LOG" 2>/dev/null || echo 0)"
echo "  Engrams minted: $(grep -c 'ENGRAM' "$PROXY_LOG" 2>/dev/null || echo 0)"

echo ""
echo "Proxy log: $PROXY_LOG"
echo "Generator log: $GENERATOR_LOG"
echo ""
echo "To stop everything: $SCRIPT_DIR/teardown.sh"
