#!/usr/bin/env bash
# End-to-end HTTP WAF demo:
#   1. Setup (cert + mock backend)
#   2. Start proxy (with sidecar in-process)
#   3. Run generator scenario
#   4. Watch metrics
#
# Usage:
#   ./demo.sh                            # built-in single-wave scenario
#   ./demo.sh --scenario multi_attack    # multi-wave attack from scenarios/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$(dirname "$LAB_DIR")"
CERTS_DIR="$LAB_DIR/certs"
LOGS_DIR="$LAB_DIR/logs"
ENGRAMS_DIR="$LAB_DIR/engrams"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

SCENARIO_ARG=""
for arg in "$@"; do
    case "$arg" in
        --scenario)  shift; SCENARIO_ARG="$1"; shift ;;
        *)           ;;
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

echo "==> Starting proxy on :8443 (metrics on :9090)"
RUST_LOG=info "$PROXY_BIN" \
    --listen 0.0.0.0:8443 \
    --upstream 127.0.0.1:8080 \
    --cert "$CERTS_DIR/cert.pem" \
    --key "$CERTS_DIR/key.pem" \
    --engram-path "$ENGRAMS_DIR/http" \
    --metrics-addr 127.0.0.1:9090 \
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
echo "==> Demo complete"
echo "    Proxy log: $PROXY_LOG"
echo "    Check rules: grep -E 'Rule added|ANOMALY|ENGRAM' $PROXY_LOG"
echo "    Final metrics: curl -s http://127.0.0.1:9090/metrics | python3 -m json.tool"
echo ""
echo "To stop everything: $SCRIPT_DIR/teardown.sh"
