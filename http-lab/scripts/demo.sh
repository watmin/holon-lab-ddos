#!/usr/bin/env bash
# End-to-end HTTP WAF demo:
#   1. Setup (cert + mock backend)
#   2. Start proxy (with sidecar in-process)
#   3. Run generator: warmup (30s) → GET flood (60s) → calm (30s)
#   4. Watch metrics
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$(dirname "$LAB_DIR")"
CERTS_DIR="$LAB_DIR/certs"
LOGS_DIR="$LAB_DIR/logs"
ENGRAMS_DIR="$LAB_DIR/engrams"

mkdir -p "$LOGS_DIR" "$ENGRAMS_DIR"

# --- 1. Build ---
echo "==> Building http-lab"
"$SCRIPT_DIR/build.sh"

# --- 2. Setup ---
"$SCRIPT_DIR/setup.sh"

# --- 3. Start proxy ---
PROXY_BIN="$REPO_DIR/target/release/http-proxy"
PROXY_LOG="$LOGS_DIR/proxy.log"
PROXY_PID_FILE="$LOGS_DIR/proxy.pid"

if [[ -f "$PROXY_PID_FILE" ]] && kill -0 "$(cat "$PROXY_PID_FILE")" 2>/dev/null; then
    echo "==> Proxy already running"
else
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
fi

# --- 4. Run generator ---
GENERATOR_BIN="$REPO_DIR/target/release/http-generator"
GENERATOR_LOG="$LOGS_DIR/generator.log"

echo ""
echo "==> Starting traffic generator (warmup 30s → flood 60s → calm 30s)"
echo "    Metrics: http://127.0.0.1:9090/metrics"
echo "    Proxy log: $PROXY_LOG"
echo ""

RUST_LOG=info "$GENERATOR_BIN" \
    --target 127.0.0.1:8443 \
    --host localhost \
    --insecure \
    2>&1 | tee "$GENERATOR_LOG"

echo ""
echo "==> Demo complete"
echo "    Check proxy log for rule generation events: grep -E 'Rule added|Anomaly|Engram' $PROXY_LOG"
echo "    Final metrics: curl -s http://127.0.0.1:9090/metrics | python3 -m json.tool"
echo ""
echo "To stop everything: $SCRIPT_DIR/teardown.sh"
