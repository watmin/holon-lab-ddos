#!/usr/bin/env bash
# End-to-end spectral firewall test against DVWA with multiple attack tools
# and concurrent LLM-driven browser traffic for realistic mixed workloads.
#
# Flow:
#   1. Start DVWA (Docker) on :8888, patch cookies, init DB, authenticate
#   2. Build proxy + generator
#   3. Setup TLS certs
#   4. Start proxy on :8443 → :8888
#   5. Setup dummy network + source forwarders for IP diversity
#   6. Start 20 LLM browser agents (warmup phase, then continuous)
#   7. Run Nikto + ZAP + Nuclei concurrently (browsers still running)
#   8. Summary with per-tool results
#
# Prerequisites:
#   - Docker (DVWA, Nikto, ZAP, Nuclei)
#   - Rust toolchain (proxy)
#   - Python venv with xai-sdk + playwright in scenarios/dvwa/.venv
#   - dummy0 interface: sudo ./setup-local-network.sh 20
#   - XAI_API_KEY environment variable
#
# Usage:
#   ./run-multi-attack.sh               # full run
#   ./run-multi-attack.sh --skip-build  # skip cargo build
#
# Environment variables:
#   WARMUP_DURATION   Seconds of browser-only warmup (default: 90)
#   AGENT_COUNT       Number of browser agents (default: 20)
#   NIKTO_MAXTIME     Nikto scan timeout in seconds (default: 120)
#   NUCLEI_MAXTIME    Nuclei scan timeout in seconds (default: 180)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
REPO_DIR="$(dirname "$LAB_DIR")"
CERTS_DIR="$LAB_DIR/certs"
LOGS_DIR="$LAB_DIR/logs"
ENGRAMS_DIR="$LAB_DIR/engrams"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

WARMUP_DURATION="${WARMUP_DURATION:-90}"
AGENT_COUNT="${AGENT_COUNT:-20}"
NIKTO_MAXTIME="${NIKTO_MAXTIME:-120}"
NUCLEI_MAXTIME="${NUCLEI_MAXTIME:-180}"

SKIP_BUILD=false
for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
    esac
done

mkdir -p "$LOGS_DIR" "$ENGRAMS_DIR"

PROXY_LOG="$LOGS_DIR/multi_proxy_${TIMESTAMP}.log"
NIKTO_LOG="$LOGS_DIR/multi_nikto_${TIMESTAMP}.log"
ZAP_LOG="$LOGS_DIR/multi_zap_${TIMESTAMP}.log"
NUCLEI_LOG="$LOGS_DIR/multi_nuclei_${TIMESTAMP}.log"
AGENT_LOG_DIR="$SCRIPT_DIR/agent_logs"

FORWARDER_PID=""
BROWSER_PID=""
NIKTO_PID=""
ZAP_PID=""
NUCLEI_PID=""

cleanup() {
    echo ""
    echo "==> Cleaning up..."
    for pid_var in BROWSER_PID FORWARDER_PID NIKTO_PID ZAP_PID NUCLEI_PID; do
        pid="${!pid_var:-}"
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if [[ -f "$LOGS_DIR/proxy.pid" ]]; then
        kill "$(cat "$LOGS_DIR/proxy.pid")" 2>/dev/null || true
        rm -f "$LOGS_DIR/proxy.pid"
    fi
    cd "$SCRIPT_DIR" && docker compose down -v 2>/dev/null || true
    echo "==> Done."
}
trap cleanup EXIT

# ===================================================================
# Phase 1: Start DVWA
# ===================================================================
echo "==> [1/8] Starting DVWA on :8888"
cd "$SCRIPT_DIR"
docker compose up -d

echo "    Waiting for DVWA to be ready..."
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:8888/ > /dev/null 2>&1; then
        echo "    DVWA ready (took ${i}s)"
        break
    fi
    if [[ $i -eq 30 ]]; then
        echo "ERROR: DVWA did not become ready in 30s"
        exit 1
    fi
    sleep 1
done

docker exec dvwa-dvwa-1 sed -i "s/'domain' => \$_SERVER\['HTTP_HOST'\]/'domain' => ''/" \
    /var/www/html/dvwa/includes/dvwaPage.inc.php 2>/dev/null || true

echo "    Waiting for MariaDB..."
for i in $(seq 1 15); do
    if docker exec dvwa-db-1 mysql -u dvwa -pdvwa -e "SELECT 1" > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo "    Initializing DVWA database..."
SETUP_RESP=$(curl -sv http://127.0.0.1:8888/setup.php 2>&1)
SETUP_SID=$(echo "$SETUP_RESP" | grep -oP 'PHPSESSID=\K[^;]+' || echo "")
SETUP_TOK=$(echo "$SETUP_RESP" | grep -oP "user_token' value='\K[^']*" || echo "")
if [[ -n "$SETUP_SID" && -n "$SETUP_TOK" ]]; then
    curl -s -b "PHPSESSID=$SETUP_SID;security=low" \
        -d "create_db=Create+%2F+Reset+Database&user_token=$SETUP_TOK" \
        http://127.0.0.1:8888/setup.php > /dev/null 2>&1 || true
    echo "    Database initialized"
else
    echo "    WARN: Could not parse setup.php tokens, DB may already be initialized"
fi

echo "    Authenticating to DVWA..."
LOGIN_RESP=$(curl -sv http://127.0.0.1:8888/login.php 2>&1)
DVWA_SID=$(echo "$LOGIN_RESP" | grep -oP 'PHPSESSID=\K[^;]+' || echo "")
DVWA_TOK=$(echo "$LOGIN_RESP" | grep -oP "user_token' value='\K[^']*" || echo "")
if [[ -z "$DVWA_SID" || -z "$DVWA_TOK" ]]; then
    echo "ERROR: Could not get DVWA login tokens"
    exit 1
fi
curl -s -b "PHPSESSID=$DVWA_SID;security=low" \
    -d "username=admin&password=password&Login=Login&user_token=$DVWA_TOK" \
    http://127.0.0.1:8888/login.php > /dev/null 2>&1
echo "    Session: $DVWA_SID"

# ===================================================================
# Phase 2: Build
# ===================================================================
if [[ "$SKIP_BUILD" == "false" ]]; then
    echo ""
    echo "==> [2/8] Building http-lab"
    ( "$LAB_DIR/scripts/build.sh" )
else
    echo ""
    echo "==> [2/8] Skipping build (--skip-build)"
fi

# ===================================================================
# Phase 3: Setup certs
# ===================================================================
echo ""
echo "==> [3/8] TLS certificates"
if [[ ! -f "$CERTS_DIR/cert.pem" ]]; then
    mkdir -p "$CERTS_DIR"
    openssl req -x509 -newkey rsa:2048 -keyout "$CERTS_DIR/key.pem" \
        -out "$CERTS_DIR/cert.pem" -days 365 -nodes \
        -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:10.99.0.100" 2>/dev/null
    echo "    Generated TLS cert (with 10.99.0.100 SAN)"
else
    echo "    Using existing cert"
fi

# ===================================================================
# Phase 4: Start proxy
# ===================================================================
PROXY_BIN="$REPO_DIR/target/release/http-proxy"

if [[ -f "$LOGS_DIR/proxy.pid" ]] && kill -0 "$(cat "$LOGS_DIR/proxy.pid")" 2>/dev/null; then
    echo "==> Stopping existing proxy"
    kill "$(cat "$LOGS_DIR/proxy.pid")" 2>/dev/null || true
    sleep 1
fi

echo ""
echo "==> [4/8] Starting proxy on 0.0.0.0:8443 → :8888 (DVWA)"
RUST_LOG=info "$PROXY_BIN" \
    --listen 0.0.0.0:8443 \
    --upstream 127.0.0.1:8888 \
    --cert "$CERTS_DIR/cert.pem" \
    --key "$CERTS_DIR/key.pem" \
    --engram-path "$ENGRAMS_DIR/multi-attack" \
    --metrics-addr 127.0.0.1:9090 \
    --denial-tokens \
    --stream-requests \
    > "$PROXY_LOG" 2>&1 &
echo $! > "$LOGS_DIR/proxy.pid"
sleep 2
echo "    Proxy running (pid=$(cat "$LOGS_DIR/proxy.pid"))"
echo "    Log: $PROXY_LOG"

# ===================================================================
# Phase 5: Network + Forwarders
# ===================================================================
echo ""
echo "==> [5/8] Source IP forwarders"

if ! ip link show dummy0 > /dev/null 2>&1; then
    echo "ERROR: dummy0 interface not found."
    echo "  Run: sudo ./setup-local-network.sh ${AGENT_COUNT}"
    exit 1
fi

VENV_DIR="$SCRIPT_DIR/.venv"
if [[ ! -d "$VENV_DIR" ]]; then
    echo "ERROR: Python venv not found at $VENV_DIR"
    exit 1
fi

# Kill any leftover forwarders on our port range
for p in $(seq "$AGENT_COUNT"); do
    PORT=$((50000 + p))
    EXISTING=$(lsof -ti ":$PORT" 2>/dev/null || true)
    if [[ -n "$EXISTING" ]]; then
        echo "    Killing existing process on port $PORT (pid=$EXISTING)"
        kill $EXISTING 2>/dev/null || true
    fi
done
sleep 1

(
    source "$VENV_DIR/bin/activate"
    python "$SCRIPT_DIR/source_forwarder.py" --count "$AGENT_COUNT"
) &
FORWARDER_PID=$!
sleep 2

# Verify at least one forwarder is listening
if ! kill -0 "$FORWARDER_PID" 2>/dev/null; then
    echo "ERROR: Forwarder process died. Check if ports 50001-$((50000 + AGENT_COUNT)) are free."
    exit 1
fi
FWD_ALIVE=0
for p in $(seq "$AGENT_COUNT"); do
    PORT=$((50000 + p))
    if bash -c "echo > /dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then
        FWD_ALIVE=$((FWD_ALIVE + 1))
    fi
done
echo "    Forwarders running: ${FWD_ALIVE}/${AGENT_COUNT} ports active (pid=$FORWARDER_PID)"
if [[ $FWD_ALIVE -eq 0 ]]; then
    echo "ERROR: No forwarder ports are listening"
    exit 1
fi

# ===================================================================
# Phase 6: Start browsers + warmup
# ===================================================================
echo ""
echo "==> [6/8] Starting ${AGENT_COUNT} LLM browser agents + warmup (${WARMUP_DURATION}s)"

# Total browser duration = warmup + longest attack tool + buffer
TOTAL_BROWSER_DURATION=$(( WARMUP_DURATION + NIKTO_MAXTIME + 60 ))

(
    source "$VENV_DIR/bin/activate"
    python "$SCRIPT_DIR/multi_agent.py" \
        --agents "$AGENT_COUNT" \
        --duration "$TOTAL_BROWSER_DURATION" \
        --session-cookie "$DVWA_SID" \
        --pace-min 0.5 \
        --pace-max 2.0 \
        --stagger 2
) &
BROWSER_PID=$!

echo "    Browser agents launching (pid=$BROWSER_PID)"
echo "    Total browser duration: ${TOTAL_BROWSER_DURATION}s"
echo ""
echo "    Warming up manifold with browser traffic for ${WARMUP_DURATION}s..."

WARMUP_END=$((SECONDS + WARMUP_DURATION))
while [[ $SECONDS -lt $WARMUP_END ]]; do
    REMAINING=$((WARMUP_END - SECONDS))
    if (( REMAINING % 15 == 0 && REMAINING > 0 )); then
        echo "    ... ${REMAINING}s remaining"
    fi
    sleep 5
done

echo "    Warmup complete. Launching attack tools."

# ===================================================================
# Phase 7: Run attack tools (browsers still running)
# ===================================================================
echo ""
echo "==> [7/8] Running attack tools concurrently (browsers still active)"
echo "    Nikto:  maxtime=${NIKTO_MAXTIME}s"
echo "    ZAP:    baseline scan"
echo "    Nuclei: maxtime=${NUCLEI_MAXTIME}s"
echo ""

# --- Nikto ---
echo "    Starting Nikto..."
docker run --rm --net=host \
    alpine/nikto \
    -h https://127.0.0.1:8443 \
    -ssl \
    -nointeractive \
    -maxtime "$NIKTO_MAXTIME" \
    > "$NIKTO_LOG" 2>&1 &
NIKTO_PID=$!

# --- ZAP ---
echo "    Starting ZAP Baseline..."
docker run --rm --net=host \
    ghcr.io/zaproxy/zaproxy:stable \
    zap-baseline.py -t https://127.0.0.1:8443 \
    -m 2 -I \
    > "$ZAP_LOG" 2>&1 &
ZAP_PID=$!

# --- Nuclei ---
echo "    Starting Nuclei..."
timeout "$NUCLEI_MAXTIME" \
    docker run --rm --net=host \
    projectdiscovery/nuclei:latest \
    -u https://127.0.0.1:8443 \
    -severity low,medium,high,critical \
    -no-color -timeout 10 \
    > "$NUCLEI_LOG" 2>&1 &
NUCLEI_PID=$!

echo ""
echo "    All attack tools running. Waiting for completion..."

# Wait for all attack tools
for tool_pid_var in NIKTO_PID ZAP_PID NUCLEI_PID; do
    pid="${!tool_pid_var}"
    tool_name="${tool_pid_var%_PID}"
    wait "$pid" 2>/dev/null || true
    echo "    ${tool_name} finished."
done

echo ""
echo "==> All attacks complete."

# --- Stop browsers ---
echo "==> Stopping browser agents..."
kill "$BROWSER_PID" 2>/dev/null || true
wait "$BROWSER_PID" 2>/dev/null || true
BROWSER_PID=""

echo "==> Stopping forwarders..."
kill "$FORWARDER_PID" 2>/dev/null || true
wait "$FORWARDER_PID" 2>/dev/null || true
FORWARDER_PID=""

# ===================================================================
# Phase 8: Summary
# ===================================================================
echo ""
echo "============================================================"
echo " Spectral Firewall — Multi-Attack Test Results"
echo "============================================================"
echo ""
echo "Proxy log:  $PROXY_LOG"
echo "Nikto log:  $NIKTO_LOG"
echo "ZAP log:    $ZAP_LOG"
echo "Nuclei log: $NUCLEI_LOG"
echo ""

STRIPPED=$(sed 's/\x1b\[[0-9;]*m//g' "$PROXY_LOG")

# --- Spectral verdicts ---
echo "--- Spectral verdicts (from proxy log) ---"
LAST_METRICS=$(grep '\[METRICS\]' "$PROXY_LOG" | tail -1)
if [[ -n "$LAST_METRICS" ]]; then
    echo "$LAST_METRICS" | grep -oP 'manifold\([^)]+\)' | tr ',' '\n' | tr '(' '\n' | tr ')' ' ' | grep = | sed 's/^/  /'
    echo ""
    echo "  enforcement:"
    echo "$LAST_METRICS" | grep -oP 'enforced\([^)]+\)' | tr ',' '\n' | tr '(' '\n' | tr ')' ' ' | grep = | sed 's/^/    /'
    echo ""
    echo "  anomaly score: $(echo "$LAST_METRICS" | grep -oP 'req\[score=\K[^,]+')"
    echo "  anomaly threshold: $(echo "$LAST_METRICS" | grep -oP 'req\[.*thr=\K[^,]+')"
else
    echo "  (no metrics found in proxy log)"
fi

# --- Per-source verdict breakdown ---
echo ""
echo "--- Per-source verdict breakdown ---"
BROWSER_DENIES=$(echo "$STRIPPED" | grep -c 'label=browser-agent' || true)
UNLABELED_DENIES=$(echo "$STRIPPED" | grep -c 'label=unknown' || true)
echo "  browser-agent denials: ${BROWSER_DENIES:-0}  (FALSE POSITIVES)"
echo "  unlabeled denials:     ${UNLABELED_DENIES:-0}  (attack tools)"

# --- Adaptive learning ---
echo ""
echo "--- Adaptive learning ---"
ADAPTIVE_TOTAL=$(echo "$STRIPPED" | grep 'adaptive_learns' | tail -1 | grep -oP 'adaptive_learns=\K\d+' || true)
echo "  total adaptive learns: ${ADAPTIVE_TOTAL:-0}"
REPUBLISHES=$(echo "$STRIPPED" | grep -c 'ADAPTIVE.*Republished' || true)
echo "  manifold republishes: ${REPUBLISHES:-0}"
BROAD_REJECTS=$(echo "$STRIPPED" | grep -c 'Broad sample rejected' || true)
echo "  broad rejections (poisoning gate): ${BROAD_REJECTS:-0}"
THRESHOLD_INIT=$(echo "$STRIPPED" | grep 'MANIFOLD.*Initial' | grep -oP 'deny_threshold=\K[0-9.]+' || true)
THRESHOLD_FINAL=$(echo "$STRIPPED" | grep 'ADAPTIVE.*Republished' | tail -1 | grep -oP 'threshold=\K[0-9.]+' || true)
echo "  threshold: warmup=${THRESHOLD_INIT:-?} → post-adaptive=${THRESHOLD_FINAL:-$THRESHOLD_INIT}"

# --- Traffic source breakdown (false positive detection) ---
echo ""
echo "--- Traffic source breakdown ---"
DENY_BROWSER=$(echo "$STRIPPED" | grep -cE '═ DENY ═.*label=browser-agent' || true)
DENY_UNKNOWN=$(echo "$STRIPPED" | grep -cE '═ DENY ═.*label=unknown' || true)
RL_BROWSER=$(echo "$STRIPPED" | grep -cE '═ RATE-LTD ═.*label=browser-agent' || true)
RL_UNKNOWN=$(echo "$STRIPPED" | grep -cE '═ RATE-LTD ═.*label=unknown' || true)
echo "  denies:      browser-agent=${DENY_BROWSER:-0}  unlabeled=${DENY_UNKNOWN:-0}"
echo "  rate-limits: browser-agent=${RL_BROWSER:-0}  unlabeled=${RL_UNKNOWN:-0}"
if [[ "${DENY_BROWSER:-0}" -gt 0 ]]; then
    echo "  ⚠ FALSE POSITIVES: ${DENY_BROWSER} browser-agent requests denied!"
fi

# --- Anomaly breadth ---
echo ""
echo "--- Anomaly breadth (deny/rate-limit log samples) ---"
echo "$STRIPPED" | grep 'concentration=' | grep 'entropy=' | tail -5 | \
    grep -oP 'concentration=[0-9.]+\s+entropy=[0-9.]+\s+gini=[0-9.]+ \([^)]+\)' | sed 's/^/  /' || echo "  (none logged)"

# --- Source IP distribution ---
echo ""
echo "--- Source IP distribution (from proxy log) ---"
echo "$STRIPPED" | grep -oP 'peer_addr=\K[0-9.]+' | sort | uniq -c | sort -rn | head -15 | \
    awk '{printf "  %-15s %s requests\n", $2, $1}' || echo "  (no peer addresses logged)"

# --- Browser agents ---
echo ""
echo "--- Browser agents (concurrent legitimate traffic) ---"
if [[ -d "$AGENT_LOG_DIR" ]]; then
    TOTAL_ACTIONS=0
    TOTAL_ERRORS=0
    AGENT_FILES=$(ls "$AGENT_LOG_DIR"/agent_*.log 2>/dev/null || true)
    if [[ -n "$AGENT_FILES" ]]; then
        for logf in $AGENT_FILES; do
            actions=$(grep -c '^\[agent\] #' "$logf" 2>/dev/null || true)
            TOTAL_ACTIONS=$((TOTAL_ACTIONS + ${actions:-0}))
            errors=$(grep -cE '\[agent\].*(failed|Error)' "$logf" 2>/dev/null || true)
            TOTAL_ERRORS=$((TOTAL_ERRORS + ${errors:-0}))
        done
        AGENT_FILE_COUNT=$(echo "$AGENT_FILES" | wc -w)
        echo "  agents: $AGENT_FILE_COUNT"
        echo "  total actions: $TOTAL_ACTIONS"
        echo "  total errors:  $TOTAL_ERRORS"
    else
        echo "  (no agent logs found)"
    fi
else
    echo "  (agent_logs directory not found)"
fi

# --- Nikto findings ---
echo ""
echo "--- Nikto findings ---"
NIKTO_FINDINGS=$(grep -cE '^\+' "$NIKTO_LOG" 2>/dev/null || echo "0")
echo "  $NIKTO_FINDINGS informational findings"

# --- ZAP findings ---
echo ""
echo "--- ZAP findings ---"
ZAP_ALERTS=$(grep -c 'WARN-NEW\|FAIL-NEW' "$ZAP_LOG" 2>/dev/null || echo "0")
ZAP_PASS=$(grep -c 'PASS' "$ZAP_LOG" 2>/dev/null || echo "0")
echo "  alerts: $ZAP_ALERTS"
echo "  passed: $ZAP_PASS"
if [[ -f "$ZAP_LOG" ]]; then
    grep 'WARN-NEW\|FAIL-NEW' "$ZAP_LOG" 2>/dev/null | head -5 | sed 's/^/  /' || true
fi

# --- Nuclei findings ---
echo ""
echo "--- Nuclei findings ---"
NUCLEI_FINDINGS=$(grep -cE '^\[' "$NUCLEI_LOG" 2>/dev/null || echo "0")
echo "  findings: $NUCLEI_FINDINGS"
if [[ -f "$NUCLEI_LOG" ]]; then
    grep -E '^\[' "$NUCLEI_LOG" 2>/dev/null | head -5 | sed 's/^/  /' || true
fi

# --- Proxy deny attribution ---
echo ""
echo "--- Proxy deny attribution (last 5) ---"
grep 'surprise probe\|drilldown' "$PROXY_LOG" | tail -5 | sed 's/^/  /' || echo "  (none logged)"

echo ""
echo "To inspect denial tokens:"
echo "  grep 'X-Denial-Context' $PROXY_LOG | head -3"
echo ""
echo "To unseal a token:"
echo "  cargo run -p http-runner --bin holon-engram -- unseal <token> --key $ENGRAMS_DIR/multi-attack/denial.key"
echo ""
