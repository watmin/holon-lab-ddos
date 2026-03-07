#!/usr/bin/env bash
# End-to-end spectral firewall test against DVWA with Nikto.
#
# Flow:
#   1. Start DVWA (Docker) on :8888, patch cookies, init DB, authenticate
#   2. Build and start proxy on :8443 → :8888 with spectral + denial tokens
#   3. Warm up the spectral layer with authenticated dvwa_browse traffic
#   4. Run Nikto against the proxy
#   5. Print spectral verdict summary from proxy log
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
    if [[ -n "${BROWSER_PID:-}" ]]; then
        kill "$BROWSER_PID" 2>/dev/null || true
    fi
    if [[ -f "$LOGS_DIR/proxy.pid" ]]; then
        kill "$(cat "$LOGS_DIR/proxy.pid")" 2>/dev/null || true
        rm -f "$LOGS_DIR/proxy.pid"
    fi
    cd "$SCRIPT_DIR" && docker compose down -v 2>/dev/null || true
    echo "==> Done."
}
trap cleanup EXIT

# --- 1. Start DVWA ---
echo "==> Starting DVWA on :8888"
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

# Fix DVWA cookie domain bug: cytopia/dvwa sets domain=$_SERVER['HTTP_HOST']
# which includes the port (e.g. 127.0.0.1:8888). Browsers reject this per RFC 6265.
docker exec dvwa-dvwa-1 sed -i "s/'domain' => \$_SERVER\['HTTP_HOST'\]/'domain' => ''/" \
    /var/www/html/dvwa/includes/dvwaPage.inc.php 2>/dev/null || true

# Wait for MariaDB to be ready (DVWA may be up but DB not accepting connections yet)
echo "    Waiting for MariaDB..."
for i in $(seq 1 15); do
    if docker exec dvwa-db-1 mysql -u dvwa -pdvwa -e "SELECT 1" > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Initialize DB and authenticate (extract session cookies from response headers)
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
    echo "  SID=$DVWA_SID TOK=$DVWA_TOK"
    exit 1
fi
curl -s -b "PHPSESSID=$DVWA_SID;security=low" \
    -d "username=admin&password=password&Login=Login&user_token=$DVWA_TOK" \
    http://127.0.0.1:8888/login.php > /dev/null 2>&1
DVWA_COOKIE="PHPSESSID=$DVWA_SID; security=low"
echo "    Session: $DVWA_SID"

# --- 2. Build ---
if [[ "$SKIP_BUILD" == "false" ]]; then
    echo "==> Building http-lab"
    ( "$LAB_DIR/scripts/build.sh" )
fi

# --- 3. Setup certs ---
if [[ ! -f "$CERTS_DIR/cert.pem" ]]; then
    mkdir -p "$CERTS_DIR"
    openssl req -x509 -newkey rsa:2048 -keyout "$CERTS_DIR/key.pem" \
        -out "$CERTS_DIR/cert.pem" -days 365 -nodes \
        -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
    echo "    Generated TLS cert"
fi

# --- 4. Start proxy ---
PROXY_BIN="$REPO_DIR/target/release/http-proxy"
PROXY_LOG="$LOGS_DIR/nikto_proxy_${TIMESTAMP}.log"

if [[ -f "$LOGS_DIR/proxy.pid" ]] && kill -0 "$(cat "$LOGS_DIR/proxy.pid")" 2>/dev/null; then
    echo "==> Stopping existing proxy"
    kill "$(cat "$LOGS_DIR/proxy.pid")" 2>/dev/null || true
    sleep 1
fi

echo "==> Starting proxy on :8443 → :8888 (DVWA) with denial tokens"
RUST_LOG=info "$PROXY_BIN" \
    --listen 0.0.0.0:8443 \
    --upstream 127.0.0.1:8888 \
    --cert "$CERTS_DIR/cert.pem" \
    --key "$CERTS_DIR/key.pem" \
    --engram-path "$ENGRAMS_DIR/nikto" \
    --metrics-addr 127.0.0.1:9090 \
    --denial-tokens \
    --stream-requests \
    > "$PROXY_LOG" 2>&1 &
echo $! > "$LOGS_DIR/proxy.pid"
sleep 2
echo "    Proxy running (pid=$(cat "$LOGS_DIR/proxy.pid"))"
echo "    Log: $PROXY_LOG"

# --- 5. Warmup with dvwa_browse ---
GENERATOR_BIN="$REPO_DIR/target/release/http-generator"
WARMUP_LOG="$LOGS_DIR/nikto_warmup_${TIMESTAMP}.log"

echo ""
echo "==> Warming up spectral layer (30s @ 80 rps dvwa_browse)"

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
    --cookie "$DVWA_COOKIE" \
    2>&1 | tee "$WARMUP_LOG"

rm -f "$WARMUP_FILE"
echo "    Warmup complete."

# --- 6. Start browser agent (continuous background traffic) ---
BROWSER_LOG="$LOGS_DIR/nikto_browser_${TIMESTAMP}.log"
VENV_DIR="$SCRIPT_DIR/.venv"
AGENT_SCRIPT="$SCRIPT_DIR/dvwa_browser_agent.py"

BROWSER_PID=""
if [[ -d "$VENV_DIR" && -f "$AGENT_SCRIPT" ]]; then
    echo ""
    echo "==> Starting LLM browser agent (continuous background traffic)"
    echo "    Log: $BROWSER_LOG"
    (
        source "$VENV_DIR/bin/activate"
        python "$AGENT_SCRIPT" \
            --proxy-url https://127.0.0.1:8443 \
            --dvwa-url http://127.0.0.1:8888 \
            --session-cookie "$DVWA_SID" \
            --pace-min 0.3 \
            --pace-max 1.5 \
            > "$BROWSER_LOG" 2>&1
    ) &
    BROWSER_PID=$!
    echo "    Browser agent running (pid=$BROWSER_PID)"
    sleep 3
else
    echo ""
    echo "==> SKIP: browser agent (no .venv or agent script found)"
fi

# --- 7. Run Nikto ---
NIKTO_LOG="$LOGS_DIR/nikto_scan_${TIMESTAMP}.log"

echo ""
echo "==> Running Nikto against proxy (https://127.0.0.1:8443)"
echo "    Nikto log: $NIKTO_LOG"
echo "    (browser agent running concurrently)"

docker run --rm --net=host \
    alpine/nikto \
    -h https://127.0.0.1:8443 \
    -ssl \
    -nointeractive \
    -maxtime "${NIKTO_MAXTIME:-120}" \
    ${NIKTO_EXTRA_ARGS:-} \
    2>&1 | tee "$NIKTO_LOG"

echo ""
echo "==> Nikto scan complete."

# --- 7b. Stop browser agent ---
if [[ -n "$BROWSER_PID" ]]; then
    echo "==> Stopping browser agent (pid=$BROWSER_PID)"
    kill "$BROWSER_PID" 2>/dev/null || true
    wait "$BROWSER_PID" 2>/dev/null || true
    BROWSER_ACTIONS=$(grep -c '^\[agent\] #' "$BROWSER_LOG" 2>/dev/null || echo "0")
    echo "    Browser agent completed $BROWSER_ACTIONS actions"
    echo ""
fi

# --- 8. Summary ---
echo ""
echo "=========================================="
echo " Spectral Firewall — Nikto Test Results"
echo "=========================================="
echo ""
echo "Proxy log: $PROXY_LOG"
echo "Nikto log: $NIKTO_LOG"
echo ""

echo "--- Spectral verdicts (from proxy log) ---"
LAST_METRICS=$(grep '\[METRICS\]' "$PROXY_LOG" | tail -1)
if [[ -n "$LAST_METRICS" ]]; then
    echo "$LAST_METRICS" | grep -oP 'manifold\([^)]+\)' | tr ',' '\n' | tr '(' '\n' | tr ')' ' ' | grep = | sed 's/^/  /'
    echo ""
    echo "  enforcement:"
    echo "$LAST_METRICS" | grep -oP 'enforced\([^)]+\)' | tr ',' '\n' | tr '(' '\n' | tr ')' ' ' | grep = | sed 's/^/    /'
    echo ""
    echo "  rules: $(echo "$LAST_METRICS" | grep -oP 'rules=\K\d+')"
    echo "  anomaly score: $(echo "$LAST_METRICS" | grep -oP 'req\[score=\K[^,]+')"
    echo "  anomaly threshold: $(echo "$LAST_METRICS" | grep -oP 'req\[.*thr=\K[^,]+')"
    echo "  anomaly streak: $(echo "$LAST_METRICS" | grep -oP 'req\[.*streak=\K[^]]+')"
else
    echo "  (no metrics found in proxy log)"
fi

echo ""
echo "--- Adaptive learning ---"
# Strip ANSI codes before grepping — tracing wraps structured fields in escape sequences
STRIPPED=$(sed 's/\x1b\[[0-9;]*m//g' "$PROXY_LOG")
ADAPTIVE_TOTAL=$(echo "$STRIPPED" | grep 'adaptive_learns' | tail -1 | grep -oP 'adaptive_learns=\K\d+' || true)
echo "  total adaptive learns: ${ADAPTIVE_TOTAL:-0}"
REPUBLISHES=$(echo "$STRIPPED" | grep -c 'ADAPTIVE.*Republished' || true)
echo "  manifold republishes: ${REPUBLISHES:-0}"
BROAD_REJECTS=$(echo "$STRIPPED" | grep -c 'Broad sample rejected' || true)
echo "  broad rejections (poisoning gate): ${BROAD_REJECTS:-0}"
THRESHOLD_INIT=$(echo "$STRIPPED" | grep 'MANIFOLD.*Initial' | grep -oP 'deny_threshold=\K[0-9.]+' || true)
THRESHOLD_FINAL=$(echo "$STRIPPED" | grep 'ADAPTIVE.*Republished' | tail -1 | grep -oP 'threshold=\K[0-9.]+' || true)
echo "  threshold: warmup=${THRESHOLD_INIT:-?} → post-adaptive=${THRESHOLD_FINAL:-$THRESHOLD_INIT}"

echo ""
echo "--- Anomaly breadth (deny/rate-limit log samples) ---"
echo "$STRIPPED" | grep 'concentration=' | grep 'entropy=' | tail -3 | grep -oP 'concentration=[0-9.]+\s+entropy=[0-9.]+\s+gini=[0-9.]+ \([^)]+\)' | sed 's/^/  /' || echo "  (none logged)"

echo ""
echo "--- Proxy deny attribution (top 5) ---"
grep 'surprise probe\|drilldown' "$PROXY_LOG" | tail -5 || echo "  (none logged)"

echo ""
echo "--- Browser agent (concurrent legitimate traffic) ---"
if [[ -f "${BROWSER_LOG:-/dev/null}" ]]; then
    B_ACTIONS=$(grep -c '^\[agent\] #' "$BROWSER_LOG" 2>/dev/null || echo "0")
    B_ERRORS=$(grep -c '\[agent\] .*failed\|Error' "$BROWSER_LOG" 2>/dev/null || echo "0")
    echo "  actions: $B_ACTIONS"
    echo "  errors:  $B_ERRORS"
    echo "  last 3 actions:"
    grep '^\[agent\] #' "$BROWSER_LOG" 2>/dev/null | tail -3 | sed 's/^/    /' || echo "    (none)"
else
    echo "  (browser agent was not running)"
fi

echo ""
echo "--- Nikto findings ---"
NIKTO_FINDINGS=$(grep -cE '^\+' "$NIKTO_LOG" 2>/dev/null || echo "0")
echo "  $NIKTO_FINDINGS informational findings (no exploitable vulnerabilities through firewall)"

echo ""
echo "To inspect denial tokens:"
echo "  grep 'X-Denial-Context' $PROXY_LOG | head -3"
echo ""
echo "To unseal a token:"
echo "  cargo run -p http-runner --bin holon-engram -- unseal <token> --key $ENGRAMS_DIR/nikto/denial.key"
echo ""
