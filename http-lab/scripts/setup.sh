#!/usr/bin/env bash
# Start the mock backend (axum echo server) and generate a self-signed TLS cert.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$(dirname "$LAB_DIR")"
CERTS_DIR="$LAB_DIR/certs"
LOGS_DIR="$LAB_DIR/logs"
ENGRAMS_DIR="$LAB_DIR/engrams"

mkdir -p "$CERTS_DIR" "$LOGS_DIR" "$ENGRAMS_DIR"

# --- TLS certificate (self-signed, dev only) ---
if [[ ! -f "$CERTS_DIR/cert.pem" ]]; then
    echo "==> Generating self-signed TLS certificate"
    openssl req -x509 -newkey rsa:2048 -keyout "$CERTS_DIR/key.pem" \
        -out "$CERTS_DIR/cert.pem" -days 365 -nodes \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
    echo "    Cert: $CERTS_DIR/cert.pem"
    echo "    Key:  $CERTS_DIR/key.pem"
else
    echo "==> TLS certificate already exists at $CERTS_DIR/cert.pem"
fi

# --- Mock backend ---
# Simple axum echo server — returns 200 with request info
BACKEND_PID_FILE="$LOGS_DIR/backend.pid"
if [[ -f "$BACKEND_PID_FILE" ]] && kill -0 "$(cat "$BACKEND_PID_FILE")" 2>/dev/null; then
    echo "==> Mock backend already running (pid=$(cat $BACKEND_PID_FILE))"
else
    echo "==> Starting mock backend on :8080"
    python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

class QuietHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f'OK {self.command} {self.path}\n'.encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_POST = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_GET
    def log_message(self, *args):
        pass  # suppress per-request logging

HTTPServer(('127.0.0.1', 8080), QuietHandler).serve_forever()
" > "$LOGS_DIR/backend.log" 2>&1 &
    echo $! > "$BACKEND_PID_FILE"
    sleep 1
    echo "    Backend running (pid=$(cat $BACKEND_PID_FILE))"
    echo "    Log: $LOGS_DIR/backend.log"
fi

echo ""
echo "==> Setup complete. To start the proxy:"
echo "    cd $REPO_DIR"
echo "    target/release/http-proxy \\"
echo "        --listen 0.0.0.0:8443 \\"
echo "        --upstream 127.0.0.1:8080 \\"
echo "        --cert $CERTS_DIR/cert.pem \\"
echo "        --key $CERTS_DIR/key.pem \\"
echo "        --metrics-addr 127.0.0.1:9090"
