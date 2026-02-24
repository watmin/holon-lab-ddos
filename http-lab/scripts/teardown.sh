#!/usr/bin/env bash
# Stop all http-lab processes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
LOGS_DIR="$LAB_DIR/logs"

stop_pid_file() {
    local name="$1"
    local pid_file="$2"
    if [[ -f "$pid_file" ]]; then
        local pid
        pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            echo "==> Stopping $name (pid=$pid)"
            kill "$pid" 2>/dev/null || true
            sleep 1
        fi
        rm -f "$pid_file"
    fi
}

stop_pid_file "proxy" "$LOGS_DIR/proxy.pid"
stop_pid_file "backend" "$LOGS_DIR/backend.pid"
stop_pid_file "generator" "$LOGS_DIR/generator.pid"

# Kill any stray processes by name
pkill -f "http-proxy" 2>/dev/null || true
pkill -f "http-generator" 2>/dev/null || true

echo "==> Teardown complete"
