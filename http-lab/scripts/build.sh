#!/usr/bin/env bash
# Build all http-lab crates.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
REPO_DIR="$(dirname "$LAB_DIR")"

cd "$REPO_DIR"

echo "==> Building http-lab (proxy lib, sidecar lib, runner binary, generator)"
cargo build --release \
    -p http-proxy \
    -p http-sidecar \
    -p http-runner \
    -p http-generator

echo "==> Build complete"
echo "    Binaries:"
echo "      target/release/http-proxy   (from http-runner crate)"
echo "      target/release/http-generator"
