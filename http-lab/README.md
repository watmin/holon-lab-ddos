# HTTP Lab

Autonomous Layer 7 Web Application Firewall powered by [Holon](https://github.com/watmin/holon) Vector Symbolic Architecture. Detects and mitigates HTTP floods, credential stuffing, scraping, and TLS-randomized attacks — without signatures, without training data, without human rules.

Built in three days of after-hours work. Mirrors [veth-lab](../veth-lab/)'s architecture and detection philosophy at Layer 7.

## What It Does

The system learns what normal HTTP traffic looks like during a warmup period, then autonomously detects anomalies and generates mitigation rules in real time. When an attack ends, the attack's subspace snapshot is stored as an **engram** — on re-detection, stored rules deploy instantly without waiting for the full detection pipeline.

**Attacks mitigated in the multi-attack scenario:**

| Attack | TLS Profile | Detection Method | Mitigation |
|--------|-------------|------------------|------------|
| GET flood (`/api/search`, 2000 rps) | `curl_800` | REQ subspace anomaly + path concentration | Rate limit to baseline rps |
| Credential stuffing (`/api/v1/auth/login`, 1500 rps) | `python_requests` | REQ subspace anomaly + path + TLS concentration | Rate limit |
| Scraper (random `/products/*` paths, 1000 rps) | `python_requests` | REQ subspace anomaly + TLS set concentration | Rate limit |
| TLS-randomized flood (`/api/data`, 1500 rps) | `bot_shuffled` | TLS subspace anomaly + cipher/ext set concentration | Rate limit |
| Replay of all above | All above | Engram library instant match | Stored rules deployed in <1 tick |

## Architecture

```
                            Clients / Attackers
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────┐
│                          Runner (http-proxy binary)                   │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                     Proxy (library crate)                        │  │
│  │                                                                  │  │
│  │  TLS Accept ─► ClientHello Parse ─► TLS Context (lossless)      │  │
│  │       │                                                          │  │
│  │       ▼                                                          │  │
│  │  HTTP Handler ─► Parse Request ─► RequestSample (structured)    │  │
│  │       │                    │                                     │  │
│  │       │                    │ try_send (drop on full)             │  │
│  │       ▼                    ▼                                     │  │
│  │  Enforcer ◄── ArcSwap ◄── mpsc channel ──────────────────┐      │  │
│  │  (wait-free)  (CompiledTree)                              │      │  │
│  │       │                                                   │      │  │
│  │       ▼                                                   │      │  │
│  │  RateLimiter (per-IP token bucket)                        │      │  │
│  │       │                                                   │      │  │
│  │       ▼                                                   │      │  │
│  │  200 / 403 / 429 / close                                  │      │  │
│  └───────────────────────────────────────────────────────────│──────┘  │
│                                                              │         │
│  ┌───────────────────────────────────────────────────────────│──────┐  │
│  │                    Sidecar (library crate)                │      │  │
│  │                                                           ▼      │  │
│  │  ┌──────────┐   ┌──────────────────┐   ┌──────────────┐         │  │
│  │  │ Holon-rs │   │ SubspaceDetector │   │ Field Tracker │         │  │
│  │  │ Encoder  │──►│ (TLS + REQ)      │   │ (decay +     │         │  │
│  │  │ (4096d)  │   │ - Online PCA     │   │  concentrate)│         │  │
│  │  └──────────┘   │ - Residual score │   └──────┬───────┘         │  │
│  │                  │ - Threshold EMA  │          │                  │  │
│  │                  └────────┬─────────┘          │                  │  │
│  │                           │                    │                  │  │
│  │                  ┌────────▼────────────────────▼──────────┐      │  │
│  │                  │           Rule Generation              │      │  │
│  │                  │  - Surprise fingerprint (unbind)       │      │  │
│  │                  │  - Concentration-based field selection  │      │  │
│  │                  │  - Adaptive ordered vs set TLS fields   │      │  │
│  │                  │  - EDN rule syntax                      │      │  │
│  │                  └────────┬───────────────────────────────┘      │  │
│  │                           │                                      │  │
│  │               ┌───────────▼──────────┐   ┌────────────────┐     │  │
│  │               │    Rule Manager      │   │ Engram Library │     │  │
│  │               │ - Upsert / expire    │◄──│ - Subspace snap│     │  │
│  │               │ - DAG compile        │   │ - Stored rules │     │  │
│  │               │ - ArcSwap deploy     │   │ - JSON persist │     │  │
│  │               └──────────────────────┘   └────────────────┘     │  │
│  │                                                                  │  │
│  │  ┌──────────────────────────────────────────────────────────┐   │  │
│  │  │  Metrics Server (Axum)        :9090                       │   │  │
│  │  │  /dashboard — real-time UI (SSE + uPlot)                  │   │  │
│  │  │  /api/events — SSE stream (metrics, rules, detections)    │   │  │
│  │  │  /api/rules — active rule list                            │   │  │
│  │  └──────────────────────────────────────────────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                            Upstream Backend (:8080)
```

## Components

| Crate | Role |
|-------|------|
| `proxy/` | TLS termination, ClientHello parsing, HTTP handling, rule enforcer, rate limiter, shared types |
| `sidecar/` | VSA encoding, dual SubspaceDetector (TLS + REQ), field tracking, rule generation, engram memory, dashboard |
| `runner/` | Binary entry point — spawns proxy + sidecar in one tokio runtime |
| `generator/` | Scenario-driven traffic generator with named TLS profiles (chrome, firefox, curl, python, bot_shuffled) |

## Quick Start

```bash
# 1. Build (from holon-lab-ddos/ root)
cargo build --release -p http-proxy -p http-generator

# 2. Setup mock backend + TLS certs
./http-lab/scripts/setup.sh

# 3. Start proxy (logs to http-lab/logs/, engrams to http-lab/engrams/)
RUST_LOG=info target/release/http-proxy \
    --cert http-lab/certs/cert.pem \
    --key http-lab/certs/key.pem \
    --engram-path http-lab/engrams/http

# 4. (Separate terminal) Run multi-attack scenario
RUST_LOG=info target/release/http-generator \
    --target 127.0.0.1:8443 \
    --host localhost \
    --insecure \
    --scenario http-lab/scenarios/multi_attack.json

# 5. Open dashboard
open http://127.0.0.1:9090/dashboard

# 6. Cleanup
./http-lab/scripts/teardown.sh
```

Or use the all-in-one demo script:

```bash
./http-lab/scripts/demo.sh --scenario multi_attack
```

## Key Design Decisions

- **Same-process architecture**: Proxy and sidecar share one tokio runtime. Sample delivery is a bounded `mpsc::channel` with `try_send` — the proxy never blocks waiting for the sidecar.
- **ArcSwap for rule tree**: The enforcer reads the compiled rule tree via `ArcSwap::load()` (wait-free). The sidecar holds a write lock briefly during `compile_and_deploy`.
- **Lossless TLS context**: Full ClientHello parsed from raw bytes before handing to rustls. Wire order, GREASE values, raw extension bytes all preserved. Order itself is a detection signal.
- **Structured HTTP requests**: Path parts, parsed query strings (params vs flags), header pairs in wire order with original casing, duplicate headers preserved.
- **Dual detection**: Two independent SubspaceDetector instances — one for TLS context (per-connection), one for full request samples (per-request). Different tuning parameters for each.
- **Concentration + surprise**: Rule generation uses concentration-based field attribution (fields that appear at anomalously high frequency during an attack), not just surprise fingerprint magnitude.
- **Adaptive TLS constraints**: Dynamically selects ordered (`tls_cipher_hash`) or set-based (`tls_cipher_set`) rule constraints depending on whether the attacker maintains consistent ordering. Catches both fixed-order and randomized TLS attacks.
- **EDN rule syntax**: Human-readable rule representation matching veth-lab's s-expression format.

## Documentation

| Document | Contents |
|----------|----------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Detection pipeline, data model, rule engine, rate limiting |
| [PROGRESS.md](docs/PROGRESS.md) | Build timeline, milestones, key decisions, open questions |
| [DASHBOARD-PLAN.md](docs/DASHBOARD-PLAN.md) | Original dashboard design plan |

## Relation to veth-lab

veth-lab operates at Layer 3-4: eBPF/XDP filters packets in the kernel using the same Holon VSA detection pipeline. http-lab operates at Layer 7: a userspace TLS-terminating reverse proxy filters HTTP requests. Both share:

- **holon-rs** for VSA encoding and vector operations
- **OnlineSubspace** (CCIPCA) for manifold-aware anomaly detection
- **EngramLibrary** for attack pattern memory
- **Rete-spirit DAG** rule engine with dimension-ordered evaluation
- **Concentration + surprise** for field-level attribution
- **EDN rule syntax** for human-readable rules

The key difference: http-lab has access to the full HTTP request and TLS ClientHello, enabling richer detection dimensions (path structure, query parameters, header patterns, TLS cipher/extension sets) and finer-grained mitigation (per-IP rate limiting vs kernel-level DROP).
