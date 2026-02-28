# HTTP Lab

Autonomous Layer 7 Web Application Firewall powered by [Holon](https://github.com/watmin/holon) Vector Symbolic Architecture. Detects and mitigates HTTP floods, credential stuffing, scraping, and TLS-randomized attacks — without signatures, without training data, without human rules.

Built in four evenings of after-hours work (Mon–Wed, Fri). Mirrors [veth-lab](../veth-lab/)'s architecture and detection philosophy at Layer 7.

## What It Does

The system learns what normal HTTP traffic looks like during a warmup period, then autonomously detects anomalies and generates surgical, compound mitigation rules in real time using a composable Lisp-like expression language. Three layers of field attribution — FieldTracker concentration, VSA surprise probing, and shape detection — produce rules that capture the full distinguishing characteristics of each attack. When an attack ends, the attack's subspace snapshot is stored as an **engram** — on re-detection, stored rules deploy instantly as a fast-path while fresh rules continue generating in parallel.

**Attacks mitigated in the multi-attack scenario (7 waves, 100% mitigated):**

| Attack | TLS Profile | Detection Method | Auto-Generated Rule |
|--------|-------------|------------------|---------------------|
| GET flood (`/api/search`, 2000 rps) | `curl_800` | REQ concentration + VSA surprise (user-agent, path segments) | `{path + user-agent "libwww-perl/6.72" + path-parts}` |
| Credential stuffing (`/api/v1/auth/login`, 1500 rps) | `python_requests` | REQ concentration + TLS concentration + path-part shape | `{path + method + content-type + path-part shapes}` |
| Scraper (random `/products/*` paths, 1000 rps) | `python_requests` | REQ concentration + surprise (Scrapy UA) + shape (5-char IDs) | `{tls-ext-types + user-agent "Scrapy/..." + (count (nth path-parts 2)) = 5}` |
| TLS-randomized flood (`/api/data`, 1500 rps) | `bot_shuffled` | TLS subspace anomaly + cipher/ext set concentration + surprise | `{tls-ext-types + tls-ciphers + tls-groups + path + user-agent}` |
| Replay of all above | All above | Engram library fast-path + fresh rule generation | Stored rules deployed in <1 tick, fresh rules generated in parallel |

**Rule evaluation performance:** O(tree depth), not O(rule count). 1M rules evaluate in ~1.1µs to ~2.6µs. Miss path: ~50ns. A single core exceeds 900K evals/sec.

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
- **ArcSwap for rule tree**: The enforcer reads the compiled expression tree via `ArcSwap::load()` (wait-free). The sidecar swaps atomically during `compile_and_deploy`.
- **Lossless TLS context**: Full ClientHello parsed from raw bytes before handing to rustls. Wire order, GREASE values, raw extension bytes all preserved. Order itself is a detection signal.
- **Structured HTTP requests**: Path parts, parsed query strings (params vs flags), header pairs in wire order with original casing, duplicate headers preserved.
- **Dual detection**: Two independent SubspaceDetector instances — one for TLS context (per-connection), one for full request samples (per-request). Different tuning parameters for each.
- **Three-layer field attribution**: Rule generation combines FieldTracker concentration (high-frequency values), VSA surprise probing (anomalous vector component unbinding against every walkable field), and shape detection (structural patterns like fixed-length strings). Content matches are preferred over shape matches for surgical mitigation.
- **Adaptive TLS constraints**: Dynamically selects ordered (`tls-cipher-order`) or set-based (`tls-ciphers`) rule constraints depending on whether the attacker maintains consistent ordering. Catches both fixed-order and randomized TLS attacks.
- **Composable rule language**: Lisp-like EDN s-expressions with 26 field dimensions, 13 operators, and 12 composition functions. Rules like `(= (first (header "user-agent")) "bot/1.0")` compose accessor chains generically. No magic named headers.
- **Rete-spirit expression tree**: Rules compiled into a discrimination DAG. Evaluation is O(tree depth), not O(rule count). 1M rules evaluate in ~1.1µs to ~2.6µs. Miss path: ~50ns.
- **Engram resilience**: Engram hits are a fast-path optimization, not a substitute for learning. The system always generates fresh rules in parallel, ensuring resilience against engram false-matches.
- **Rule refinement progression**: Broader rules are generated early (streak=3), compound rules with surprise data added later (streak=5+). Both coexist — the tree's `Specificity` evaluator picks the most surgical match.

## Documentation

| Document | Contents |
|----------|----------|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Detection pipeline, data model, rule engine, rate limiting |
| [RULE-LANGUAGE.md](docs/RULE-LANGUAGE.md) | Full language specification: dimensions, operators, composition functions, evaluation order |
| [PROGRESS.md](docs/PROGRESS.md) | Build timeline, milestones, key decisions, open questions |
| [TECH-DEBT.md](docs/TECH-DEBT.md) | Known tech debt, test coverage gaps, multi-core strategy |
| [DASHBOARD-PLAN.md](docs/DASHBOARD-PLAN.md) | Original dashboard design plan |

## Relation to veth-lab

veth-lab operates at Layer 3-4: eBPF/XDP filters packets in the kernel using the same Holon VSA detection pipeline. http-lab operates at Layer 7: a userspace TLS-terminating reverse proxy filters HTTP requests. Both share:

- **holon-rs** for VSA encoding and vector operations
- **OnlineSubspace** (CCIPCA) for manifold-aware anomaly detection
- **EngramLibrary** for attack pattern memory
- **Rete-spirit DAG** rule engine with dimension-ordered evaluation
- **Concentration + surprise** for field-level attribution
- **EDN rule syntax** for human-readable rules

The key difference: http-lab has access to the full HTTP request and TLS ClientHello, enabling richer detection dimensions (path structure, query parameters, header patterns, per-header content and shape, TLS cipher/extension sets) and finer-grained mitigation (per-IP rate limiting vs kernel-level DROP). The composable expression language with accessor chains (`(first (header "name"))`, `(nth path-parts N)`, `(count ...)`) allows the detection pipeline to generate arbitrarily specific rules — something traditional WAFs require human analysts to write.

## Why This Matters

Traditional WAFs evaluate rules sequentially — O(n) per request, often involving regex matching. Adding rules linearly degrades throughput. The expression tree eliminates this: rules are compiled into a discrimination DAG where evaluation is a fixed number of hash lookups. At runtime, no rule is ever "checked" — field values navigate directly to the matching terminal node.

Traditional WAFs also require human-authored rules or curated signature databases. This system generates its own rules from raw traffic — no signatures, no training data, no analyst. The three-layer field attribution (concentration + surprise probing + shape detection) discovers signals that human analysts would write, but does so autonomously and in real time.

The combination — autonomous surgical rule generation + sub-microsecond constant-time evaluation — is what makes this viable as a production WAF, not just a lab prototype.
