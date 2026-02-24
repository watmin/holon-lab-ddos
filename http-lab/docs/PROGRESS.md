# http-lab Progress

## Overview

L7 WAF lab — HTTP flood DDoS detection and mitigation via TLS-terminating reverse
proxy + holon-rs sidecar running a Rete-spirit rule engine. Mirrors veth-lab structure
and philosophy at Layer 7.

## Phase 1: DDoS

### Status

| Component | Status | Notes |
|-----------|--------|-------|
| Scaffold + Cargo.toml | ✅ Done | Workspace registered, runner crate added |
| proxy/src/types.rs | ✅ Done | TlsContext, ConnectionContext, RequestSample, rule types |
| proxy/src/tls.rs | ✅ Done | ClientHello parser + ReplayStream + tokio-rustls handshake |
| proxy/src/http.rs | ✅ Done | Hyper HTTP/1.1 + upstream forwarding + sample enqueue |
| proxy/src/tree.rs | ✅ Done | Rete-spirit DAG compiler (HTTP DIM_ORDER) |
| proxy/src/enforcer.rs | ✅ Done | Synchronous ArcSwap rule check |
| runner/src/main.rs | ✅ Done | Binary: spawns proxy + sidecar tasks in-process |
| sidecar/src/detectors.rs | ✅ Done | SubspaceDetector + EngramLibrary wrappers |
| sidecar/src/detection.rs | ✅ Done | Detection → RuleSpec compilation |
| sidecar/src/field_tracker.rs | ✅ Done | Per-field value tracking with decay |
| sidecar/src/rule_manager.rs | ✅ Done | Upsert, expire, compile, ArcSwap write |
| sidecar/src/lib.rs | ✅ Done | Dual detection loops (TLS + request) |
| sidecar/src/metrics_server.rs | ✅ Done | Axum dashboard (/metrics, /health) |
| generator/src/main.rs | ✅ Done | Multi-phase HTTP flood with TLS profiles |
| scripts/ | ✅ Done | build.sh, setup.sh, demo.sh, teardown.sh |

### Phase 1a — Working Proxy (no rules) ✅ COMPLETE

- [x] `types.rs` — TlsContext, ConnectionContext, RequestSample, rule types, CompiledTree
- [x] `tls.rs` — Raw ClientHello parser, TlsContext → holon Vector, tokio-rustls handshake
- [x] `http.rs` — Hyper HTTP/1.1 server, upstream forwarding, sample enqueue
- [x] `runner/main.rs` — TLS accept loop, spawns sidecar tasks in-process
- [x] `setup.sh` — start mock backend (python http.server)
- [x] `build.sh` — cargo build wrapper

**Result**: working TLS-terminating reverse proxy that parses ClientHello and logs TlsContext per connection.

### Phase 1b — Detection + Rules ✅ COMPLETE

- [x] `tree.rs` — Rete-spirit DAG compiler for HTTP dimensions (SrcIp, TlsGroupHash, Method, Path, Host, UA, ContentType)
- [x] `enforcer.rs` — synchronous rule check via ArcSwap on every request
- [x] `sidecar/detectors.rs` — SubspaceDetector, EngramLibrary wrappers
- [x] `sidecar/detection.rs` — Detection → RuleSpec compilation
- [x] `sidecar/field_tracker.rs` — per-field value tracking with decay
- [x] `sidecar/rule_manager.rs` — upsert, expire, compile, redundancy check, ArcSwap write
- [x] `sidecar/lib.rs` — dual detection loops (TLS + request), ArcSwap wiring
- [x] `sidecar/metrics_server.rs` — axum /metrics + /health dashboard
- [x] `runner/main.rs` updated — spawns sidecar tasks, wires ArcSwap + channels

**Result**: proxy detects anomalies and enforces auto-generated rules.

### Phase 1c — Generator + Demo ✅ COMPLETE

- [x] `generator/` — scenario-driven HTTP flood with named TLS profiles
- [x] `demo.sh` — end-to-end: warmup → GET flood → calm → detection → mitigation
- [x] `scenarios/ddos-demo.json` — reference scenario file

**Result**: reproducible DDoS detection demo. Run `./scripts/demo.sh` to execute.

## Key Decisions

### 2026-02-23

- Same process as veth-lab (sidecar is a lib, proxy binary owns everything)
- Full ClientHello parser from day one — we parse raw bytes we already own before
  handing to rustls. ~150 lines, no crypto involved.
- TlsContext (not "fingerprint") — lossless, ordered, raw extension bytes preserved
- RequestSample headers: Vec<(String,String)> — wire order, duplicates preserved
- Proxy always acts synchronously (ArcSwap::load); sidecar enqueue is try_send (drop on full)
- Body inspection deferred to phase 2 (exploit detection)
- Connection close on TLS/IP rule match; RST hardening deferred to phase 2
- `runner` crate added as the actual binary to avoid circular dep: proxy lib ← sidecar lib ← runner bin

## Performance Observations

(to be populated as experiments run)

## Open Questions

- Rate-limit granularity: per-IP or per-(IP, path)?
- Warmup duration for baseline: 30s sufficient for HTTP traffic diversity?
- ArcSwap vs RwLock for tree: ArcSwap chosen (wait-free reads, sidecar holds write lock briefly)

## Phase 2 (Future)

- Body inspection (streaming windowed VSA, PayloadSubspaceDetector)
- Exploit detection: SQLi, XSS, path traversal
- Connection RST via SO_LINGER
- JA4 string output for external tool correlation
- XDP integration for kernel-level enforcement
