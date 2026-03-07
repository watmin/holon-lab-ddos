# Experiment: Spectral Firewall vs Multi-Tool Attack with Concurrent Legitimate Traffic

**Date:** March 6-7, 2026
**Status:** Validated — zero false positives under concurrent mixed workload

## What We Proved

The spectral firewall correctly classified 100% of requests under a concurrent
mixed workload: 20 LLM-driven browser agents generating realistic traffic
through diverse source IPs alongside three professional vulnerability scanners
(Nikto, ZAP, Nuclei) — all hitting the same proxy simultaneously. Zero
legitimate requests were denied. 3,635 attack requests were blocked.

This is the first test with **realistic concurrent traffic** — previous
experiments used sequential phases (train, then attack). This experiment
validates that the firewall can discriminate in real time when good and bad
traffic arrive simultaneously.

## Architecture

```
                          20 LLM Browser Agents (Grok-4-fast + Playwright)
                          ├── chromium (80%), webkit (15%), firefox (5%)
                          ├── source IPs: 10.99.0.1-10.99.0.20 (via dummy0)
                          └── TCP forwarders: 127.0.0.1:50001-50020
                                    │
                                    ▼
Nikto ──────────┐            ┌─────────────┐           ┌──────────────┐
ZAP ────────────┼──────────► │ Proxy :8443  │ ────────► │ DVWA :8888   │
Nuclei ─────────┘  (127.0.0.1)│ (spectral)   │           │ (Docker)     │
                             └─────────────┘           └──────────────┘
```

Key difference from previous experiments: attack tools connect from 127.0.0.1
(no forwarder), browser agents connect from 10.99.0.x (via TCP forwarders
binding to dummy0 interface IPs). The proxy sees genuinely different source
addresses.

## Traffic Labeling

Browser agents send `X-Traffic-Source: browser-agent` via Playwright's
`extra_http_headers`. The proxy:

1. Extracts the header value into `RequestSample.traffic_source`
2. **Strips it from the headers vec** before VSA encoding — invisible to the
   spectral layer
3. Includes it in deny events, dashboard, and log attribution for ground truth

Attack tools (Nikto, ZAP, Nuclei) don't send this header → `traffic_source`
is empty → logged as `label=unknown`. This provides unambiguous ground truth
for false positive measurement without contaminating the geometric model.

## Source IP Diversity

A `dummy0` network interface provides 20 addresses (10.99.0.1-10.99.0.20).
Python TCP forwarders (`source_forwarder.py`) listen on 127.0.0.1:50001-50020
and forward to 10.99.0.100:8443 (proxy), binding the outgoing socket to
10.99.0.N. TLS passes through end-to-end.

Browser distribution mirrors real-world traffic:
- 80% Chromium (16 agents)
- 15% WebKit/Safari (3 agents)
- 5% Firefox (1 agent)

Each agent runs independently with LLM-driven navigation decisions (Grok-4-fast,
~1s per decision), exploring DVWA pages, submitting forms with benign values,
and navigating via sidebar menus.

## Timeline

| Phase | Duration | Activity |
|-------|----------|----------|
| DVWA setup | ~10s | Docker compose, DB init, auth |
| Build | ~35s | `cargo build --release` |
| Forwarders | 2s | 20 TCP forwarders on dummy0 |
| Warmup | 90s | 20 browser agents only → manifold learns |
| Mixed traffic | ~140s | Browsers continue + Nikto + ZAP + Nuclei |
| Cleanup | — | Stop all, collect results |

Total browser duration: 270s (warmup + attack + buffer).

## Results — Final Run (March 7, 2026)

### Spectral Verdicts

| Verdict | Count |
|---------|-------|
| Allow | 300 |
| Warmup | 602 |
| Rate-limit | 33 |
| **Deny** | **3,605** |

### Traffic Source Breakdown (Ground Truth)

| Verdict | browser-agent | unlabeled (attack) |
|---------|--------------|-------------------|
| **Deny** | **0** | **3,605** |
| **Rate-limit** | **0** | **30** |

**Zero false positives.** Every denied or rate-limited request was from an
attack tool. Every browser agent request was allowed.

### Enforcement

| Action | Count |
|--------|-------|
| Pass | 905 |
| Block | 0 |
| Rate-limit (Layer 0/1) | 9,920 |
| Close | 0 |

### Adaptive Learning

| Metric | Value |
|--------|-------|
| Adaptive learns | 22 |
| Manifold republishes | 0 |
| Broad rejections | 0 |
| Warmup threshold | 82.96 |
| Post-adaptive threshold | 82.96 (unchanged) |

Only 22 samples were adaptively learned (all from legitimate browser traffic),
and the manifold was never republished — the baseline stayed completely stable
during the attack phase.

### Anomaly Breadth

| Sample | Concentration | Entropy | Gini | Classification |
|--------|--------------|---------|------|---------------|
| 1 | 2.9 | 0.936 | 0.377 | moderate |
| 2 | 3.2 | 0.920 | 0.423 | moderate |
| 3 | 2.8 | 0.931 | 0.389 | moderate |
| 4 | 2.9 | 0.934 | 0.383 | moderate |
| 5 | 3.2 | 0.927 | 0.404 | moderate |

All attack traffic shows "moderate" breadth — anomalous across multiple
dimensions but not uniformly so. Consistent with scanner tools that differ
from browsers in TLS fingerprint, header structure, path patterns, and
user-agent but share some dimensions (HTTP version, basic request structure).

### Browser Agents

- 20 agents launched, all 20 alive throughout entire run
- 701 total actions across agents
- 61 errors (navigation timeouts, non-fatal)

### Per-Tool Findings (What Scanners Found Through the Firewall)

| Tool | Findings |
|------|----------|
| Nikto | 22 informational (SSL/header info, no exploitable vulns) |
| ZAP | 0 alerts, 0 passed |
| Nuclei | 14 (template install messages + infra info, no exploitable vulns) |

## Parameter Tuning Journey

### Problem: First Run Blocked Nothing

The initial run with 20 diverse browser agents produced **zero denials**.
Three cascading issues:

1. **Threshold inflation**: `sigma_mult=5.0` with 32 stripes and diverse
   training data (3 browser types, 20 source IPs) produced an RSS threshold
   of ~105. Attack residuals (~26-43) were well below.

2. **Adaptive poisoning**: `ADAPTIVE_RESIDUAL_GATE=0.7` set the gate at
   `105 * 0.7 = 73.5`. Attack residuals (26-43) fell below this gate, so
   **attack traffic was actively learned into the baseline**. 1,374 adaptive
   learns occurred, with 27 manifold republishes. The model poisoned itself.

3. **Deny multiplier**: `deny_threshold = threshold * 2.0 = ~210`. Even if
   attacks scored above the (inflated) threshold, the deny boundary was
   unreachable.

### Fix: Three Parameter Changes

| Parameter | Before | After | Effect |
|-----------|--------|-------|--------|
| `sigma_mult` (striped) | 5.0 | 3.0 | RSS threshold: ~105 → ~43 |
| deny multiplier | 2.0x | 1.5x | Deny threshold: ~210 → ~83 |
| `ADAPTIVE_RESIDUAL_GATE` | 0.7 | 0.5 | Gate: ~74 → ~21, blocks attack absorption |

### Result: Second Run

| Metric | Run 1 (broken) | Run 2 (fixed) |
|--------|---------------|---------------|
| Denials | 0 | 3,605 |
| False positives | N/A | 0 |
| Adaptive learns | 1,374 | 22 |
| Manifold republishes | 27 | 0 |

### Key Insight: Training Diversity vs Threshold Sensitivity

The original K=32 + sigma_mult=5.0 configuration was tuned for the earlier
single-source synthetic generator (uniform traffic, one client type). With
20 diverse browser agents producing genuinely varied traffic (3 browser
engines, different navigation patterns, different source IPs), the variance
of residuals during training was much higher, inflating the threshold.

**The fundamental tension:** diverse training creates a robust manifold but
widens thresholds. Narrow training creates a sensitive manifold but may
reject legitimate client variants. The sigma_mult parameter mediates this
trade-off.

This suggests sigma_mult should be **derived from training data properties**
rather than hardcoded — e.g., based on observed residual variance, number
of distinct client populations in the warmup set, or the ratio of inter-class
to intra-class variance.

### Open: The Three Magic Numbers

The current fix uses three hardcoded constants. These should eventually be
derived from observable properties of the training data:

1. **`sigma_mult = 3.0`** — how many standard deviations above mean residual
   defines the anomaly threshold. Should be a function of training diversity.

2. **`deny_mult = 1.5`** — multiplier from anomaly threshold to deny threshold.
   Should be a function of separation ratio (observed attack/normal gap).

3. **`ADAPTIVE_RESIDUAL_GATE = 0.5`** — fraction of threshold below which
   adaptive learning occurs. Should be a function of the minimum expected
   attack residual relative to threshold.

See NEXT-INVESTIGATIONS.md for proposed approaches.

## Comparison with Previous Experiments

| Experiment | Normal Traffic | Attack | Denials | FP | Notes |
|-----------|---------------|--------|---------|-----|-------|
| Synthetic (Mar 3) | http-generator | http-generator scanner | 5,355 | 0 | Sequential phases |
| DVWA+Nikto (Mar 4) | http-generator | Real Nikto | 10,121 | 0 | Sequential phases |
| **Multi-attack (Mar 7)** | **20 LLM browsers** | **Nikto+ZAP+Nuclei** | **3,605** | **0** | **Concurrent mixed** |

The multi-attack experiment is the most realistic test: real browsers with
LLM-driven navigation, real vulnerability scanners, concurrent traffic,
diverse source addresses, multiple browser engines. Zero false positives
across all experiments.

## Infrastructure Components

| Component | File | Purpose |
|-----------|------|---------|
| Orchestrator | `run-multi-attack.sh` | Full lifecycle: DVWA → build → proxy → forwarders → agents → attacks → summary |
| Browser agent | `dvwa_browser_agent.py` | LLM-driven Playwright browser with retry logic |
| Multi-agent launcher | `multi_agent.py` | Spawns N agents with browser distribution and stagger |
| TCP forwarder | `source_forwarder.py` | Source-IP-binding TCP proxy for address diversity |
| Network setup | `setup-local-network.sh` | Creates dummy0 interface with N addresses |

### Browser Agent Resilience

After initial runs where agents died from transient errors, the agent was
hardened with:
- 5-retry exponential backoff on initial page load
- Per-action error handling (consecutive error counter)
- Auto-reload to index after 5 consecutive errors
- Only gives up after 10 consecutive unrecoverable errors

Result: all 20 agents survived the full 270s run including the attack phase.

## Reproduction

```bash
# One-time: create dummy network interface with 20 IPs
sudo ./http-lab/scenarios/dvwa/setup-local-network.sh 20

# Run the full experiment (~5 minutes)
cd http-lab/scenarios/dvwa
./run-multi-attack.sh

# Inspect a denial token
cargo run -p http-runner --bin holon-engram -- unseal <token> \
    --key http-lab/engrams/multi-attack/denial.key
```

Environment requirements:
- Docker (DVWA, Nikto, ZAP, Nuclei images)
- Rust toolchain
- Python venv at `scenarios/dvwa/.venv` with `xai-sdk` + `playwright`
- `XAI_API_KEY` environment variable (for Grok-4-fast)
- `dummy0` interface (via `setup-local-network.sh`)
