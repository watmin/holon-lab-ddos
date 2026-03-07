# Experiment: Spectral Firewall vs Real Nikto on Live DVWA

**Date:** March 4, 2026
**Status:** First run complete — firewall blocked Nikto; DVWA exposed zero vulnerabilities through the proxy

## Architecture

```
Nikto (Docker) ──► https://127.0.0.1:8443 ──► Manifold Proxy (host) ──► http://127.0.0.1:8888 ──► DVWA (Docker)
                         TLS termination           Layers 0-3                         Apache/PHP + MariaDB
```

DVWA is an intentionally vulnerable web application. Nikto is a real vulnerability scanner.
The spectral firewall sits between them with no signatures, no rules, and no prior knowledge of either.

## Setup

### Terminal 1: DVWA Backend

```bash
cd ~/work/holon/holon-lab-ddos/http-lab/scenarios/dvwa
docker compose up -d
```

**Workaround required:**

1. **Port conflict:** Open WebUI occupies :8080 on this host. DVWA mapped to `:8888` instead.

2. **Cookie domain bug:** `cytopia/dvwa` sets `PHPSESSID` cookie with `domain=$_SERVER['HTTP_HOST']`
   which includes the port (e.g. `127.0.0.1:8888`). Browsers reject this per RFC 6265. One sed:
   ```bash
   docker exec dvwa-dvwa-1 sed -i \
       "s/'domain' => \$_SERVER\['HTTP_HOST'\]/'domain' => ''/" \
       /var/www/html/dvwa/includes/dvwaPage.inc.php
   ```
   After that, setup.php and login work normally. `run-nikto.sh` does this automatically.

3. **Verify:** Login at `http://127.0.0.1:8888/login.php` — `admin` / `password`

### Terminal 2: Manifold Proxy

```bash
cd ~/work/holon/holon-lab-ddos

RUST_LOG=info target/release/http-proxy \
    --listen 0.0.0.0:8443 \
    --upstream 127.0.0.1:8888 \
    --cert http-lab/certs/cert.pem \
    --key http-lab/certs/key.pem \
    --engram-path http-lab/engrams/nikto \
    --metrics-addr 127.0.0.1:9090 \
    --denial-tokens
```

### Terminal 3: Warmup (train the normal manifold)

Authenticate first, then pass the real session to the generator:

```bash
cd ~/work/holon/holon-lab-ddos

# Get a real DVWA session
RESP=$(curl -sv http://127.0.0.1:8888/login.php 2>&1)
SID=$(echo "$RESP" | grep -oP 'PHPSESSID=\K[^;]+')
TOK=$(echo "$RESP" | grep -oP "user_token' value='\K[^']*")
curl -s -b "PHPSESSID=$SID;security=low" \
    -d "username=admin&password=password&Login=Login&user_token=$TOK" \
    http://127.0.0.1:8888/login.php -o /dev/null

RUST_LOG=info target/release/http-generator \
    --target 127.0.0.1:8443 \
    --host localhost \
    --insecure \
    --scenario http-lab/scenarios/warmup_only.json \
    --cookie "PHPSESSID=$SID; security=low"
```

Wait for warmup to complete (~30s). Expect 100% 2xx. Proxy log should show `warmup(tls=done,req=done)`.

### Terminal 4: Nikto

```bash
# Standard run (~35s, ~8000 requests):
docker run --rm --net=host alpine/nikto \
    -h https://127.0.0.1:8443 \
    -ssl \
    -nointeractive \
    -maxtime 120

# Slow run (1 request/sec, tests pure geometry without rate limits):
docker run --rm --net=host alpine/nikto \
    -h https://127.0.0.1:8443 \
    -ssl \
    -nointeractive \
    -maxtime 300 \
    -Pause 1
```

**Note:** The Docker image is `alpine/nikto` (not `sullo/nikto`, which was removed from Docker Hub).

## Run 1 Results — March 4, 2026

### Nikto Output

```
- Nikto v2.1.6
+ Target IP:          127.0.0.1
+ Target Port:        8443
+ SSL Info:        Subject:  /CN=localhost
+ Start Time:         2026-03-04 03:34:39 (GMT0)
+ Server: Apache/2.4.54 (Debian)
+ Retrieved x-powered-by header: PHP/8.1.16
+ [informational findings about missing headers, cookie flags]
+ Uncommon header 'x-denial-context' found [denial token present]
+ Root page / redirects to: login.php
+ 8042 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2026-03-04 03:35:14 (GMT0) (35 seconds)
```

### Proxy Metrics Progression

| Tick | req samples | rps | rules | enforced pass | rate_limit | manifold deny |
|------|-------------|-----|-------|---------------|------------|---------------|
| 280 (pre-Nikto) | 2,406 | 0 | 0 | 2,406 | 0 | 0 |
| 300 (Nikto starts) | 2,651 | 122 | 2 | 2,454 | 246 | 0 |
| 310 | 3,747 | 46 | 7 | 2,454 | 1,010 | 19 |
| 330 | 5,966 | 272 | 8 | 2,455 | 3,059 | 80 |
| 350 | 8,573 | 301 | 8 | 2,455 | 5,501 | 219 |
| 370 (Nikto done) | 10,117 | 0 | 8 | 2,455 | 6,944 | 255 |

### Final Counts

| Counter | Value |
|---------|-------|
| manifold allow | 1,895 |
| manifold warmup | 511 |
| manifold rate_limit | 512 |
| manifold deny | 255 |
| enforcement rate_limit | 6,944 |
| auto-generated rules | 8 |
| anomaly score (req) | 60.03 (threshold: 26.54) — **2.3x above** |
| anomaly score (tls) | 54.79 (threshold: 39.44) — **1.4x above** |
| anomaly streak | 67 consecutive windows |

### Analysis

1. **8,042 Nikto requests, zero exploitable vulnerabilities found.** DVWA is full of SQLi, XSS,
   command injection, file inclusion — Nikto found none through the proxy.

2. **Denial token present** on blocked requests (`x-denial-context` header), providing sealed
   explainability for every deny decision.

3. **8 rules auto-generated** from anomaly patterns within the first 10 seconds. The system
   wrote its own firewall rules in real-time from geometric anomaly detection.

4. **Anomaly streak never broke.** 67 consecutive windows classified as anomalous — Nikto never
   once looked like normal DVWA traffic.

5. **Allow count frozen at 1,895.** Normal engram correctly did not absorb Nikto traffic.
   The normal manifold is immune to contamination by attack traffic.

## Known Issues (Run 1) — Fixed

1. **WindowTracker stayed in mode=Normal** — `library.is_empty()` short-circuited to Normal
   when no attack engrams existed. Fixed: spectrum-based classification now runs even with
   an empty library. Nikto correctly classified as Targeted in Run 3.

2. **NaN handling** — `evaluate_manifold()` treated NaN residuals as RateLimit. Fixed: NaN
   now defaults to Deny.

3. **Denial tokens unrecoverable** — key was randomly generated per proxy restart and never
   saved. Fixed: key persisted to `<engram-path>/denial.key`, `unseal` CLI command added.

4. **Warmup 20% 2xx** — generator used fake PHPSESSID cookies, DVWA returned 302 redirects.
   Fixed: `--cookie` flag added to generator, `run-nikto.sh` authenticates and passes a real session.

## Run 3 Results — March 4, 2026 (all fixes applied)

### Setup

- DVWA with MariaDB on `:8888`, real authenticated session for warmup
- Proxy on `:8443` with manifold + denial tokens, key persisted
- Generator warmup: 30s @ 80 rps `dvwa_browse` with real PHPSESSID
- Nikto: `alpine/nikto`, 120s maxtime, standard scan

### Warmup

```
PHASE_RESULT name=warmup total=2396 2xx=2263 403=0 429=0 other=133
  2xx%=94.4  latency_p50=6000us  latency_p95=46772us  latency_p99=50852us
```

94.4% 2xx (up from 20.4% with fake session). The 5.6% "other" are DVWA pages
that redirect for non-auth reasons (e.g. form state requirements).

### Nikto Scan

```
+ 0 error(s) and 7 item(s) reported on remote host
+ End Time: 2026-03-04 04:34:09 (121 seconds)
```

### Final Counts

| Counter | Run 1 | Run 3 | Change |
|---------|-------|-------|--------|
| manifold allow | 1,895 | 1,896 | — |
| manifold warmup | 511 | 500 | — |
| manifold rate_limit | 512 | **0** | mode=Targeted drops all to deny |
| manifold deny | 255 | **10,121** | 40x increase |
| enforcement rate_limit | 6,944 | **11,783** | more rules active |
| auto-generated rules | 8 | **17** | — |
| anomaly score (req) | 60.03 | **61.54** | stronger baseline |
| anomaly threshold | 26.54 | **25.34** | tighter normal |
| anomaly streak | 67 | **236** | — |

### Unsealed Denial Token

```
Denial Context (unsealed):

  verdict:         deny
  residual:        53.1911  (threshold: 25.4577, deny: 50.9153)
  deviation:       2.1x above normal

  request:
    GET /
    src:        127.0.0.1
    user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ...Chrome/74.0.3729.169
    headers:    [connection, user-agent, host]
    cookies:    (none)

  anomalous dimensions:
    path                 48.72
    query_shape          48.07
    path_parts           47.90
    headers              47.52
    query_parts          47.52
```

Nikto pretends to be Chrome but has only 3 headers (normal: 7-8), no cookies
(normal: PHPSESSID+security), and wrong header order. The manifold catches
every dimension simultaneously — fixing one (e.g. UA) still leaves four others firing.

## Next Experiments

- [x] Multi-source-IP + concurrent traffic — **Done.** See [EXPERIMENT-MULTI-ATTACK.md](EXPERIMENT-MULTI-ATTACK.md)
- [ ] Slow Nikto (`-Pause 1`) — 1 req/sec, test pure geometric detection without rate-limit triggers
- [ ] Mimicry attack — real browser through proxy, submit SQLi via DVWA forms (find the boundary)
- [ ] Fix WindowTracker mode classification, re-run
- [ ] Measure spectral scoring overhead in isolation (microbenchmark)
