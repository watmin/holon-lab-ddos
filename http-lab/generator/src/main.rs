//! HTTP flood generator with configurable TLS ClientHello profiles.
//!
//! Drives multi-phase scenarios (warmup → attack → calm) with named TLS
//! profiles that control exact cipher suite lists and extension ordering.
//! Uses hyper + tokio-rustls directly so we control the raw TLS ClientHello.

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
use tokio::sync::Semaphore;
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
// Request patterns
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

static LEGIT_PATHS: &[&str] = &[
    "/", "/index.html", "/about", "/contact",
    "/blog", "/products", "/api/status", "/api/v1/health",
];

struct RequestSpec {
    method: &'static str,
    path: String,
    user_agent: String,
    extra_headers: Vec<(&'static str, String)>,
}

fn build_request(pattern: &str, path_override: Option<&str>, rng: &mut impl Rng) -> RequestSpec {
    match pattern {
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

// =============================================================================
// HTTP request over TLS
// =============================================================================

static SENT_COUNT: AtomicU64 = AtomicU64::new(0);
static ERROR_COUNT: AtomicU64 = AtomicU64::new(0);
static STATUS_2XX: AtomicU64 = AtomicU64::new(0);
static STATUS_403: AtomicU64 = AtomicU64::new(0);
static STATUS_429: AtomicU64 = AtomicU64::new(0);
static STATUS_OTHER: AtomicU64 = AtomicU64::new(0);

/// Send multiple HTTP requests over a single TLS connection.
/// Returns (success_count, error_count) for requests on this connection.
async fn send_requests_on_conn(
    target: SocketAddr,
    host: &str,
    specs: Vec<RequestSpec>,
    tls_config: Arc<ClientConfig>,
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
        match sender.send_request(req).await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let _ = resp.into_body().collect().await;
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
                break; // connection likely dead
            }
        }
    }
    Ok((ok, err))
}

use http_body_util::BodyExt;

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

        // Build a batch of requests for this connection
        let batch_size = REQUESTS_PER_CONN.min(
            ((end - Instant::now()).as_millis() as usize * phase.rps as usize / 1000)
                .max(1)
                .min(REQUESTS_PER_CONN)
        );
        let specs: Vec<RequestSpec> = (0..batch_size)
            .map(|_| build_request(&phase.pattern, phase.path.as_deref(), &mut rng))
            .collect();
        let host = host_arc.clone();

        tokio::spawn(async move {
            let _permit = permit;
            match send_requests_on_conn(target, &host, specs, tls_config).await {
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
            let total_sent = SENT_COUNT.load(Ordering::Relaxed);
            let total_errors = ERROR_COUNT.load(Ordering::Relaxed);
            info!(
                "Phase '{}': conns={} sent={} errors={} | 2xx={} 403={} 429={} other={}",
                phase.name, spawned, total_sent, total_errors,
                STATUS_2XX.load(Ordering::Relaxed),
                STATUS_403.load(Ordering::Relaxed),
                STATUS_429.load(Ordering::Relaxed),
                STATUS_OTHER.load(Ordering::Relaxed),
            );
            last_report = Instant::now();
        }

        // Sleep per-batch, not per-request
        let batch_interval = Duration::from_micros(
            (interval.as_micros() as u64).saturating_mul(batch_size as u64)
        );
        sleep(batch_interval).await;
    }

    // Wait for in-flight tasks to drain
    let _ = semaphore.clone().acquire_many(max_concurrent as u32).await;

    let total_sent = SENT_COUNT.load(Ordering::Relaxed);
    let total_errors = ERROR_COUNT.load(Ordering::Relaxed);
    info!(
        "Phase '{}' done: conns={} sent={} errors={}",
        phase.name, spawned, total_sent, total_errors,
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

    let total_sent = SENT_COUNT.load(Ordering::Relaxed);
    let total_errors = ERROR_COUNT.load(Ordering::Relaxed);
    info!("All phases complete. Total sent={} errors={}", total_sent, total_errors);
    Ok(())
}
