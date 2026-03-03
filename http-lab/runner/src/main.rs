//! HTTP WAF Proxy — binary entry point.
//!
//! Spawns:
//!   - TLS accept loop (proxy tasks)
//!   - Sidecar detection tasks (in-process, same tokio runtime)
//!
//! The ArcSwap<ExprCompiledTree> and bounded mpsc channel are created here and
//! shared between proxy and sidecar via Arc.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwap;
use chrono::Local;
use clap::Parser;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

use holon::kernel::{Encoder, VectorManager};

use http_proxy::{
    denial_token::DenialKey,
    enforcer::RateLimiter,
    expr_tree::ExprCompiledTree,
    manifold::ManifoldState,
    tls::accept_tls,
    types::{ConnectionContext, SampleMessage},
    http::serve_connection,
};

/// HTTP WAF Proxy
#[derive(Parser, Debug)]
#[command(name = "http-proxy", about = "L7 WAF proxy with holon-rs sidecar")]
struct Args {
    /// Address to listen on
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: SocketAddr,

    /// Upstream backend address
    #[arg(long, default_value = "127.0.0.1:8080")]
    upstream: SocketAddr,

    /// TLS certificate file (PEM)
    #[arg(long, default_value = "certs/cert.pem")]
    cert: String,

    /// TLS private key file (PEM)
    #[arg(long, default_value = "certs/key.pem")]
    key: String,

    /// Sidecar sample channel capacity (samples dropped when full).
    /// Smaller values prevent sidecar stalls during rate transitions
    /// at the cost of dropping samples under burst load.
    #[arg(long, default_value_t = 512)]
    sample_channel_capacity: usize,

    /// Engram library path for persistence (requires --persist-engrams to enable)
    #[arg(long, default_value = "engrams/http")]
    engram_path: String,

    /// Enable engram persistence (save on shutdown, load on startup).
    /// Without this flag, engrams are ephemeral — rebuilt each run.
    #[arg(long, default_value_t = false)]
    persist_engrams: bool,

    /// Directory for log files (also writes to stdout)
    #[arg(long, default_value = "http-lab/logs")]
    log_dir: PathBuf,

    /// Metrics server address
    #[arg(long, default_value = "127.0.0.1:9090")]
    metrics_addr: SocketAddr,

    /// Rule time-to-live in seconds (rules expire after this many seconds
    /// without being refreshed). Lower values useful for demos.
    #[arg(long)]
    rule_ttl: Option<u64>,

    /// Enable denial context tokens (X-Denial-Context header) on manifold
    /// deny/rate-limit responses. Generates a random AES-256-GCM key on startup.
    #[arg(long, default_value_t = false)]
    denial_tokens: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Logging: stdout + timestamped file (same pattern as veth-lab)
    std::fs::create_dir_all(&args.log_dir)?;
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let log_filename = format!("proxy_{}.log", timestamp);
    let log_path = args.log_dir.join(&log_filename);
    let file_appender = tracing_appender::rolling::never(&args.log_dir, &log_filename);
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_ansi(true)
                .with_target(false)
        )
        .with(
            fmt::layer()
                .with_ansi(false)
                .with_target(false)
                .with_writer(non_blocking)
        )
        .with(tracing_subscriber::filter::LevelFilter::INFO)
        .init();

    info!("HTTP WAF Proxy starting");
    info!("  listen:   {}", args.listen);
    info!("  upstream: {}", args.upstream);
    info!("  metrics:  {}", args.metrics_addr);
    info!("  log:      {}", log_path.display());

    // Load TLS certificate and key
    let server_config = load_tls_config(&args.cert, &args.key)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // Shared rule tree (starts empty — all traffic passes until sidecar populates rules)
    let tree: Arc<ArcSwap<ExprCompiledTree>> = Arc::new(ArcSwap::new(Arc::new(ExprCompiledTree::empty())));

    // Shared manifold state (starts empty — all traffic passes until sidecar trains)
    let manifold: Arc<ArcSwap<ManifoldState>> = Arc::new(ArcSwap::new(Arc::new(ManifoldState::empty())));

    // Denial context tokens (optional — enabled via --denial-tokens)
    let denial_key: Option<Arc<DenialKey>> = if args.denial_tokens {
        let key = DenialKey::generate();
        info!("Denial context tokens enabled (AES-256-GCM)");
        Some(Arc::new(key))
    } else {
        None
    };

    // Bounded sample channel — proxy uses try_send (drop on full)
    let (sample_tx, sample_rx) = mpsc::channel::<SampleMessage>(args.sample_channel_capacity);

    // Spawn sidecar tasks in-process
    let sidecar_tree = tree.clone();
    let sidecar_manifold = manifold.clone();
    let sidecar_engram_path = if args.persist_engrams {
        Some(args.engram_path.clone())
    } else {
        None
    };
    let sidecar_metrics_addr = args.metrics_addr;
    let sidecar_rule_ttl = args.rule_ttl;
    tokio::spawn(async move {
        if let Err(e) = http_sidecar::run(
            sample_rx,
            sidecar_tree,
            sidecar_manifold,
            sidecar_engram_path,
            sidecar_metrics_addr,
            sidecar_rule_ttl,
        ).await {
            error!("sidecar error: {}", e);
        }
    });

    // Initialize holon encoder (shared across connections)
    let encoder = Arc::new(Encoder::new(VectorManager::new(4096)));

    // Per-IP token bucket rate limiter (shared across all connections)
    let rate_limiter = Arc::new(RateLimiter::new());

    // TLS accept loop
    let listener = TcpListener::bind(args.listen).await?;
    info!("Listening on {}", args.listen);

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("accept error: {}", e);
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let tree = tree.clone();
        let manifold = manifold.clone();
        let sample_tx = sample_tx.clone();
        let encoder = encoder.clone();
        let rate_limiter = rate_limiter.clone();
        let denial_key = denial_key.clone();
        let upstream = args.upstream;

        tokio::spawn(async move {
            match accept_tls(tcp_stream, &acceptor).await {
                Ok((tls_stream, tls_ctx)) => {
                    let conn_ctx = Arc::new(ConnectionContext::new(
                        peer_addr.ip(),
                        peer_addr.port(),
                        tls_ctx,
                        &encoder,
                    ));
                    debug!(
                        conn_id = conn_ctx.conn_id,
                        src = %peer_addr,
                        ja4 = %conn_ctx.tls_ctx.ja4_string(),
                        "TLS connection accepted"
                    );
                    serve_connection(
                        tls_stream,
                        conn_ctx,
                        upstream,
                        tree,
                        sample_tx,
                        rate_limiter,
                        encoder,
                        manifold,
                        denial_key,
                    ).await;
                }
                Err(e) => {
                    warn!(src = %peer_addr, "TLS handshake failed: {}", e);
                }
            }
        });
    }
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<ServerConfig> {
    use rustls::pki_types::CertificateDer;
    use std::io::BufReader;

    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| anyhow::anyhow!("cannot open cert '{}': {}", cert_path, e))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()?;

    let key_file = std::fs::File::open(key_path)
        .map_err(|e| anyhow::anyhow!("cannot open key '{}': {}", key_path, e))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in '{}'", key_path))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(config)
}
