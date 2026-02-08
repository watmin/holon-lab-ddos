//! DDoS Lab Control Plane
//! 
//! HTTP API for managing XDP filter and traffic generator

use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use xdp_filter::{FilterMode, FilterStats, XdpFilter};
use xdp_generator::{AttackConfig, AttackStats, AttackType, TrafficGenerator};

#[derive(Parser, Debug)]
#[command(name = "ddos-lab")]
#[command(about = "DDoS Lab - XDP filter and traffic generator control plane")]
struct Args {
    /// Interface to attach XDP filter to
    #[arg(short, long, default_value = "eno1")]
    interface: String,

    /// HTTP API port
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Target IP for attacks
    #[arg(long, default_value = "192.168.1.200")]
    target: String,

    /// Skip loading XDP filter (generator only mode)
    #[arg(long)]
    no_filter: bool,
}

/// Shared application state
struct AppState {
    filter: Option<XdpFilter>,
    generator: TrafficGenerator,
    config: RwLock<AttackConfig>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();
    info!("Starting DDoS Lab control plane");

    // Initialize components
    let filter = if args.no_filter {
        info!("Skipping XDP filter (--no-filter)");
        None
    } else {
        info!("Loading XDP filter on {}", args.interface);
        // Note: XdpFilter::new requires the eBPF program to be built first
        // For now, we'll make this optional and handle the error gracefully
        match XdpFilter::new(&args.interface) {
            Ok(f) => Some(f),
            Err(e) => {
                tracing::warn!("Failed to load XDP filter: {}. Continuing without filter.", e);
                None
            }
        }
    };

    let target_ip: std::net::Ipv4Addr = args.target.parse()?;
    
    let attack_config = AttackConfig {
        target_ip,
        target_port: 443,
        source_network: 10,
        pps: 10_000,
        attack_type: AttackType::SynFlood,
        interface: args.interface.clone(),
        gateway_mac: None,
    };

    let generator = TrafficGenerator::new(attack_config.clone());

    let state = Arc::new(AppState {
        filter,
        generator,
        config: RwLock::new(attack_config),
    });

    // Build router
    let app = Router::new()
        .route("/", get(index))
        .route("/stats", get(get_stats))
        .route("/filter/stats", get(get_filter_stats))
        .route("/filter/mode", post(set_filter_mode))
        .route("/filter/top-ips", get(get_top_ips))
        .route("/attack/status", get(get_attack_status))
        .route("/attack/start", post(start_attack))
        .route("/attack/stop", post(stop_attack))
        .route("/attack/config", get(get_attack_config))
        .route("/attack/config", post(set_attack_config))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    info!("Listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// === Handlers ===

async fn index() -> &'static str {
    r#"DDoS Lab Control Plane

Endpoints:
  GET  /stats              - Combined stats
  GET  /filter/stats       - Filter statistics
  POST /filter/mode        - Set filter mode {"mode": "detect"|"enforce"}
  GET  /filter/top-ips     - Top source IPs
  GET  /attack/status      - Attack status
  POST /attack/start       - Start attack
  POST /attack/stop        - Stop attack
  GET  /attack/config      - Get attack config
  POST /attack/config      - Set attack config
"#
}

#[derive(Serialize)]
struct CombinedStats {
    filter: Option<FilterStats>,
    attack: AttackStats,
}

async fn get_stats(State(state): State<Arc<AppState>>) -> Json<CombinedStats> {
    let filter = if let Some(ref f) = state.filter {
        f.stats().await.ok()
    } else {
        None
    };

    Json(CombinedStats {
        filter,
        attack: state.generator.stats(),
    })
}

async fn get_filter_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<FilterStats>, StatusCode> {
    match &state.filter {
        Some(f) => f
            .stats()
            .await
            .map(Json)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Deserialize)]
struct ModeRequest {
    mode: String,
}

async fn set_filter_mode(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ModeRequest>,
) -> Result<&'static str, StatusCode> {
    let mode = match req.mode.as_str() {
        "detect" => FilterMode::Detect,
        "enforce" => FilterMode::Enforce,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    match &state.filter {
        Some(f) => f
            .set_mode(mode)
            .await
            .map(|_| "OK")
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Serialize)]
struct TopIp {
    ip: String,
    count: u64,
}

async fn get_top_ips(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<TopIp>>, StatusCode> {
    match &state.filter {
        Some(f) => {
            let ips = f
                .top_ips(20)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            
            Ok(Json(
                ips.into_iter()
                    .map(|(ip, count)| TopIp {
                        ip: ip.to_string(),
                        count,
                    })
                    .collect(),
            ))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_attack_status(State(state): State<Arc<AppState>>) -> Json<AttackStats> {
    Json(state.generator.stats())
}

async fn start_attack(State(state): State<Arc<AppState>>) -> Result<&'static str, StatusCode> {
    state
        .generator
        .start()
        .await
        .map(|_| "Attack started")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn stop_attack(State(state): State<Arc<AppState>>) -> &'static str {
    state.generator.stop();
    "Attack stopped"
}

#[derive(Serialize, Deserialize)]
struct AttackConfigDto {
    target_ip: String,
    target_port: u16,
    source_network: u8,
    pps: u32,
    attack_type: String,
}

async fn get_attack_config(State(state): State<Arc<AppState>>) -> Json<AttackConfigDto> {
    let config = state.config.read().await;
    Json(AttackConfigDto {
        target_ip: config.target_ip.to_string(),
        target_port: config.target_port,
        source_network: config.source_network,
        pps: config.pps,
        attack_type: format!("{:?}", config.attack_type),
    })
}

async fn set_attack_config(
    State(state): State<Arc<AppState>>,
    Json(dto): Json<AttackConfigDto>,
) -> Result<&'static str, StatusCode> {
    let target_ip: std::net::Ipv4Addr = dto
        .target_ip
        .parse()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let attack_type = match dto.attack_type.to_lowercase().as_str() {
        "syn" | "synflood" => AttackType::SynFlood,
        "udp" | "udpflood" => AttackType::UdpFlood,
        "icmp" | "icmpflood" => AttackType::IcmpFlood,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let config = AttackConfig {
        target_ip,
        target_port: dto.target_port,
        source_network: dto.source_network,
        pps: dto.pps,
        attack_type,
        interface: state.config.read().await.interface.clone(),
        gateway_mac: None,
    };

    state.generator.set_config(config.clone()).await;
    *state.config.write().await = config;

    Ok("Config updated")
}
