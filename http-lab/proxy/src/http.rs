//! HTTP/1.1 server, upstream forwarding, and sample enqueue.
//!
//! Each accepted TLS connection gets a `ConnectionContext` (containing the
//! TlsContext + pre-computed VSA vector) and then drives a hyper HTTP/1.1
//! connection. Per-request:
//!   1. Build a RequestSample from the request headers.
//!   2. Check the rule enforcer (synchronous, wait-free).
//!   3. If allowed, forward to upstream and return the response.
//!   4. Best-effort try_send of the RequestSample to the sidecar channel.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::Builder as ClientBuilder;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::tls::ReplayStream;

use holon::kernel::Encoder;

use crate::enforcer::{RateLimiter, Verdict};
use crate::expr_tree::ExprCompiledTree;
use crate::denial_token::{self, DenialContext, DenialKey};
use crate::manifold::{ManifoldState, ManifoldVerdict, evaluate_manifold, drilldown_audit};
use crate::types::{
    ConnectionContext, DenyEventData, HttpVersion, RequestSample,
    SampleMessage, TlsSample, now_us, request_walk_full_json,
};

// =============================================================================
// Serve one TLS connection
// =============================================================================

/// Drive a single TLS connection: send the TLS sample, then serve HTTP requests.
pub async fn serve_connection(
    io: tokio_rustls::server::TlsStream<ReplayStream>,
    conn_ctx: Arc<ConnectionContext>,
    upstream_addr: SocketAddr,
    tree: Arc<ArcSwap<ExprCompiledTree>>,
    sample_tx: mpsc::Sender<SampleMessage>,
    rate_limiter: Arc<RateLimiter>,
    encoder: Arc<Encoder>,
    manifold: Arc<ArcSwap<ManifoldState>>,
    denial_key: Option<Arc<DenialKey>>,
    stream_requests: bool,
) {
    // Best-effort: send TLS sample to sidecar
    let tls_sample = TlsSample::from_conn(&conn_ctx);
    let _ = sample_tx.try_send(SampleMessage::TlsSample(tls_sample));

    let conn_ctx_c = conn_ctx.clone();
    let tree_c = tree.clone();
    let sample_tx_c = sample_tx.clone();
    let rl = rate_limiter.clone();
    let enc = encoder.clone();
    let mfld = manifold.clone();
    let dk = denial_key.clone();

    let svc = service_fn(move |req: Request<Incoming>| {
        let conn_ctx = conn_ctx_c.clone();
        let tree = tree_c.clone();
        let sample_tx = sample_tx_c.clone();
        let rate_limiter = rl.clone();
        let encoder = enc.clone();
        let manifold = mfld.clone();
        let denial_key = dk.clone();
        async move {
            handle_request(req, conn_ctx, upstream_addr, tree, sample_tx, rate_limiter, encoder, manifold, denial_key, stream_requests).await
        }
    });

    if let Err(e) = http1::Builder::new()
        .serve_connection(TokioIo::new(io), svc)
        .await
    {
        debug!("connection closed: {}", e);
    }
}

// =============================================================================
// Per-request handler
// =============================================================================

async fn handle_request(
    req: Request<Incoming>,
    conn_ctx: Arc<ConnectionContext>,
    upstream_addr: SocketAddr,
    tree: Arc<ArcSwap<ExprCompiledTree>>,
    sample_tx: mpsc::Sender<SampleMessage>,
    rate_limiter: Arc<RateLimiter>,
    encoder: Arc<Encoder>,
    manifold: Arc<ArcSwap<ManifoldState>>,
    denial_key: Option<Arc<DenialKey>>,
    stream_requests: bool,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let mut sample = build_request_sample(&req, &conn_ctx);

    // Layer 3: synchronous rule check (wait-free ArcSwap load)
    let compiled = tree.load();
    let (verdict, rule_id) = crate::enforcer::evaluate(&sample, &compiled);

    if let Some(rid) = rule_id {
        crate::increment_rule_counter(rid);
    }

    match verdict {
        Verdict::CloseConnection => {
            crate::ENFORCED_CLOSE_CONN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::new(Bytes::new()))
                .unwrap());
        }
        Verdict::Block(status) => {
            crate::ENFORCED_BLOCKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _ = sample_tx.try_send(SampleMessage::RequestSample(sample));
            return Ok(Response::builder()
                .status(status)
                .body(Full::new(Bytes::from("Blocked\n")))
                .unwrap());
        }
        Verdict::RateLimit(rps) => {
            if !rate_limiter.allow(sample.src_ip, rps) {
                crate::ENFORCED_RATE_LIMITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let _ = sample_tx.try_send(SampleMessage::RequestSample(sample));
                return Ok(Response::builder()
                    .status(StatusCode::TOO_MANY_REQUESTS)
                    .body(Full::new(Bytes::from("Rate limited\n")))
                    .unwrap());
            }
            // Layer 3 rate-limit allowed through — still forward + sample
        }
        Verdict::Pass | Verdict::Count => {}
    }

    // Layers 0+1: manifold scoring (only when manifold is trained)
    let mstate = manifold.load();
    let n_stripes = crate::N_STRIPES;
    let mut spectral_downgrade = false;
    if mstate.is_ready() {
        let stripe_vecs_raw = encoder.encode_walkable_striped(&sample, n_stripes);
        let stripe_vecs: Vec<Vec<f64>> = stripe_vecs_raw.iter()
            .map(|v| v.data().iter().map(|&b| b as f64).collect())
            .collect();
        let mverdict = evaluate_manifold(&stripe_vecs, &mstate);

        match mverdict {
            ManifoldVerdict::Allow { residual } => {
                crate::MANIFOLD_ALLOW.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if stream_requests {
                    let baseline = mstate.baseline.as_ref();
                    let request_walk = request_walk_full_json(&sample);
                    let _ = sample_tx.try_send(SampleMessage::DenyEvent(DenyEventData {
                        src_ip: sample.src_ip.to_string(),
                        method: sample.method.clone(),
                        path: sample.path.clone(),
                        query: sample.query.clone(),
                        user_agent: sample.user_agent.clone(),
                        residual,
                        threshold: baseline.map(|b| b.threshold()).unwrap_or(0.0),
                        deny_threshold: mstate.deny_threshold,
                        verdict: "allow".into(),
                        request_walk,
                        attribution: vec![],
                        concentration: 0.0,
                        entropy: 0.0,
                        gini: 0.0,
                        timestamp_us: sample.timestamp_us,
                        traffic_source: sample.traffic_source.clone().unwrap_or_default(),
                    }));
                }
            }
            ManifoldVerdict::Warmup => {
                crate::MANIFOLD_WARMUP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if stream_requests {
                    let request_walk = request_walk_full_json(&sample);
                    let _ = sample_tx.try_send(SampleMessage::DenyEvent(DenyEventData {
                        src_ip: sample.src_ip.to_string(),
                        method: sample.method.clone(),
                        path: sample.path.clone(),
                        query: sample.query.clone(),
                        user_agent: sample.user_agent.clone(),
                        residual: 0.0,
                        threshold: 0.0,
                        deny_threshold: 0.0,
                        verdict: "warmup".into(),
                        request_walk,
                        attribution: vec![],
                        concentration: 0.0,
                        entropy: 0.0,
                        gini: 0.0,
                        timestamp_us: sample.timestamp_us,
                        traffic_source: sample.traffic_source.clone().unwrap_or_default(),
                    }));
                }
            }
            ManifoldVerdict::RateLimit { rps, residual } => {
                crate::MANIFOLD_RATE_LIMIT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if !rate_limiter.allow(sample.src_ip, rps as u32) {
                    let drilldown = drilldown_audit(&stripe_vecs, &mstate, &encoder, &sample, n_stripes, 250);
                    let fields: Vec<String> = drilldown.fields.iter().take(5)
                        .map(|a| format!("{}={:.1}", a.field, a.score))
                        .collect();
                    warn!(
                        src = %sample.src_ip,
                        method = %sample.method,
                        path = %sample.path,
                        residual = format!("{:.3}", residual),
                        gini = format!("{:.3}", drilldown.gini),
                        fields = fields.join(","),
                        "manifold rate-limit"
                    );
                    log_attribution("RATE-LTD", &sample, residual, &mstate, &drilldown);
                    let token = build_denial_token(
                        "rate_limit", residual, &mstate, &drilldown,
                        &sample, &denial_key,
                    );
                    let baseline = mstate.baseline.as_ref();
                    let request_walk = request_walk_full_json(&sample);
                    let _ = sample_tx.try_send(SampleMessage::DenyEvent(DenyEventData {
                        src_ip: sample.src_ip.to_string(),
                        method: sample.method.clone(),
                        path: sample.path.clone(),
                        query: sample.query.clone(),
                        user_agent: sample.user_agent.clone(),
                        residual,
                        threshold: baseline.map(|b| b.threshold()).unwrap_or(0.0),
                        deny_threshold: mstate.deny_threshold,
                        verdict: "rate_limit".into(),
                        request_walk,
                        attribution: drilldown.fields.iter().map(|a| (a.field.clone(), a.score)).collect(),
                        concentration: drilldown.concentration,
                        entropy: drilldown.entropy,
                        gini: drilldown.gini,
                        timestamp_us: sample.timestamp_us,
                        traffic_source: sample.traffic_source.clone().unwrap_or_default(),
                    }));
                    let _ = sample_tx.try_send(SampleMessage::RequestSample(sample));
                    let mut builder = Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS);
                    if let Some(t) = &token {
                        builder = builder.header("X-Denial-Context", t.as_str());
                    }
                    return Ok(builder
                        .body(Full::new(Bytes::from("Manifold rate limited\n")))
                        .unwrap());
                }
            }
            ManifoldVerdict::Deny { residual, profile_alignment } => {
                let drilldown = drilldown_audit(&stripe_vecs, &mstate, &encoder, &sample, n_stripes, 250);

                // Dual-signal downgrade gate (lenient mode only):
                //   Magnitude: residual in soft zone (deny_threshold..hard_deny_threshold)
                //   Direction: profile alignment > 0.5 (cross-stripe residual pattern
                //              is more than half explained by learned normal profiles)
                // Both must agree for a downgrade; either alone → hard deny.
                let downgrade = mstate.deny_mode == "lenient"
                    && residual < mstate.hard_deny_threshold
                    && profile_alignment > 0.5;

                if downgrade {
                    crate::MANIFOLD_DOWNGRADE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let fields: Vec<String> = drilldown.fields.iter().take(5)
                        .map(|a| format!("{}={:.1}", a.field, a.score))
                        .collect();
                    warn!(
                        src = %sample.src_ip,
                        method = %sample.method,
                        path = %sample.path,
                        residual = format!("{:.3}", residual),
                        profile_alignment = format!("{:.3}", profile_alignment),
                        fields = fields.join(","),
                        "manifold downgrade (dual-signal: magnitude+direction)"
                    );
                    log_attribution("DOWNGRADE", &sample, residual, &mstate, &drilldown);
                    let baseline = mstate.baseline.as_ref();
                    let request_walk = request_walk_full_json(&sample);
                    let _ = sample_tx.try_send(SampleMessage::DenyEvent(DenyEventData {
                        src_ip: sample.src_ip.to_string(),
                        method: sample.method.clone(),
                        path: sample.path.clone(),
                        query: sample.query.clone(),
                        user_agent: sample.user_agent.clone(),
                        residual,
                        threshold: baseline.map(|b| b.threshold()).unwrap_or(0.0),
                        deny_threshold: mstate.deny_threshold,
                        verdict: "downgrade".into(),
                        request_walk,
                        attribution: drilldown.fields.iter().map(|a| (a.field.clone(), a.score)).collect(),
                        concentration: drilldown.concentration,
                        entropy: drilldown.entropy,
                        gini: drilldown.gini,
                        timestamp_us: sample.timestamp_us,
                        traffic_source: sample.traffic_source.clone().unwrap_or_default(),
                    }));
                    spectral_downgrade = true;
                } else {
                    crate::MANIFOLD_DENY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let fields: Vec<String> = drilldown.fields.iter().take(5)
                        .map(|a| format!("{}={:.1}", a.field, a.score))
                        .collect();
                    warn!(
                        src = %sample.src_ip,
                        method = %sample.method,
                        path = %sample.path,
                        residual = format!("{:.3}", residual),
                        profile_alignment = format!("{:.3}", profile_alignment),
                        gini = format!("{:.3}", drilldown.gini),
                        fields = fields.join(","),
                        "manifold deny"
                    );
                    log_attribution("DENY", &sample, residual, &mstate, &drilldown);
                    let token = build_denial_token(
                        "deny", residual, &mstate, &drilldown,
                        &sample, &denial_key,
                    );
                    let baseline = mstate.baseline.as_ref();
                    let request_walk = request_walk_full_json(&sample);
                    let _ = sample_tx.try_send(SampleMessage::DenyEvent(DenyEventData {
                        src_ip: sample.src_ip.to_string(),
                        method: sample.method.clone(),
                        path: sample.path.clone(),
                        query: sample.query.clone(),
                        user_agent: sample.user_agent.clone(),
                        residual,
                        threshold: baseline.map(|b| b.threshold()).unwrap_or(0.0),
                        deny_threshold: mstate.deny_threshold,
                        verdict: "deny".into(),
                        request_walk,
                        attribution: drilldown.fields.iter().map(|a| (a.field.clone(), a.score)).collect(),
                        concentration: drilldown.concentration,
                        entropy: drilldown.entropy,
                        gini: drilldown.gini,
                        timestamp_us: sample.timestamp_us,
                        traffic_source: sample.traffic_source.clone().unwrap_or_default(),
                    }));
                    let _ = sample_tx.try_send(SampleMessage::RequestSample(sample));
                    let mut builder = Response::builder()
                        .status(StatusCode::FORBIDDEN);
                    if let Some(t) = &token {
                        builder = builder.header("X-Denial-Context", t.as_str());
                    }
                    return Ok(builder
                        .body(Full::new(Bytes::from("Denied by manifold\n")))
                        .unwrap());
                }
            }
        }
    } else {
        crate::MANIFOLD_WARMUP.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    // Request passed all layers — forward to upstream, then send sample with response status
    crate::ENFORCED_PASS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    match forward_to_upstream(req, upstream_addr, &sample).await {
        Ok(resp) => {
            sample.response_status = Some(resp.status().as_u16());
            let _ = sample_tx.try_send(SampleMessage::RequestSample(sample));
            if spectral_downgrade {
                let (mut parts, body) = resp.into_parts();
                parts.headers.insert(
                    hyper::header::HeaderName::from_static("x-spectral-downgrade"),
                    hyper::header::HeaderValue::from_static("structural"),
                );
                Ok(Response::from_parts(parts, body))
            } else {
                Ok(resp)
            }
        }
        Err(e) => {
            warn!("upstream error: {}", e);
            sample.response_status = None;
            let _ = sample_tx.try_send(SampleMessage::RequestSample(sample));
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("Bad gateway\n")))
                .unwrap())
        }
    }
}

// =============================================================================
// Build RequestSample from hyper request
// =============================================================================

fn build_request_sample(
    req: &Request<Incoming>,
    conn_ctx: &ConnectionContext,
) -> RequestSample {
    let method = req.method().to_string();
    let uri = req.uri();
    let path = uri.path().to_string();
    let query = uri.query().map(|s| s.to_string());
    let version = match req.version() {
        hyper::Version::HTTP_10 => HttpVersion::Http10,
        _ => HttpVersion::Http11,
    };

    // Extract and strip out-of-band traffic label before VSA sees it
    let traffic_source = req.headers().get("x-traffic-source")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Collect headers in wire order, duplicates preserved (label stripped)
    let headers: Vec<(String, String)> = req.headers().iter()
        .filter(|(k, _)| k.as_str() != "x-traffic-source")
        .map(|(k, v)| {
            (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())
        })
        .collect();

    // Convenience extractions
    let host = req.headers().get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let user_agent = req.headers().get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let content_type = req.headers().get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let content_length = req.headers().get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    // Parse cookies from Cookie header
    let cookies = req.headers().get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(|s| parse_cookies(s))
        .unwrap_or_default();

    RequestSample {
        method,
        path,
        query,
        version,
        headers,
        host,
        user_agent,
        content_type,
        content_length,
        cookies,
        body: None,       // body deferred to phase 2
        src_ip: conn_ctx.src_ip,
        conn_id: conn_ctx.conn_id,
        tls_ctx: conn_ctx.tls_ctx.clone(),
        tls_vec: conn_ctx.tls_vec.clone(),
        timestamp_us: now_us(),
        traffic_source,
        response_status: None,
    }
}

fn build_denial_token(
    verdict: &str,
    residual: f64,
    mstate: &ManifoldState,
    drilldown: &crate::manifold::DrilldownResult,
    sample: &RequestSample,
    denial_key: &Option<Arc<DenialKey>>,
) -> Option<String> {
    let key = denial_key.as_ref()?;
    let baseline = mstate.baseline.as_ref()?;
    let ctx = DenialContext {
        verdict: verdict.to_string(),
        residual,
        threshold: baseline.threshold(),
        deny_threshold: mstate.deny_threshold,
        top_fields: drilldown.fields.iter().take(30).map(|a| a.into()).collect(),
        src_ip: sample.src_ip.to_string(),
        method: sample.method.clone(),
        path: sample.path.clone(),
        query: sample.query.clone(),
        user_agent: sample.user_agent.clone(),
        header_names: sample.headers.iter().map(|(k, _)| k.clone()).collect(),
        cookie_keys: sample.cookies.iter().map(|(k, _)| k.clone()).collect(),
        concentration: drilldown.concentration,
        entropy: drilldown.entropy,
        gini: drilldown.gini,
        timestamp_us: sample.timestamp_us,
    };
    match denial_token::seal(&ctx, key) {
        Ok(token) => Some(token),
        Err(e) => {
            warn!("denial token seal error: {}", e);
            None
        }
    }
}

fn log_attribution(
    verdict: &str,
    sample: &RequestSample,
    residual: f64,
    mstate: &ManifoldState,
    drilldown: &crate::manifold::DrilldownResult,
) {
    let threshold = mstate.baseline.as_ref().map(|b| b.threshold()).unwrap_or(0.0);
    let deviation = if threshold > 0.0 { residual / threshold } else { 0.0 };
    let ua = sample.user_agent.as_deref().unwrap_or("-");
    let top: Vec<String> = drilldown.fields.iter().take(15)
        .map(|a| format!("  {:>6.1}  {}", a.score, a.field))
        .collect();
    let gini_label = if drilldown.gini < 0.3 { "BROAD" }
        else if drilldown.gini < 0.6 { "moderate" }
        else { "narrow" };
    let sep = "═".repeat(60);
    let src_label = sample.traffic_source.as_deref().unwrap_or("unknown");
    info!(
        "\n╔══ {} ══ {} {} ══ src={} label={} ua={}\n\
         ║  residual={:.2}  threshold={:.2}  deny_thr={:.2}  deviation={:.1}x\n\
         ║  concentration={:.1}  entropy={:.3}  gini={:.3} ({})\n\
         ║  top fields:\n{}\n\
         ╚{}",
        verdict, sample.method, sample.path,
        sample.src_ip, src_label, ua,
        residual, threshold, mstate.deny_threshold, deviation,
        drilldown.concentration, drilldown.entropy, drilldown.gini, gini_label,
        top.join("\n"),
        sep,
    );
}

fn parse_cookies(header: &str) -> Vec<(String, String)> {
    header.split(';')
        .filter_map(|pair| {
            let pair = pair.trim();
            let eq = pair.find('=')?;
            let key = pair[..eq].trim().to_string();
            let val = pair[eq + 1..].trim().to_string();
            Some((key, val))
        })
        .collect()
}

// =============================================================================
// Upstream forwarding
// =============================================================================

async fn forward_to_upstream(
    req: Request<Incoming>,
    upstream_addr: SocketAddr,
    _sample: &RequestSample,
) -> Result<Response<Full<Bytes>>> {
    let stream = TcpStream::connect(upstream_addr).await?;
    let io = TokioIo::new(stream);

    let (mut sender, conn) = ClientBuilder::new()
        .handshake(io)
        .await?;

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("upstream connection error: {}", e);
        }
    });

    // Reconstruct a request with the same method, URI, headers
    let (parts, body) = req.into_parts();
    let upstream_req = Request::from_parts(parts, body);

    let upstream_resp = sender.send_request(upstream_req).await?;
    let (parts, body) = upstream_resp.into_parts();
    let body_bytes = body.collect().await?.to_bytes();

    Ok(Response::from_parts(parts, Full::new(body_bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cookies_basic() {
        let cookies = parse_cookies("foo=bar; baz=qux");
        assert_eq!(cookies, vec![
            ("foo".to_string(), "bar".to_string()),
            ("baz".to_string(), "qux".to_string()),
        ]);
    }

    #[test]
    fn parse_cookies_with_spaces() {
        let cookies = parse_cookies("  a = 1 ;  b = 2  ");
        assert_eq!(cookies, vec![
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "2".to_string()),
        ]);
    }

    #[test]
    fn parse_cookies_value_with_equals() {
        let cookies = parse_cookies("token=abc=def=ghi");
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].0, "token");
        assert_eq!(cookies[0].1, "abc=def=ghi");
    }

    #[test]
    fn parse_cookies_empty() {
        let cookies = parse_cookies("");
        assert!(cookies.is_empty());
    }

    #[test]
    fn parse_cookies_no_value() {
        // A cookie entry like "foo" with no = should be skipped
        let cookies = parse_cookies("foo; bar=baz");
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0], ("bar".to_string(), "baz".to_string()));
    }

    #[test]
    fn parse_cookies_single() {
        let cookies = parse_cookies("session=abc123");
        assert_eq!(cookies, vec![("session".to_string(), "abc123".to_string())]);
    }
}
