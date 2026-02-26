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
use tracing::{debug, warn};

use crate::tls::ReplayStream;

use crate::enforcer::{RateLimiter, Verdict};
use crate::types::{
    CompiledTree, ConnectionContext, HttpVersion, RequestSample,
    SampleMessage, TlsSample, now_us,
};

// =============================================================================
// Serve one TLS connection
// =============================================================================

/// Drive a single TLS connection: send the TLS sample, then serve HTTP requests.
pub async fn serve_connection(
    io: tokio_rustls::server::TlsStream<ReplayStream>,
    conn_ctx: Arc<ConnectionContext>,
    upstream_addr: SocketAddr,
    tree: Arc<ArcSwap<CompiledTree>>,
    sample_tx: mpsc::Sender<SampleMessage>,
    rate_limiter: Arc<RateLimiter>,
) {
    // Best-effort: send TLS sample to sidecar
    let tls_sample = TlsSample::from_conn(&conn_ctx);
    let _ = sample_tx.try_send(SampleMessage::TlsSample(tls_sample));

    let conn_ctx_c = conn_ctx.clone();
    let tree_c = tree.clone();
    let sample_tx_c = sample_tx.clone();
    let rl = rate_limiter.clone();

    let svc = service_fn(move |req: Request<Incoming>| {
        let conn_ctx = conn_ctx_c.clone();
        let tree = tree_c.clone();
        let sample_tx = sample_tx_c.clone();
        let rate_limiter = rl.clone();
        async move {
            handle_request(req, conn_ctx, upstream_addr, tree, sample_tx, rate_limiter).await
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
    tree: Arc<ArcSwap<CompiledTree>>,
    sample_tx: mpsc::Sender<SampleMessage>,
    rate_limiter: Arc<RateLimiter>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let sample = build_request_sample(&req, &conn_ctx);

    // Phase 1: synchronous rule check (wait-free ArcSwap load)
    let compiled = tree.load();
    let verdict = crate::enforcer::evaluate(&sample, &compiled);

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
            crate::ENFORCED_PASS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _ = sample_tx.try_send(SampleMessage::RequestSample(sample.clone()));
        }
        Verdict::Pass | Verdict::Count => {
            crate::ENFORCED_PASS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let _ = sample_tx.try_send(SampleMessage::RequestSample(sample.clone()));
        }
    }

    // Forward to upstream
    match forward_to_upstream(req, upstream_addr, &sample).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            warn!("upstream error: {}", e);
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

    // Collect headers in wire order, duplicates preserved
    let headers: Vec<(String, String)> = req.headers().iter()
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
        body_len: content_length.unwrap_or(0),
        src_ip: conn_ctx.src_ip,
        conn_id: conn_ctx.conn_id,
        tls_ctx: conn_ctx.tls_ctx.clone(),
        tls_vec: conn_ctx.tls_vec.clone(),
        timestamp_us: now_us(),
    }
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
