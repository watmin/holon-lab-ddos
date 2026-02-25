//! Integration tests for the HTTP WAF proxy.
//!
//! Spins up:
//!   1. A mock backend HTTP server (plain TCP)
//!   2. The TLS proxy + sidecar (in-process)
//!   3. A TLS client that sends requests through the proxy
//!
//! Validates end-to-end: TLS handshake → HTTP request → upstream forwarding →
//! response, rule enforcement (block/pass), and sample enqueue to sidecar.

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use holon::kernel::{Encoder, VectorManager};

use http_proxy::tls::accept_tls;
use http_proxy::types::*;
use http_proxy::http::serve_connection;
use http_proxy::tree::compile;

// =============================================================================
// TLS config helpers (self-signed certs via rcgen)
// =============================================================================

fn generate_tls_config() -> (rustls::ServerConfig, rustls::ClientConfig) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    (server_config, client_config)
}

// =============================================================================
// Mock backend
// =============================================================================

async fn mock_backend(listener: TcpListener) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => break,
        };
        tokio::spawn(async move {
            let svc = service_fn(|req: Request<hyper::body::Incoming>| async move {
                let body = format!("OK from backend: {} {}", req.method(), req.uri().path());
                Ok::<_, std::convert::Infallible>(
                    Response::new(Full::new(Bytes::from(body)))
                )
            });
            let _ = server_http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
    }
}

// =============================================================================
// Integration tests
// =============================================================================

/// Helper: set up the full stack and return (proxy_addr, client_config, sample_rx, tree).
async fn setup() -> (
    SocketAddr,
    Arc<rustls::ClientConfig>,
    mpsc::Receiver<SampleMessage>,
    Arc<ArcSwap<CompiledTree>>,
) {
    // 1. Start mock backend
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    tokio::spawn(mock_backend(backend_listener));

    // 2. TLS config
    let (server_config, client_config) = generate_tls_config();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    // 3. Shared state
    let tree: Arc<ArcSwap<CompiledTree>> = Arc::new(ArcSwap::new(Arc::new(CompiledTree::empty())));
    let (sample_tx, sample_rx) = mpsc::channel::<SampleMessage>(1024);
    let encoder = Arc::new(Encoder::new(VectorManager::new(4096)));

    // 4. Start proxy listener
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let tree_clone = tree.clone();
    tokio::spawn(async move {
        loop {
            let (tcp_stream, peer_addr) = match proxy_listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            let tree = tree_clone.clone();
            let sample_tx = sample_tx.clone();
            let encoder = encoder.clone();
            tokio::spawn(async move {
                match accept_tls(tcp_stream, &acceptor).await {
                    Ok((tls_stream, tls_ctx)) => {
                        let conn_ctx = Arc::new(ConnectionContext::new(
                            peer_addr.ip(),
                            peer_addr.port(),
                            tls_ctx,
                            &encoder,
                        ));
                        serve_connection(
                            tls_stream,
                            conn_ctx,
                            backend_addr,
                            tree,
                            sample_tx,
                        ).await;
                    }
                    Err(_) => {}
                }
            });
        }
    });

    (proxy_addr, Arc::new(client_config), sample_rx, tree)
}

/// Send an HTTP/1.1 request through a TLS connection to the proxy.
async fn send_request(
    proxy_addr: SocketAddr,
    client_config: &rustls::ClientConfig,
    method: &str,
    path: &str,
    headers: Vec<(&str, &str)>,
) -> (StatusCode, String) {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config.clone()));
    let tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();

    let io = TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(io)
        .await
        .unwrap();

    tokio::spawn(async move { let _ = conn.await; });

    let mut builder = Request::builder()
        .method(method)
        .uri(path);
    for (k, v) in headers {
        builder = builder.header(k, v);
    }
    let req = builder
        .body(Full::new(Bytes::new()))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8_lossy(&body).to_string();

    (status, body_str)
}

// =============================================================================
// Tests
// =============================================================================

#[tokio::test]
async fn proxy_forwards_to_backend() {
    let (proxy_addr, client_config, _rx, _tree) = setup().await;
    let (status, body) = send_request(
        proxy_addr, &client_config, "GET", "/hello",
        vec![("Host", "localhost")],
    ).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("OK from backend"), "got: {}", body);
    assert!(body.contains("/hello"), "got: {}", body);
}

#[tokio::test]
async fn proxy_forwards_post_request() {
    let (proxy_addr, client_config, _rx, _tree) = setup().await;
    let (status, body) = send_request(
        proxy_addr, &client_config, "POST", "/api/data",
        vec![("Host", "localhost"), ("Content-Type", "application/json")],
    ).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("POST"), "got: {}", body);
    assert!(body.contains("/api/data"), "got: {}", body);
}

#[tokio::test]
async fn proxy_sends_tls_sample_to_channel() {
    let (proxy_addr, client_config, mut rx, _tree) = setup().await;
    let _ = send_request(
        proxy_addr, &client_config, "GET", "/",
        vec![("Host", "localhost")],
    ).await;

    // Should receive at least a TLS sample + request sample
    let mut got_tls = false;
    let mut got_req = false;
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(SampleMessage::TlsSample(_)) => got_tls = true,
                    Some(SampleMessage::RequestSample(r)) => {
                        got_req = true;
                        assert_eq!(r.method, "GET");
                        assert_eq!(r.path, "/");
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep_until(deadline) => break,
        }
        if got_tls && got_req { break; }
    }
    assert!(got_tls, "expected TLS sample on channel");
    assert!(got_req, "expected request sample on channel");
}

#[tokio::test]
async fn proxy_blocks_with_rule() {
    let (proxy_addr, client_config, _rx, tree) = setup().await;

    // First request should pass (no rules)
    let (status, _) = send_request(
        proxy_addr, &client_config, "GET", "/before",
        vec![("Host", "localhost")],
    ).await;
    assert_eq!(status, StatusCode::OK);

    // Deploy a block rule for all traffic (wildcard)
    let rule = RuleSpec::new(vec![], RuleAction::block());
    let compiled = compile(&[rule]);
    tree.store(Arc::new(compiled));

    // Second request (new connection) should be blocked
    let (status, body) = send_request(
        proxy_addr, &client_config, "GET", "/after",
        vec![("Host", "localhost")],
    ).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("Blocked"), "got: {}", body);
}

#[tokio::test]
async fn proxy_rate_limits_with_rule() {
    let (proxy_addr, client_config, _rx, tree) = setup().await;

    let rule = RuleSpec::new(vec![], RuleAction::RateLimit { rps: 10 });
    let compiled = compile(&[rule]);
    tree.store(Arc::new(compiled));

    let (status, body) = send_request(
        proxy_addr, &client_config, "GET", "/",
        vec![("Host", "localhost")],
    ).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(body.contains("Rate limited"), "got: {}", body);
}

#[tokio::test]
async fn tls_context_captured_correctly() {
    let (proxy_addr, client_config, mut rx, _tree) = setup().await;
    let _ = send_request(
        proxy_addr, &client_config, "GET", "/",
        vec![("Host", "localhost")],
    ).await;

    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(SampleMessage::TlsSample(tls)) => {
                        assert!(!tls.tls_ctx.cipher_suites.is_empty(),
                            "cipher suites should be captured");
                        assert!(tls.tls_ctx.handshake_version > 0,
                            "handshake version should be set");
                        assert!(!tls.tls_ctx.extensions.is_empty(),
                            "extensions should be captured");
                        // ALPN should include h2 and/or http/1.1 from rustls defaults
                        let ja4 = tls.tls_ctx.ja4_string();
                        assert!(!ja4.is_empty(), "JA4 string should not be empty");
                        break;
                    }
                    Some(_) => continue,
                    None => panic!("channel closed without TLS sample"),
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                panic!("timed out waiting for TLS sample");
            }
        }
    }
}

#[tokio::test]
async fn multiple_requests_on_same_connection() {
    let (proxy_addr, client_config, mut rx, _tree) = setup().await;

    // Open one TLS connection, send multiple requests
    let connector = tokio_rustls::TlsConnector::from(Arc::new((*client_config).clone()));
    let tcp = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = connector.connect(server_name, tcp).await.unwrap();

    let io = TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(io)
        .await
        .unwrap();
    tokio::spawn(async move { let _ = conn.await; });

    for i in 0..3 {
        let req = Request::builder()
            .method("GET")
            .uri(format!("/req/{}", i))
            .header("Host", "localhost")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Should receive 1 TLS sample + 3 request samples
    let mut tls_count = 0;
    let mut req_count = 0;
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(SampleMessage::TlsSample(_)) => tls_count += 1,
                    Some(SampleMessage::RequestSample(_)) => req_count += 1,
                    None => break,
                }
            }
            _ = tokio::time::sleep_until(deadline) => break,
        }
        if tls_count >= 1 && req_count >= 3 { break; }
    }
    assert_eq!(tls_count, 1, "expected exactly 1 TLS sample per connection");
    assert_eq!(req_count, 3, "expected 3 request samples");
}

#[tokio::test]
async fn request_sample_captures_headers() {
    let (proxy_addr, client_config, mut rx, _tree) = setup().await;
    let _ = send_request(
        proxy_addr, &client_config, "GET", "/test?q=1",
        vec![
            ("Host", "example.com"),
            ("User-Agent", "test-agent/1.0"),
            ("X-Custom", "custom-value"),
        ],
    ).await;

    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(SampleMessage::RequestSample(r)) => {
                        assert_eq!(r.method, "GET");
                        assert_eq!(r.path, "/test");
                        assert_eq!(r.query.as_deref(), Some("q=1"));
                        assert_eq!(r.host.as_deref(), Some("example.com"));
                        assert_eq!(r.user_agent.as_deref(), Some("test-agent/1.0"));
                        assert_eq!(r.header("x-custom"), vec!["custom-value"]);
                        assert!(!r.tls_ctx.cipher_suites.is_empty());
                        break;
                    }
                    Some(_) => continue,
                    None => panic!("channel closed"),
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                panic!("timed out waiting for request sample");
            }
        }
    }
}
