//! TLS ClientHello parser and tokio-rustls accept loop.
//!
//! We ARE the TLS endpoint. Clients send their ClientHello to us. We read the
//! raw bytes from our TCP socket, parse the ClientHello structure ourselves to
//! capture a lossless TlsContext, then hand the same bytes to rustls for the
//! cryptographic handshake.
//!
//! No crypto is involved in our parsing — we only read the plaintext handshake
//! structure that precedes encryption.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tracing::{debug, warn};

use crate::types::TlsContext;

// =============================================================================
// ClientHello binary parser
// =============================================================================

/// Parse a TLS ClientHello from the first bytes of a TLS connection.
///
/// TLS record structure:
///   [0]    content_type (0x16 = handshake)
///   [1..2] record_version (e.g. 0x0301)
///   [3..4] record_length
///   [5]    handshake_type (0x01 = ClientHello)
///   [6..8] handshake_length (3-byte big-endian)
///   [9..10] client_version
///   [11..42] random (32 bytes)
///   [43]   session_id_length
///   [44..] session_id (0-32 bytes)
///   ...    cipher_suites_length (2 bytes) + cipher_suites
///   ...    compression_methods_length (1 byte) + methods
///   ...    extensions_length (2 bytes) + extensions
pub fn parse_client_hello(buf: &[u8]) -> Result<TlsContext> {
    let mut r = Reader::new(buf);

    // TLS record header
    let content_type = r.read_u8()?;
    if content_type != 0x16 {
        bail!("not a TLS handshake record (type=0x{:02x})", content_type);
    }
    let record_version = r.read_u16_be()?;
    let _record_len = r.read_u16_be()?;

    // Handshake header
    let hs_type = r.read_u8()?;
    if hs_type != 0x01 {
        bail!("not a ClientHello (handshake_type=0x{:02x})", hs_type);
    }
    let _hs_len = r.read_u24_be()?;

    // ClientHello fixed fields
    let handshake_version = r.read_u16_be()?;
    r.skip(32)?; // random

    // Session ID
    let session_id_len = r.read_u8()? as usize;
    r.skip(session_id_len)?;

    // Cipher suites
    let cs_len = r.read_u16_be()? as usize;
    if cs_len % 2 != 0 { bail!("cipher_suites_length not even: {}", cs_len); }
    let mut cipher_suites = Vec::with_capacity(cs_len / 2);
    for _ in 0..(cs_len / 2) {
        cipher_suites.push(r.read_u16_be()?);
    }

    // Compression methods
    let comp_len = r.read_u8()? as usize;
    r.skip(comp_len)?;

    // Extensions (optional — may not be present in very old clients)
    let mut extensions: Vec<(u16, Vec<u8>)> = Vec::new();
    let mut supported_groups: Vec<u16> = Vec::new();
    let mut ec_point_formats: Vec<u8> = Vec::new();
    let mut sig_algs: Vec<u16> = Vec::new();
    let mut alpn: Vec<String> = Vec::new();
    let mut sni: Option<String> = None;
    let mut session_ticket = false;
    let mut psk_modes: Vec<u8> = Vec::new();
    let mut key_share_groups: Vec<u16> = Vec::new();

    if r.remaining() >= 2 {
        let exts_total_len = r.read_u16_be()? as usize;
        let exts_end = r.pos + exts_total_len;

        while r.pos < exts_end && r.remaining() >= 4 {
            let ext_type = r.read_u16_be()?;
            let ext_len = r.read_u16_be()? as usize;
            let ext_data = r.read_bytes(ext_len)?;

            // Pre-parse named extensions for convenience fields
            match ext_type {
                0x0000 => sni = parse_sni(ext_data),
                0x000a => supported_groups = parse_u16_list_prefixed(ext_data),
                0x000b => ec_point_formats = parse_u8_list_prefixed(ext_data),
                0x000d => sig_algs = parse_u16_list_prefixed(ext_data),
                0x0010 => alpn = parse_alpn(ext_data),
                0x0023 => session_ticket = true,
                0x002d => psk_modes = parse_u8_list_prefixed(ext_data),
                0x0033 => key_share_groups = parse_key_share_groups(ext_data),
                _ => {}
            }

            extensions.push((ext_type, ext_data.to_vec()));
        }
    }

    Ok(TlsContext {
        record_version,
        handshake_version,
        cipher_suites,
        extensions,
        supported_groups,
        ec_point_formats,
        sig_algs,
        alpn,
        sni,
        session_ticket,
        psk_modes,
        key_share_groups,
    })
}

// ---- Extension-specific parsers ----

fn parse_sni(data: &[u8]) -> Option<String> {
    // server_name_list (2-byte len) → name_type (1) + name_len (2) + name
    if data.len() < 5 { return None; }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len { return None; }
    let name_type = data[2];
    if name_type != 0x00 { return None; } // host_name
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + name_len { return None; }
    String::from_utf8(data[5..5 + name_len].to_vec()).ok()
}

fn parse_u16_list_prefixed(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 { return Vec::new(); }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut out = Vec::new();
    let mut i = 2;
    while i + 1 < 2 + list_len && i + 1 < data.len() {
        out.push(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    out
}

fn parse_u8_list_prefixed(data: &[u8]) -> Vec<u8> {
    if data.is_empty() { return Vec::new(); }
    let list_len = data[0] as usize;
    data[1..].iter().take(list_len).copied().collect()
}

fn parse_alpn(data: &[u8]) -> Vec<String> {
    if data.len() < 2 { return Vec::new(); }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut out = Vec::new();
    let mut i = 2usize;
    while i < 2 + list_len && i < data.len() {
        let proto_len = data[i] as usize;
        i += 1;
        if i + proto_len > data.len() { break; }
        if let Ok(s) = std::str::from_utf8(&data[i..i + proto_len]) {
            out.push(s.to_string());
        }
        i += proto_len;
    }
    out
}

fn parse_key_share_groups(data: &[u8]) -> Vec<u16> {
    // key_share extension: 2-byte total length, then entries: group(2) + key_exchange_length(2) + key_exchange
    if data.len() < 2 { return Vec::new(); }
    let total = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut out = Vec::new();
    let mut i = 2usize;
    while i + 3 < 2 + total && i + 3 < data.len() {
        let group = u16::from_be_bytes([data[i], data[i + 1]]);
        let ke_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        out.push(group);
        i += 4 + ke_len;
    }
    out
}

// =============================================================================
// Simple byte reader
// =============================================================================

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }

    fn remaining(&self) -> usize { self.data.len().saturating_sub(self.pos) }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() { bail!("unexpected end of ClientHello (u8)"); }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16_be(&mut self) -> Result<u16> {
        if self.pos + 1 >= self.data.len() { bail!("unexpected end of ClientHello (u16)"); }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u24_be(&mut self) -> Result<u32> {
        if self.pos + 2 >= self.data.len() { bail!("unexpected end of ClientHello (u24)"); }
        let v = ((self.data[self.pos] as u32) << 16)
            | ((self.data[self.pos + 1] as u32) << 8)
            | (self.data[self.pos + 2] as u32);
        self.pos += 3;
        Ok(v)
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        if self.pos + n > self.data.len() { bail!("unexpected end of ClientHello (skip {})", n); }
        self.pos += n;
        Ok(())
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() { bail!("unexpected end of ClientHello (read {} bytes)", n); }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

// =============================================================================
// TLS accept: read ClientHello, parse, replay into rustls
// =============================================================================

/// Peek and parse the TLS ClientHello from a TCP stream, then complete the
/// TLS handshake via tokio-rustls.
///
/// Returns a `TlsStream<ReplayStream>` — the ReplayStream wraps the original
/// TcpStream and replays the ClientHello bytes so rustls sees them fresh.
pub async fn accept_tls(
    stream: TcpStream,
    acceptor: &TlsAcceptor,
) -> Result<(TlsStream<ReplayStream>, TlsContext)> {
    // Read the first TLS record (ClientHello is always the first flight).
    // Maximum ClientHello is bounded by the 2-byte record length field: 64 KiB.
    // In practice browsers send <4 KiB. We read the 5-byte header first, then
    // the full record body.
    let mut header = [0u8; 5];
    let mut peeker = PeekStream::new(stream);
    peeker.read_exact_peek(&mut header).await?;

    if header[0] != 0x16 {
        bail!("first byte is not TLS handshake (0x{:02x})", header[0]);
    }
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;

    // Read the full record body
    let total = 5 + record_len;
    peeker.ensure_peeked(total).await?;

    // Parse while we still have the full bytes accessible
    let tls_ctx = match parse_client_hello(&peeker.peek_buf[..total]) {
        Ok(ctx) => {
            debug!(
                ja4 = %ctx.ja4_string(),
                ciphers = ctx.cipher_suites.len(),
                extensions = ctx.extensions.len(),
                sni = ?ctx.sni,
                "ClientHello parsed"
            );
            ctx
        }
        Err(e) => {
            warn!("ClientHello parse failed (non-fatal, continuing handshake): {}", e);
            TlsContext::default()
        }
    };

    // Complete the TLS handshake — rustls reads from PeekStream which replays
    // all the bytes we already buffered before consuming from the real socket.
    let inner = peeker.into_inner();
    let tls_stream = acceptor.accept(inner).await
        .map_err(|e| anyhow::anyhow!("TLS handshake failed: {}", e))?;

    Ok((tls_stream, tls_ctx))
}

// =============================================================================
// Default TlsContext (when parse fails)
// =============================================================================

impl Default for TlsContext {
    fn default() -> Self {
        TlsContext {
            record_version: 0,
            handshake_version: 0,
            cipher_suites: Vec::new(),
            extensions: Vec::new(),
            supported_groups: Vec::new(),
            ec_point_formats: Vec::new(),
            sig_algs: Vec::new(),
            alpn: Vec::new(),
            sni: None,
            session_ticket: false,
            psk_modes: Vec::new(),
            key_share_groups: Vec::new(),
        }
    }
}

// =============================================================================
// PeekStream: buffers bytes we've read so rustls can re-read them
// =============================================================================

/// A TCP stream wrapper that buffers bytes read for peeking, then replays them.
///
/// We need to read the ClientHello bytes for parsing, but rustls also needs
/// to read those same bytes. PeekStream holds a buffer of peeked bytes that
/// are served first before delegating to the underlying stream.
struct PeekStream {
    inner: TcpStream,
    peek_buf: Vec<u8>,
    peek_pos: usize,
}

impl PeekStream {
    fn new(stream: TcpStream) -> Self {
        Self { inner: stream, peek_buf: Vec::new(), peek_pos: 0 }
    }

    /// Read exactly `n` bytes into `buf` from the underlying stream, buffering
    /// them for replay.
    async fn read_exact_peek(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let n = buf.len();
        self.ensure_peeked(n).await?;
        buf.copy_from_slice(&self.peek_buf[self.peek_pos..self.peek_pos + n]);
        Ok(())
    }

    /// Ensure at least `n` bytes are in peek_buf.
    async fn ensure_peeked(&mut self, n: usize) -> io::Result<()> {
        while self.peek_buf.len() < n {
            let mut tmp = [0u8; 4096];
            let read = self.inner.read(&mut tmp).await?;
            if read == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed during ClientHello"));
            }
            self.peek_buf.extend_from_slice(&tmp[..read]);
        }
        Ok(())
    }

    fn into_inner(self) -> ReplayStream {
        ReplayStream {
            prefix: self.peek_buf,
            prefix_pos: 0,
            inner: self.inner,
        }
    }
}

/// A stream that serves buffered bytes before delegating to the real socket.
/// This is what we hand to tokio-rustls so it sees the full ClientHello.
pub struct ReplayStream {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: TcpStream,
}

impl AsyncRead for ReplayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix_pos < self.prefix.len() {
            let available = &self.prefix[self.prefix_pos..];
            let to_copy = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_copy]);
            self.prefix_pos += to_copy;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReplayStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid TLS ClientHello record for testing.
    /// Constructs the binary structure from parameters.
    fn build_client_hello(
        record_version: u16,
        handshake_version: u16,
        cipher_suites: &[u16],
        extensions: &[(u16, &[u8])],
    ) -> Vec<u8> {
        let mut hello = Vec::new();

        // client_version
        hello.extend_from_slice(&handshake_version.to_be_bytes());
        // random (32 bytes)
        hello.extend_from_slice(&[0xAA; 32]);
        // session_id (0 length)
        hello.push(0);
        // cipher_suites
        let cs_len = (cipher_suites.len() * 2) as u16;
        hello.extend_from_slice(&cs_len.to_be_bytes());
        for &cs in cipher_suites {
            hello.extend_from_slice(&cs.to_be_bytes());
        }
        // compression_methods (1 method: null)
        hello.push(1);
        hello.push(0);

        // extensions
        let mut ext_bytes = Vec::new();
        for &(ext_type, ext_data) in extensions {
            ext_bytes.extend_from_slice(&ext_type.to_be_bytes());
            ext_bytes.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
            ext_bytes.extend_from_slice(ext_data);
        }
        hello.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
        hello.extend_from_slice(&ext_bytes);

        // Wrap in handshake header
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        let hs_len = hello.len() as u32;
        handshake.push(((hs_len >> 16) & 0xff) as u8);
        handshake.push(((hs_len >> 8) & 0xff) as u8);
        handshake.push((hs_len & 0xff) as u8);
        handshake.extend_from_slice(&hello);

        // Wrap in TLS record header
        let mut record = Vec::new();
        record.push(0x16); // handshake
        record.extend_from_slice(&record_version.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    fn build_sni_extension(hostname: &str) -> Vec<u8> {
        let name = hostname.as_bytes();
        let name_len = name.len() as u16;
        let entry_len = name_len + 3; // type(1) + length(2) + name
        let list_len = entry_len;
        let mut data = Vec::new();
        data.extend_from_slice(&list_len.to_be_bytes());
        data.push(0x00); // host_name type
        data.extend_from_slice(&name_len.to_be_bytes());
        data.extend_from_slice(name);
        data
    }

    fn build_alpn_extension(protos: &[&str]) -> Vec<u8> {
        let mut entries = Vec::new();
        for p in protos {
            entries.push(p.len() as u8);
            entries.extend_from_slice(p.as_bytes());
        }
        let mut data = Vec::new();
        data.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        data.extend_from_slice(&entries);
        data
    }

    fn build_u16_list_extension(values: &[u16]) -> Vec<u8> {
        let mut data = Vec::new();
        let list_len = (values.len() * 2) as u16;
        data.extend_from_slice(&list_len.to_be_bytes());
        for &v in values {
            data.extend_from_slice(&v.to_be_bytes());
        }
        data
    }

    // --- Parser tests ---

    #[test]
    fn parse_minimal_client_hello() {
        let buf = build_client_hello(0x0301, 0x0303, &[0x1301, 0x1302], &[]);
        let ctx = parse_client_hello(&buf).unwrap();
        assert_eq!(ctx.record_version, 0x0301);
        assert_eq!(ctx.handshake_version, 0x0303);
        assert_eq!(ctx.cipher_suites, vec![0x1301, 0x1302]);
        assert!(ctx.extensions.is_empty());
        assert!(ctx.sni.is_none());
    }

    #[test]
    fn parse_client_hello_with_sni() {
        let sni_data = build_sni_extension("example.com");
        let buf = build_client_hello(0x0301, 0x0303, &[0x1301], &[(0x0000, &sni_data)]);
        let ctx = parse_client_hello(&buf).unwrap();
        assert_eq!(ctx.sni, Some("example.com".to_string()));
        assert_eq!(ctx.extensions.len(), 1);
        assert_eq!(ctx.extensions[0].0, 0x0000);
    }

    #[test]
    fn parse_client_hello_with_alpn() {
        let alpn_data = build_alpn_extension(&["h2", "http/1.1"]);
        let buf = build_client_hello(0x0301, 0x0303, &[0x1301], &[(0x0010, &alpn_data)]);
        let ctx = parse_client_hello(&buf).unwrap();
        assert_eq!(ctx.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
    }

    #[test]
    fn parse_client_hello_with_supported_groups() {
        let groups_data = build_u16_list_extension(&[0x001d, 0x0017, 0x0018]);
        let buf = build_client_hello(0x0301, 0x0303, &[0x1301], &[(0x000a, &groups_data)]);
        let ctx = parse_client_hello(&buf).unwrap();
        assert_eq!(ctx.supported_groups, vec![0x001d, 0x0017, 0x0018]);
    }

    #[test]
    fn parse_client_hello_with_multiple_extensions() {
        let sni_data = build_sni_extension("test.local");
        let alpn_data = build_alpn_extension(&["http/1.1"]);
        let groups_data = build_u16_list_extension(&[0x001d]);
        let sig_data = build_u16_list_extension(&[0x0403, 0x0804]);
        let buf = build_client_hello(
            0x0301, 0x0303, &[0x1301, 0x1302, 0xc02c],
            &[
                (0x0000, &sni_data),   // SNI
                (0x000a, &groups_data), // supported_groups
                (0x000d, &sig_data),    // sig_algs
                (0x0010, &alpn_data),   // ALPN
                (0x0023, &[]),          // session_ticket (empty)
            ],
        );
        let ctx = parse_client_hello(&buf).unwrap();
        assert_eq!(ctx.sni, Some("test.local".to_string()));
        assert_eq!(ctx.cipher_suites, vec![0x1301, 0x1302, 0xc02c]);
        assert_eq!(ctx.supported_groups, vec![0x001d]);
        assert_eq!(ctx.sig_algs, vec![0x0403, 0x0804]);
        assert_eq!(ctx.alpn, vec!["http/1.1"]);
        assert!(ctx.session_ticket);
        assert_eq!(ctx.extensions.len(), 5);
    }

    #[test]
    fn parse_preserves_extension_order() {
        let sni_data = build_sni_extension("a.com");
        let alpn_data = build_alpn_extension(&["h2"]);
        let buf = build_client_hello(
            0x0301, 0x0303, &[0x1301],
            &[(0x0010, &alpn_data), (0x0000, &sni_data)],
        );
        let ctx = parse_client_hello(&buf).unwrap();
        assert_eq!(ctx.extensions[0].0, 0x0010); // ALPN first
        assert_eq!(ctx.extensions[1].0, 0x0000); // SNI second
    }

    #[test]
    fn parse_preserves_cipher_suite_order() {
        let buf = build_client_hello(0x0301, 0x0303, &[0xc02c, 0x1301, 0x1302], &[]);
        let ctx = parse_client_hello(&buf).unwrap();
        assert_eq!(ctx.cipher_suites, vec![0xc02c, 0x1301, 0x1302]);
    }

    #[test]
    fn parse_includes_grease_values() {
        let buf = build_client_hello(0x0301, 0x0303, &[0x0a0a, 0x1301, 0x4a4a], &[]);
        let ctx = parse_client_hello(&buf).unwrap();
        assert_eq!(ctx.cipher_suites, vec![0x0a0a, 0x1301, 0x4a4a]);
    }

    // --- Error cases ---

    #[test]
    fn parse_rejects_non_handshake() {
        let mut buf = build_client_hello(0x0301, 0x0303, &[0x1301], &[]);
        buf[0] = 0x17; // change to application_data
        assert!(parse_client_hello(&buf).is_err());
    }

    #[test]
    fn parse_rejects_non_client_hello() {
        let mut buf = build_client_hello(0x0301, 0x0303, &[0x1301], &[]);
        buf[5] = 0x02; // change handshake type to ServerHello
        assert!(parse_client_hello(&buf).is_err());
    }

    #[test]
    fn parse_rejects_truncated_input() {
        let buf = build_client_hello(0x0301, 0x0303, &[0x1301], &[]);
        // Truncate at various points
        assert!(parse_client_hello(&buf[..4]).is_err());
        assert!(parse_client_hello(&buf[..8]).is_err());
        assert!(parse_client_hello(&buf[..20]).is_err());
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(parse_client_hello(&[]).is_err());
    }

    // --- Extension sub-parsers ---

    #[test]
    fn parse_sni_valid() {
        let data = build_sni_extension("hello.world");
        let result = parse_sni(&data);
        assert_eq!(result, Some("hello.world".to_string()));
    }

    #[test]
    fn parse_sni_empty_returns_none() {
        assert!(parse_sni(&[]).is_none());
        assert!(parse_sni(&[0, 0]).is_none());
    }

    #[test]
    fn parse_alpn_multiple() {
        let data = build_alpn_extension(&["h2", "http/1.1", "spdy/3"]);
        let result = parse_alpn(&data);
        assert_eq!(result, vec!["h2", "http/1.1", "spdy/3"]);
    }

    #[test]
    fn parse_alpn_empty() {
        assert!(parse_alpn(&[]).is_empty());
    }

    #[test]
    fn parse_u16_list_prefixed_works() {
        let data = build_u16_list_extension(&[0x0017, 0x001d, 0x0018]);
        let result = parse_u16_list_prefixed(&data);
        assert_eq!(result, vec![0x0017, 0x001d, 0x0018]);
    }

    #[test]
    fn parse_u16_list_prefixed_empty() {
        assert!(parse_u16_list_prefixed(&[]).is_empty());
        assert!(parse_u16_list_prefixed(&[0, 0]).is_empty());
    }

    // --- Reader tests ---

    #[test]
    fn reader_u8_at_end() {
        let data = [0x42];
        let mut r = Reader::new(&data);
        assert_eq!(r.read_u8().unwrap(), 0x42);
        assert!(r.read_u8().is_err());
    }

    #[test]
    fn reader_u16_exact_fit() {
        let data = [0x01, 0x02];
        let mut r = Reader::new(&data);
        assert_eq!(r.read_u16_be().unwrap(), 0x0102);
        assert!(r.read_u8().is_err());
    }

    #[test]
    fn reader_u16_one_byte_short() {
        let data = [0x01];
        let mut r = Reader::new(&data);
        assert!(r.read_u16_be().is_err());
    }

    #[test]
    fn reader_skip_and_remaining() {
        let data = [0; 10];
        let mut r = Reader::new(&data);
        assert_eq!(r.remaining(), 10);
        r.skip(5).unwrap();
        assert_eq!(r.remaining(), 5);
        assert!(r.skip(6).is_err());
        r.skip(5).unwrap();
        assert_eq!(r.remaining(), 0);
    }
}
