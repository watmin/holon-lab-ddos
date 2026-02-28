//! Shared types for the HTTP WAF proxy.
//!
//! TlsContext, ConnectionContext, RequestSample, rule types, and the
//! in-memory Rete-spirit CompiledTree are all defined here so the sidecar
//! crate can depend on the proxy lib without cycles.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use holon::kernel::{Encoder, Vector};
use holon::{ScalarValue, WalkType, Walkable, WalkableValue};

// =============================================================================
// TLS ClientHello Context (lossless, ordered)
// =============================================================================

/// Full, lossless capture of a TLS ClientHello received from a client.
///
/// Fields are stored in wire order — order itself is a detection signal.
/// DDoS tools typically produce identical, perfectly ordered ClientHellos;
/// browsers randomize extension ordering. That variance is captured here.
///
/// The `extensions` field carries raw bytes for every extension so the
/// sidecar can re-parse any extension without information loss.
/// Named fields (supported_groups, sig_algs, etc.) are pre-parsed
/// convenience views, not a replacement for the raw.
#[derive(Debug, Clone)]
pub struct TlsContext {
    /// Outer TLS record layer version (e.g. 0x0301 = TLS 1.0 for compatibility)
    pub record_version: u16,
    /// ClientHello.client_version field
    pub handshake_version: u16,

    /// Length of the session ID field (0 = none, 32 = TLS 1.3 compat mode).
    pub session_id_len: u8,

    /// Cipher suites in wire order. GREASE values (0xXaXa) included.
    pub cipher_suites: Vec<u16>,

    /// Compression methods advertised by the client. TLS 1.3 always [0x00].
    pub compression_methods: Vec<u8>,

    /// All extensions in wire order: (extension_type, raw_extension_data).
    /// Raw bytes are preserved exactly as received — no lossy projection.
    pub extensions: Vec<(u16, Vec<u8>)>,

    // -----------------------------------------------------------------------
    // Pre-parsed from extensions for convenient access.
    // These are always derivable from `extensions` above.
    // -----------------------------------------------------------------------

    /// Supported elliptic curves / key exchange groups (ext 0x000a), wire order.
    pub supported_groups: Vec<u16>,
    /// EC point formats (ext 0x000b).
    pub ec_point_formats: Vec<u8>,
    /// Signature algorithms (ext 0x000d), wire order.
    pub sig_algs: Vec<u16>,
    /// ALPN protocol list (ext 0x0010), wire order.
    pub alpn: Vec<String>,
    /// Server Name Indication (ext 0x0000).
    pub sni: Option<String>,
    /// Whether a session ticket extension (0x0023) is present.
    pub session_ticket: bool,
    /// PSK key exchange modes (ext 0x002d).
    pub psk_modes: Vec<u8>,
    /// Key share groups (ext 0x0033), wire order.
    pub key_share_groups: Vec<u16>,
    /// Supported TLS versions (ext 0x002b). The *real* version negotiation in TLS 1.3.
    pub supported_versions: Vec<u16>,
    /// Certificate compression algorithms (ext 0x001b), e.g. brotli=2, zlib=1.
    pub compress_certificate: Vec<u16>,
}

impl TlsContext {
    /// Encode this TLS context into a holon Vector via the provided encoder.
    pub fn to_vec(&self, encoder: &Encoder) -> Vector {
        encoder.encode_walkable(self)
    }

    /// Canonical string of the supported_groups list (wire order, hex codes).
    pub fn group_string(&self) -> String {
        self.supported_groups.iter()
            .map(|g| format!("0x{:04x}", g))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Canonical string of the cipher suite list (wire order, hex codes).
    pub fn cipher_string(&self) -> String {
        self.cipher_suites.iter()
            .map(|c| format!("0x{:04x}", c))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Canonical string of the extension type list (wire order, hex codes).
    pub fn ext_order_string(&self) -> String {
        self.extensions.iter()
            .map(|(t, _)| format!("0x{:04x}", t))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Sorted canonical string of cipher suites (order-independent set).
    pub fn cipher_set_string(&self) -> String {
        let mut sorted: Vec<u16> = self.cipher_suites.clone();
        sorted.sort();
        sorted.iter()
            .map(|c| format!("0x{:04x}", c))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Sorted canonical string of extension types (order-independent set).
    pub fn ext_set_string(&self) -> String {
        let mut sorted: Vec<u16> = self.extensions.iter().map(|&(t, _)| t).collect();
        sorted.sort();
        sorted.iter()
            .map(|t| format!("0x{:04x}", t))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Sorted canonical string of supported groups (order-independent set).
    pub fn group_set_string(&self) -> String {
        let mut sorted: Vec<u16> = self.supported_groups.clone();
        sorted.sort();
        sorted.iter()
            .map(|g| format!("0x{:04x}", g))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Compute the classical JA4 fingerprint string for logging and external tool
    /// correlation. This is purely a derived string — not used for detection.
    ///
    /// Format: `{proto}{version}{sni}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}`
    pub fn ja4_string(&self) -> String {
        let proto = 't'; // TCP (we're not handling QUIC)
        let version = match self.handshake_version {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            _ => "00",
        };
        let sni_char = if self.sni.is_some() { 'd' } else { 'i' };

        // JA4 filters GREASE from counts
        let cipher_count = self.cipher_suites.iter()
            .filter(|&&c| !is_grease(c))
            .count()
            .min(99);
        let ext_count = self.extensions.iter()
            .filter(|&&(t, _)| !is_grease(t))
            .count()
            .min(99);

        let alpn_str = self.alpn.first()
            .map(|s| {
                let chars: Vec<char> = s.chars().collect();
                format!("{}{}", chars.first().unwrap_or(&'0'), chars.last().unwrap_or(&'0'))
            })
            .unwrap_or_else(|| "00".to_string());

        // JA4 sorts cipher suites and extensions before hashing
        let mut sorted_ciphers: Vec<u16> = self.cipher_suites.iter()
            .filter(|&&c| !is_grease(c))
            .copied()
            .collect();
        sorted_ciphers.sort_unstable();

        let mut sorted_exts: Vec<u16> = self.extensions.iter()
            .filter(|&&(t, _)| !is_grease(t) && t != 0x0000 && t != 0x0010)
            .map(|&(t, _)| t)
            .collect();
        sorted_exts.sort_unstable();

        let cipher_hash = truncated_sha256_hex(&sorted_ciphers.iter()
            .map(|c| format!("{:04x}", c))
            .collect::<Vec<_>>()
            .join(","));
        let ext_hash = truncated_sha256_hex(&sorted_exts.iter()
            .map(|e| format!("{:04x}", e))
            .collect::<Vec<_>>()
            .join(","));

        format!("{}{}{}{:02}{:02}{}_{}_{}", proto, version, sni_char,
                cipher_count, ext_count, alpn_str, cipher_hash, ext_hash)
    }
}

fn is_grease(val: u16) -> bool {
    matches!(val, 0x0a0a | 0x1a1a | 0x2a2a | 0x3a3a | 0x4a4a |
             0x5a5a | 0x6a6a | 0x7a7a | 0x8a8a | 0x9a9a | 0xaaaa |
             0xbaba | 0xcaca | 0xdada | 0xeaea | 0xfafa)
}

fn truncated_sha256_hex(input: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // Cheap approximation — real JA4 uses SHA-256. Good enough for logging.
    let mut h = DefaultHasher::new();
    input.hash(&mut h);
    format!("{:012x}", h.finish())
}

// =============================================================================
// Walkable encoding helpers
// =============================================================================

use crate::tls_names;

fn scalar_s(s: String) -> WalkableValue {
    WalkableValue::Scalar(ScalarValue::String(s))
}

fn scalar_str(s: &str) -> WalkableValue {
    WalkableValue::Scalar(ScalarValue::String(s.to_string()))
}

fn named_list<F: Fn(u16) -> &'static str>(vals: &[u16], namer: F) -> WalkableValue {
    WalkableValue::List(vals.iter().map(|&v| scalar_str(namer(v))).collect())
}

fn named_set<F: Fn(u16) -> &'static str>(vals: &[u16], namer: F) -> WalkableValue {
    WalkableValue::Set(vals.iter().map(|&v| scalar_str(namer(v))).collect())
}

fn string_list(vals: &[String]) -> WalkableValue {
    WalkableValue::List(vals.iter().map(|s| scalar_s(s.clone())).collect())
}

impl Walkable for TlsContext {
    fn walk_type(&self) -> WalkType {
        WalkType::Map
    }

    fn walk_map_items(&self) -> Vec<(&str, WalkableValue)> {
        let mut items: Vec<(&str, WalkableValue)> = Vec::with_capacity(20);

        // Record-layer version (usually TLS1.0 compat) + handshake version
        items.push(("record_version", scalar_str(tls_names::tls_version_name(self.record_version))));
        items.push(("version", scalar_str(tls_names::tls_version_name(self.handshake_version))));

        // Session ID length — 0 vs 32 distinguishes TLS 1.3 compat mode
        items.push(("session_id_len", WalkableValue::Scalar(ScalarValue::Int(self.session_id_len as i64))));

        // Cipher suites: Set (which ciphers) + List (exact ordering)
        items.push(("ciphers", named_set(&self.cipher_suites, tls_names::cipher_suite_name)));
        items.push(("cipher_order", named_list(&self.cipher_suites, tls_names::cipher_suite_name)));

        // Compression methods
        items.push(("compression", WalkableValue::List(
            self.compression_methods.iter()
                .map(|&m| scalar_str(tls_names::compression_method_name(m)))
                .collect()
        )));

        // Extension types: Set (which extensions) + List (exact ordering — fingerprint gold)
        let ext_types: Vec<u16> = self.extensions.iter().map(|&(t, _)| t).collect();
        items.push(("ext_types", named_set(&ext_types, tls_names::extension_name)));
        items.push(("ext_order", named_list(&ext_types, tls_names::extension_name)));

        // Extensions map: name → parsed value for known types, "present" otherwise
        let mut ext_map: Vec<(String, WalkableValue)> = Vec::new();
        for &(ext_type, _) in &self.extensions {
            let key = tls_names::extension_name(ext_type).to_string();
            let value = match ext_type {
                0x0000 => match self.sni {
                    Some(ref sni) => scalar_s(sni.clone()),
                    None => scalar_str("present"),
                },
                0x0010 => string_list(&self.alpn),
                0x002b => named_list(&self.supported_versions, tls_names::tls_version_name),
                0x002d => WalkableValue::List(
                    self.psk_modes.iter()
                        .map(|&m| scalar_str(tls_names::psk_mode_name(m)))
                        .collect()
                ),
                0x0033 => named_set(&self.key_share_groups, tls_names::named_group_name),
                0x001b => WalkableValue::List(
                    self.compress_certificate.iter()
                        .map(|&a| scalar_str(tls_names::compress_cert_name(a)))
                        .collect()
                ),
                _ => scalar_str("present"),
            };
            ext_map.push((key, value));
        }
        items.push(("extensions", WalkableValue::Map(ext_map)));

        // Supported groups as Set
        items.push(("groups", named_set(&self.supported_groups, tls_names::named_group_name)));

        // Signature algorithms as Set
        items.push(("sig_algs", named_set(&self.sig_algs, tls_names::sig_alg_name)));

        // Supported versions (the real TLS version negotiation)
        if !self.supported_versions.is_empty() {
            items.push(("supported_versions", named_list(&self.supported_versions, tls_names::tls_version_name)));
        }

        // ALPN protocols as ordered List
        if !self.alpn.is_empty() {
            items.push(("alpn", string_list(&self.alpn)));
        }

        // SNI
        if let Some(ref sni) = self.sni {
            items.push(("sni", scalar_s(sni.clone())));
        }

        // EC point formats
        if !self.ec_point_formats.is_empty() {
            items.push(("ec_point_formats", WalkableValue::List(
                self.ec_point_formats.iter()
                    .map(|&f| scalar_str(tls_names::ec_point_format_name(f)))
                    .collect()
            )));
        }

        // PSK modes
        if !self.psk_modes.is_empty() {
            items.push(("psk_modes", WalkableValue::List(
                self.psk_modes.iter()
                    .map(|&m| scalar_str(tls_names::psk_mode_name(m)))
                    .collect()
            )));
        }

        // Key share groups as Set
        if !self.key_share_groups.is_empty() {
            items.push(("key_shares", named_set(&self.key_share_groups, tls_names::named_group_name)));
        }

        // Certificate compression algorithms
        if !self.compress_certificate.is_empty() {
            items.push(("compress_certificate", WalkableValue::List(
                self.compress_certificate.iter()
                    .map(|&a| scalar_str(tls_names::compress_cert_name(a)))
                    .collect()
            )));
        }

        items
    }
}

// =============================================================================
// Connection context
// =============================================================================

static CONN_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Connection-scoped context. Created once at TLS accept time, shared via
/// Arc into every RequestSample produced from this connection.
#[derive(Debug, Clone)]
pub struct ConnectionContext {
    pub conn_id: u64,
    pub src_ip: IpAddr,
    pub src_port: u16,
    /// Lossless ClientHello data, shared cheaply across requests.
    pub tls_ctx: Arc<TlsContext>,
    /// Pre-computed VSA encoding of the TLS context.
    pub tls_vec: Vector,
}

impl ConnectionContext {
    pub fn new(src_ip: IpAddr, src_port: u16, tls_ctx: TlsContext, encoder: &Encoder) -> Self {
        let conn_id = CONN_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tls_ctx = Arc::new(tls_ctx);
        let tls_vec = encoder.encode_walkable(tls_ctx.as_ref());
        Self { conn_id, src_ip, src_port, tls_ctx, tls_vec }
    }
}

// =============================================================================
// TLS sample (one per connection, sent to sidecar TLS loop)
// =============================================================================

/// Lightweight sample sent to the sidecar TLS detection loop, one per connection.
#[derive(Debug, Clone)]
pub struct TlsSample {
    pub conn_id: u64,
    pub src_ip: IpAddr,
    pub tls_ctx: Arc<TlsContext>,
    pub tls_vec: Vector,
    pub timestamp_us: u64,
}

impl TlsSample {
    pub fn from_conn(ctx: &ConnectionContext) -> Self {
        Self {
            conn_id: ctx.conn_id,
            src_ip: ctx.src_ip,
            tls_ctx: ctx.tls_ctx.clone(),
            tls_vec: ctx.tls_vec.clone(),
            timestamp_us: now_us(),
        }
    }
}

// =============================================================================
// HTTP version
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
}

// =============================================================================
// Query string segments
// =============================================================================

/// A parsed segment from a query string, distinguishing three forms:
///
/// - `foo=bar` → `Pair("foo", "bar")` — key bound to a value
/// - `foo=`    → `Pair("foo", "")`    — key explicitly bound to empty string
/// - `foo`     → `Flag("foo")`        — key with no assignment (not the same as `foo=`)
/// - ``        → `Empty`              — empty segment from `&&`, trailing `&`, etc.
///
/// Malformed input (like `?` appearing inside a segment) is kept raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryPart<'a> {
    Pair(&'a str, &'a str),
    Flag(&'a str),
    Empty,
}

impl std::fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpVersion::Http10 => write!(f, "HTTP/1.0"),
            HttpVersion::Http11 => write!(f, "HTTP/1.1"),
        }
    }
}

// =============================================================================
// Request sample (one per HTTP request, sent to sidecar request loop)
// =============================================================================

/// Full HTTP request sample with lossless header fidelity and connection context.
///
/// `headers` preserves wire order and duplicate headers exactly as received.
/// Named convenience fields (host, user_agent, etc.) are derived — they do not
/// replace the raw `headers` vec as the canonical source.
#[derive(Debug, Clone)]
pub struct RequestSample {
    // --- Request line ---
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub version: HttpVersion,

    /// All headers in wire order. Duplicates preserved. Canonical source.
    pub headers: Vec<(String, String)>,

    // --- Convenience (derived from headers) ---
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    /// Cookie key=value pairs parsed from the Cookie header, in order.
    pub cookies: Vec<(String, String)>,

    // --- Body (phase 2 — None during phase 1 header inspection) ---
    /// Full body bytes for small payloads; None when body is absent or large.
    pub body: Option<Bytes>,
    pub body_len: u64,

    // --- Connection context (cheap Arc clone) ---
    pub src_ip: IpAddr,
    pub conn_id: u64,
    pub tls_ctx: Arc<TlsContext>,
    pub tls_vec: Vector,

    pub timestamp_us: u64,
}

impl RequestSample {
    /// All values for a header name (case-insensitive), in wire order.
    ///
    /// Returns an empty vec if the header is absent. Duplicate header
    /// expressions return N values; most headers return one.
    pub fn header(&self, name: &str) -> Vec<&str> {
        let name_lower = name.to_ascii_lowercase();
        self.headers.iter()
            .filter(|(k, _)| k.to_ascii_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// First value for a header name (case-insensitive), or None if absent.
    /// Convenience for the common single-valued case.
    pub fn header_first(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_ascii_lowercase();
        self.headers.iter()
            .find(|(k, _)| k.to_ascii_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    /// Whether a header is present (case-insensitive).
    pub fn has_header(&self, name: &str) -> bool {
        let name_lower = name.to_ascii_lowercase();
        self.headers.iter().any(|(k, _)| k.to_ascii_lowercase() == name_lower)
    }

    /// Iterate all headers in wire order as (name, value) pairs.
    pub fn headers_iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Header names in wire order (duplicates included, as expressed).
    pub fn header_names(&self) -> Vec<&str> {
        self.headers.iter().map(|(k, _)| k.as_str()).collect()
    }

    /// Path split by '/' preserving leading/trailing slashes as empty strings.
    /// e.g. "/api/v2/users/" → ["", "api", "v2", "users", ""]
    pub fn path_parts(&self) -> Vec<&str> {
        self.path.split('/').collect()
    }

    /// Parse query string into ordered segments.
    ///
    /// Each segment is one of:
    /// - `QueryPart::Pair(key, value)` — `foo=bar` or `foo=` (explicit empty value)
    /// - `QueryPart::Flag(name)` — `baz` (no `=` at all, semantically different from `baz=`)
    /// - `QueryPart::Empty` — from `&&`, trailing `&`, or leading `&`
    ///
    /// Order and duplicates preserved. Handles malformed input like `?a=1&b?c=2&`
    /// by keeping `?` in the key raw.
    pub fn query_parts(&self) -> Vec<QueryPart<'_>> {
        match self.query {
            Some(ref q) if !q.is_empty() => {
                q.split('&')
                    .map(|segment| {
                        if segment.is_empty() {
                            QueryPart::Empty
                        } else if let Some(eq) = segment.find('=') {
                            QueryPart::Pair(&segment[..eq], &segment[eq + 1..])
                        } else {
                            QueryPart::Flag(segment)
                        }
                    })
                    .collect()
            }
            _ => Vec::new(),
        }
    }

    /// src_ip as a compact string for use as a rule dimension value.
    pub fn src_ip_str(&self) -> String {
        self.src_ip.to_string()
    }
}

impl Walkable for RequestSample {
    fn walk_type(&self) -> WalkType {
        WalkType::Map
    }

    fn walk_map_items(&self) -> Vec<(&str, WalkableValue)> {
        let mut items: Vec<(&str, WalkableValue)> = Vec::with_capacity(16);

        // --- Request line ---
        items.push(("method", scalar_s(self.method.clone())));
        items.push(("path", scalar_s(self.path.clone())));

        // Path split by '/' — positional encoding captures directory structure
        items.push(("path_parts", WalkableValue::List(
            self.path.split('/').map(|p| scalar_s(p.to_string())).collect()
        )));

        items.push(("version", scalar_s(self.version.to_string())));

        // Raw query string (exact bytes as received — captures encoding oddities)
        if let Some(ref q) = self.query {
            items.push(("query", scalar_s(q.clone())));

            // Structured query decomposition. Each segment encodes differently:
            //   "foo=bar" → List["foo", "bar"]  (pair: key bound to value)
            //   "foo="    → List["foo", ""]      (pair: key bound to empty string)
            //   "foo"     → Scalar "foo"         (flag: no assignment — structurally distinct)
            //   ""        → Scalar ""            (empty segment from && or trailing &)
            //
            // Malformed input like "baz?bur=qax" keeps the ? in the key raw.
            let parts: Vec<WalkableValue> = q.split('&')
                .map(|segment| {
                    if segment.is_empty() {
                        scalar_s(String::new())
                    } else if let Some(eq) = segment.find('=') {
                        WalkableValue::List(vec![
                            scalar_s(segment[..eq].to_string()),
                            scalar_s(segment[eq + 1..].to_string()),
                        ])
                    } else {
                        scalar_s(segment.to_string())
                    }
                })
                .collect();
            items.push(("query_parts", WalkableValue::List(parts)));
        }

        // --- Headers ---
        // Header names in wire order (hyper lowercases names; order is preserved)
        items.push(("header_order", WalkableValue::List(
            self.headers.iter()
                .map(|(k, _)| scalar_s(k.clone()))
                .collect()
        )));

        // Full headers as List of [name, value] pairs — lossless, ordered, duplicates preserved
        items.push(("headers", WalkableValue::List(
            self.headers.iter()
                .map(|(k, v)| WalkableValue::List(vec![
                    scalar_s(k.clone()),
                    scalar_s(v.clone()),
                ]))
                .collect()
        )));

        items.push(("header_count", WalkableValue::Scalar(ScalarValue::linear(
            self.headers.len() as f64
        ))));

        // Cookies as List of [key, value] pairs
        if !self.cookies.is_empty() {
            items.push(("cookies", WalkableValue::List(
                self.cookies.iter()
                    .map(|(k, v)| WalkableValue::List(vec![
                        scalar_s(k.clone()),
                        scalar_s(v.clone()),
                    ]))
                    .collect()
            )));
        }

        // --- Body ---
        if self.body_len > 0 {
            items.push(("body_len", WalkableValue::Scalar(ScalarValue::log(self.body_len as f64))));
        }

        // --- Connection context ---
        items.push(("src_ip", scalar_s(self.src_ip_str())));

        // Full nested TLS context — encoder handles deep nesting via role-filler binding
        items.push(("tls", self.tls_ctx.to_walkable_value()));

        items
    }
}

// =============================================================================
// Sidecar sample channel messages
// =============================================================================

/// Message sent on the bounded sample channel to the sidecar.
#[derive(Debug, Clone)]
pub enum SampleMessage {
    /// One per connection (TLS context).
    TlsSample(TlsSample),
    /// One per HTTP request (headers; body None in phase 1).
    RequestSample(RequestSample),
}

// =============================================================================
// Rule types (HTTP-specific)
// =============================================================================

/// Identifies which HTTP field a rule predicate operates on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum FieldDim {
    SrcIp,
    TlsGroupHash,
    TlsCipherHash,
    TlsExtOrderHash,
    TlsCipherSet,
    TlsExtSet,
    TlsGroupSet,
    Method,
    PathPrefix,
    Host,
    UserAgent,
    ContentType,
}

impl FieldDim {
    /// True for TLS-layer dimensions.
    pub fn is_tls(&self) -> bool {
        matches!(self,
            FieldDim::TlsGroupHash | FieldDim::TlsCipherHash | FieldDim::TlsExtOrderHash |
            FieldDim::TlsCipherSet | FieldDim::TlsExtSet | FieldDim::TlsGroupSet
        )
    }

    /// True for HTTP-layer dimensions.
    pub fn is_http(&self) -> bool {
        matches!(self,
            FieldDim::Method | FieldDim::PathPrefix | FieldDim::Host |
            FieldDim::UserAgent | FieldDim::ContentType
        )
    }

    pub fn name(&self) -> &'static str {
        match self {
            FieldDim::SrcIp => "src-ip",
            FieldDim::TlsGroupHash => "tls-group-hash",
            FieldDim::TlsCipherHash => "tls-cipher-hash",
            FieldDim::TlsExtOrderHash => "tls-ext-order-hash",
            FieldDim::TlsCipherSet => "tls-cipher-set",
            FieldDim::TlsExtSet => "tls-ext-set",
            FieldDim::TlsGroupSet => "tls-group-set",
            FieldDim::Method => "method",
            FieldDim::PathPrefix => "path-prefix",
            FieldDim::Host => "host",
            FieldDim::UserAgent => "user-agent",
            FieldDim::ContentType => "content-type",
        }
    }

    /// Extract the string value from a RequestSample for this dimension.
    pub fn extract_value(&self, req: &RequestSample) -> String {
        match self {
            FieldDim::SrcIp => req.src_ip.to_string(),
            FieldDim::TlsGroupHash => req.tls_ctx.group_string(),
            FieldDim::TlsCipherHash => req.tls_ctx.cipher_string(),
            FieldDim::TlsExtOrderHash => req.tls_ctx.ext_order_string(),
            FieldDim::TlsCipherSet => req.tls_ctx.cipher_set_string(),
            FieldDim::TlsExtSet => req.tls_ctx.ext_set_string(),
            FieldDim::TlsGroupSet => req.tls_ctx.group_set_string(),
            FieldDim::Method => req.method.clone(),
            FieldDim::PathPrefix => req.path.clone(),
            FieldDim::Host => req.host.clone().unwrap_or_default(),
            FieldDim::UserAgent => req.user_agent.clone().unwrap_or_default(),
            FieldDim::ContentType => req.content_type.clone().unwrap_or_default(),
        }
    }

    /// Extract the string value from a TlsSample for TLS-level dims.
    pub fn extract_value_tls(&self, sample: &TlsSample) -> String {
        match self {
            FieldDim::SrcIp => sample.src_ip.to_string(),
            FieldDim::TlsGroupHash => sample.tls_ctx.group_string(),
            FieldDim::TlsCipherHash => sample.tls_ctx.cipher_string(),
            FieldDim::TlsExtOrderHash => sample.tls_ctx.ext_order_string(),
            FieldDim::TlsCipherSet => sample.tls_ctx.cipher_set_string(),
            FieldDim::TlsExtSet => sample.tls_ctx.ext_set_string(),
            FieldDim::TlsGroupSet => sample.tls_ctx.group_set_string(),
            _ => String::new(),
        }
    }
}

/// The traversal order for the Rete-spirit DAG.
/// Primary discriminators (most-partitioning) first.
pub const DIM_ORDER: &[FieldDim] = &[
    FieldDim::SrcIp,
    FieldDim::TlsCipherSet,
    FieldDim::TlsExtSet,
    FieldDim::TlsGroupSet,
    FieldDim::TlsGroupHash,
    FieldDim::TlsCipherHash,
    FieldDim::Method,
    FieldDim::PathPrefix,
    FieldDim::Host,
    FieldDim::UserAgent,
    FieldDim::ContentType,
];

/// A matching predicate for one field dimension.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Predicate {
    /// field == value (string equality)
    Eq(FieldDim, String),
    /// field > value (lexicographic; reserved for future numeric WAF expressions)
    Gt(FieldDim, String),
    /// field < value (lexicographic; reserved for future numeric WAF expressions)
    Lt(FieldDim, String),
}

impl Predicate {
    pub fn eq(dim: FieldDim, val: impl Into<String>) -> Self { Predicate::Eq(dim, val.into()) }

    pub fn dim(&self) -> FieldDim {
        match self { Predicate::Eq(d, _) | Predicate::Gt(d, _) | Predicate::Lt(d, _) => *d }
    }

    pub fn value(&self) -> &str {
        match self { Predicate::Eq(_, v) | Predicate::Gt(_, v) | Predicate::Lt(_, v) => v }
    }

    pub fn matches_req(&self, req: &RequestSample) -> bool {
        let v = self.dim().extract_value(req);
        self.matches_value(&v)
    }

    pub fn matches_tls(&self, sample: &TlsSample) -> bool {
        let v = self.dim().extract_value_tls(sample);
        self.matches_value(&v)
    }

    fn matches_value(&self, v: &str) -> bool {
        match self {
            Predicate::Eq(_, expected) => v == expected,
            Predicate::Gt(_, threshold) => v > threshold.as_str(),
            Predicate::Lt(_, threshold) => v < threshold.as_str(),
        }
    }

    /// Render as an s-expression clause: `(= method "GET")`
    pub fn to_sexpr_clause(&self) -> String {
        match self {
            Predicate::Eq(d, v) => format!("(= {} \"{}\")", d.name(), v),
            Predicate::Gt(d, v) => format!("(> {} \"{}\")", d.name(), v),
            Predicate::Lt(d, v) => format!("(< {} \"{}\")", d.name(), v),
        }
    }

    pub fn describe(&self) -> String {
        self.to_sexpr_clause()
    }
}

/// Structured name for rules/actions: (namespace, name).
pub type RuleName = Option<(String, String)>;

/// Action to take when a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RuleAction {
    Block { status: u16, name: RuleName },
    RateLimit { rps: u32, name: RuleName },
    CloseConnection { name: RuleName },
    Count { name: RuleName },
    Pass { name: RuleName },
}

impl RuleAction {
    pub fn block() -> Self { RuleAction::Block { status: 403, name: None } }
    pub fn close() -> Self { RuleAction::CloseConnection { name: None } }
    pub fn pass() -> Self { RuleAction::Pass { name: None } }
    pub fn count() -> Self { RuleAction::Count { name: None } }

    pub fn is_terminal(&self) -> bool {
        !matches!(self, RuleAction::Count { .. })
    }

    pub fn describe(&self) -> &'static str {
        match self {
            RuleAction::Block { .. } => "block",
            RuleAction::RateLimit { .. } => "rate-limit",
            RuleAction::CloseConnection { .. } => "close",
            RuleAction::Count { .. } => "count",
            RuleAction::Pass { .. } => "pass",
        }
    }

    pub fn name(&self) -> &RuleName {
        match self {
            RuleAction::Block { name, .. } => name,
            RuleAction::RateLimit { name, .. } => name,
            RuleAction::CloseConnection { name } => name,
            RuleAction::Count { name } => name,
            RuleAction::Pass { name } => name,
        }
    }

    pub fn to_sexpr(&self) -> String {
        let base = match self {
            RuleAction::Block { status, .. } => format!("(block {})", status),
            RuleAction::RateLimit { rps, .. } => format!("(rate-limit {})", rps),
            RuleAction::CloseConnection { .. } => "(close-connection)".to_string(),
            RuleAction::Count { .. } => "(count)".to_string(),
            RuleAction::Pass { .. } => "(pass)".to_string(),
        };
        if let Some((ns, n)) = self.name() {
            let inner = &base[1..base.len()-1];
            format!("({} :name [\"{}\" \"{}\"])", inner, ns, n)
        } else {
            base
        }
    }
}

/// A complete rule specification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuleSpec {
    pub constraints: Vec<Predicate>,
    pub action: RuleAction,
    pub priority: u8,
    pub comment: Option<String>,
    pub label: Option<String>,
}

impl RuleSpec {
    pub fn new(constraints: Vec<Predicate>, action: RuleAction) -> Self {
        Self { constraints, action, priority: 100, comment: None, label: None }
    }

    pub fn display_label(&self) -> String {
        if let Some(ref l) = self.label {
            return l.clone();
        }
        let c: Vec<_> = self.constraints.iter().map(|p| p.to_sexpr_clause()).collect();
        format!("[{}] → {}", c.join(" "), self.action.describe())
    }

    /// Canonical identity key for deduplication in the rule manager.
    pub fn identity_key(&self) -> String {
        let mut parts: Vec<String> = self.constraints.iter()
            .map(|p| p.to_sexpr_clause())
            .collect();
        parts.sort();
        format!("{}::{}", parts.join(","), self.action.describe())
    }

    /// Check if all constraints match this request.
    pub fn matches_req(&self, req: &RequestSample) -> bool {
        self.constraints.iter().all(|p| p.matches_req(req))
    }

    /// Check if all constraints match this TLS sample.
    pub fn matches_tls(&self, sample: &TlsSample) -> bool {
        self.constraints.iter().all(|p| p.matches_tls(sample))
    }

    fn action_to_sexpr(action: &RuleAction) -> String {
        action.to_sexpr()
    }

    /// Just the constraint array as an s-expression: `[(= method "GET") (= path "/api")]`
    pub fn constraints_sexpr(&self) -> String {
        let mut sorted: Vec<&Predicate> = self.constraints.iter().collect();
        sorted.sort_by_key(|p| p.dim() as u8);
        if sorted.is_empty() {
            "[]".to_string()
        } else {
            let clauses: Vec<String> = sorted.iter().map(|p| p.to_sexpr_clause()).collect();
            format!("[{}]", clauses.join(" "))
        }
    }

    /// Alias for `to_edn()`.
    pub fn to_edn_compact(&self) -> String { self.to_edn() }

    /// Emit rule as EDN (compact, single-line).
    pub fn to_edn(&self) -> String {
        let mut sorted: Vec<&Predicate> = self.constraints.iter().collect();
        sorted.sort_by_key(|p| p.dim() as u8);

        let constraints_str = if sorted.is_empty() {
            "[]".to_string()
        } else {
            let clauses: Vec<String> = sorted.iter().map(|p| p.to_sexpr_clause()).collect();
            format!("[{}]", clauses.join(" "))
        };

        let action_str = Self::action_to_sexpr(&self.action);
        let priority_str = if self.priority != 100 {
            format!(" :priority {}", self.priority)
        } else {
            String::new()
        };
        let comment_str = if let Some(ref c) = self.comment {
            format!(" :comment \"{}\"", c.replace('"', "\\\""))
        } else {
            String::new()
        };

        format!("{{:constraints {} :actions [{}]{}{}}}", constraints_str, action_str, priority_str, comment_str)
    }

    /// Emit rule as EDN (pretty, multi-line format for logs).
    pub fn to_edn_pretty(&self) -> String {
        let indent = "               ";

        let mut sorted: Vec<&Predicate> = self.constraints.iter().collect();
        sorted.sort_by_key(|p| p.dim() as u8);

        let constraints_str = if sorted.is_empty() {
            "[]".to_string()
        } else if sorted.len() == 1 {
            format!("[{}]", sorted[0].to_sexpr_clause())
        } else {
            let clauses: Vec<String> = sorted.iter().map(|p| p.to_sexpr_clause()).collect();
            let mut s = format!("[{}", clauses[0]);
            for clause in &clauses[1..] {
                s.push_str(&format!("\n{}{}", indent, clause));
            }
            s.push(']');
            s
        };

        let action_str = Self::action_to_sexpr(&self.action);

        if self.priority != 100 || self.comment.is_some() {
            let mut parts = vec![
                format!("{{:constraints {}", constraints_str),
                format!(" :actions     [{}]", action_str),
            ];
            if self.priority != 100 {
                parts.push(format!(" :priority    {}", self.priority));
            }
            if let Some(ref comment) = self.comment {
                parts.push(format!(" :comment     \"{}\"", comment.replace('"', "\\\"")));
            }
            parts.push("}".to_string());
            parts.join("\n")
        } else {
            format!("{{:constraints {}\n :actions     [{}]}}", constraints_str, action_str)
        }
    }
}

// =============================================================================
// Compiled rule tree (Rete-spirit DAG — pure userspace)
// =============================================================================

/// Specificity rank for best-match selection. Fields are compared in
/// declaration order (derive(Ord) gives lexicographic comparison).
/// To add a new tiebreaker, insert a field at the appropriate position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Specificity {
    /// Cross-layer (TLS+HTTP = 2) > single-layer (1) > unconstrained (0).
    pub layers: u8,
    /// HTTP constraints are more surgical than TLS-only.
    pub has_http: u8,
    /// More constraints = narrower match.
    pub constraints: u8,
}

/// A node in the in-memory rule tree.
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Which dimension this node branches on.
    pub dim: FieldDim,
    /// Exact-match children: field_value → child_index
    pub children: HashMap<String, usize>,
    /// Wildcard child: for rules that don't constrain this dimension.
    pub wildcard: Option<usize>,
    /// Action at this node (from highest-priority terminating rule).
    pub action: Option<(RuleAction, u32, Specificity)>,
}

/// The compiled rule tree, held behind an ArcSwap for zero-downtime updates.
/// Proxy tasks load() this on every request; sidecar writes via store().
#[derive(Debug, Clone)]
pub struct CompiledTree {
    pub nodes: Vec<TreeNode>,
    pub root: usize,
    /// Canonical EDN of all rules used to build this tree (for diffing).
    pub rule_fingerprint: String,
    /// Per-rule labels: rule_id → (edn_label, action_description).
    pub rule_labels: HashMap<u32, (String, String)>,
}

impl CompiledTree {
    /// An empty tree that passes all traffic.
    pub fn empty() -> Self {
        let root = TreeNode {
            dim: DIM_ORDER[0],
            children: HashMap::new(),
            wildcard: None,
            action: None,
        };
        Self { nodes: vec![root], root: 0, rule_fingerprint: String::new(), rule_labels: HashMap::new() }
    }

    /// Evaluate a request against this tree. Returns (action, rule_id) if any rule matches.
    /// Explores all paths (specific + wildcard) and picks the most specific match.
    pub fn evaluate_req(&self, req: &RequestSample) -> Option<(&RuleAction, u32)> {
        self.dfs_req(req, self.root).map(|(a, id, _)| (a, id))
    }

    /// Evaluate a TLS sample against this tree. Returns (action, rule_id) if any rule matches.
    pub fn evaluate_tls(&self, sample: &TlsSample) -> Option<(&RuleAction, u32)> {
        self.dfs_tls(sample, self.root).map(|(a, id, _)| (a, id))
    }

    /// DFS returning (action, rule_id, specificity).
    /// Explores both specific and wildcard branches; picks the most specific
    /// match via lexicographic tuple comparison, mirroring veth-lab's
    /// best-priority accumulator.
    fn dfs_req<'a>(&'a self, req: &RequestSample, node_idx: usize) -> Option<(&'a RuleAction, u32, Specificity)> {
        let node = self.nodes.get(node_idx)?;

        let field_val = node.dim.extract_value(req);
        let specific = node.children.get(&field_val)
            .and_then(|&child| self.dfs_req(req, child));

        let wildcard = node.wildcard
            .and_then(|child| self.dfs_req(req, child));

        let best_child = pick_best(specific, wildcard);
        let this_node = node.action.as_ref().map(|(a, id, s)| (a, *id, *s));
        pick_best(best_child, this_node)
    }

    fn dfs_tls<'a>(&'a self, sample: &TlsSample, node_idx: usize) -> Option<(&'a RuleAction, u32, Specificity)> {
        let node = self.nodes.get(node_idx)?;
        let field_val = node.dim.extract_value_tls(sample);
        let specific = node.children.get(&field_val)
            .and_then(|&child| self.dfs_tls(sample, child));
        let wildcard = node.wildcard
            .and_then(|child| self.dfs_tls(sample, child));
        let best_child = pick_best(specific, wildcard);
        let this_node = node.action.as_ref().map(|(a, id, s)| (a, *id, *s));
        pick_best(best_child, this_node)
    }
}

/// Pick the more specific match. Ties go to `a` (specific-branch candidate).
fn pick_best<'a>(
    a: Option<(&'a RuleAction, u32, Specificity)>,
    b: Option<(&'a RuleAction, u32, Specificity)>,
) -> Option<(&'a RuleAction, u32, Specificity)> {
    match (a, b) {
        (Some(av), Some(bv)) => {
            if bv.2 > av.2 { Some(bv) } else { Some(av) }
        }
        (Some(v), None) | (None, Some(v)) => Some(v),
        (None, None) => None,
    }
}

// =============================================================================
// DAG serialization (for dashboard visualization)
// =============================================================================

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DagNode {
    pub id: usize,
    pub dim: String,
    pub children: Vec<usize>,
    pub edges: Vec<DagEdge>,
    pub wildcard: Option<usize>,
    pub action: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DagEdge {
    pub target: usize,
    pub label: String,
}

impl CompiledTree {
    pub fn to_dag_nodes(&self) -> Vec<DagNode> {
        self.nodes.iter().enumerate().map(|(i, node)| {
            let mut edges: Vec<DagEdge> = node.children.iter()
                .map(|(val, &target)| DagEdge { target, label: val.clone() })
                .collect();
            edges.sort_by(|a, b| a.label.cmp(&b.label));

            let child_ids: Vec<usize> = edges.iter().map(|e| e.target).collect();
            let mut all_children = child_ids.clone();
            if let Some(wc) = node.wildcard {
                all_children.push(wc);
            }

            let action = node.action.as_ref().map(|(act, _, _)| act.to_sexpr());

            let dim_label = if node.action.is_some() && all_children.is_empty() {
                "terminal".to_string()
            } else {
                node.dim.name().to_string()
            };

            DagNode {
                id: i,
                dim: dim_label,
                children: all_children,
                edges,
                wildcard: node.wildcard,
                action,
            }
        }).collect()
    }
}

// =============================================================================
// Utility
// =============================================================================

pub fn now_us() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

// =============================================================================
// Test helpers
// =============================================================================

/// Build a minimal RequestSample for testing. Avoids repeating boilerplate.
#[cfg(test)]
pub fn test_request_sample(
    method: &str,
    path: &str,
    src_ip: IpAddr,
    headers: Vec<(String, String)>,
    tls_ctx: Arc<TlsContext>,
    tls_vec: Vector,
) -> RequestSample {
    let host = headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone());
    let user_agent = headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .map(|(_, v)| v.clone());
    let content_type = headers.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone());
    RequestSample {
        method: method.to_string(),
        path: path.to_string(),
        query: None,
        version: HttpVersion::Http11,
        headers,
        host,
        user_agent,
        content_type,
        content_length: None,
        cookies: vec![],
        body: None,
        body_len: 0,
        src_ip,
        conn_id: 1,
        tls_ctx,
        tls_vec,
        timestamp_us: now_us(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use holon::kernel::{Encoder, VectorManager};

    fn make_encoder() -> Encoder {
        Encoder::new(VectorManager::new(4096))
    }

    fn default_tls() -> (Arc<TlsContext>, Vector) {
        let ctx = Arc::new(TlsContext::default());
        let enc = make_encoder();
        let vec = enc.encode_walkable(ctx.as_ref());
        (ctx, vec)
    }

    fn sample_tls_context() -> TlsContext {
        TlsContext {
            record_version: 0x0301,
            handshake_version: 0x0303,
            session_id_len: 32,
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b],
            compression_methods: vec![0x00],
            extensions: vec![
                (0x0000, vec![0; 10]), // SNI
                (0x000a, vec![0; 6]),  // supported_groups
                (0x000d, vec![0; 8]),  // sig_algs
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018],
            ec_point_formats: vec![0x00],
            sig_algs: vec![0x0403, 0x0804, 0x0401],
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            sni: Some("example.com".to_string()),
            session_ticket: false,
            psk_modes: vec![0x01],
            key_share_groups: vec![0x001d, 0x0017],
            supported_versions: vec![0x0304, 0x0303],
            compress_certificate: vec![],
        }
    }

    // --- TlsContext canonical strings ---

    #[test]
    fn tls_group_string_deterministic() {
        let ctx = sample_tls_context();
        assert_eq!(ctx.group_string(), ctx.group_string());
    }

    #[test]
    fn tls_group_string_changes_with_groups() {
        let ctx1 = sample_tls_context();
        let mut ctx2 = sample_tls_context();
        ctx2.supported_groups = vec![0x0018, 0x0017, 0x001d];
        assert_ne!(ctx1.group_string(), ctx2.group_string());
    }

    #[test]
    fn tls_cipher_string_deterministic() {
        let ctx = sample_tls_context();
        assert_eq!(ctx.cipher_string(), ctx.cipher_string());
    }

    #[test]
    fn tls_ext_order_string_changes_with_order() {
        let ctx1 = sample_tls_context();
        let mut ctx2 = sample_tls_context();
        ctx2.extensions = vec![
            (0x000d, vec![0; 8]),
            (0x000a, vec![0; 6]),
            (0x0000, vec![0; 10]),
        ];
        assert_ne!(ctx1.ext_order_string(), ctx2.ext_order_string());
    }

    #[test]
    fn empty_tls_context_strings_are_empty() {
        let ctx = TlsContext::default();
        assert_eq!(ctx.group_string(), "");
        assert_eq!(ctx.cipher_string(), "");
        assert_eq!(ctx.ext_order_string(), "");
    }

    // --- TlsContext Walkable + VSA encoding ---

    #[test]
    fn tls_context_encodes_to_vector() {
        let ctx = sample_tls_context();
        let enc = make_encoder();
        let vec = enc.encode_walkable(&ctx);
        assert_eq!(vec.data().len(), 4096);
        // Encoded vector should not be all zeros
        assert!(vec.data().iter().any(|&b| b != 0));
    }

    #[test]
    fn identical_tls_contexts_produce_same_vector() {
        let ctx1 = sample_tls_context();
        let ctx2 = sample_tls_context();
        let enc = make_encoder();
        let v1 = enc.encode_walkable(&ctx1);
        let v2 = enc.encode_walkable(&ctx2);
        assert_eq!(v1.data(), v2.data());
    }

    // --- JA4 string ---

    #[test]
    fn ja4_string_not_empty() {
        let ctx = sample_tls_context();
        let ja4 = ctx.ja4_string();
        assert!(!ja4.is_empty());
        assert!(ja4.starts_with('t')); // TCP
    }

    #[test]
    fn ja4_includes_sni_indicator() {
        let ctx_with_sni = sample_tls_context();
        let mut ctx_no_sni = sample_tls_context();
        ctx_no_sni.sni = None;
        let ja4_d = ctx_with_sni.ja4_string();
        let ja4_i = ctx_no_sni.ja4_string();
        assert!(ja4_d.contains('d'));
        assert!(ja4_i.contains('i'));
    }

    // --- FieldDim extraction ---

    #[test]
    fn extract_src_ip_v4() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let req = test_request_sample("GET", "/", ip, vec![], tls_ctx, tls_vec);
        assert_eq!(FieldDim::SrcIp.extract_value(&req), "10.0.0.1");
    }

    #[test]
    fn extract_method_returns_string() {
        let (tls_ctx, tls_vec) = default_tls();
        let req = test_request_sample("POST", "/api", "1.2.3.4".parse().unwrap(), vec![], tls_ctx, tls_vec);
        assert_eq!(FieldDim::Method.extract_value(&req), "POST");
    }

    #[test]
    fn extract_different_methods_differ() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let req_get = test_request_sample("GET", "/", ip, vec![], tls_ctx.clone(), tls_vec.clone());
        let req_post = test_request_sample("POST", "/", ip, vec![], tls_ctx, tls_vec);
        assert_ne!(
            FieldDim::Method.extract_value(&req_get),
            FieldDim::Method.extract_value(&req_post)
        );
    }

    // --- Predicate matching ---

    #[test]
    fn predicate_eq_matches() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let req = test_request_sample("GET", "/", ip, vec![], tls_ctx, tls_vec);
        let pred = Predicate::eq(FieldDim::SrcIp, "10.0.0.1");
        assert!(pred.matches_req(&req));
    }

    #[test]
    fn predicate_eq_rejects_mismatch() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let req = test_request_sample("GET", "/", ip, vec![], tls_ctx, tls_vec);
        let pred = Predicate::eq(FieldDim::SrcIp, "192.168.1.1");
        assert!(!pred.matches_req(&req));
    }

    #[test]
    fn predicate_gt_lt() {
        let pred_gt = Predicate::Gt(FieldDim::Method, "GET".to_string());
        let pred_lt = Predicate::Lt(FieldDim::Method, "GET".to_string());
        assert!(pred_gt.matches_value("POST")); // P > G lexicographically
        assert!(!pred_gt.matches_value("GET"));
        assert!(!pred_gt.matches_value("DELETE")); // D < G
        assert!(pred_lt.matches_value("DELETE"));
        assert!(!pred_lt.matches_value("GET"));
    }

    // --- RuleSpec ---

    #[test]
    fn rule_identity_key_is_order_independent() {
        let rule1 = RuleSpec::new(
            vec![Predicate::eq(FieldDim::SrcIp, "10.0.0.1"), Predicate::eq(FieldDim::Method, "GET")],
            RuleAction::block(),
        );
        let rule2 = RuleSpec::new(
            vec![Predicate::eq(FieldDim::Method, "GET"), Predicate::eq(FieldDim::SrcIp, "10.0.0.1")],
            RuleAction::block(),
        );
        assert_eq!(rule1.identity_key(), rule2.identity_key());
    }

    #[test]
    fn rule_spec_matches_req() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let req = test_request_sample("GET", "/api", ip, vec![], tls_ctx, tls_vec);
        let rule = RuleSpec::new(vec![Predicate::eq(FieldDim::SrcIp, "10.0.0.1")], RuleAction::block());
        assert!(rule.matches_req(&req));
    }

    // --- EDN rendering ---

    #[test]
    fn predicate_sexpr_clause() {
        let p = Predicate::eq(FieldDim::Method, "GET");
        assert_eq!(p.to_sexpr_clause(), "(= method \"GET\")");
    }

    #[test]
    fn rule_to_edn_pretty_single_constraint() {
        let rule = RuleSpec::new(
            vec![Predicate::eq(FieldDim::PathPrefix, "/api/search")],
            RuleAction::RateLimit { rps: 100, name: None },
        );
        let edn = rule.to_edn_pretty();
        assert!(edn.contains("(= path-prefix \"/api/search\")"));
        assert!(edn.contains("(rate-limit 100)"));
    }

    #[test]
    fn rule_to_edn_compact() {
        let rule = RuleSpec::new(
            vec![Predicate::eq(FieldDim::SrcIp, "10.0.0.1")],
            RuleAction::block(),
        );
        let edn = rule.to_edn();
        assert!(edn.contains("(= src-ip \"10.0.0.1\")"));
        assert!(edn.contains("(block 403)"));
    }

    // --- RequestSample accessors ---

    #[test]
    fn request_sample_header_lookup() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let hdrs = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("X-Custom".to_string(), "val1".to_string()),
            ("X-Custom".to_string(), "val2".to_string()),
        ];
        let req = test_request_sample("GET", "/", ip, hdrs, tls_ctx, tls_vec);

        // header() returns all values as a list
        assert_eq!(req.header("host"), vec!["example.com"]);
        assert_eq!(req.header("HOST"), vec!["example.com"]);
        assert_eq!(req.header("x-custom"), vec!["val1", "val2"]);
        assert!(req.header("X-Missing").is_empty());

        // header_first() returns first value
        assert_eq!(req.header_first("host"), Some("example.com"));
        assert_eq!(req.header_first("x-custom"), Some("val1"));
        assert_eq!(req.header_first("X-Missing"), None);

        assert!(req.has_header("Host"));
        assert!(!req.has_header("X-Missing"));
    }

    #[test]
    fn request_sample_header_names() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let hdrs = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("Accept".to_string(), "text/html".to_string()),
            ("Host".to_string(), "other.com".to_string()),
        ];
        let req = test_request_sample("GET", "/", ip, hdrs, tls_ctx, tls_vec);
        assert_eq!(req.header_names(), vec!["Host", "Accept", "Host"]);
    }

    #[test]
    fn request_sample_path_parts() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let req = test_request_sample("GET", "/api/v2/users/", ip, vec![], tls_ctx, tls_vec);
        assert_eq!(req.path_parts(), vec!["", "api", "v2", "users", ""]);
    }

    #[test]
    fn request_sample_path_parts_root() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let req = test_request_sample("GET", "/", ip, vec![], tls_ctx, tls_vec);
        assert_eq!(req.path_parts(), vec!["", ""]);
    }

    #[test]
    fn query_parts_pair_and_flag() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let mut req = test_request_sample("GET", "/search", ip, vec![], tls_ctx, tls_vec);
        req.query = Some("foo=bar&page=2&debug".to_string());
        let parts = req.query_parts();
        assert_eq!(parts, vec![
            QueryPart::Pair("foo", "bar"),
            QueryPart::Pair("page", "2"),
            QueryPart::Flag("debug"),
        ]);
    }

    #[test]
    fn query_parts_empty_value_vs_flag() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let mut req = test_request_sample("GET", "/", ip, vec![], tls_ctx, tls_vec);
        req.query = Some("foo=bar&baz=&qux".to_string());
        let parts = req.query_parts();
        assert_eq!(parts, vec![
            QueryPart::Pair("foo", "bar"),
            QueryPart::Pair("baz", ""),   // explicit empty value
            QueryPart::Flag("qux"),        // flag, no assignment
        ]);
    }

    #[test]
    fn query_parts_malformed_double_question_mark() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let mut req = test_request_sample("GET", "/", ip, vec![], tls_ctx, tls_vec);
        // Simulates "?foo=bar&baz?bur=qax&" — hyper gives us everything after the first ?
        req.query = Some("foo=bar&baz?bur=qax&".to_string());
        let parts = req.query_parts();
        assert_eq!(parts, vec![
            QueryPart::Pair("foo", "bar"),
            QueryPart::Pair("baz?bur", "qax"),  // ? stays in key raw
            QueryPart::Empty,                     // trailing &
        ]);
    }

    #[test]
    fn query_parts_empty_segments() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let mut req = test_request_sample("GET", "/", ip, vec![], tls_ctx, tls_vec);
        req.query = Some("&foo=bar&&baz&".to_string());
        let parts = req.query_parts();
        assert_eq!(parts, vec![
            QueryPart::Empty,                     // leading &
            QueryPart::Pair("foo", "bar"),
            QueryPart::Empty,                     // double &&
            QueryPart::Flag("baz"),
            QueryPart::Empty,                     // trailing &
        ]);
    }

    #[test]
    fn query_parts_none() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let req = test_request_sample("GET", "/", ip, vec![], tls_ctx, tls_vec);
        assert!(req.query_parts().is_empty());
    }

    // --- CompiledTree evaluation ---

    #[test]
    fn empty_compiled_tree_passes_everything() {
        let tree = CompiledTree::empty();
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let req = test_request_sample("GET", "/", ip, vec![], tls_ctx, tls_vec);
        assert!(tree.evaluate_req(&req).is_none());
    }

    // --- RequestSample Walkable ---

    #[test]
    fn request_sample_encodes_to_vector() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let req = test_request_sample(
            "GET", "/api/search", ip,
            vec![("User-Agent".to_string(), "Mozilla/5.0".to_string())],
            tls_ctx, tls_vec,
        );
        let enc = make_encoder();
        let vec = enc.encode_walkable(&req);
        assert_eq!(vec.data().len(), 4096);
        assert!(vec.data().iter().any(|&b| b != 0));
    }

    // --- Pretty-print walkable as pseudo-JSON ---

    fn render_walkable_value(val: &WalkableValue, indent: usize) -> String {
        let pad = "  ".repeat(indent);
        let pad1 = "  ".repeat(indent + 1);
        match val {
            WalkableValue::Scalar(s) => match s {
                ScalarValue::String(v) => format!("\"{}\"", v),
                ScalarValue::Int(v) => format!("{}", v),
                ScalarValue::Float(v) => format!("{}", v),
                ScalarValue::Bool(v) => format!("{}", v),
                ScalarValue::Null => "null".to_string(),
                ScalarValue::LogFloat { value, .. } => format!("{{\"$log\": {}}}", value),
                ScalarValue::LinearFloat { value, .. } => format!("{{\"$linear\": {}}}", value),
                ScalarValue::TimeFloat { value, .. } => format!("{{\"$time\": {}}}", value),
            },
            WalkableValue::Map(items) => {
                if items.is_empty() { return "{}".to_string(); }
                let entries: Vec<String> = items.iter()
                    .map(|(k, v)| format!("{}\"{}\": {}", pad1, k, render_walkable_value(v, indent + 1)))
                    .collect();
                format!("{{\n{}\n{}}}", entries.join(",\n"), pad)
            }
            WalkableValue::List(items) => {
                if items.is_empty() { return "[]".to_string(); }
                if items.len() <= 6 && items.iter().all(|i| matches!(i, WalkableValue::Scalar(_))) {
                    let vals: Vec<String> = items.iter()
                        .map(|i| render_walkable_value(i, 0))
                        .collect();
                    return format!("[{}]", vals.join(", "));
                }
                let entries: Vec<String> = items.iter()
                    .map(|v| format!("{}{}", pad1, render_walkable_value(v, indent + 1)))
                    .collect();
                format!("[\n{}\n{}]", entries.join(",\n"), pad)
            }
            WalkableValue::Set(items) => {
                if items.is_empty() { return "#{}".to_string(); }
                let vals: Vec<String> = items.iter()
                    .map(|i| render_walkable_value(i, 0))
                    .collect();
                format!("#{{{}}}", vals.join(", "))
            }
        }
    }

    fn render_walkable(w: &dyn Walkable) -> String {
        let val = w.to_walkable_value();
        render_walkable_value(&val, 0)
    }

    fn chrome_tls() -> TlsContext {
        TlsContext {
            record_version: 0x0301,
            handshake_version: 0x0303,
            session_id_len: 32,
            cipher_suites: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
                0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            compression_methods: vec![0x00],
            extensions: vec![
                (0x0000, vec![0; 15]),  // SNI
                (0x0017, vec![]),       // extended_master_secret
                (0xff01, vec![0]),      // renegotiation_info
                (0x000a, vec![0; 8]),   // supported_groups
                (0x000b, vec![0x01, 0x00]), // ec_point_formats
                (0x0023, vec![]),       // session_ticket
                (0x0010, vec![0; 10]),  // ALPN
                (0x0005, vec![0x01, 0x00, 0x00, 0x00, 0x00]), // status_request
                (0x000d, vec![0; 18]),  // sig_algs
                (0x002b, vec![0; 3]),   // supported_versions
                (0x002d, vec![0x01]),   // psk_key_exchange_modes
                (0x0033, vec![0; 37]),  // key_share
                (0x001b, vec![0; 3]),   // compress_certificate
            ],
            supported_groups: vec![0x001d, 0x0017, 0x0018, 0x0019, 0x0100],
            ec_point_formats: vec![0x00],
            sig_algs: vec![0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            sni: Some("shop.example.com".to_string()),
            session_ticket: true,
            psk_modes: vec![0x01],
            key_share_groups: vec![0x001d, 0x0017],
            supported_versions: vec![0x0304, 0x0303],
            compress_certificate: vec![0x0002],
        }
    }

    fn curl_tls() -> TlsContext {
        TlsContext {
            record_version: 0x0301,
            handshake_version: 0x0303,
            session_id_len: 32,
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b],
            compression_methods: vec![0x00],
            extensions: vec![
                (0x0000, vec![0; 10]),  // SNI
                (0x000a, vec![0; 4]),   // supported_groups
                (0x000d, vec![0; 8]),   // sig_algs
                (0x0010, vec![0; 6]),   // ALPN
            ],
            supported_groups: vec![0x001d, 0x0017],
            ec_point_formats: vec![],
            sig_algs: vec![0x0403, 0x0804],
            alpn: vec!["http/1.1".to_string()],
            sni: Some("shop.example.com".to_string()),
            session_ticket: false,
            psk_modes: vec![],
            key_share_groups: vec![0x001d],
            supported_versions: vec![0x0304, 0x0303],
            compress_certificate: vec![],
        }
    }

    #[test]
    fn render_chrome_browser_request() {
        let tls = chrome_tls();
        let enc = make_encoder();
        let tls_vec = enc.encode_walkable(&tls);
        let tls_ctx = Arc::new(tls);

        let req = RequestSample {
            method: "GET".to_string(),
            path: "/api/v2/products/search".to_string(),
            query: Some("q=wireless+headphones&category=electronics&sort=price&page=2".to_string()),
            version: HttpVersion::Http11,
            headers: vec![
                ("host".into(), "shop.example.com".into()),
                ("user-agent".into(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into()),
                ("accept".into(), "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8".into()),
                ("accept-language".into(), "en-US,en;q=0.5".into()),
                ("accept-encoding".into(), "gzip, deflate, br".into()),
                ("connection".into(), "keep-alive".into()),
                ("cookie".into(), "session=abc123def456; theme=dark; cart_id=98765".into()),
                ("sec-fetch-dest".into(), "document".into()),
                ("sec-fetch-mode".into(), "navigate".into()),
                ("sec-fetch-site".into(), "same-origin".into()),
            ],
            host: Some("shop.example.com".into()),
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".into()),
            content_type: None,
            content_length: None,
            cookies: vec![
                ("session".into(), "abc123def456".into()),
                ("theme".into(), "dark".into()),
                ("cart_id".into(), "98765".into()),
            ],
            body: None,
            body_len: 0,
            src_ip: "203.0.113.42".parse().unwrap(),
            conn_id: 1,
            tls_ctx,
            tls_vec,
            timestamp_us: 0,
        };

        let output = render_walkable(&req);
        println!("\n=== Chrome Browser GET with query ===\n{}\n", output);
    }

    #[test]
    fn render_api_post_request() {
        let tls = chrome_tls();
        let enc = make_encoder();
        let tls_vec = enc.encode_walkable(&tls);
        let tls_ctx = Arc::new(tls);

        let req = RequestSample {
            method: "POST".to_string(),
            path: "/api/v1/auth/login".to_string(),
            query: None,
            version: HttpVersion::Http11,
            headers: vec![
                ("host".into(), "shop.example.com".into()),
                ("user-agent".into(), "MyApp/2.1.0 (Android 14)".into()),
                ("content-type".into(), "application/json".into()),
                ("content-length".into(), "84".into()),
                ("accept".into(), "application/json".into()),
                ("authorization".into(), "Bearer eyJhbGciOiJIUzI1NiJ9.xxxxx".into()),
                ("x-request-id".into(), "f47ac10b-58cc-4372-a567-0e02b2c3d479".into()),
            ],
            host: Some("shop.example.com".into()),
            user_agent: Some("MyApp/2.1.0 (Android 14)".into()),
            content_type: Some("application/json".into()),
            content_length: Some(84),
            cookies: vec![],
            body: None,
            body_len: 84,
            src_ip: "198.51.100.7".parse().unwrap(),
            conn_id: 2,
            tls_ctx,
            tls_vec,
            timestamp_us: 0,
        };

        let output = render_walkable(&req);
        println!("\n=== API POST (JSON body, auth bearer) ===\n{}\n", output);
    }

    #[test]
    fn render_curl_flood_request() {
        let tls = curl_tls();
        let enc = make_encoder();
        let tls_vec = enc.encode_walkable(&tls);
        let tls_ctx = Arc::new(tls);

        let req = RequestSample {
            method: "GET".to_string(),
            path: "/".to_string(),
            query: None,
            version: HttpVersion::Http11,
            headers: vec![
                ("host".into(), "shop.example.com".into()),
                ("user-agent".into(), "curl/8.0.0".into()),
                ("accept".into(), "*/*".into()),
            ],
            host: Some("shop.example.com".into()),
            user_agent: Some("curl/8.0.0".into()),
            content_type: None,
            content_length: None,
            cookies: vec![],
            body: None,
            body_len: 0,
            src_ip: "10.0.0.99".parse().unwrap(),
            conn_id: 3,
            tls_ctx,
            tls_vec,
            timestamp_us: 0,
        };

        let output = render_walkable(&req);
        println!("\n=== curl flood (minimal headers, simple TLS) ===\n{}\n", output);
    }

    #[test]
    fn render_malformed_query_request() {
        let tls = curl_tls();
        let enc = make_encoder();
        let tls_vec = enc.encode_walkable(&tls);
        let tls_ctx = Arc::new(tls);

        let req = RequestSample {
            method: "GET".to_string(),
            path: "/search".to_string(),
            query: Some("q=test&lang=en&debug&&tracker?id=evil&=nokey&trailflag&".to_string()),
            version: HttpVersion::Http11,
            headers: vec![
                ("host".into(), "shop.example.com".into()),
                ("user-agent".into(), "bot/1.0".into()),
                ("accept".into(), "*/*".into()),
                ("x-forwarded-for".into(), "1.2.3.4".into()),
                ("x-forwarded-for".into(), "5.6.7.8".into()),
            ],
            host: Some("shop.example.com".into()),
            user_agent: Some("bot/1.0".into()),
            content_type: None,
            content_length: None,
            cookies: vec![],
            body: None,
            body_len: 0,
            src_ip: "192.0.2.1".parse().unwrap(),
            conn_id: 4,
            tls_ctx,
            tls_vec,
            timestamp_us: 0,
        };

        let output = render_walkable(&req);
        println!("\n=== Malformed query + duplicate headers ===\n{}\n", output);
    }

    #[test]
    fn render_tls_context_chrome() {
        let tls = chrome_tls();
        let output = render_walkable(&tls);
        println!("\n=== TLS Context (Chrome 120) ===\n{}\n", output);
    }

    #[test]
    fn render_tls_context_curl() {
        let tls = curl_tls();
        let output = render_walkable(&tls);
        println!("\n=== TLS Context (curl) ===\n{}\n", output);
    }
}
