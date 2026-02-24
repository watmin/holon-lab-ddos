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
use holon::{ScalarRef, ScalarValue, WalkType, Walkable, WalkableRef, WalkableValue};

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

    /// Cipher suites in wire order. GREASE values (0xXaXa) included.
    pub cipher_suites: Vec<u16>,

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
}

impl TlsContext {
    /// Encode this TLS context into a holon Vector via the provided encoder.
    pub fn to_vec(&self, encoder: &Encoder) -> Vector {
        encoder.encode_walkable(self)
    }

    /// Compute a stable u32 hash of the supported_groups list for use as a
    /// tree dimension value. Same tool → same groups → same hash.
    pub fn tls_group_hash(&self) -> u32 {
        let mut h: u32 = 0x811c9dc5;
        for &g in &self.supported_groups {
            h ^= (g & 0xff) as u32;
            h = h.wrapping_mul(0x01000193);
            h ^= (g >> 8) as u32;
            h = h.wrapping_mul(0x01000193);
        }
        h
    }

    /// Compute a stable u32 hash of the cipher suite list (wire order preserved).
    pub fn cipher_hash(&self) -> u32 {
        let mut h: u32 = 0x811c9dc5;
        for &c in &self.cipher_suites {
            h ^= (c & 0xff) as u32;
            h = h.wrapping_mul(0x01000193);
            h ^= (c >> 8) as u32;
            h = h.wrapping_mul(0x01000193);
        }
        h
    }

    /// Compute a stable u32 hash of the extension type list (wire order preserved).
    pub fn ext_order_hash(&self) -> u32 {
        let mut h: u32 = 0x811c9dc5;
        for &(t, _) in &self.extensions {
            h ^= (t & 0xff) as u32;
            h = h.wrapping_mul(0x01000193);
            h ^= (t >> 8) as u32;
            h = h.wrapping_mul(0x01000193);
        }
        h
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

impl Walkable for TlsContext {
    fn walk_type(&self) -> WalkType {
        WalkType::Map
    }

    fn walk_map_items(&self) -> Vec<(&str, WalkableValue)> {
        let mut items = vec![
            ("tls_version", WalkableValue::Scalar(ScalarValue::Int(self.handshake_version as i64))),
            ("cipher_count", WalkableValue::Scalar(ScalarValue::Int(self.cipher_suites.len() as i64))),
            ("ext_count", WalkableValue::Scalar(ScalarValue::Int(self.extensions.len() as i64))),
            ("group_count", WalkableValue::Scalar(ScalarValue::Int(self.supported_groups.len() as i64))),
            ("sig_alg_count", WalkableValue::Scalar(ScalarValue::Int(self.sig_algs.len() as i64))),
            ("has_sni", WalkableValue::Scalar(ScalarValue::Int(if self.sni.is_some() { 1 } else { 0 }))),
            ("session_ticket", WalkableValue::Scalar(ScalarValue::Int(if self.session_ticket { 1 } else { 0 }))),
            ("cipher_hash", WalkableValue::Scalar(ScalarValue::Int(self.cipher_hash() as i64))),
            ("ext_order_hash", WalkableValue::Scalar(ScalarValue::Int(self.ext_order_hash() as i64))),
            ("group_hash", WalkableValue::Scalar(ScalarValue::Int(self.tls_group_hash() as i64))),
        ];
        if let Some(ref alpn) = self.alpn.first() {
            items.push(("alpn_first", WalkableValue::Scalar(ScalarValue::String((*alpn).clone()))));
        }
        items
    }

    fn walk_map_visitor(&self, visitor: &mut dyn FnMut(&str, WalkableRef<'_>)) {
        visitor("tls_version", WalkableRef::int(self.handshake_version as i64));
        visitor("cipher_count", WalkableRef::int(self.cipher_suites.len() as i64));
        visitor("ext_count", WalkableRef::int(self.extensions.len() as i64));
        visitor("group_count", WalkableRef::int(self.supported_groups.len() as i64));
        visitor("sig_alg_count", WalkableRef::int(self.sig_algs.len() as i64));
        visitor("has_sni", WalkableRef::int(if self.sni.is_some() { 1 } else { 0 }));
        visitor("session_ticket", WalkableRef::int(if self.session_ticket { 1 } else { 0 }));
        visitor("cipher_hash", WalkableRef::int(self.cipher_hash() as i64));
        visitor("ext_order_hash", WalkableRef::int(self.ext_order_hash() as i64));
        visitor("group_hash", WalkableRef::int(self.tls_group_hash() as i64));
        if let Some(alpn) = self.alpn.first() {
            visitor("alpn_first", WalkableRef::string(alpn));
        }
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
    /// First value for a header name (case-insensitive). Returns None if absent.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_ascii_lowercase();
        self.headers.iter()
            .find(|(k, _)| k.to_ascii_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    /// All values for a header name (case-insensitive), in wire order.
    /// Duplicates are included.
    pub fn header_all(&self, name: &str) -> Vec<&str> {
        let name_lower = name.to_ascii_lowercase();
        self.headers.iter()
            .filter(|(k, _)| k.to_ascii_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// Whether a header is present (case-insensitive).
    pub fn has_header(&self, name: &str) -> bool {
        let name_lower = name.to_ascii_lowercase();
        self.headers.iter().any(|(k, _)| k.to_ascii_lowercase() == name_lower)
    }

    /// Iterate all headers in wire order.
    pub fn headers_iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Extract path prefix up to first '?' (same as `path` since query is separate).
    pub fn path_prefix(&self) -> &str {
        &self.path
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
        let mut items = vec![
            ("method", WalkableValue::Scalar(ScalarValue::String(self.method.clone()))),
            ("path", WalkableValue::Scalar(ScalarValue::String(self.path.clone()))),
            ("src_ip", WalkableValue::Scalar(ScalarValue::String(self.src_ip_str()))),
            ("header_count", WalkableValue::Scalar(ScalarValue::Int(self.headers.len() as i64))),
            ("has_cookie", WalkableValue::Scalar(ScalarValue::Int(if self.cookies.is_empty() { 0 } else { 1 }))),
            ("tls_group_hash", WalkableValue::Scalar(ScalarValue::Int(self.tls_ctx.tls_group_hash() as i64))),
            ("tls_cipher_hash", WalkableValue::Scalar(ScalarValue::Int(self.tls_ctx.cipher_hash() as i64))),
            ("tls_ext_order_hash", WalkableValue::Scalar(ScalarValue::Int(self.tls_ctx.ext_order_hash() as i64))),
        ];
        if let Some(ref ua) = self.user_agent {
            items.push(("user_agent", WalkableValue::Scalar(ScalarValue::String(ua.clone()))));
        }
        if let Some(ref ct) = self.content_type {
            items.push(("content_type", WalkableValue::Scalar(ScalarValue::String(ct.clone()))));
        }
        if let Some(ref host) = self.host {
            items.push(("host", WalkableValue::Scalar(ScalarValue::String(host.clone()))));
        }
        if self.body_len > 0 {
            items.push(("body_len", WalkableValue::Scalar(ScalarValue::log(self.body_len as f64))));
        }
        items
    }

    fn walk_map_visitor(&self, visitor: &mut dyn FnMut(&str, WalkableRef<'_>)) {
        visitor("method", WalkableRef::string(&self.method));
        visitor("path", WalkableRef::string(&self.path));
        let src_ip_str = self.src_ip_str();
        visitor("src_ip", WalkableRef::string(&src_ip_str));
        visitor("header_count", WalkableRef::int(self.headers.len() as i64));
        visitor("has_cookie", WalkableRef::int(if self.cookies.is_empty() { 0 } else { 1 }));
        visitor("tls_group_hash", WalkableRef::int(self.tls_ctx.tls_group_hash() as i64));
        visitor("tls_cipher_hash", WalkableRef::int(self.tls_ctx.cipher_hash() as i64));
        visitor("tls_ext_order_hash", WalkableRef::int(self.tls_ctx.ext_order_hash() as i64));
        if let Some(ref ua) = self.user_agent {
            visitor("user_agent", WalkableRef::string(ua));
        }
        if let Some(ref ct) = self.content_type {
            visitor("content_type", WalkableRef::string(ct));
        }
        if let Some(ref host) = self.host {
            visitor("host", WalkableRef::string(host));
        }
        if self.body_len > 0 {
            visitor("body_len", WalkableRef::Scalar(ScalarRef::log(self.body_len as f64)));
        }
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
    Method,
    PathPrefix,
    Host,
    UserAgent,
    ContentType,
}

impl FieldDim {
    pub fn name(&self) -> &'static str {
        match self {
            FieldDim::SrcIp => "src-ip",
            FieldDim::TlsGroupHash => "tls-group-hash",
            FieldDim::TlsCipherHash => "tls-cipher-hash",
            FieldDim::TlsExtOrderHash => "tls-ext-order-hash",
            FieldDim::Method => "method",
            FieldDim::PathPrefix => "path-prefix",
            FieldDim::Host => "host",
            FieldDim::UserAgent => "user-agent",
            FieldDim::ContentType => "content-type",
        }
    }

    /// Extract the u32-comparable value from a RequestSample for this dimension.
    /// String fields use FNV-1a hash so they can be compared in the tree.
    pub fn extract_u32(&self, req: &RequestSample) -> u32 {
        match self {
            FieldDim::SrcIp => ip_to_u32(req.src_ip),
            FieldDim::TlsGroupHash => req.tls_ctx.tls_group_hash(),
            FieldDim::TlsCipherHash => req.tls_ctx.cipher_hash(),
            FieldDim::TlsExtOrderHash => req.tls_ctx.ext_order_hash(),
            FieldDim::Method => fnv1a_str(&req.method),
            FieldDim::PathPrefix => fnv1a_str(&req.path),
            FieldDim::Host => fnv1a_str(req.host.as_deref().unwrap_or("")),
            FieldDim::UserAgent => fnv1a_str(req.user_agent.as_deref().unwrap_or("")),
            FieldDim::ContentType => fnv1a_str(req.content_type.as_deref().unwrap_or("")),
        }
    }

    /// Extract the u32-comparable value from a TlsSample for TLS-level dims.
    pub fn extract_u32_tls(&self, sample: &TlsSample) -> u32 {
        match self {
            FieldDim::SrcIp => ip_to_u32(sample.src_ip),
            FieldDim::TlsGroupHash => sample.tls_ctx.tls_group_hash(),
            FieldDim::TlsCipherHash => sample.tls_ctx.cipher_hash(),
            FieldDim::TlsExtOrderHash => sample.tls_ctx.ext_order_hash(),
            _ => 0,
        }
    }
}

fn ip_to_u32(ip: IpAddr) -> u32 {
    match ip {
        IpAddr::V4(v4) => u32::from_ne_bytes(v4.octets()),
        IpAddr::V6(_) => 0, // IPv6 not in scope for phase 1
    }
}

pub fn fnv1a_str(s: &str) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in s.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

/// The traversal order for the Rete-spirit DAG.
/// Primary discriminators (most-partitioning) first.
pub const DIM_ORDER: &[FieldDim] = &[
    FieldDim::SrcIp,
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
    /// field == value (u32 comparison)
    Eq(FieldDim, u32),
    /// field > value
    Gt(FieldDim, u32),
    /// field < value
    Lt(FieldDim, u32),
}

impl Predicate {
    pub fn eq(dim: FieldDim, val: u32) -> Self { Predicate::Eq(dim, val) }

    pub fn dim(&self) -> FieldDim {
        match self { Predicate::Eq(d, _) | Predicate::Gt(d, _) | Predicate::Lt(d, _) => *d }
    }

    pub fn matches_req(&self, req: &RequestSample) -> bool {
        let v = self.dim().extract_u32(req);
        self.matches_value(v)
    }

    pub fn matches_tls(&self, sample: &TlsSample) -> bool {
        let v = self.dim().extract_u32_tls(sample);
        self.matches_value(v)
    }

    fn matches_value(&self, v: u32) -> bool {
        match self {
            Predicate::Eq(_, expected) => v == *expected,
            Predicate::Gt(_, threshold) => v > *threshold,
            Predicate::Lt(_, threshold) => v < *threshold,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Predicate::Eq(d, v) => format!("({} = {})", d.name(), v),
            Predicate::Gt(d, v) => format!("({} > {})", d.name(), v),
            Predicate::Lt(d, v) => format!("({} < {})", d.name(), v),
        }
    }
}

/// Action to take when a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RuleAction {
    /// Block the request with an HTTP error response.
    Block { status: u16 },
    /// Rate-limit: allow up to `rps` requests per second from matching clients.
    RateLimit { rps: u32 },
    /// Close the TCP connection (for TLS/IP level rules).
    CloseConnection,
    /// Count matches for observability without taking action.
    Count { label: String },
    /// Explicitly pass (can be used to whitelist).
    Pass,
}

impl RuleAction {
    pub fn block() -> Self { RuleAction::Block { status: 403 } }
    pub fn close() -> Self { RuleAction::CloseConnection }
    pub fn pass() -> Self { RuleAction::Pass }
    pub fn count(label: impl Into<String>) -> Self { RuleAction::Count { label: label.into() } }

    pub fn is_terminal(&self) -> bool {
        !matches!(self, RuleAction::Count { .. })
    }

    pub fn describe(&self) -> &'static str {
        match self {
            RuleAction::Block { .. } => "BLOCK",
            RuleAction::RateLimit { .. } => "RATE-LIMIT",
            RuleAction::CloseConnection => "CLOSE",
            RuleAction::Count { .. } => "COUNT",
            RuleAction::Pass => "PASS",
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
        let c: Vec<_> = self.constraints.iter().map(|p| p.describe()).collect();
        format!("[{}] → {}", c.join(" "), self.action.describe())
    }

    /// Canonical identity key for deduplication in the rule manager.
    pub fn identity_key(&self) -> String {
        let mut parts: Vec<String> = self.constraints.iter()
            .map(|p| p.describe())
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
}

// =============================================================================
// Compiled rule tree (Rete-spirit DAG — pure userspace)
// =============================================================================

/// A node in the in-memory rule tree.
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Which dimension this node branches on.
    pub dim: FieldDim,
    /// Exact-match children: field_value → child_index
    pub children: HashMap<u32, usize>,
    /// Wildcard child: for rules that don't constrain this dimension.
    pub wildcard: Option<usize>,
    /// Action at this node (from highest-priority terminating rule).
    pub action: Option<(RuleAction, u32)>, // (action, rule_id)
}

/// The compiled rule tree, held behind an ArcSwap for zero-downtime updates.
/// Proxy tasks load() this on every request; sidecar writes via store().
#[derive(Debug, Clone)]
pub struct CompiledTree {
    pub nodes: Vec<TreeNode>,
    pub root: usize,
    /// Canonical EDN of all rules used to build this tree (for diffing).
    pub rule_fingerprint: String,
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
        Self { nodes: vec![root], root: 0, rule_fingerprint: String::new() }
    }

    /// Evaluate a request against this tree. Returns the matching action if any.
    pub fn evaluate_req(&self, req: &RequestSample) -> Option<&RuleAction> {
        self.dfs_req(req, self.root)
    }

    /// Evaluate a TLS sample against this tree. Returns the matching action if any.
    pub fn evaluate_tls(&self, sample: &TlsSample) -> Option<&RuleAction> {
        self.dfs_tls(sample, self.root)
    }

    fn dfs_req<'a>(&'a self, req: &RequestSample, node_idx: usize) -> Option<&'a RuleAction> {
        let node = self.nodes.get(node_idx)?;

        // Check specific child first (higher priority than wildcard)
        let field_val = node.dim.extract_u32(req);
        let specific = node.children.get(&field_val)
            .and_then(|&child| self.dfs_req(req, child));

        // Check wildcard child
        let wildcard = node.wildcard
            .and_then(|child| self.dfs_req(req, child));

        // Return deepest/specific match, falling back to wildcard, then this node's action
        specific
            .or(wildcard)
            .or_else(|| node.action.as_ref().map(|(a, _)| a))
    }

    fn dfs_tls<'a>(&'a self, sample: &TlsSample, node_idx: usize) -> Option<&'a RuleAction> {
        let node = self.nodes.get(node_idx)?;
        let field_val = node.dim.extract_u32_tls(sample);
        let specific = node.children.get(&field_val)
            .and_then(|&child| self.dfs_tls(sample, child));
        let wildcard = node.wildcard
            .and_then(|child| self.dfs_tls(sample, child));
        specific
            .or(wildcard)
            .or_else(|| node.action.as_ref().map(|(a, _)| a))
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
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b],
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
        }
    }

    // --- TlsContext hashing ---

    #[test]
    fn tls_group_hash_deterministic() {
        let ctx = sample_tls_context();
        assert_eq!(ctx.tls_group_hash(), ctx.tls_group_hash());
    }

    #[test]
    fn tls_group_hash_changes_with_groups() {
        let ctx1 = sample_tls_context();
        let mut ctx2 = sample_tls_context();
        ctx2.supported_groups = vec![0x0018, 0x0017, 0x001d]; // different order
        assert_ne!(ctx1.tls_group_hash(), ctx2.tls_group_hash());
    }

    #[test]
    fn tls_cipher_hash_deterministic() {
        let ctx = sample_tls_context();
        assert_eq!(ctx.cipher_hash(), ctx.cipher_hash());
    }

    #[test]
    fn tls_ext_order_hash_changes_with_order() {
        let ctx1 = sample_tls_context();
        let mut ctx2 = sample_tls_context();
        ctx2.extensions = vec![
            (0x000d, vec![0; 8]),
            (0x000a, vec![0; 6]),
            (0x0000, vec![0; 10]),
        ];
        assert_ne!(ctx1.ext_order_hash(), ctx2.ext_order_hash());
    }

    #[test]
    fn empty_tls_context_hashes_are_consistent() {
        let ctx = TlsContext::default();
        let h1 = ctx.tls_group_hash();
        let h2 = ctx.cipher_hash();
        let h3 = ctx.ext_order_hash();
        // All should return the FNV-1a offset basis since no data is mixed in
        assert_eq!(h1, 0x811c9dc5);
        assert_eq!(h2, 0x811c9dc5);
        assert_eq!(h3, 0x811c9dc5);
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
        let val = FieldDim::SrcIp.extract_u32(&req);
        let expected = u32::from_ne_bytes([10, 0, 0, 1]);
        assert_eq!(val, expected);
    }

    #[test]
    fn extract_method_hash_is_deterministic() {
        let (tls_ctx, tls_vec) = default_tls();
        let req = test_request_sample("POST", "/api", "1.2.3.4".parse().unwrap(), vec![], tls_ctx, tls_vec);
        let v1 = FieldDim::Method.extract_u32(&req);
        let v2 = FieldDim::Method.extract_u32(&req);
        assert_eq!(v1, v2);
        assert_ne!(v1, 0);
    }

    #[test]
    fn extract_different_methods_differ() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let req_get = test_request_sample("GET", "/", ip, vec![], tls_ctx.clone(), tls_vec.clone());
        let req_post = test_request_sample("POST", "/", ip, vec![], tls_ctx, tls_vec);
        assert_ne!(
            FieldDim::Method.extract_u32(&req_get),
            FieldDim::Method.extract_u32(&req_post)
        );
    }

    // --- Predicate matching ---

    #[test]
    fn predicate_eq_matches() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let req = test_request_sample("GET", "/", ip, vec![], tls_ctx, tls_vec);
        let ip_u32 = u32::from_ne_bytes([10, 0, 0, 1]);
        let pred = Predicate::eq(FieldDim::SrcIp, ip_u32);
        assert!(pred.matches_req(&req));
    }

    #[test]
    fn predicate_eq_rejects_mismatch() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let req = test_request_sample("GET", "/", ip, vec![], tls_ctx, tls_vec);
        let wrong_ip = u32::from_ne_bytes([192, 168, 1, 1]);
        let pred = Predicate::eq(FieldDim::SrcIp, wrong_ip);
        assert!(!pred.matches_req(&req));
    }

    #[test]
    fn predicate_gt_lt() {
        let pred_gt = Predicate::Gt(FieldDim::SrcIp, 100);
        let pred_lt = Predicate::Lt(FieldDim::SrcIp, 100);
        assert!(pred_gt.matches_value(101));
        assert!(!pred_gt.matches_value(100));
        assert!(!pred_gt.matches_value(99));
        assert!(pred_lt.matches_value(99));
        assert!(!pred_lt.matches_value(100));
    }

    // --- RuleSpec ---

    #[test]
    fn rule_identity_key_is_order_independent() {
        let rule1 = RuleSpec::new(
            vec![Predicate::eq(FieldDim::SrcIp, 1), Predicate::eq(FieldDim::Method, 2)],
            RuleAction::block(),
        );
        let rule2 = RuleSpec::new(
            vec![Predicate::eq(FieldDim::Method, 2), Predicate::eq(FieldDim::SrcIp, 1)],
            RuleAction::block(),
        );
        assert_eq!(rule1.identity_key(), rule2.identity_key());
    }

    #[test]
    fn rule_spec_matches_req() {
        let (tls_ctx, tls_vec) = default_tls();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_u32 = u32::from_ne_bytes([10, 0, 0, 1]);
        let req = test_request_sample("GET", "/api", ip, vec![], tls_ctx, tls_vec);
        let rule = RuleSpec::new(vec![Predicate::eq(FieldDim::SrcIp, ip_u32)], RuleAction::block());
        assert!(rule.matches_req(&req));
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
        assert_eq!(req.header("host"), Some("example.com"));
        assert_eq!(req.header("HOST"), Some("example.com"));
        assert_eq!(req.header("x-custom"), Some("val1"));
        assert_eq!(req.header_all("x-custom"), vec!["val1", "val2"]);
        assert!(req.has_header("Host"));
        assert!(!req.has_header("X-Missing"));
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
}
