//! Expression language for WAF rule constraints.
//!
//! Three orthogonal concepts:
//! - **Domain accessors**: raw data sources by protocol layer
//! - **Generic functions**: composable transforms (first, last, nth, get, key, val, ...)
//! - **Operators**: test predicates (=, exists, prefix, ...)
//!
//! Full specification: docs/RULE-LANGUAGE.md

use std::collections::BTreeSet;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

use crate::tls_names;
use crate::types::{QueryPart, RequestSample, TlsContext, TlsSample};

// =============================================================================
// Value — typed rule values
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Num(i64),
    Bool(bool),
    List(Vec<Value>),
    Set(BTreeSet<String>),
    Pair(Box<Value>, Box<Value>),
    Nil,
}

impl Value {
    pub fn str(s: impl Into<String>) -> Self { Value::Str(s.into()) }
    pub fn num(n: i64) -> Self { Value::Num(n) }
    pub fn list(items: Vec<Value>) -> Self { Value::List(items) }
    pub fn pair(k: Value, v: Value) -> Self { Value::Pair(Box::new(k), Box::new(v)) }

    pub fn set_from_strs(items: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Value::Set(items.into_iter().map(|s| s.into()).collect())
    }

    pub fn as_str(&self) -> Option<&str> {
        match self { Value::Str(s) => Some(s), _ => None }
    }

    pub fn as_num(&self) -> Option<i64> {
        match self { Value::Num(n) => Some(*n), _ => None }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self { Value::Bool(b) => Some(*b), _ => None }
    }

    pub fn as_list(&self) -> Option<&[Value]> {
        match self { Value::List(v) => Some(v), _ => None }
    }

    pub fn as_set(&self) -> Option<&BTreeSet<String>> {
        match self { Value::Set(s) => Some(s), _ => None }
    }

    pub fn is_nil(&self) -> bool { matches!(self, Value::Nil) }

    /// Canonical string for HashMap branching keys in the tree.
    pub fn canonical_key(&self) -> String {
        self.canonical_key_cow().into_owned()
    }

    /// Zero-copy canonical key — borrows for Str, allocates only when needed.
    pub fn canonical_key_cow(&self) -> std::borrow::Cow<'_, str> {
        use std::borrow::Cow;
        match self {
            Value::Str(s) => Cow::Borrowed(s.as_str()),
            Value::Num(n) => Cow::Owned(n.to_string()),
            Value::Bool(b) => Cow::Owned(b.to_string()),
            Value::List(items) => {
                let parts: Vec<String> = items.iter().map(|v| v.canonical_key()).collect();
                Cow::Owned(format!("[{}]", parts.join(",")))
            }
            Value::Set(items) => {
                let parts: Vec<&String> = items.iter().collect();
                Cow::Owned(format!("#{{{}}}", parts.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")))
            }
            Value::Pair(k, v) => Cow::Owned(format!("[{},{}]", k.canonical_key(), v.canonical_key())),
            Value::Nil => Cow::Borrowed("nil"),
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Str(s) => write!(f, "\"{}\"", s),
            Value::Num(n) => write!(f, "{}", n),
            Value::Bool(b) => write!(f, "{}", b),
            Value::List(items) => {
                let parts: Vec<String> = items.iter().map(|v| v.to_string()).collect();
                write!(f, "[{}]", parts.join(" "))
            }
            Value::Set(items) => {
                let quoted: Vec<String> = items.iter().map(|s| format!("\"{}\"", s)).collect();
                write!(f, "#{{{}}}", quoted.join(" "))
            }
            Value::Pair(k, v) => write!(f, "[{} {}]", k, v),
            Value::Nil => write!(f, "nil"),
        }
    }
}

impl Hash for Value {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Value::Str(s) => s.hash(state),
            Value::Num(n) => n.hash(state),
            Value::Bool(b) => b.hash(state),
            Value::List(items) => items.hash(state),
            Value::Set(items) => {
                for item in items { item.hash(state); }
            }
            Value::Pair(k, v) => { k.hash(state); v.hash(state); }
            Value::Nil => {}
        }
    }
}

// =============================================================================
// SimpleDim — fixed, non-parameterized field dimensions
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SimpleDim {
    // HTTP request line
    Method,
    Path,
    SrcIp,
    BodyLen,
    Protocol,

    // HTTP pair-lists and collections
    Headers,
    Cookies,
    QueryParams,
    HeaderOrder,
    PathParts,
    QueryFlags,
    QueryRaw,

    // TLS scalar
    TlsVersion,
    TlsRecordVersion,
    TlsSessionIdLen,
    Sni,

    // TLS sets (order-independent)
    TlsCiphers,
    TlsExtTypes,
    TlsGroups,
    TlsSigAlgs,
    TlsKeyShares,

    // TLS lists (order matters)
    TlsCipherOrder,
    TlsExtOrder,
    TlsAlpn,
    TlsVersions,
    TlsPskModes,
    TlsCompression,

    // TLS map
    TlsExtensions,
}

impl SimpleDim {
    pub fn name(&self) -> &'static str {
        match self {
            SimpleDim::Method => "method",
            SimpleDim::Path => "path",
            SimpleDim::SrcIp => "src-ip",
            SimpleDim::BodyLen => "body-len",
            SimpleDim::Protocol => "protocol",
            SimpleDim::Headers => "headers",
            SimpleDim::Cookies => "cookies",
            SimpleDim::QueryParams => "query-params",
            SimpleDim::HeaderOrder => "header-order",
            SimpleDim::PathParts => "path-parts",
            SimpleDim::QueryFlags => "query-flags",
            SimpleDim::QueryRaw => "query-raw",
            SimpleDim::TlsVersion => "tls-version",
            SimpleDim::TlsRecordVersion => "tls-record-version",
            SimpleDim::TlsSessionIdLen => "tls-session-id-len",
            SimpleDim::Sni => "sni",
            SimpleDim::TlsCiphers => "tls-ciphers",
            SimpleDim::TlsExtTypes => "tls-ext-types",
            SimpleDim::TlsGroups => "tls-groups",
            SimpleDim::TlsSigAlgs => "tls-sig-algs",
            SimpleDim::TlsKeyShares => "tls-key-shares",
            SimpleDim::TlsCipherOrder => "tls-cipher-order",
            SimpleDim::TlsExtOrder => "tls-ext-order",
            SimpleDim::TlsAlpn => "tls-alpn",
            SimpleDim::TlsVersions => "tls-versions",
            SimpleDim::TlsPskModes => "tls-psk-modes",
            SimpleDim::TlsCompression => "tls-compression",
            SimpleDim::TlsExtensions => "tls-extensions",
        }
    }

    pub fn is_tls(&self) -> bool {
        matches!(self,
            SimpleDim::TlsVersion | SimpleDim::TlsRecordVersion |
            SimpleDim::TlsSessionIdLen | SimpleDim::Sni |
            SimpleDim::TlsCiphers | SimpleDim::TlsExtTypes |
            SimpleDim::TlsGroups | SimpleDim::TlsSigAlgs |
            SimpleDim::TlsKeyShares | SimpleDim::TlsCipherOrder |
            SimpleDim::TlsExtOrder | SimpleDim::TlsAlpn |
            SimpleDim::TlsVersions | SimpleDim::TlsPskModes |
            SimpleDim::TlsCompression | SimpleDim::TlsExtensions
        )
    }

    pub fn is_http(&self) -> bool {
        matches!(self,
            SimpleDim::Method | SimpleDim::Path | SimpleDim::BodyLen |
            SimpleDim::Headers | SimpleDim::Cookies | SimpleDim::QueryParams |
            SimpleDim::HeaderOrder | SimpleDim::PathParts |
            SimpleDim::QueryFlags | SimpleDim::QueryRaw | SimpleDim::Protocol
        )
    }

    /// Layer rank for DIM_ORDER tiebreaking: TLS=0, HTTP=1, other=2.
    pub fn layer_rank(&self) -> u8 {
        if self.is_tls() { 0 } else if self.is_http() { 1 } else { 2 }
    }
}

// =============================================================================
// Dimension — resolved accessor chain (tree node identity)
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Dimension {
    Simple(SimpleDim),
    Header(String),
    Cookie(String),
    Query(String),
    First(Box<Dimension>),
    Last(Box<Dimension>),
    Nth(Box<Dimension>, i32),
    Get(Box<Dimension>, String),
    Key(Box<Dimension>),
    Val(Box<Dimension>),
    Count(Box<Dimension>),
    Keys(Box<Dimension>),
    Vals(Box<Dimension>),
    SetOf(Box<Dimension>),
    Lower(Box<Dimension>),
}

impl Dimension {
    pub fn is_tls(&self) -> bool {
        match self {
            Dimension::Simple(s) => s.is_tls(),
            Dimension::Header(_) | Dimension::Cookie(_) | Dimension::Query(_) => false,
            Dimension::First(inner) | Dimension::Last(inner) |
            Dimension::Key(inner) | Dimension::Val(inner) |
            Dimension::Count(inner) | Dimension::Keys(inner) |
            Dimension::Vals(inner) | Dimension::SetOf(inner) |
            Dimension::Lower(inner) => inner.is_tls(),
            Dimension::Nth(inner, _) => inner.is_tls(),
            Dimension::Get(inner, _) => inner.is_tls(),
        }
    }

    pub fn is_http(&self) -> bool {
        match self {
            Dimension::Simple(s) => s.is_http(),
            Dimension::Header(_) | Dimension::Cookie(_) | Dimension::Query(_) => true,
            Dimension::First(inner) | Dimension::Last(inner) |
            Dimension::Key(inner) | Dimension::Val(inner) |
            Dimension::Count(inner) | Dimension::Keys(inner) |
            Dimension::Vals(inner) | Dimension::SetOf(inner) |
            Dimension::Lower(inner) => inner.is_http(),
            Dimension::Nth(inner, _) => inner.is_http(),
            Dimension::Get(inner, _) => inner.is_http(),
        }
    }

    /// Layer rank for DIM_ORDER tiebreaking.
    pub fn layer_rank(&self) -> u8 {
        if self.is_tls() { 0 } else if self.is_http() { 1 } else { 2 }
    }

    /// Render as s-expression for display.
    pub fn to_sexpr(&self) -> String {
        match self {
            Dimension::Simple(s) => s.name().to_string(),
            Dimension::Header(name) => format!("(header \"{}\")", name),
            Dimension::Cookie(name) => format!("(cookie \"{}\")", name),
            Dimension::Query(name) => format!("(query \"{}\")", name),
            Dimension::First(inner) => format!("(first {})", inner.to_sexpr()),
            Dimension::Last(inner) => format!("(last {})", inner.to_sexpr()),
            Dimension::Nth(inner, n) => format!("(nth {} {})", inner.to_sexpr(), n),
            Dimension::Get(inner, key) => format!("(get {} \"{}\")", inner.to_sexpr(), key),
            Dimension::Key(inner) => format!("(key {})", inner.to_sexpr()),
            Dimension::Val(inner) => format!("(val {})", inner.to_sexpr()),
            Dimension::Count(inner) => format!("(count {})", inner.to_sexpr()),
            Dimension::Keys(inner) => format!("(keys {})", inner.to_sexpr()),
            Dimension::Vals(inner) => format!("(vals {})", inner.to_sexpr()),
            Dimension::SetOf(inner) => format!("(set {})", inner.to_sexpr()),
            Dimension::Lower(inner) => format!("(lower {})", inner.to_sexpr()),
        }
    }
}

// Convenience constructors for common compositions
impl Dimension {
    pub fn method() -> Self { Dimension::Simple(SimpleDim::Method) }
    pub fn path() -> Self { Dimension::Simple(SimpleDim::Path) }
    pub fn src_ip() -> Self { Dimension::Simple(SimpleDim::SrcIp) }
    pub fn header(name: impl Into<String>) -> Self { Dimension::Header(name.into()) }
    pub fn cookie(name: impl Into<String>) -> Self { Dimension::Cookie(name.into()) }
    pub fn query(name: impl Into<String>) -> Self { Dimension::Query(name.into()) }

    pub fn header_first(name: impl Into<String>) -> Self {
        Dimension::First(Box::new(Dimension::Header(name.into())))
    }
    pub fn cookie_first(name: impl Into<String>) -> Self {
        Dimension::First(Box::new(Dimension::Cookie(name.into())))
    }
    pub fn query_first(name: impl Into<String>) -> Self {
        Dimension::First(Box::new(Dimension::Query(name.into())))
    }
}

// =============================================================================
// Extraction — pull typed Values from protocol data
// =============================================================================

fn hex16(v: u16) -> String { format!("0x{:04x}", v) }
fn hex8(v: u8) -> String { format!("0x{:02x}", v) }

fn str_list(items: impl IntoIterator<Item = String>) -> Value {
    Value::List(items.into_iter().map(Value::Str).collect())
}

fn str_set(items: impl IntoIterator<Item = String>) -> Value {
    Value::Set(items.into_iter().collect())
}

fn pair_list(items: impl IntoIterator<Item = (String, String)>) -> Value {
    Value::List(
        items.into_iter()
            .map(|(k, v)| Value::pair(Value::Str(k), Value::Str(v)))
            .collect(),
    )
}

impl SimpleDim {
    /// Extract the base value from a TlsContext.
    fn extract_tls(&self, tls: &TlsContext, src_ip: Option<IpAddr>) -> Value {
        match self {
            SimpleDim::SrcIp => match src_ip {
                Some(ip) => Value::Str(ip.to_string()),
                None => Value::Nil,
            },
            SimpleDim::Sni => match &tls.sni {
                Some(s) => Value::Str(s.clone()),
                None => Value::Nil,
            },
            SimpleDim::TlsVersion => Value::Str(tls_names::tls_version_name(tls.handshake_version).to_string()),
            SimpleDim::TlsRecordVersion => Value::Str(tls_names::tls_version_name(tls.record_version).to_string()),
            SimpleDim::TlsSessionIdLen => Value::Num(tls.session_id_len as i64),

            SimpleDim::TlsCiphers => str_set(tls.cipher_suites.iter().map(|c| hex16(*c))),
            SimpleDim::TlsExtTypes => {
                str_set(tls.extensions.iter().map(|(t, _)| hex16(*t)))
            }
            SimpleDim::TlsGroups => str_set(tls.supported_groups.iter().map(|g| hex16(*g))),
            SimpleDim::TlsSigAlgs => str_set(tls.sig_algs.iter().map(|s| hex16(*s))),
            SimpleDim::TlsKeyShares => str_set(tls.key_share_groups.iter().map(|k| hex16(*k))),

            SimpleDim::TlsCipherOrder => str_list(tls.cipher_suites.iter().map(|c| hex16(*c))),
            SimpleDim::TlsExtOrder => str_list(tls.extensions.iter().map(|(t, _)| hex16(*t))),
            SimpleDim::TlsAlpn => str_list(tls.alpn.iter().cloned()),
            SimpleDim::TlsVersions => str_list(tls.supported_versions.iter().map(|v| tls_names::tls_version_name(*v).to_string())),
            SimpleDim::TlsPskModes => str_list(tls.psk_modes.iter().map(|m| tls_names::psk_mode_name(*m).to_string())),
            SimpleDim::TlsCompression => str_list(tls.compression_methods.iter().map(|m| hex8(*m))),

            SimpleDim::TlsExtensions => {
                Value::List(
                    tls.extensions.iter()
                        .map(|(t, _)| Value::pair(
                            Value::Str(hex16(*t)),
                            Value::Str(tls_names::extension_name(*t).to_string()),
                        ))
                        .collect()
                )
            }

            // HTTP dims return Nil when called against TLS-only context
            _ => Value::Nil,
        }
    }

    /// Extract the base value from a RequestSample.
    fn extract_req(&self, req: &RequestSample) -> Value {
        match self {
            SimpleDim::Method => Value::Str(req.method.clone()),
            SimpleDim::Path => Value::Str(req.path.clone()),
            SimpleDim::SrcIp => Value::Str(req.src_ip.to_string()),
            SimpleDim::BodyLen => Value::Num(req.body_len as i64),
            SimpleDim::Protocol => Value::Str(req.version.to_string()),

            SimpleDim::Headers => pair_list(
                req.headers.iter().map(|(k, v)| (k.clone(), v.clone()))
            ),
            SimpleDim::Cookies => pair_list(
                req.cookies.iter().map(|(k, v)| (k.clone(), v.clone()))
            ),
            SimpleDim::QueryParams => {
                Value::List(
                    req.query_parts().into_iter().filter_map(|part| match part {
                        QueryPart::Pair(k, v) => Some(Value::pair(Value::Str(k.to_string()), Value::Str(v.to_string()))),
                        QueryPart::Flag(name) => Some(Value::pair(Value::Str(name.to_string()), Value::Nil)),
                        QueryPart::Empty => None,
                    }).collect()
                )
            }
            SimpleDim::HeaderOrder => str_list(
                req.headers.iter().map(|(k, _)| k.clone())
            ),
            SimpleDim::PathParts => str_list(
                req.path.split('/').map(|s| s.to_string())
            ),
            SimpleDim::QueryFlags => str_list(
                req.query_parts().into_iter().filter_map(|part| match part {
                    QueryPart::Flag(name) => Some(name.to_string()),
                    _ => None,
                })
            ),
            SimpleDim::QueryRaw => match &req.query {
                Some(q) => Value::Str(q.clone()),
                None => Value::Nil,
            },

            // TLS dims delegate to the embedded context
            _ => self.extract_tls(&req.tls_ctx, Some(req.src_ip)),
        }
    }
}

impl Dimension {
    /// Extract a typed Value from a RequestSample.
    pub fn extract_from_request(&self, req: &RequestSample) -> Value {
        match self {
            Dimension::Simple(s) => s.extract_req(req),
            Dimension::Header(name) => {
                str_list(req.header(name).into_iter().map(|v| v.to_string()))
            }
            Dimension::Cookie(name) => {
                let name_lower = name.to_ascii_lowercase();
                str_list(
                    req.cookies.iter()
                        .filter(|(k, _)| k.to_ascii_lowercase() == name_lower)
                        .map(|(_, v)| v.clone())
                )
            }
            Dimension::Query(name) => {
                str_list(
                    req.query_parts().into_iter().filter_map(|part| match part {
                        QueryPart::Pair(k, v) if k == name => Some(v.to_string()),
                        _ => None,
                    })
                )
            }
            // Generic functions: recurse then transform
            Dimension::First(inner) => apply_first(inner.extract_from_request(req)),
            Dimension::Last(inner) => apply_last(inner.extract_from_request(req)),
            Dimension::Nth(inner, n) => apply_nth(inner.extract_from_request(req), *n),
            Dimension::Get(inner, key) => apply_get(inner.extract_from_request(req), key),
            Dimension::Key(inner) => apply_key(inner.extract_from_request(req)),
            Dimension::Val(inner) => apply_val(inner.extract_from_request(req)),
            Dimension::Count(inner) => apply_count(inner.extract_from_request(req)),
            Dimension::Keys(inner) => apply_keys(inner.extract_from_request(req)),
            Dimension::Vals(inner) => apply_vals(inner.extract_from_request(req)),
            Dimension::SetOf(inner) => apply_set(inner.extract_from_request(req)),
            Dimension::Lower(inner) => apply_lower(inner.extract_from_request(req)),
        }
    }

    /// Extract a typed Value from a TlsSample (TLS-only context).
    pub fn extract_from_tls(&self, sample: &TlsSample) -> Value {
        self.extract_from_tls_ctx(&sample.tls_ctx, Some(sample.src_ip))
    }

    /// Extract from raw TlsContext + optional IP.
    pub fn extract_from_tls_ctx(&self, tls: &TlsContext, src_ip: Option<IpAddr>) -> Value {
        match self {
            Dimension::Simple(s) => s.extract_tls(tls, src_ip),
            Dimension::Header(_) | Dimension::Cookie(_) | Dimension::Query(_) => Value::Nil,
            Dimension::First(inner) => apply_first(inner.extract_from_tls_ctx(tls, src_ip)),
            Dimension::Last(inner) => apply_last(inner.extract_from_tls_ctx(tls, src_ip)),
            Dimension::Nth(inner, n) => apply_nth(inner.extract_from_tls_ctx(tls, src_ip), *n),
            Dimension::Get(inner, key) => apply_get(inner.extract_from_tls_ctx(tls, src_ip), key),
            Dimension::Key(inner) => apply_key(inner.extract_from_tls_ctx(tls, src_ip)),
            Dimension::Val(inner) => apply_val(inner.extract_from_tls_ctx(tls, src_ip)),
            Dimension::Count(inner) => apply_count(inner.extract_from_tls_ctx(tls, src_ip)),
            Dimension::Keys(inner) => apply_keys(inner.extract_from_tls_ctx(tls, src_ip)),
            Dimension::Vals(inner) => apply_vals(inner.extract_from_tls_ctx(tls, src_ip)),
            Dimension::SetOf(inner) => apply_set(inner.extract_from_tls_ctx(tls, src_ip)),
            Dimension::Lower(inner) => apply_lower(inner.extract_from_tls_ctx(tls, src_ip)),
        }
    }
}

// ---------------------------------------------------------------------------
// Generic function implementations (Value → Value transforms)
// ---------------------------------------------------------------------------

fn apply_first(v: Value) -> Value {
    match v {
        Value::List(items) => items.into_iter().next().unwrap_or(Value::Nil),
        _ => Value::Nil,
    }
}

fn apply_last(v: Value) -> Value {
    match v {
        Value::List(items) => items.into_iter().last().unwrap_or(Value::Nil),
        _ => Value::Nil,
    }
}

fn apply_nth(v: Value, n: i32) -> Value {
    match v {
        Value::List(items) => {
            let idx = if n >= 0 {
                n as usize
            } else {
                let abs = (-n) as usize;
                if abs > items.len() { return Value::Nil; }
                items.len() - abs
            };
            items.into_iter().nth(idx).unwrap_or(Value::Nil)
        }
        _ => Value::Nil,
    }
}

fn apply_get(v: Value, key: &str) -> Value {
    match v {
        Value::List(items) => {
            for item in items {
                if let Value::Pair(k, val) = item {
                    if let Value::Str(ref s) = *k {
                        if s == key { return *val; }
                    }
                }
            }
            Value::Nil
        }
        _ => Value::Nil,
    }
}

fn apply_key(v: Value) -> Value {
    match v {
        Value::Pair(k, _) => *k,
        _ => Value::Nil,
    }
}

fn apply_val(v: Value) -> Value {
    match v {
        Value::Pair(_, v) => *v,
        _ => Value::Nil,
    }
}

fn apply_count(v: Value) -> Value {
    match v {
        Value::List(items) => Value::Num(items.len() as i64),
        Value::Set(items) => Value::Num(items.len() as i64),
        Value::Str(s) => Value::Num(s.chars().count() as i64),
        _ => Value::Num(0),
    }
}

fn apply_keys(v: Value) -> Value {
    match v {
        Value::List(items) => Value::List(
            items.into_iter().filter_map(|item| match item {
                Value::Pair(k, _) => Some(*k),
                _ => None,
            }).collect()
        ),
        _ => Value::Nil,
    }
}

fn apply_vals(v: Value) -> Value {
    match v {
        Value::List(items) => Value::List(
            items.into_iter().filter_map(|item| match item {
                Value::Pair(_, v) => Some(*v),
                _ => None,
            }).collect()
        ),
        _ => Value::Nil,
    }
}

fn apply_set(v: Value) -> Value {
    match v {
        Value::List(items) => {
            let mut set = BTreeSet::new();
            for item in items {
                if let Value::Str(s) = item {
                    set.insert(s);
                }
            }
            Value::Set(set)
        }
        _ => Value::Nil,
    }
}

fn apply_lower(v: Value) -> Value {
    match v {
        Value::Str(s) => Value::Str(s.to_ascii_lowercase()),
        _ => Value::Nil,
    }
}

// =============================================================================
// Expr evaluation — test a constraint against extracted data
// =============================================================================

impl Expr {
    /// Evaluate this expression against a RequestSample.
    pub fn matches_request(&self, req: &RequestSample) -> bool {
        let extracted = self.dim.extract_from_request(req);
        self.test(&extracted)
    }

    /// Evaluate this expression against a TlsSample.
    pub fn matches_tls(&self, sample: &TlsSample) -> bool {
        let extracted = self.dim.extract_from_tls(sample);
        self.test(&extracted)
    }

    /// Core matching logic: does the extracted value satisfy this expression?
    fn test(&self, extracted: &Value) -> bool {
        match &self.op {
            Operator::Eq => extracted == &self.value,
            Operator::Exists => match extracted {
                Value::List(items) => items.contains(&self.value),
                Value::Set(items) => {
                    if let Some(s) = self.value.as_str() { items.contains(s) } else { false }
                }
                _ => !extracted.is_nil(),
            },
            Operator::Gt => cmp_values(extracted, &self.value).map_or(false, |o| o == std::cmp::Ordering::Greater),
            Operator::Lt => cmp_values(extracted, &self.value).map_or(false, |o| o == std::cmp::Ordering::Less),
            Operator::Gte => cmp_values(extracted, &self.value).map_or(false, |o| o != std::cmp::Ordering::Less),
            Operator::Lte => cmp_values(extracted, &self.value).map_or(false, |o| o != std::cmp::Ordering::Greater),
            Operator::Prefix => match (extracted, &self.value) {
                (Value::Str(s), Value::Str(pfx)) => s.starts_with(pfx.as_str()),
                _ => false,
            },
            Operator::Suffix => match (extracted, &self.value) {
                (Value::Str(s), Value::Str(sfx)) => s.ends_with(sfx.as_str()),
                _ => false,
            },
            Operator::Contains => match (extracted, &self.value) {
                (Value::Str(s), Value::Str(sub)) => s.contains(sub.as_str()),
                _ => false,
            },
            Operator::Regex(pat) => match extracted {
                Value::Str(s) => regex::Regex::new(pat).map_or(false, |re| re.is_match(s)),
                _ => false,
            },
            Operator::Not => extracted.is_nil(),
            Operator::Subset => match (extracted, &self.value) {
                (Value::Set(a), Value::Set(b)) => a.is_subset(b),
                _ => false,
            },
            Operator::Superset => match (extracted, &self.value) {
                (Value::Set(a), Value::Set(b)) => a.is_superset(b),
                _ => false,
            },
        }
    }
}

fn cmp_values(a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
    match (a, b) {
        (Value::Num(a), Value::Num(b)) => Some(a.cmp(b)),
        (Value::Str(a), Value::Str(b)) => Some(a.cmp(b)),
        _ => None,
    }
}

// =============================================================================
// Operator — test predicates
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Operator {
    // Tier 1: tree-native
    Eq,
    Exists,

    // Tier 2: guard predicates
    Gt,
    Lt,
    Gte,
    Lte,
    Prefix,
    Suffix,
    Contains,
    Regex(String),
    Not,
    Subset,
    Superset,
}

impl Operator {
    pub fn name(&self) -> &str {
        match self {
            Operator::Eq => "=",
            Operator::Exists => "exists",
            Operator::Gt => ">",
            Operator::Lt => "<",
            Operator::Gte => ">=",
            Operator::Lte => "<=",
            Operator::Prefix => "prefix",
            Operator::Suffix => "suffix",
            Operator::Contains => "contains",
            Operator::Regex(_) => "regex",
            Operator::Not => "not",
            Operator::Subset => "subset",
            Operator::Superset => "superset",
        }
    }

    pub fn is_tier1(&self) -> bool {
        matches!(self, Operator::Eq | Operator::Exists)
    }
}

// =============================================================================
// MatchMode — how a tree node branches
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// Extract single value, children.get(canonical) — O(1).
    Exact,
    /// Extract collection, check each element against children — O(n).
    Membership,
}

// =============================================================================
// Expr — a single constraint expression
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Expr {
    pub op: Operator,
    pub dim: Dimension,
    pub value: Value,
}

impl Expr {
    pub fn new(op: Operator, dim: Dimension, value: Value) -> Self {
        Self { op, dim, value }
    }

    pub fn eq(dim: Dimension, value: Value) -> Self {
        Self { op: Operator::Eq, dim, value }
    }

    pub fn exists(dim: Dimension, value: Value) -> Self {
        Self { op: Operator::Exists, dim, value }
    }

    pub fn prefix(dim: Dimension, value: impl Into<String>) -> Self {
        Self { op: Operator::Prefix, dim, value: Value::Str(value.into()) }
    }

    /// Determine the match mode for this expression in the tree.
    pub fn match_mode(&self) -> MatchMode {
        match self.op {
            Operator::Exists => MatchMode::Membership,
            Operator::Eq => MatchMode::Exact,
            _ => MatchMode::Exact,
        }
    }

    /// Whether this expression can be a tree-native dimension (tier 1)
    /// or must be a guard predicate (tier 2).
    pub fn is_tier1(&self) -> bool { self.op.is_tier1() }

    /// Render as s-expression: `(= (first (header "host")) "example.com")`
    pub fn to_sexpr(&self) -> String {
        match &self.op {
            Operator::Regex(pat) => format!("(regex {} \"{}\")", self.dim.to_sexpr(), pat),
            Operator::Not => format!("(not {})", self.dim.to_sexpr()),
            _ => format!("({} {} {})", self.op.name(), self.dim.to_sexpr(), self.value),
        }
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_sexpr())
    }
}

// =============================================================================
// RuleExpr — a complete rule using the new expression language
// =============================================================================

use crate::types::RuleAction;

use crate::types::RuleName;

#[derive(Debug, Clone)]
pub struct RuleExpr {
    pub constraints: Vec<Expr>,
    pub action: RuleAction,
    pub priority: u8,
    pub comment: Option<String>,
    pub label: Option<(String, String)>,
}

impl RuleExpr {
    pub fn new(constraints: Vec<Expr>, action: RuleAction) -> Self {
        Self { constraints, action, priority: 100, comment: None, label: None }
    }

    pub fn identity_key(&self) -> String {
        let mut parts: Vec<String> = self.constraints.iter()
            .map(|e| e.to_sexpr())
            .collect();
        parts.sort();
        let label_suffix = self.label.as_ref()
            .map(|(ns, n)| format!("::label={}/{}", ns, n))
            .unwrap_or_default();
        format!("{}::{}{}", parts.join(","), self.action.describe(), label_suffix)
    }

    pub fn constraints_sexpr(&self) -> String {
        if self.constraints.is_empty() {
            "[]".to_string()
        } else {
            let clauses: Vec<String> = self.constraints.iter().map(|e| e.to_sexpr()).collect();
            format!("[{}]", clauses.join(" "))
        }
    }

    /// Classify which layers this rule's constraints span.
    pub fn layer_count(&self) -> (bool, bool) {
        let has_tls = self.constraints.iter().any(|e| e.dim.is_tls());
        let has_http = self.constraints.iter().any(|e| e.dim.is_http());
        (has_tls, has_http)
    }

    pub fn display_label(&self) -> String {
        if let Some((ns, n)) = self.action.name() {
            return format!("{}/{}", ns, n);
        }
        if let Some((ns, n)) = &self.label {
            return format!("{}/{}", ns, n);
        }
        let c: Vec<_> = self.constraints.iter().map(|e| e.to_sexpr()).collect();
        format!("[{}] → {}", c.join(" "), self.action.describe())
    }

    fn action_to_sexpr(action: &RuleAction) -> String {
        action.to_sexpr()
    }

    /// Alias for `to_edn()`.
    pub fn to_edn_compact(&self) -> String { self.to_edn() }

    fn optional_fields_edn(&self) -> String {
        let mut extra = String::new();
        if self.priority != 100 {
            extra.push_str(&format!(" :priority {}", self.priority));
        }
        if let Some(ref c) = self.comment {
            extra.push_str(&format!(" :comment \"{}\"", c));
        }
        if let Some((ref ns, ref n)) = self.label {
            extra.push_str(&format!(" :label [\"{}\" \"{}\"]", ns, n));
        }
        extra
    }

    /// Emit rule as EDN (compact, single-line).
    pub fn to_edn(&self) -> String {
        let constraints_str = self.constraints_sexpr();
        let action_str = Self::action_to_sexpr(&self.action);
        let extra = self.optional_fields_edn();
        format!("{{:constraints {} :actions [{}]{}}}", constraints_str, action_str, extra)
    }

    /// Emit rule as EDN (pretty, multi-line format for logs).
    pub fn to_edn_pretty(&self) -> String {
        let indent = "               ";
        let clauses: Vec<String> = self.constraints.iter().map(|e| e.to_sexpr()).collect();

        let constraints_str = if clauses.is_empty() {
            "[]".to_string()
        } else if clauses.len() == 1 {
            format!("[{}]", clauses[0])
        } else {
            let mut s = format!("[{}", clauses[0]);
            for clause in &clauses[1..] {
                s.push_str(&format!("\n{}{}", indent, clause));
            }
            s.push(']');
            s
        };

        let action_str = Self::action_to_sexpr(&self.action);
        let extra = self.optional_fields_edn();

        format!("{{:constraints {}\n :actions     [{}]{}}}", constraints_str, action_str, extra)
    }
}

// =============================================================================
// EDN Parser — parse rule EDN strings back into RuleExpr (using edn-rs)
// =============================================================================

use edn_rs::Edn;

pub fn parse_edn(input: &str) -> Result<RuleExpr, String> {
    let edn: Edn = input.parse().map_err(|e| format!("EDN parse error: {:?}", e))?;
    parse_rule_edn(&edn)
}

fn parse_rule_edn(edn: &Edn) -> Result<RuleExpr, String> {
    let constraints_edn = edn.get(":constraints")
        .ok_or("missing :constraints")?;
    let actions_edn = edn.get(":actions")
        .ok_or("missing :actions")?;
    let priority = edn.get(":priority")
        .map(|p| p.to_string().parse::<u8>().unwrap_or(100))
        .unwrap_or(100);

    let comment = edn.get(":comment")
        .map(|c| c.to_string().trim_matches('"').to_string());

    let label = edn.get(":label").and_then(|l| {
        let vec = edn_to_list(l).ok()?;
        if vec.len() == 2 {
            let ns = edn_to_string(&vec[0]).ok()?;
            let n = edn_to_string(&vec[1]).ok()?;
            Some((ns, n))
        } else {
            None
        }
    });

    let constraints = parse_constraints_edn(constraints_edn)?;
    let action = parse_actions_edn(actions_edn)?;
    let mut rule = RuleExpr::new(constraints, action);
    rule.priority = priority;
    rule.comment = comment;
    rule.label = label;
    Ok(rule)
}

fn parse_constraints_edn(edn: &Edn) -> Result<Vec<Expr>, String> {
    let vec = match edn {
        Edn::Vector(v) => v.clone().to_vec(),
        _ => return Err("constraints must be a vector".into()),
    };
    vec.iter().map(parse_expr_edn).collect()
}

fn parse_expr_edn(edn: &Edn) -> Result<Expr, String> {
    let list = edn_to_list(edn)?;
    if list.len() < 2 {
        return Err(format!("expression needs at least 2 elements, got {}", list.len()));
    }

    let op_name = edn_to_symbol(&list[0])?;
    match op_name.as_str() {
        "not" => {
            let dim = parse_dim_edn(&list[1])?;
            Ok(Expr::new(Operator::Not, dim, Value::Nil))
        }
        "regex" => {
            if list.len() < 3 { return Err("regex needs 3 elements".into()); }
            let dim = parse_dim_edn(&list[1])?;
            let pat = edn_to_string(&list[2])?;
            Ok(Expr::new(Operator::Regex(pat), dim, Value::Nil))
        }
        _ => {
            if list.len() < 3 { return Err(format!("'{}' needs 3 elements", op_name)); }
            let op = parse_operator_edn(&op_name)?;
            let dim = parse_dim_edn(&list[1])?;
            let value = edn_to_value(&list[2])?;
            Ok(Expr::new(op, dim, value))
        }
    }
}

fn parse_operator_edn(name: &str) -> Result<Operator, String> {
    match name {
        "=" => Ok(Operator::Eq),
        "exists" => Ok(Operator::Exists),
        ">" => Ok(Operator::Gt),
        "<" => Ok(Operator::Lt),
        ">=" => Ok(Operator::Gte),
        "<=" => Ok(Operator::Lte),
        "prefix" => Ok(Operator::Prefix),
        "suffix" => Ok(Operator::Suffix),
        "contains" => Ok(Operator::Contains),
        "subset" => Ok(Operator::Subset),
        "superset" => Ok(Operator::Superset),
        other => Err(format!("unknown operator '{}'", other)),
    }
}

fn parse_dim_edn(edn: &Edn) -> Result<Dimension, String> {
    match edn {
        Edn::Symbol(s) => parse_simple_dim_edn(s).map(Dimension::Simple),
        Edn::List(lst) => {
            let items = lst.clone().to_vec();
            if items.is_empty() { return Err("empty dimension expression".into()); }
            let func = edn_to_symbol(&items[0])?;
            match func.as_str() {
                "header" => Ok(Dimension::Header(edn_to_string(&items[1])?)),
                "cookie" => Ok(Dimension::Cookie(edn_to_string(&items[1])?)),
                "query" => Ok(Dimension::Query(edn_to_string(&items[1])?)),
                "first" => Ok(Dimension::First(Box::new(parse_dim_edn(&items[1])?))),
                "last" => Ok(Dimension::Last(Box::new(parse_dim_edn(&items[1])?))),
                "key" => Ok(Dimension::Key(Box::new(parse_dim_edn(&items[1])?))),
                "val" => Ok(Dimension::Val(Box::new(parse_dim_edn(&items[1])?))),
                "count" => Ok(Dimension::Count(Box::new(parse_dim_edn(&items[1])?))),
                "keys" => Ok(Dimension::Keys(Box::new(parse_dim_edn(&items[1])?))),
                "vals" => Ok(Dimension::Vals(Box::new(parse_dim_edn(&items[1])?))),
                "set" => Ok(Dimension::SetOf(Box::new(parse_dim_edn(&items[1])?))),
                "lower" => Ok(Dimension::Lower(Box::new(parse_dim_edn(&items[1])?))),
                "nth" => {
                    if items.len() < 3 { return Err("nth needs inner + index".into()); }
                    let inner = parse_dim_edn(&items[1])?;
                    let n = edn_to_i64(&items[2])? as i32;
                    Ok(Dimension::Nth(Box::new(inner), n))
                }
                "get" => {
                    if items.len() < 3 { return Err("get needs inner + key".into()); }
                    let inner = parse_dim_edn(&items[1])?;
                    let key = edn_to_string(&items[2])?;
                    Ok(Dimension::Get(Box::new(inner), key))
                }
                other => Err(format!("unknown function '{}'", other)),
            }
        }
        other => Err(format!("expected symbol or list for dimension, got {:?}", other)),
    }
}

fn parse_simple_dim_edn(name: &str) -> Result<SimpleDim, String> {
    match name {
        "method" => Ok(SimpleDim::Method),
        "path" => Ok(SimpleDim::Path),
        "src-ip" => Ok(SimpleDim::SrcIp),
        "body-len" => Ok(SimpleDim::BodyLen),
        "protocol" => Ok(SimpleDim::Protocol),
        "headers" => Ok(SimpleDim::Headers),
        "cookies" => Ok(SimpleDim::Cookies),
        "query-params" => Ok(SimpleDim::QueryParams),
        "header-order" => Ok(SimpleDim::HeaderOrder),
        "path-parts" => Ok(SimpleDim::PathParts),
        "query-flags" => Ok(SimpleDim::QueryFlags),
        "query-raw" => Ok(SimpleDim::QueryRaw),
        "tls-version" => Ok(SimpleDim::TlsVersion),
        "tls-record-version" => Ok(SimpleDim::TlsRecordVersion),
        "tls-session-id-len" => Ok(SimpleDim::TlsSessionIdLen),
        "sni" => Ok(SimpleDim::Sni),
        "tls-ciphers" => Ok(SimpleDim::TlsCiphers),
        "tls-ext-types" => Ok(SimpleDim::TlsExtTypes),
        "tls-groups" => Ok(SimpleDim::TlsGroups),
        "tls-sig-algs" => Ok(SimpleDim::TlsSigAlgs),
        "tls-key-shares" => Ok(SimpleDim::TlsKeyShares),
        "tls-cipher-order" => Ok(SimpleDim::TlsCipherOrder),
        "tls-ext-order" => Ok(SimpleDim::TlsExtOrder),
        "tls-alpn" => Ok(SimpleDim::TlsAlpn),
        "tls-versions" => Ok(SimpleDim::TlsVersions),
        "tls-psk-modes" => Ok(SimpleDim::TlsPskModes),
        "tls-compression" => Ok(SimpleDim::TlsCompression),
        "tls-extensions" => Ok(SimpleDim::TlsExtensions),
        other => Err(format!("unknown dimension '{}'", other)),
    }
}

fn edn_to_value(edn: &Edn) -> Result<Value, String> {
    match edn {
        Edn::Str(s) => Ok(Value::Str(s.clone())),
        Edn::Int(n) => Ok(Value::Num(*n)),
        Edn::UInt(n) => Ok(Value::Num(*n as i64)),
        Edn::Double(d) => {
            let f: f64 = d.to_string().parse().map_err(|e| format!("bad double: {}", e))?;
            Ok(Value::Num(f as i64))
        }
        Edn::Bool(b) => Ok(Value::Bool(*b)),
        Edn::Nil => Ok(Value::Nil),
        Edn::Vector(v) => {
            let items: Result<Vec<Value>, String> = v.clone().to_vec().iter()
                .map(edn_to_value)
                .collect();
            Ok(Value::List(items?))
        }
        Edn::Set(s) => {
            let mut set = BTreeSet::new();
            for item in s.clone().to_set() {
                set.insert(edn_element_to_string(&item));
            }
            Ok(Value::Set(set))
        }
        Edn::Symbol(s) => Ok(Value::Str(s.clone())),
        other => Err(format!("unsupported EDN value: {:?}", other)),
    }
}

fn edn_element_to_string(edn: &Edn) -> String {
    match edn {
        Edn::Str(s) => s.clone(),
        Edn::Symbol(s) => s.clone(),
        other => other.to_string().trim_matches('"').to_string(),
    }
}

fn parse_actions_edn(edn: &Edn) -> Result<RuleAction, String> {
    let vec = match edn {
        Edn::Vector(v) => v.clone().to_vec(),
        _ => return Err("actions must be a vector".into()),
    };
    if vec.is_empty() { return Err("actions vector is empty".into()); }
    parse_action_edn(&vec[0])
}

fn parse_action_name(list: &[Edn]) -> Result<RuleName, String> {
    for i in 0..list.len() {
        if let Ok(kw) = edn_to_symbol(&list[i]) {
            if kw == ":name" && i + 1 < list.len() {
                let vec = edn_to_list(&list[i + 1])?;
                if vec.len() != 2 {
                    return Err(":name must be a 2-element vector".into());
                }
                let ns = edn_to_string(&vec[0])?;
                let n = edn_to_string(&vec[1])?;
                return Ok(Some((ns, n)));
            }
        }
    }
    Ok(None)
}

fn parse_action_edn(edn: &Edn) -> Result<RuleAction, String> {
    let list = edn_to_list(edn)?;
    if list.is_empty() { return Err("action list is empty".into()); }
    let action_sym = edn_to_symbol(&list[0])?;
    let name = parse_action_name(&list)?;

    match action_sym.as_str() {
        "rate-limit" => {
            if list.len() < 2 { return Err("rate-limit needs rps".into()); }
            let rps = edn_to_i64(&list[1])? as u32;
            Ok(RuleAction::RateLimit { rps, name })
        }
        "block" => {
            if list.len() < 2 { return Err("block needs status".into()); }
            let status = edn_to_i64(&list[1])? as u16;
            Ok(RuleAction::Block { status, name })
        }
        "close-connection" => Ok(RuleAction::CloseConnection { name }),
        "count" => Ok(RuleAction::Count { name }),
        "pass" => Ok(RuleAction::Pass { name }),
        other => Err(format!("unknown action '{}'", other)),
    }
}

fn edn_to_list(edn: &Edn) -> Result<Vec<Edn>, String> {
    match edn {
        Edn::List(lst) => Ok(lst.clone().to_vec()),
        Edn::Vector(vec) => Ok(vec.clone().to_vec()),
        other => Err(format!("expected list/vector, got {:?}", other)),
    }
}

fn edn_to_symbol(edn: &Edn) -> Result<String, String> {
    match edn {
        Edn::Symbol(s) => Ok(s.clone()),
        Edn::Key(s) => Ok(s.clone()),
        other => Ok(other.to_string().trim_matches('"').to_string()),
    }
}

fn edn_to_string(edn: &Edn) -> Result<String, String> {
    match edn {
        Edn::Str(s) => Ok(s.clone()),
        Edn::Symbol(s) => Ok(s.clone()),
        other => Ok(other.to_string().trim_matches('"').to_string()),
    }
}

fn edn_to_i64(edn: &Edn) -> Result<i64, String> {
    match edn {
        Edn::Int(n) => Ok(*n),
        Edn::UInt(n) => Ok(*n as i64),
        Edn::Double(d) => {
            let f: f64 = d.to_string().parse().map_err(|_| format!("bad double: {}", d))?;
            Ok(f as i64)
        }
        other => {
            let s = other.to_string();
            s.parse::<i64>().map_err(|_| format!("expected number, got '{}'", s))
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use holon::kernel::{Encoder, VectorManager};

    fn make_encoder() -> Encoder {
        Encoder::new(VectorManager::new(4096))
    }

    fn sample_tls() -> TlsContext {
        TlsContext {
            record_version: 0x0301,
            handshake_version: 0x0303,
            session_id_len: 32,
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b],
            compression_methods: vec![0x00],
            extensions: vec![
                (0x0000, vec![0; 10]),
                (0x000a, vec![0; 6]),
                (0x000d, vec![0; 8]),
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

    fn sample_req() -> RequestSample {
        let tls = Arc::new(sample_tls());
        let enc = make_encoder();
        let vec = enc.encode_walkable(tls.as_ref());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let headers = vec![
            ("host".to_string(), "example.com".to_string()),
            ("user-agent".to_string(), "python-requests/2.31.0".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
            ("accept".to_string(), "text/html".to_string()),
            ("accept".to_string(), "application/json".to_string()),
        ];
        let mut req = crate::types::test_request_sample("POST", "/api/v1/auth/login", ip, headers, tls, vec);
        req.query = Some("page=1&sort=name&debug&page=2".to_string());
        req.cookies = vec![
            ("session".to_string(), "abc123".to_string()),
            ("theme".to_string(), "dark".to_string()),
        ];
        req.body_len = 256;
        req
    }

    // -----------------------------------------------------------------------
    // Value tests
    // -----------------------------------------------------------------------

    #[test]
    fn value_canonical_key_string() {
        assert_eq!(Value::str("hello").canonical_key(), "hello");
    }

    #[test]
    fn value_canonical_key_number() {
        assert_eq!(Value::num(42).canonical_key(), "42");
    }

    #[test]
    fn value_canonical_key_list() {
        let v = Value::list(vec![Value::str("a"), Value::str("b")]);
        assert_eq!(v.canonical_key(), "[a,b]");
    }

    #[test]
    fn value_canonical_key_set() {
        let v = Value::set_from_strs(vec!["b", "a", "c"]);
        assert_eq!(v.canonical_key(), "#{a,b,c}");
    }

    #[test]
    fn value_canonical_key_pair() {
        let v = Value::pair(Value::str("host"), Value::str("example.com"));
        assert_eq!(v.canonical_key(), "[host,example.com]");
    }

    #[test]
    fn value_display() {
        assert_eq!(Value::str("hello").to_string(), "\"hello\"");
        assert_eq!(Value::num(42).to_string(), "42");
        assert_eq!(Value::Bool(true).to_string(), "true");
        assert_eq!(Value::Nil.to_string(), "nil");
    }

    // -----------------------------------------------------------------------
    // Dimension type tests
    // -----------------------------------------------------------------------

    #[test]
    fn dimension_simple_layer_classification() {
        assert!(SimpleDim::TlsCiphers.is_tls());
        assert!(!SimpleDim::TlsCiphers.is_http());
        assert!(SimpleDim::Method.is_http());
        assert!(!SimpleDim::Method.is_tls());
    }

    #[test]
    fn dimension_composed_layer_classification() {
        let d = Dimension::header_first("host");
        assert!(d.is_http());
        assert!(!d.is_tls());

        let d = Dimension::First(Box::new(Dimension::Simple(SimpleDim::TlsAlpn)));
        assert!(d.is_tls());
        assert!(!d.is_http());
    }

    #[test]
    fn dimension_sexpr_simple() {
        assert_eq!(Dimension::method().to_sexpr(), "method");
        assert_eq!(Dimension::path().to_sexpr(), "path");
    }

    #[test]
    fn dimension_sexpr_parameterized() {
        assert_eq!(Dimension::header("host").to_sexpr(), "(header \"host\")");
        assert_eq!(Dimension::cookie("session").to_sexpr(), "(cookie \"session\")");
        assert_eq!(Dimension::query("page").to_sexpr(), "(query \"page\")");
    }

    #[test]
    fn dimension_sexpr_composed() {
        let d = Dimension::header_first("host");
        assert_eq!(d.to_sexpr(), "(first (header \"host\"))");

        let d = Dimension::Count(Box::new(Dimension::Simple(SimpleDim::Headers)));
        assert_eq!(d.to_sexpr(), "(count headers)");

        let d = Dimension::Key(Box::new(Dimension::Last(Box::new(
            Dimension::Simple(SimpleDim::QueryParams),
        ))));
        assert_eq!(d.to_sexpr(), "(key (last query-params))");

        let d = Dimension::Nth(Box::new(Dimension::Simple(SimpleDim::PathParts)), 2);
        assert_eq!(d.to_sexpr(), "(nth path-parts 2)");

        let d = Dimension::Nth(Box::new(Dimension::Simple(SimpleDim::QueryFlags)), -1);
        assert_eq!(d.to_sexpr(), "(nth query-flags -1)");

        let d = Dimension::Get(
            Box::new(Dimension::Simple(SimpleDim::TlsExtensions)),
            "alpn".to_string(),
        );
        assert_eq!(d.to_sexpr(), "(get tls-extensions \"alpn\")");
    }

    #[test]
    fn dimension_sexpr_deep_composition() {
        let d = Dimension::Count(Box::new(Dimension::Val(Box::new(
            Dimension::Last(Box::new(Dimension::Simple(SimpleDim::QueryParams))),
        ))));
        assert_eq!(d.to_sexpr(), "(count (val (last query-params)))");
    }

    #[test]
    fn dimension_equality_for_tree_sharing() {
        let d1 = Dimension::header_first("host");
        let d2 = Dimension::First(Box::new(Dimension::Header("host".to_string())));
        assert_eq!(d1, d2);
        assert_ne!(d1, Dimension::header_first("user-agent"));
    }

    // -----------------------------------------------------------------------
    // Extraction: HTTP scalar fields
    // -----------------------------------------------------------------------

    #[test]
    fn extract_method() {
        let req = sample_req();
        assert_eq!(Dimension::method().extract_from_request(&req), Value::str("POST"));
    }

    #[test]
    fn extract_path() {
        let req = sample_req();
        assert_eq!(Dimension::path().extract_from_request(&req), Value::str("/api/v1/auth/login"));
    }

    #[test]
    fn extract_src_ip() {
        let req = sample_req();
        assert_eq!(Dimension::src_ip().extract_from_request(&req), Value::str("10.0.0.1"));
    }

    #[test]
    fn extract_body_len() {
        let req = sample_req();
        assert_eq!(
            Dimension::Simple(SimpleDim::BodyLen).extract_from_request(&req),
            Value::Num(256),
        );
    }

    #[test]
    fn extract_protocol() {
        let req = sample_req();
        assert_eq!(
            Dimension::Simple(SimpleDim::Protocol).extract_from_request(&req),
            Value::str("HTTP/1.1"),
        );
    }

    // -----------------------------------------------------------------------
    // Extraction: HTTP collections
    // -----------------------------------------------------------------------

    #[test]
    fn extract_headers_pair_list() {
        let req = sample_req();
        let v = Dimension::Simple(SimpleDim::Headers).extract_from_request(&req);
        if let Value::List(items) = &v {
            assert_eq!(items.len(), 5);
            assert_eq!(items[0], Value::pair(Value::str("host"), Value::str("example.com")));
        } else {
            panic!("expected List, got {:?}", v);
        }
    }

    #[test]
    fn extract_header_by_name() {
        let req = sample_req();
        let v = Dimension::header("accept").extract_from_request(&req);
        assert_eq!(v, Value::list(vec![Value::str("text/html"), Value::str("application/json")]));
    }

    #[test]
    fn extract_header_first_composition() {
        let req = sample_req();
        let v = Dimension::header_first("host").extract_from_request(&req);
        assert_eq!(v, Value::str("example.com"));
    }

    #[test]
    fn extract_header_missing() {
        let req = sample_req();
        let v = Dimension::header("x-missing").extract_from_request(&req);
        assert_eq!(v, Value::list(vec![]));
    }

    #[test]
    fn extract_header_order() {
        let req = sample_req();
        let v = Dimension::Simple(SimpleDim::HeaderOrder).extract_from_request(&req);
        if let Value::List(items) = &v {
            assert_eq!(items[0], Value::str("host"));
            assert_eq!(items[1], Value::str("user-agent"));
        } else {
            panic!("expected List");
        }
    }

    #[test]
    fn extract_cookies_pair_list() {
        let req = sample_req();
        let v = Dimension::Simple(SimpleDim::Cookies).extract_from_request(&req);
        assert_eq!(v, Value::list(vec![
            Value::pair(Value::str("session"), Value::str("abc123")),
            Value::pair(Value::str("theme"), Value::str("dark")),
        ]));
    }

    #[test]
    fn extract_cookie_by_name() {
        let req = sample_req();
        let v = Dimension::cookie("session").extract_from_request(&req);
        assert_eq!(v, Value::list(vec![Value::str("abc123")]));
    }

    #[test]
    fn extract_cookie_first() {
        let req = sample_req();
        let v = Dimension::cookie_first("theme").extract_from_request(&req);
        assert_eq!(v, Value::str("dark"));
    }

    // -----------------------------------------------------------------------
    // Extraction: path parts
    // -----------------------------------------------------------------------

    #[test]
    fn extract_path_parts() {
        let req = sample_req();
        let v = Dimension::Simple(SimpleDim::PathParts).extract_from_request(&req);
        // "/api/v1/auth/login" → ["", "api", "v1", "auth", "login"]
        assert_eq!(v, Value::list(vec![
            Value::str(""), Value::str("api"), Value::str("v1"),
            Value::str("auth"), Value::str("login"),
        ]));
    }

    #[test]
    fn extract_path_parts_nth() {
        let req = sample_req();
        let d = Dimension::Nth(Box::new(Dimension::Simple(SimpleDim::PathParts)), 1);
        assert_eq!(d.extract_from_request(&req), Value::str("api"));
    }

    #[test]
    fn extract_path_parts_nth_negative() {
        let req = sample_req();
        let d = Dimension::Nth(Box::new(Dimension::Simple(SimpleDim::PathParts)), -1);
        assert_eq!(d.extract_from_request(&req), Value::str("login"));
    }

    // -----------------------------------------------------------------------
    // Extraction: query params
    // -----------------------------------------------------------------------

    #[test]
    fn extract_query_params_full() {
        let req = sample_req();
        // query = "page=1&sort=name&debug&page=2"
        let v = Dimension::Simple(SimpleDim::QueryParams).extract_from_request(&req);
        if let Value::List(items) = &v {
            assert_eq!(items.len(), 4);
            assert_eq!(items[0], Value::pair(Value::str("page"), Value::str("1")));
            assert_eq!(items[1], Value::pair(Value::str("sort"), Value::str("name")));
            assert_eq!(items[2], Value::pair(Value::str("debug"), Value::Nil));
            assert_eq!(items[3], Value::pair(Value::str("page"), Value::str("2")));
        } else {
            panic!("expected List");
        }
    }

    #[test]
    fn extract_query_by_name() {
        let req = sample_req();
        // "page" appears twice: page=1 and page=2
        let v = Dimension::query("page").extract_from_request(&req);
        assert_eq!(v, Value::list(vec![Value::str("1"), Value::str("2")]));
    }

    #[test]
    fn extract_query_first() {
        let req = sample_req();
        let v = Dimension::query_first("sort").extract_from_request(&req);
        assert_eq!(v, Value::str("name"));
    }

    #[test]
    fn extract_query_flags() {
        let req = sample_req();
        let v = Dimension::Simple(SimpleDim::QueryFlags).extract_from_request(&req);
        assert_eq!(v, Value::list(vec![Value::str("debug")]));
    }

    #[test]
    fn extract_query_raw() {
        let req = sample_req();
        let v = Dimension::Simple(SimpleDim::QueryRaw).extract_from_request(&req);
        assert_eq!(v, Value::str("page=1&sort=name&debug&page=2"));
    }

    // -----------------------------------------------------------------------
    // Extraction: TLS fields
    // -----------------------------------------------------------------------

    #[test]
    fn extract_tls_version() {
        let req = sample_req();
        let v = Dimension::Simple(SimpleDim::TlsVersion).extract_from_request(&req);
        // handshake_version 0x0303 = TLS 1.2
        if let Value::Str(s) = &v {
            assert!(s.contains("1.2"), "expected TLS 1.2 in '{}'", s);
        } else {
            panic!("expected Str");
        }
    }

    #[test]
    fn extract_tls_ciphers_set() {
        let req = sample_req();
        let v = Dimension::Simple(SimpleDim::TlsCiphers).extract_from_request(&req);
        if let Value::Set(items) = &v {
            assert!(items.contains("0x1301"));
            assert!(items.contains("0xc02b"));
            assert_eq!(items.len(), 5);
        } else {
            panic!("expected Set, got {:?}", v);
        }
    }

    #[test]
    fn extract_tls_cipher_order() {
        let req = sample_req();
        let v = Dimension::Simple(SimpleDim::TlsCipherOrder).extract_from_request(&req);
        if let Value::List(items) = &v {
            assert_eq!(items[0], Value::str("0x1301"));
            assert_eq!(items[4], Value::str("0xc02b"));
        } else {
            panic!("expected List");
        }
    }

    #[test]
    fn extract_tls_alpn() {
        let req = sample_req();
        let v = Dimension::Simple(SimpleDim::TlsAlpn).extract_from_request(&req);
        assert_eq!(v, Value::list(vec![Value::str("h2"), Value::str("http/1.1")]));
    }

    #[test]
    fn extract_tls_sni() {
        let req = sample_req();
        let v = Dimension::Simple(SimpleDim::Sni).extract_from_request(&req);
        assert_eq!(v, Value::str("example.com"));
    }

    #[test]
    fn extract_tls_session_id_len() {
        let req = sample_req();
        let v = Dimension::Simple(SimpleDim::TlsSessionIdLen).extract_from_request(&req);
        assert_eq!(v, Value::Num(32));
    }

    #[test]
    fn extract_tls_groups_set() {
        let req = sample_req();
        let v = Dimension::Simple(SimpleDim::TlsGroups).extract_from_request(&req);
        if let Value::Set(items) = &v {
            assert!(items.contains("0x001d"));
            assert!(items.contains("0x0017"));
            assert!(items.contains("0x0018"));
            assert_eq!(items.len(), 3);
        } else {
            panic!("expected Set");
        }
    }

    #[test]
    fn extract_tls_ext_types_set() {
        let req = sample_req();
        let v = Dimension::Simple(SimpleDim::TlsExtTypes).extract_from_request(&req);
        if let Value::Set(items) = &v {
            assert!(items.contains("0x0000"));
            assert!(items.contains("0x000a"));
            assert!(items.contains("0x000d"));
        } else {
            panic!("expected Set");
        }
    }

    #[test]
    fn extract_tls_from_tls_sample() {
        let tls = sample_tls();
        let sample = TlsSample {
            conn_id: 1,
            src_ip: "10.0.0.1".parse().unwrap(),
            tls_ctx: Arc::new(tls),
            tls_vec: make_encoder().encode_walkable(&TlsContext::default()),
            timestamp_us: 0,
        };
        let v = Dimension::Simple(SimpleDim::TlsCiphers).extract_from_tls(&sample);
        if let Value::Set(items) = &v {
            assert_eq!(items.len(), 5);
        } else {
            panic!("expected Set");
        }
    }

    // -----------------------------------------------------------------------
    // Generic function composition tests
    // -----------------------------------------------------------------------

    #[test]
    fn compose_first_alpn() {
        let req = sample_req();
        let d = Dimension::First(Box::new(Dimension::Simple(SimpleDim::TlsAlpn)));
        assert_eq!(d.extract_from_request(&req), Value::str("h2"));
    }

    #[test]
    fn compose_last_alpn() {
        let req = sample_req();
        let d = Dimension::Last(Box::new(Dimension::Simple(SimpleDim::TlsAlpn)));
        assert_eq!(d.extract_from_request(&req), Value::str("http/1.1"));
    }

    #[test]
    fn compose_count_headers() {
        let req = sample_req();
        let d = Dimension::Count(Box::new(Dimension::Simple(SimpleDim::Headers)));
        assert_eq!(d.extract_from_request(&req), Value::Num(5));
    }

    #[test]
    fn compose_count_string() {
        let req = sample_req();
        // count of method "POST" = 4 chars
        let d = Dimension::Count(Box::new(Dimension::method()));
        assert_eq!(d.extract_from_request(&req), Value::Num(4));
    }

    #[test]
    fn compose_keys_of_headers() {
        let req = sample_req();
        let d = Dimension::Keys(Box::new(Dimension::Simple(SimpleDim::Headers)));
        let v = d.extract_from_request(&req);
        if let Value::List(items) = &v {
            assert_eq!(items[0], Value::str("host"));
            assert_eq!(items.len(), 5);
        } else {
            panic!("expected List");
        }
    }

    #[test]
    fn compose_vals_of_cookies() {
        let req = sample_req();
        let d = Dimension::Vals(Box::new(Dimension::Simple(SimpleDim::Cookies)));
        assert_eq!(d.extract_from_request(&req), Value::list(vec![
            Value::str("abc123"), Value::str("dark"),
        ]));
    }

    #[test]
    fn compose_set_of_header_order() {
        let req = sample_req();
        let d = Dimension::SetOf(Box::new(Dimension::Simple(SimpleDim::HeaderOrder)));
        if let Value::Set(items) = d.extract_from_request(&req) {
            assert!(items.contains("host"));
            assert!(items.contains("accept"));
            assert_eq!(items.len(), 4); // deduped: host, user-agent, content-type, accept
        } else {
            panic!("expected Set");
        }
    }

    #[test]
    fn compose_lower() {
        let req = sample_req();
        let d = Dimension::Lower(Box::new(Dimension::header_first("user-agent")));
        assert_eq!(d.extract_from_request(&req), Value::str("python-requests/2.31.0"));
    }

    #[test]
    fn compose_get_on_pair_list() {
        let req = sample_req();
        // get "session" from cookies pair-list
        let d = Dimension::Get(
            Box::new(Dimension::Simple(SimpleDim::Cookies)),
            "session".to_string(),
        );
        assert_eq!(d.extract_from_request(&req), Value::str("abc123"));
    }

    #[test]
    fn compose_key_val_on_first_header() {
        let req = sample_req();
        let d_key = Dimension::Key(Box::new(Dimension::First(Box::new(
            Dimension::Simple(SimpleDim::Headers),
        ))));
        let d_val = Dimension::Val(Box::new(Dimension::First(Box::new(
            Dimension::Simple(SimpleDim::Headers),
        ))));
        assert_eq!(d_key.extract_from_request(&req), Value::str("host"));
        assert_eq!(d_val.extract_from_request(&req), Value::str("example.com"));
    }

    #[test]
    fn compose_deep_count_query_param_values() {
        let req = sample_req();
        // (count (query "page")) → 2 (page=1 and page=2)
        let d = Dimension::Count(Box::new(Dimension::query("page")));
        assert_eq!(d.extract_from_request(&req), Value::Num(2));
    }

    // -----------------------------------------------------------------------
    // Expr evaluation tests
    // -----------------------------------------------------------------------

    #[test]
    fn expr_eq_method_matches() {
        let req = sample_req();
        let e = Expr::eq(Dimension::method(), Value::str("POST"));
        assert!(e.matches_request(&req));
    }

    #[test]
    fn expr_eq_method_no_match() {
        let req = sample_req();
        let e = Expr::eq(Dimension::method(), Value::str("GET"));
        assert!(!e.matches_request(&req));
    }

    #[test]
    fn expr_eq_header_first_matches() {
        let req = sample_req();
        let e = Expr::eq(Dimension::header_first("host"), Value::str("example.com"));
        assert!(e.matches_request(&req));
    }

    #[test]
    fn expr_exists_alpn() {
        let req = sample_req();
        let e = Expr::exists(Dimension::Simple(SimpleDim::TlsAlpn), Value::str("h2"));
        assert!(e.matches_request(&req));
        let e2 = Expr::exists(Dimension::Simple(SimpleDim::TlsAlpn), Value::str("h3"));
        assert!(!e2.matches_request(&req));
    }

    #[test]
    fn expr_exists_in_set() {
        let req = sample_req();
        let e = Expr::exists(Dimension::Simple(SimpleDim::TlsCiphers), Value::str("0x1301"));
        assert!(e.matches_request(&req));
        let e2 = Expr::exists(Dimension::Simple(SimpleDim::TlsCiphers), Value::str("0x9999"));
        assert!(!e2.matches_request(&req));
    }

    #[test]
    fn expr_prefix_path() {
        let req = sample_req();
        let e = Expr::prefix(Dimension::path(), "/api/v1");
        assert!(e.matches_request(&req));
        let e2 = Expr::prefix(Dimension::path(), "/admin");
        assert!(!e2.matches_request(&req));
    }

    #[test]
    fn expr_gt_body_len() {
        let req = sample_req();
        let e = Expr::new(Operator::Gt, Dimension::Simple(SimpleDim::BodyLen), Value::Num(100));
        assert!(e.matches_request(&req));
        let e2 = Expr::new(Operator::Gt, Dimension::Simple(SimpleDim::BodyLen), Value::Num(300));
        assert!(!e2.matches_request(&req));
    }

    #[test]
    fn expr_contains_in_path() {
        let req = sample_req();
        let e = Expr::new(Operator::Contains, Dimension::path(), Value::str("auth"));
        assert!(e.matches_request(&req));
    }

    #[test]
    fn expr_eq_tls_ciphers_set() {
        let req = sample_req();
        let expected = Value::set_from_strs(vec![
            "0x1301", "0x1302", "0x1303", "0xc02b", "0xc02c",
        ]);
        let e = Expr::eq(Dimension::Simple(SimpleDim::TlsCiphers), expected);
        assert!(e.matches_request(&req));
    }

    #[test]
    fn expr_eq_count_headers() {
        let req = sample_req();
        let d = Dimension::Count(Box::new(Dimension::Simple(SimpleDim::Headers)));
        let e = Expr::eq(d, Value::Num(5));
        assert!(e.matches_request(&req));
    }

    #[test]
    fn expr_exists_query_flag() {
        let req = sample_req();
        let e = Expr::exists(Dimension::Simple(SimpleDim::QueryFlags), Value::str("debug"));
        assert!(e.matches_request(&req));
        let e2 = Expr::exists(Dimension::Simple(SimpleDim::QueryFlags), Value::str("verbose"));
        assert!(!e2.matches_request(&req));
    }

    // -----------------------------------------------------------------------
    // Expr s-expression rendering tests
    // -----------------------------------------------------------------------

    #[test]
    fn expr_sexpr_eq_simple() {
        let e = Expr::eq(Dimension::method(), Value::str("POST"));
        assert_eq!(e.to_sexpr(), "(= method \"POST\")");
    }

    #[test]
    fn expr_sexpr_eq_composed() {
        let e = Expr::eq(Dimension::header_first("host"), Value::str("example.com"));
        assert_eq!(e.to_sexpr(), "(= (first (header \"host\")) \"example.com\")");
    }

    #[test]
    fn expr_sexpr_exists() {
        let e = Expr::exists(Dimension::Simple(SimpleDim::TlsAlpn), Value::str("h2"));
        assert_eq!(e.to_sexpr(), "(exists tls-alpn \"h2\")");
    }

    #[test]
    fn expr_sexpr_set_equality() {
        let e = Expr::eq(
            Dimension::Simple(SimpleDim::TlsCiphers),
            Value::set_from_strs(vec!["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]),
        );
        let sexpr = e.to_sexpr();
        assert!(sexpr.starts_with("(= tls-ciphers #{"));
        assert!(sexpr.contains("TLS_AES_128_GCM_SHA256"));
    }

    #[test]
    fn expr_sexpr_prefix() {
        let e = Expr::prefix(Dimension::path(), "/api/v1");
        assert_eq!(e.to_sexpr(), "(prefix path \"/api/v1\")");
    }

    #[test]
    fn expr_match_mode() {
        assert_eq!(Expr::eq(Dimension::method(), Value::str("GET")).match_mode(), MatchMode::Exact);
        assert_eq!(
            Expr::exists(Dimension::Simple(SimpleDim::TlsAlpn), Value::str("h2")).match_mode(),
            MatchMode::Membership,
        );
    }

    #[test]
    fn expr_tier_classification() {
        assert!(Expr::eq(Dimension::method(), Value::str("GET")).is_tier1());
        assert!(Expr::exists(Dimension::Simple(SimpleDim::TlsAlpn), Value::str("h2")).is_tier1());
        assert!(!Expr::prefix(Dimension::path(), "/api").is_tier1());
    }

    // -----------------------------------------------------------------------
    // RuleExpr tests
    // -----------------------------------------------------------------------

    #[test]
    fn rule_expr_identity_key_stable() {
        let r1 = RuleExpr::new(
            vec![
                Expr::eq(Dimension::method(), Value::str("POST")),
                Expr::eq(Dimension::header_first("host"), Value::str("example.com")),
            ],
            RuleAction::Block { status: 403, name: None },
        );
        let r2 = RuleExpr::new(
            vec![
                Expr::eq(Dimension::header_first("host"), Value::str("example.com")),
                Expr::eq(Dimension::method(), Value::str("POST")),
            ],
            RuleAction::Block { status: 403, name: None },
        );
        assert_eq!(r1.identity_key(), r2.identity_key());
    }

    #[test]
    fn rule_expr_constraints_sexpr() {
        let r = RuleExpr::new(
            vec![
                Expr::eq(Dimension::method(), Value::str("POST")),
                Expr::exists(Dimension::Simple(SimpleDim::PathParts), Value::str("admin")),
            ],
            RuleAction::RateLimit { rps: 100, name: None },
        );
        let sexpr = r.constraints_sexpr();
        assert!(sexpr.contains("(= method \"POST\")"));
        assert!(sexpr.contains("(exists path-parts \"admin\")"));
    }

    #[test]
    fn rule_expr_layer_count() {
        let r = RuleExpr::new(
            vec![
                Expr::eq(Dimension::Simple(SimpleDim::TlsCiphers), Value::set_from_strs(vec!["a"])),
                Expr::eq(Dimension::method(), Value::str("POST")),
            ],
            RuleAction::Block { status: 403, name: None },
        );
        let (has_tls, has_http) = r.layer_count();
        assert!(has_tls);
        assert!(has_http);
    }

    // -----------------------------------------------------------------------
    // EDN rendering tests
    // -----------------------------------------------------------------------

    #[test]
    fn rule_expr_to_edn_compact() {
        let r = RuleExpr::new(
            vec![Expr::eq(Dimension::method(), Value::str("POST"))],
            RuleAction::RateLimit { rps: 100, name: None },
        );
        let edn = r.to_edn();
        assert!(edn.contains(":constraints"));
        assert!(edn.contains("(= method \"POST\")"));
        assert!(edn.contains("(rate-limit 100)"));
        assert!(!edn.contains(":priority"));
    }

    #[test]
    fn rule_expr_to_edn_with_priority() {
        let mut r = RuleExpr::new(
            vec![Expr::eq(Dimension::method(), Value::str("POST"))],
            RuleAction::block(),
        );
        r.priority = 50;
        let edn = r.to_edn();
        assert!(edn.contains(":priority 50"));
    }

    #[test]
    fn rule_expr_to_edn_pretty_single() {
        let r = RuleExpr::new(
            vec![Expr::eq(Dimension::method(), Value::str("POST"))],
            RuleAction::block(),
        );
        let pretty = r.to_edn_pretty();
        assert!(pretty.contains(":constraints [(= method \"POST\")]"));
        assert!(pretty.contains(":actions     [(block 403)]"));
    }

    #[test]
    fn rule_expr_to_edn_pretty_multi() {
        let r = RuleExpr::new(
            vec![
                Expr::eq(Dimension::method(), Value::str("POST")),
                Expr::eq(Dimension::header_first("host"), Value::str("example.com")),
            ],
            RuleAction::RateLimit { rps: 82, name: None },
        );
        let pretty = r.to_edn_pretty();
        assert!(pretty.contains("(= method \"POST\")"));
        assert!(pretty.contains("(= (first (header \"host\")) \"example.com\")"));
        assert!(pretty.contains("(rate-limit 82)"));
        assert!(pretty.contains('\n'));
    }

    #[test]
    fn rule_expr_display_label() {
        let r = RuleExpr::new(
            vec![
                Expr::eq(Dimension::method(), Value::str("POST")),
                Expr::eq(
                    Dimension::Simple(SimpleDim::TlsCiphers),
                    Value::set_from_strs(vec!["0x1301"]),
                ),
            ],
            RuleAction::block(),
        );
        let label = r.display_label();
        assert!(label.contains("(= method \"POST\")"));
        assert!(label.contains("block"));
    }

    #[test]
    fn rule_expr_to_edn_compact_alias() {
        let r = RuleExpr::new(
            vec![Expr::eq(Dimension::method(), Value::str("GET"))],
            RuleAction::pass(),
        );
        assert_eq!(r.to_edn(), r.to_edn_compact());
    }

    #[test]
    fn rule_expr_to_edn_all_actions() {
        let actions = vec![
            (RuleAction::block(), "block"),
            (RuleAction::RateLimit { rps: 50, name: None }, "rate-limit"),
            (RuleAction::CloseConnection { name: None }, "close-connection"),
            (RuleAction::count(), "count"),
            (RuleAction::pass(), "pass"),
        ];
        for (action, expected) in actions {
            let r = RuleExpr::new(vec![], action);
            assert!(r.to_edn().contains(expected), "expected '{}' in '{}'", expected, r.to_edn());
        }
    }

    // -----------------------------------------------------------------
    // EDN parser tests
    // -----------------------------------------------------------------

    #[test]
    fn parse_simple_eq_method() {
        let edn = r#"{:constraints [(= method "POST")] :actions [(rate-limit 100)]}"#;
        let rule = parse_edn(edn).unwrap();
        assert_eq!(rule.constraints.len(), 1);
        assert_eq!(rule.constraints[0].op, Operator::Eq);
        assert_eq!(rule.constraints[0].dim, Dimension::Simple(SimpleDim::Method));
        assert_eq!(rule.constraints[0].value, Value::str("POST"));
        assert!(matches!(rule.action, RuleAction::RateLimit { rps: 100, .. }));
    }

    #[test]
    fn parse_set_value() {
        let edn = r#"{:constraints [(= tls-ext-types #{"0x0000" "0x000a" "0x000d"})] :actions [(close-connection)]}"#;
        let rule = parse_edn(edn).unwrap();
        let set = rule.constraints[0].value.as_set().unwrap();
        assert_eq!(set.len(), 3);
        assert!(set.contains("0x0000"));
        assert!(set.contains("0x000a"));
        assert!(set.contains("0x000d"));
        assert!(matches!(rule.action, RuleAction::CloseConnection { .. }));
    }

    #[test]
    fn parse_set_with_quoted_elements() {
        let edn = r#"{:constraints [(= tls-ciphers #{"0x1301" "0x1302"})]:actions [(rate-limit 50)]}"#;
        let rule = parse_edn(edn).unwrap();
        let set = rule.constraints[0].value.as_set().unwrap();
        assert!(set.contains("0x1301"));
        assert!(set.contains("0x1302"));
    }

    #[test]
    fn parse_composed_dimension_first_header() {
        let edn = r#"{:constraints [(= (first (header "host")) "example.com")] :actions [(block 403)]}"#;
        let rule = parse_edn(edn).unwrap();
        assert_eq!(rule.constraints[0].dim, Dimension::header_first("host"));
        assert!(matches!(rule.action, RuleAction::Block { status: 403, .. }));
    }

    #[test]
    fn parse_nested_composition() {
        let edn = r#"{:constraints [(= (lower (first (header "x-custom"))) "value")] :actions [(pass)]}"#;
        let rule = parse_edn(edn).unwrap();
        let expected = Dimension::Lower(Box::new(
            Dimension::First(Box::new(Dimension::Header("x-custom".into())))
        ));
        assert_eq!(rule.constraints[0].dim, expected);
        assert!(matches!(rule.action, RuleAction::Pass { .. }));
    }

    #[test]
    fn parse_exists_operator() {
        let edn = r#"{:constraints [(exists path-parts "admin")] :actions [(block 403)]}"#;
        let rule = parse_edn(edn).unwrap();
        assert_eq!(rule.constraints[0].op, Operator::Exists);
        assert_eq!(rule.constraints[0].value, Value::str("admin"));
    }

    #[test]
    fn parse_prefix_operator() {
        let edn = r#"{:constraints [(prefix path "/api/v1")] :actions [(rate-limit 200)]}"#;
        let rule = parse_edn(edn).unwrap();
        assert_eq!(rule.constraints[0].op, Operator::Prefix);
        assert_eq!(rule.constraints[0].value, Value::str("/api/v1"));
    }

    #[test]
    fn parse_numeric_value() {
        let edn = r#"{:constraints [(> body-len 1024)] :actions [(block 413)]}"#;
        let rule = parse_edn(edn).unwrap();
        assert_eq!(rule.constraints[0].op, Operator::Gt);
        assert_eq!(rule.constraints[0].value, Value::Num(1024));
    }

    #[test]
    fn parse_list_value() {
        let edn = r#"{:constraints [(= header-order ["host" "user-agent" "accept"])] :actions [(rate-limit 50)]}"#;
        let rule = parse_edn(edn).unwrap();
        let list = rule.constraints[0].value.as_list().unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0], Value::str("host"));
    }

    #[test]
    fn parse_priority() {
        let edn = r#"{:constraints [(= method "GET")] :actions [(pass)] :priority 50}"#;
        let rule = parse_edn(edn).unwrap();
        assert_eq!(rule.priority, 50);
    }

    #[test]
    fn parse_count_action() {
        let edn = r#"{:constraints [(= method "GET")] :actions [(count "test-label")]}"#;
        let rule = parse_edn(edn).unwrap();
        assert!(matches!(rule.action, RuleAction::Count { .. }));
    }

    #[test]
    fn parse_multiple_constraints() {
        let edn = r#"{:constraints [(= tls-ext-types #{"0x0000" "0x000a"}) (= method "POST") (= (first (header "content-type")) "application/json")] :actions [(rate-limit 83)]}"#;
        let rule = parse_edn(edn).unwrap();
        assert_eq!(rule.constraints.len(), 3);
        assert_eq!(rule.constraints[0].dim, Dimension::Simple(SimpleDim::TlsExtTypes));
        assert_eq!(rule.constraints[1].dim, Dimension::Simple(SimpleDim::Method));
        assert_eq!(rule.constraints[2].dim, Dimension::header_first("content-type"));
    }

    #[test]
    fn parse_nth_dimension() {
        let edn = r#"{:constraints [(= (nth path-parts 2) "users")] :actions [(rate-limit 100)]}"#;
        let rule = parse_edn(edn).unwrap();
        assert_eq!(rule.constraints[0].dim, Dimension::Nth(Box::new(Dimension::Simple(SimpleDim::PathParts)), 2));
    }

    #[test]
    fn parse_get_dimension() {
        let edn = r#"{:constraints [(= (get headers "host") "example.com")] :actions [(pass)]}"#;
        let rule = parse_edn(edn).unwrap();
        assert_eq!(rule.constraints[0].dim, Dimension::Get(Box::new(Dimension::Simple(SimpleDim::Headers)), "host".into()));
    }

    #[test]
    fn parse_regex_operator() {
        let edn = r#"{:constraints [(regex path "^/api/v[0-9]+")] :actions [(rate-limit 50)]}"#;
        let rule = parse_edn(edn).unwrap();
        assert!(matches!(rule.constraints[0].op, Operator::Regex(ref p) if p == "^/api/v[0-9]+"));
    }

    #[test]
    fn parse_not_operator() {
        let edn = r#"{:constraints [(not sni)] :actions [(close-connection)]}"#;
        let rule = parse_edn(edn).unwrap();
        assert_eq!(rule.constraints[0].op, Operator::Not);
        assert_eq!(rule.constraints[0].dim, Dimension::Simple(SimpleDim::Sni));
    }

    /// Roundtrip: build → to_edn → parse → to_edn. Both EDN strings match.
    #[test]
    fn roundtrip_simple_rule() {
        let original = RuleExpr::new(
            vec![Expr::eq(Dimension::method(), Value::str("POST"))],
            RuleAction::RateLimit { rps: 100, name: None },
        );
        let edn = original.to_edn();
        let parsed = parse_edn(&edn).unwrap();
        assert_eq!(parsed.to_edn(), edn);
    }

    #[test]
    fn roundtrip_composed_tls_http() {
        let original = RuleExpr::new(vec![
            Expr::eq(
                Dimension::Simple(SimpleDim::TlsExtTypes),
                Value::set_from_strs(vec!["0x0000", "0x000a", "0x000d"]),
            ),
            Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
            Expr::eq(Dimension::method(), Value::str("POST")),
        ], RuleAction::RateLimit { rps: 83, name: None });
        let edn = original.to_edn();
        let parsed = parse_edn(&edn).unwrap();
        assert_eq!(parsed.to_edn(), edn);
    }

    #[test]
    fn roundtrip_with_priority() {
        let mut original = RuleExpr::new(
            vec![Expr::eq(Dimension::path(), Value::str("/admin"))],
            RuleAction::block(),
        );
        original.priority = 10;
        let edn = original.to_edn();
        let parsed = parse_edn(&edn).unwrap();
        assert_eq!(parsed.priority, 10);
        assert_eq!(parsed.to_edn(), edn);
    }

    #[test]
    fn roundtrip_pretty_format() {
        let original = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes),
                Value::set_from_strs(vec!["0x0000", "0x000a"]),
            ),
            Expr::eq(Dimension::method(), Value::str("POST")),
        ], RuleAction::RateLimit { rps: 83, name: None });
        let pretty = original.to_edn_pretty();
        let parsed = parse_edn(&pretty).unwrap();
        assert_eq!(parsed.to_edn(), original.to_edn());
    }

    #[test]
    fn roundtrip_all_actions() {
        let actions = vec![
            RuleAction::block(),
            RuleAction::RateLimit { rps: 50, name: None },
            RuleAction::CloseConnection { name: None },
            RuleAction::count(),
            RuleAction::pass(),
        ];
        for action in actions {
            let original = RuleExpr::new(
                vec![Expr::eq(Dimension::method(), Value::str("GET"))],
                action,
            );
            let edn = original.to_edn();
            let parsed = parse_edn(&edn).unwrap();
            assert_eq!(parsed.to_edn(), edn, "roundtrip failed for: {}", edn);
        }
    }

    #[test]
    fn parse_error_unknown_dim() {
        let edn = r#"{:constraints [(= banana "yes")] :actions [(pass)]}"#;
        assert!(parse_edn(edn).is_err());
    }

    #[test]
    fn parse_error_missing_actions() {
        let edn = r#"{:constraints [(= method "GET")]}"#;
        assert!(parse_edn(edn).is_err());
    }

    #[test]
    fn parse_error_unterminated_string() {
        let edn = r#"{:constraints [(= method "GET)] :actions [(pass)]}"#;
        assert!(parse_edn(edn).is_err());
    }
}
