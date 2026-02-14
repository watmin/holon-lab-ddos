//! Veth Filter - Userspace loader and rule management
//!
//! Loads the XDP filter and provides an API for:
//! - Managing drop/rate-limit rules via bitmask Rete engine
//! - Reading statistics
//! - Receiving packet samples via ring buffer

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap, MapData, PerCpuArray, PerCpuValues, AsyncPerfEventArray, ProgramArray},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use holon::{ScalarValue, WalkType, Walkable, WalkableRef, WalkableValue, ScalarRef};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

pub mod tree;

// =============================================================================
// Legacy Rule Types (kept for backward compatibility)
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum RuleType {
    SrcIp = 0,
    DstIp = 1,
    SrcPort = 2,
    DstPort = 3,
    Protocol = 4,
}

/// Action to take when a rule matches.
/// Note: The repr(u8) discriminants are used in eBPF for simple actions.
/// Complex actions (with names) are handled at compile time in userspace.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RuleAction {
    Pass,
    Drop,
    RateLimit { pps: u32, name: Option<(String, String)> },  // name: (namespace, name)
    Count { name: Option<(String, String)> },
}

impl RuleAction {
    /// Get the action type as a u8 for eBPF (matches ACT_* constants)
    pub fn action_type(&self) -> u8 {
        match self {
            RuleAction::Pass => ACT_PASS,
            RuleAction::Drop => ACT_DROP,
            RuleAction::RateLimit { .. } => ACT_RATE_LIMIT,
            RuleAction::Count { .. } => ACT_COUNT,
        }
    }

    /// Get PPS for rate limit actions, None for others
    pub fn rate_pps(&self) -> Option<u32> {
        match self {
            RuleAction::RateLimit { pps, .. } => Some(*pps),
            _ => None,
        }
    }

    /// Get the name tuple (namespace, name) if this action has one
    pub fn name(&self) -> Option<&(String, String)> {
        match self {
            RuleAction::RateLimit { name, .. } | RuleAction::Count { name } => {
                name.as_ref()
            }
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleKey {
    pub rule_type: u8,
    pub _pad: [u8; 3],
    pub value: u32,
}

unsafe impl aya::Pod for RuleKey {}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RuleValue {
    pub action: u8,
    pub _pad: [u8; 3],
    pub rate_pps: u32,
    pub tokens: u32,
    pub last_update_ns: u64,
    pub match_count: u64,
}

unsafe impl aya::Pod for RuleValue {}

// =============================================================================
// Bitmask Rete Engine Types
// =============================================================================

/// Dispatch dimension identifiers (must match eBPF DONT_CARE array indices)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum FieldDim {
    // Phase 1
    Proto = 0,
    SrcIp = 1,
    DstIp = 2,
    L4Word0 = 3,   // src_port or icmp type/code
    L4Word1 = 4,   // dst_port or icmp checksum
    // Phase 2
    TcpFlags = 5,
    Ttl = 6,
    DfBit = 7,
    TcpWindow = 8,
}

impl FieldDim {
    /// Map name for this dimension's dispatch map
    pub fn map_name(&self) -> &'static str {
        match self {
            FieldDim::Proto => "DISPATCH_PROTO",
            FieldDim::SrcIp => "DISPATCH_SRC_IP",
            FieldDim::DstIp => "DISPATCH_DST_IP",
            FieldDim::L4Word0 => "DISPATCH_L4W0",
            FieldDim::L4Word1 => "DISPATCH_L4W1",
            FieldDim::TcpFlags => "DISPATCH_TCP_FLAGS",
            FieldDim::Ttl => "DISPATCH_TTL",
            FieldDim::DfBit => "DISPATCH_DF",
            FieldDim::TcpWindow => "DISPATCH_TCP_WIN",
        }
    }

    /// Whether this is a Phase 2 dimension
    pub fn is_phase2(&self) -> bool {
        (*self as u8) >= 5
    }

    /// Human-readable name for display
    pub fn display_name(&self) -> &'static str {
        match self {
            FieldDim::Proto => "proto",
            FieldDim::SrcIp => "src_ip",
            FieldDim::DstIp => "dst_ip",
            FieldDim::L4Word0 => "src_port",
            FieldDim::L4Word1 => "dst_port",
            FieldDim::TcpFlags => "tcp_flags",
            FieldDim::Ttl => "ttl",
            FieldDim::DfBit => "df_bit",
            FieldDim::TcpWindow => "tcp_window",
        }
    }

    /// All dimensions
    pub fn all() -> &'static [FieldDim] {
        &[
            FieldDim::Proto, FieldDim::SrcIp, FieldDim::DstIp,
            FieldDim::L4Word0, FieldDim::L4Word1,
            FieldDim::TcpFlags, FieldDim::Ttl, FieldDim::DfBit, FieldDim::TcpWindow,
        ]
    }

    /// Format a value for this dimension as human-readable string
    pub fn format_value(&self, value: u32) -> String {
        match self {
            FieldDim::SrcIp | FieldDim::DstIp => {
                let bytes = value.to_ne_bytes();
                format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
            }
            FieldDim::Proto => match value {
                1 => "ICMP".to_string(),
                6 => "TCP".to_string(),
                17 => "UDP".to_string(),
                v => format!("{}", v),
            },
            FieldDim::TcpFlags => format!("0x{:02x}", value),
            FieldDim::DfBit => if value == 1 { "DF".to_string() } else { "!DF".to_string() },
            _ => format!("{}", value),
        }
    }

    /// S-expression field name (kebab-case, Lisp style)
    pub fn sexpr_name(&self) -> &'static str {
        match self {
            FieldDim::Proto => "proto",
            FieldDim::SrcIp => "src-addr",
            FieldDim::DstIp => "dst-addr",
            FieldDim::L4Word0 => "src-port",
            FieldDim::L4Word1 => "dst-port",
            FieldDim::TcpFlags => "tcp-flags",
            FieldDim::Ttl => "ttl",
            FieldDim::DfBit => "df",
            FieldDim::TcpWindow => "tcp-window",
        }
    }

    /// Format a value as an s-expression atom — raw numbers everywhere,
    /// IPs as dotted notation (the only non-numeric field).
    pub fn sexpr_value(&self, value: u32) -> String {
        match self {
            FieldDim::SrcIp | FieldDim::DstIp => {
                let bytes = value.to_ne_bytes();
                format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
            }
            _ => format!("{}", value),
        }
    }
}

// =============================================================================
// Field Reference and Predicate Types (extensible rule language foundation)
// =============================================================================

/// What field a predicate operates on.
/// `Dim` covers parsed header fields (proto, src_ip, dst_port, ttl, etc.).
/// Future variants (ByteAt, PktLen, Dscp, ...) extend matching without
/// changing `Predicate` or tree structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FieldRef {
    /// A parsed packet header field
    Dim(FieldDim),
    // Future:
    // ByteAt { offset: u16, len: u8 },
    // PktLen,
    // Dscp,
}

/// A matching predicate for a single field constraint.
/// Only `Eq` is implemented now; the enum is designed for extension
/// (ranges, bitmask, negation, disjunction) without refactoring.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Predicate {
    /// Exact equality: field == value
    Eq(FieldRef, u32),
    /// Set membership: field in [val1, val2, ...]
    In(FieldRef, Vec<u32>),
    // Future:
    // Gt(FieldRef, u32),
    // Lt(FieldRef, u32),
    // Gte(FieldRef, u32),
    // Lte(FieldRef, u32),
    // Mask(FieldRef, u32),
    // Not(Box<Predicate>),
    // Or(Vec<Predicate>),
}

impl Predicate {
    /// Convenience: create an Eq predicate on a parsed header field.
    pub fn eq(dim: FieldDim, value: u32) -> Self {
        Predicate::Eq(FieldRef::Dim(dim), value)
    }

    /// Extract (FieldDim, value) if this is an Eq on a Dim ref.
    /// Returns `None` for In and future predicate variants.
    pub fn as_eq_dim(&self) -> Option<(FieldDim, u32)> {
        match self {
            Predicate::Eq(FieldRef::Dim(dim), value) => Some((*dim, *value)),
            Predicate::In(_, _) => None,
        }
    }

    /// Get the field dimension this predicate tests (works for Eq and In)
    pub fn field_dim(&self) -> Option<FieldDim> {
        match self {
            Predicate::Eq(FieldRef::Dim(dim), _) | Predicate::In(FieldRef::Dim(dim), _) => Some(*dim),
        }
    }

    /// Render this predicate as an s-expression clause.
    pub fn to_sexpr_clause(&self) -> String {
        match self {
            Predicate::Eq(FieldRef::Dim(dim), value) => {
                format!("(= {} {})", dim.sexpr_name(), dim.sexpr_value(*value))
            }
            Predicate::In(FieldRef::Dim(dim), values) => {
                let vals: Vec<String> = values.iter()
                    .map(|v| dim.sexpr_value(*v))
                    .collect();
                format!("(in {} {})", dim.sexpr_name(), vals.join(" "))
            }
        }
    }
}

/// Total number of dispatch dimensions
pub const NUM_DIMENSIONS: usize = 9;

/// Maximum number of concurrent rules (u64 bitmask)
pub const MAX_RULES: usize = 64;

/// Rule metadata (must match eBPF RuleMeta struct)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RuleMeta {
    pub action: u8,
    pub _pad: [u8; 3],
    pub rate_pps: u32,
}

unsafe impl aya::Pod for RuleMeta {}

/// Token bucket state (must match eBPF struct)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TokenBucket {
    pub rate_pps: u32,
    pub tokens: u32,
    pub last_update_ns: u64,
    pub allowed_count: u64,
    pub dropped_count: u64,
}

unsafe impl aya::Pod for TokenBucket {}

// =============================================================================
// Tree Rete Engine Types (must match eBPF structs exactly)
// =============================================================================

/// Blue/green slot size: max nodes per slot
/// 2.5M per slot × 2 slots = 5M total TREE_NODES capacity.
/// Supports ~1M rules at ~2 nodes/rule with headroom for Holon additions.
pub const TREE_SLOT_SIZE: u32 = 2_500_000;

/// Sentinel: dimension value meaning "this is a leaf node"
pub const DIM_LEAF: u8 = 0xFF;

/// Action constants (must match eBPF)
pub const ACT_PASS: u8 = 0;
pub const ACT_DROP: u8 = 1;
pub const ACT_RATE_LIMIT: u8 = 2;
pub const ACT_COUNT: u8 = 3;

/// Node in the decision tree (must match eBPF TreeNode exactly).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TreeNode {
    pub dimension: u8,
    pub has_action: u8,
    pub action: u8,
    pub priority: u8,
    pub rate_pps: u32,
    pub wildcard_child: u32,
    pub rule_id: u32,
}

unsafe impl aya::Pod for TreeNode {}

impl Default for TreeNode {
    fn default() -> Self {
        Self {
            dimension: DIM_LEAF,
            has_action: 0,
            action: ACT_PASS,
            priority: 0,
            rate_pps: 0,
            wildcard_child: 0,
            rule_id: 0,
        }
    }
}

/// Edge key: (parent_node_id, field_value) -> child_node_id.
/// Must match eBPF EdgeKey exactly.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EdgeKey {
    pub parent: u32,
    pub value: u32,
}

unsafe impl aya::Pod for EdgeKey {}

/// A rule specification: set of constraints + actions.
/// Each constraint is a `Predicate` (currently only `Eq`).
/// Unconstrained dimensions get dont_care bits set (bitmask rete) or wildcard (tree rete).
#[derive(Debug, Clone)]
pub struct RuleSpec {
    /// Constraints: each predicate must match for the rule to fire.
    pub constraints: Vec<Predicate>,
    /// Actions to take when all constraints match (typically one, but supports multiple)
    pub actions: Vec<RuleAction>,
    /// Priority (0-255, higher = more important). Default 100.
    pub priority: u8,
    /// Optional comment for documentation (max 256 chars)
    pub comment: Option<String>,
    /// Optional label for metrics: [namespace, name] (each max 64 chars)
    pub label: Option<(String, String)>,
}

impl RuleSpec {
    /// Create a simple single-field drop rule
    pub fn drop_field(dim: FieldDim, value: u32) -> Self {
        Self { 
            constraints: vec![Predicate::eq(dim, value)], 
            actions: vec![RuleAction::Drop], 
            priority: 100,
            comment: None,
            label: None,
        }
    }

    /// Create a simple single-field rate limit rule
    pub fn rate_limit_field(dim: FieldDim, value: u32, pps: u32) -> Self {
        Self { 
            constraints: vec![Predicate::eq(dim, value)], 
            actions: vec![RuleAction::RateLimit { pps, name: None }], 
            priority: 100,
            comment: None,
            label: None,
        }
    }

    /// Create a compound rule with multiple constraints (all must match)
    pub fn compound(constraints: Vec<Predicate>, action: RuleAction) -> Self {
        Self { constraints, actions: vec![action], priority: 100, comment: None, label: None }
    }

    /// Create a rule with explicit priority
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Create a rule with a comment
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        let mut comment = comment.into();
        // Truncate to 256 chars
        if comment.len() > 256 {
            comment.truncate(256);
        }
        self.comment = Some(comment);
        self
    }

    /// Create a rule with a label for metrics (namespace, name)
    pub fn with_label(mut self, namespace: impl Into<String>, name: impl Into<String>) -> Self {
        let mut ns = namespace.into();
        let mut nm = name.into();
        // Truncate to 64 chars each
        if ns.len() > 64 {
            ns.truncate(64);
        }
        if nm.len() > 64 {
            nm.truncate(64);
        }
        self.label = Some((ns, nm));
        self
    }

    /// Compute a stable canonical hash for this rule (for deduplication and rate state keying).
    /// Includes sorted constraints, all actions (sorted), and priority.
    pub fn canonical_hash(&self) -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        
        // Sort constraints for canonical ordering
        // Build a representation that includes dim + predicate type + values
        let mut sorted_parts: Vec<String> = Vec::new();
        for pred in &self.constraints {
            match pred {
                Predicate::Eq(FieldRef::Dim(dim), val) => {
                    sorted_parts.push(format!("eq-{}-{}", *dim as u8, val));
                }
                Predicate::In(FieldRef::Dim(dim), vals) => {
                    let mut sorted_vals = vals.clone();
                    sorted_vals.sort();
                    let vals_str = sorted_vals.iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    sorted_parts.push(format!("in-{}-{}", *dim as u8, vals_str));
                }
            }
        }
        sorted_parts.sort();
        for part in &sorted_parts {
            part.hash(&mut hasher);
        }
        
        // Hash all actions (sorted by type first, then by fields)
        let mut action_strs: Vec<String> = self.actions.iter().map(|a| {
            match a {
                RuleAction::Pass => "pass".to_string(),
                RuleAction::Drop => "drop".to_string(),
                RuleAction::RateLimit { pps, name } => {
                    let name_str = name.as_ref()
                        .map(|(ns, n)| format!("{}:{}", ns, n))
                        .unwrap_or_default();
                    format!("ratelimit:{}:{}", pps, name_str)
                }
                RuleAction::Count { name } => {
                    let name_str = name.as_ref()
                        .map(|(ns, n)| format!("{}:{}", ns, n))
                        .unwrap_or_default();
                    format!("count:{}", name_str)
                }
            }
        }).collect();
        action_strs.sort();
        for s in &action_strs {
            s.hash(&mut hasher);
        }
        
        // Hash priority
        self.priority.hash(&mut hasher);
        
        // Truncate to u32 (non-zero)
        let h = hasher.finish() as u32;
        if h == 0 { 1 } else { h }
    }

    /// Compute the bucket key for this rule (for rate limiters and counters).
    /// 
    /// Named actions (rate-limit or count with :name ["ns" "name"]) share a bucket/counter
    /// across all rules with the same namespace and name. Unnamed actions get a per-rule key
    /// based on the rule's canonical hash.
    /// 
    /// Returns the key (u32) for the first rate-limit or count action, or None if neither.
    pub fn bucket_key(&self) -> Option<u32> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        // Find first rate-limit or count action
        for action in &self.actions {
            match action {
                RuleAction::RateLimit { pps: _, name } | RuleAction::Count { name } => {
                    if let Some((namespace, name)) = name {
                        // Named bucket: hash namespace + name
                        let mut hasher = DefaultHasher::new();
                        namespace.hash(&mut hasher);
                        name.hash(&mut hasher);
                        let h = hasher.finish() as u32;
                        return Some(if h == 0 { 1 } else { h });
                    } else {
                        // Unnamed bucket: use rule's canonical hash (default behavior)
                        return Some(self.canonical_hash());
                    }
                }
                _ => continue,
            }
        }
        None
    }

    /// Generate a canonical EDN string representation of constraints for logging/metrics.
    /// Constraints are sorted by dimension for consistency.
    pub fn constraints_to_edn(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        
        // Sort constraints by dimension for canonical ordering
        let mut sorted: Vec<&Predicate> = self.constraints.iter().collect();
        sorted.sort_by_key(|p| {
            p.field_dim().map(|d| d as u8).unwrap_or(255)
        });
        
        for pred in sorted {
            match pred {
                Predicate::Eq(FieldRef::Dim(dim), val) => {
                    let (dim_name, val_str) = Self::format_dim_value(*dim, *val);
                    parts.push(format!("(= {} {})", dim_name, val_str));
                }
                Predicate::In(FieldRef::Dim(dim), vals) => {
                    let dim_name = Self::dim_name(*dim);
                    let val_strs: Vec<String> = vals.iter()
                        .map(|v| Self::format_dim_value(*dim, *v).1)
                        .collect();
                    parts.push(format!("(in {} {})", dim_name, val_strs.join(" ")));
                }
            }
        }
        
        format!("[{}]", parts.join(" "))
    }

    /// Helper: format dimension name
    fn dim_name(dim: FieldDim) -> &'static str {
        match dim {
            FieldDim::Proto => "proto",
            FieldDim::SrcIp => "src-ip",
            FieldDim::DstIp => "dst-ip",
            FieldDim::L4Word0 => "src-port",
            FieldDim::L4Word1 => "dst-port",
            FieldDim::TcpFlags => "tcp-flags",
            FieldDim::Ttl => "ttl",
            FieldDim::DfBit => "df-bit",
            FieldDim::TcpWindow => "tcp-window",
        }
    }

    /// Helper: format dimension value (handles IP byte order, etc.)
    fn format_dim_value(dim: FieldDim, val: u32) -> (&'static str, String) {
        let dim_name = Self::dim_name(dim);
        let val_str = match dim {
            FieldDim::Proto => val.to_string(),
            FieldDim::SrcIp | FieldDim::DstIp => {
                // IP addresses are stored in network byte order (big-endian)
                let ip = std::net::Ipv4Addr::from(val.to_be());
                ip.to_string()
            }
            FieldDim::L4Word0 | FieldDim::L4Word1 | FieldDim::TcpFlags |
            FieldDim::Ttl | FieldDim::DfBit | FieldDim::TcpWindow => val.to_string(),
        };
        (dim_name, val_str)
    }

    /// Get the display label for this rule.
    /// Returns the explicit label if set, otherwise returns canonical constraint EDN
    /// with an implied "system" namespace for auto-generated rules.
    pub fn display_label(&self) -> String {
        if let Some((ns, name)) = &self.label {
            format!("[{} {}]", ns, name)
        } else {
            // Implied "system" namespace for auto-generated constraint-based labels
            format!("[system {}]", self.constraints_to_edn())
        }
    }

    /// Whether this rule needs Phase 2 fields
    pub fn needs_phase2(&self) -> bool {
        self.constraints.iter().any(|p| {
            p.as_eq_dim().map_or(false, |(dim, _)| dim.is_phase2())
        })
    }

    /// Human-readable description (legacy format)
    pub fn describe(&self) -> String {
        self.to_sexpr()
    }

    /// Emit rule as an s-expression in Clara-style LHS => RHS form.
    ///
    /// Single constraint:  `((= src-addr 10.0.0.100) => (drop))`
    /// Compound:           `((and (= proto 17) (= src-port 53)) => (rate-limit 1906))`
    /// With priority != 100: appends `:priority N`
    pub fn to_sexpr(&self) -> String {
        let (lhs, rhs, prio) = self.sexpr_parts();
        if let Some(p) = prio {
            format!("({} => {} :priority {})", lhs, rhs, p)
        } else {
            format!("({} => {})", lhs, rhs)
        }
    }

    /// Pretty-print rule as a multi-line s-expression (Clara style).
    ///
    /// ```text
    /// ((and (= proto 17)
    ///       (= src-port 53))
    ///  =>
    ///  (rate-limit 1234))
    /// ```
    pub fn to_sexpr_pretty(&self) -> String {
        let (lhs, rhs, prio) = self.sexpr_parts();

        // For compound rules, break clauses across lines aligned after `(and `
        let lhs_pretty = if self.constraints.len() > 1 {
            let clauses: Vec<String> = self.constraints.iter()
                .map(|p| p.to_sexpr_clause())
                .collect();
            // "(and " is 5 chars, inside outer "(" that's at col 1, so align at col 6
            let indent = "      ";
            let mut s = format!("(and {}", clauses[0]);
            for clause in &clauses[1..] {
                s.push_str(&format!("\n{}{}", indent, clause));
            }
            s.push(')');
            s
        } else {
            lhs
        };

        let prio_suffix = if let Some(p) = prio {
            format!(" :priority {}", p)
        } else {
            String::new()
        };

        format!("({}\n =>\n {}{})", lhs_pretty, rhs, prio_suffix)
    }

    /// Internal: build the LHS string, RHS string, and optional priority.
    fn sexpr_parts(&self) -> (String, String, Option<u8>) {
        let lhs = if self.constraints.is_empty() {
            "()".to_string()
        } else if self.constraints.len() == 1 {
            self.constraints[0].to_sexpr_clause()
        } else {
            let clauses: Vec<String> = self.constraints.iter()
                .map(|p| p.to_sexpr_clause())
                .collect();
            format!("(and {})", clauses.join(" "))
        };

        // For old-style sexpr, use first action only (backward compat for logging)
        let rhs = if let Some(first_action) = self.actions.first() {
            Self::action_to_sexpr(first_action)
        } else {
            "(pass)".to_string()
        };

        let prio = if self.priority != 100 { Some(self.priority) } else { None };
        (lhs, rhs, prio)
    }

    /// Format a single action as s-expression
    fn action_to_sexpr(action: &RuleAction) -> String {
        match action {
            RuleAction::Pass => "(pass)".to_string(),
            RuleAction::Drop => "(drop)".to_string(),
            RuleAction::RateLimit { pps, name: None } => {
                format!("(rate-limit {})", pps)
            }
            RuleAction::RateLimit { pps, name: Some((ns, n)) } => {
                format!("(rate-limit {} :name [\"{}\", \"{}\"])", pps, ns, n)
            }
            RuleAction::Count { name: None } => {
                "(count)".to_string()
            }
            RuleAction::Count { name: Some((ns, n)) } => {
                format!("(count :name [\"{}\", \"{}\"])", ns, n)
            }
        }
    }

    /// Emit rule as EDN (compact, single-line format for file storage)
    ///
    /// Example: `{:constraints [(= proto 17) (= src-port 53)] :actions [(rate-limit 500)] :priority 190}`
    pub fn to_edn(&self) -> String {
        let constraints_str = if self.constraints.is_empty() {
            "[]".to_string()
        } else {
            let clauses: Vec<String> = self.constraints.iter()
                .map(|p| p.to_sexpr_clause())
                .collect();
            format!("[{}]", clauses.join(" "))
        };

        let actions_str = {
            let action_exprs: Vec<String> = self.actions.iter()
                .map(|a| Self::action_to_sexpr(a))
                .collect();
            format!("[{}]", action_exprs.join(" "))
        };

        let priority_str = if self.priority != 100 {
            format!(" :priority {}", self.priority)
        } else {
            String::new()
        };

        let comment_str = if let Some(ref comment) = self.comment {
            // Escape quotes in comment
            let escaped = comment.replace('"', "\\\"");
            format!(" :comment \"{}\"", escaped)
        } else {
            String::new()
        };

        let label_str = if let Some((ref ns, ref name)) = self.label {
            let ns_escaped = ns.replace('"', "\\\"");
            let name_escaped = name.replace('"', "\\\"");
            format!(" :label [\"{}\" \"{}\"]", ns_escaped, name_escaped)
        } else {
            String::new()
        };

        format!("{{:constraints {} :actions {}{}{}{}}}", constraints_str, actions_str, priority_str, comment_str, label_str)
    }

    /// Emit rule as EDN (pretty, multi-line format for logs)
    ///
    /// Example:
    /// ```edn
    /// {:constraints [(= proto 17)
    ///                (= src-port 53)]
    ///  :actions     [(rate-limit 500)]
    ///  :priority    190}
    /// ```
    pub fn to_edn_pretty(&self) -> String {
        let constraint_indent = "               ";  // 15 spaces: align with first ( in ":constraints ["
        let actions_indent = "              ";      // 14 spaces: align with first ( in " :actions     ["
        
        let constraints_str = if self.constraints.is_empty() {
            "[]".to_string()
        } else if self.constraints.len() == 1 {
            format!("[{}]", self.constraints[0].to_sexpr_clause())
        } else {
            let clauses: Vec<String> = self.constraints.iter()
                .map(|p| p.to_sexpr_clause())
                .collect();
            let mut s = format!("[{}", clauses[0]);
            for clause in &clauses[1..] {
                s.push_str(&format!("\n{}{}", constraint_indent, clause));
            }
            s.push(']');
            s
        };

        let actions_str = if self.actions.len() == 1 {
            format!("[{}]", Self::action_to_sexpr(&self.actions[0]))
        } else {
            let action_exprs: Vec<String> = self.actions.iter()
                .map(|a| Self::action_to_sexpr(a))
                .collect();
            let mut s = format!("[{}", action_exprs[0]);
            for expr in &action_exprs[1..] {
                s.push_str(&format!("\n{}{}", actions_indent, expr));
            }
            s.push(']');
            s
        };

        if self.priority != 100 || self.comment.is_some() || self.label.is_some() {
            let mut parts = vec![
                format!("{{:constraints {}", constraints_str),
                format!(" :actions     {}", actions_str),
            ];
            if self.priority != 100 {
                parts.push(format!(" :priority    {}", self.priority));
            }
            if let Some(ref comment) = self.comment {
                let escaped = comment.replace('"', "\\\"");
                parts.push(format!(" :comment     \"{}\"", escaped));
            }
            if let Some((ref ns, ref name)) = self.label {
                let ns_escaped = ns.replace('"', "\\\"");
                let name_escaped = name.replace('"', "\\\"");
                parts.push(format!(" :label       [\"{}\" \"{}\"]", ns_escaped, name_escaped));
            }
            parts.push("}".to_string());
            parts.join("\n")
        } else {
            format!("{{:constraints {}\n :actions     {}}}",
                    constraints_str, actions_str)
        }
    }
}

// =============================================================================
// Packet Sample + Walkable (unchanged)
// =============================================================================

pub const SAMPLE_DATA_SIZE: usize = 128;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketSample {
    pub pkt_len: u32,
    pub cap_len: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub matched_rule: u8,
    pub action_taken: u8,
    pub tcp_flags: u8,
    pub ttl: u8,
    pub df_bit: u8,
    pub tcp_window: u16,
    pub data: [u8; SAMPLE_DATA_SIZE],
}

unsafe impl aya::Pod for PacketSample {}

impl PacketSample {
    pub fn src_ip_addr(&self) -> Ipv4Addr { Ipv4Addr::from(self.src_ip.to_ne_bytes()) }
    pub fn dst_ip_addr(&self) -> Ipv4Addr { Ipv4Addr::from(self.dst_ip.to_ne_bytes()) }
    pub fn protocol_name(&self) -> &'static str {
        match self.protocol { 1 => "ICMP", 6 => "TCP", 17 => "UDP", _ => "OTHER" }
    }
    pub fn src_port_band(&self) -> &'static str {
        match self.src_port {
            53 => "dns", 123 => "ntp", 0..=1023 => "wellknown",
            1024..=49151 => "registered", _ => "ephemeral",
        }
    }
    pub fn dst_port_band(&self) -> &'static str {
        match self.dst_port {
            80 | 8080 => "http", 443 => "https", 53 => "dns", 123 => "ntp",
            0..=1023 => "wellknown", 1024..=49151 => "registered", _ => "ephemeral",
        }
    }
    pub fn direction(&self) -> &'static str {
        if self.src_port < 1024 && self.dst_port >= 1024 { "amplified" }
        else if self.src_port >= 1024 && self.dst_port < 1024 { "outbound" }
        else { "normal" }
    }
    pub fn size_class(&self) -> &'static str {
        match self.pkt_len { 0..=100 => "tiny", 101..=500 => "small", 501..=1500 => "medium", _ => "large" }
    }

    // ── p0f-level fields ──

    /// Human-readable TCP flags (e.g. "SYN", "SYN|ACK", "0x00")
    pub fn tcp_flags_name(&self) -> String {
        if self.protocol != 6 { return "n/a".to_string(); }
        let mut parts = Vec::new();
        if self.tcp_flags & 0x01 != 0 { parts.push("FIN"); }
        if self.tcp_flags & 0x02 != 0 { parts.push("SYN"); }
        if self.tcp_flags & 0x04 != 0 { parts.push("RST"); }
        if self.tcp_flags & 0x08 != 0 { parts.push("PSH"); }
        if self.tcp_flags & 0x10 != 0 { parts.push("ACK"); }
        if self.tcp_flags & 0x20 != 0 { parts.push("URG"); }
        if parts.is_empty() {
            format!("0x{:02x}", self.tcp_flags)
        } else {
            parts.join("|")
        }
    }

    /// TTL band — p0f uses initial TTL to fingerprint OS
    pub fn ttl_band(&self) -> &'static str {
        match self.ttl {
            0..=32   => "ttl_32",   // unusual
            33..=64  => "ttl_64",   // Linux
            65..=128 => "ttl_128",  // Windows
            _        => "ttl_255",  // Solaris / network gear
        }
    }

    /// DF bit as human string
    pub fn df_name(&self) -> &'static str {
        if self.df_bit != 0 { "df_set" } else { "df_clear" }
    }

    /// TCP window size class (p0f-style)
    pub fn tcp_window_class(&self) -> &'static str {
        if self.protocol != 6 { return "n/a"; }
        match self.tcp_window {
            0             => "zero",
            1..=1024      => "tiny",
            1025..=8192   => "small",
            8193..=32768  => "medium",
            32769..=65534 => "large",
            65535         => "max",
        }
    }
}

impl Walkable for PacketSample {
    fn walk_type(&self) -> WalkType { WalkType::Map }
    fn walk_map_items(&self) -> Vec<(&str, WalkableValue)> {
        let mut items = vec![
            ("src_ip", WalkableValue::Scalar(ScalarValue::String(self.src_ip_addr().to_string()))),
            ("dst_ip", WalkableValue::Scalar(ScalarValue::String(self.dst_ip_addr().to_string()))),
            ("src_port", WalkableValue::Scalar(ScalarValue::Int(self.src_port as i64))),
            ("dst_port", WalkableValue::Scalar(ScalarValue::Int(self.dst_port as i64))),
            ("protocol", WalkableValue::Scalar(ScalarValue::Int(self.protocol as i64))),
            // Derived semantic fields (help Holon group similar traffic)
            ("src_port_band", WalkableValue::Scalar(ScalarValue::String(self.src_port_band().to_string()))),
            ("dst_port_band", WalkableValue::Scalar(ScalarValue::String(self.dst_port_band().to_string()))),
            ("direction", WalkableValue::Scalar(ScalarValue::String(self.direction().to_string()))),
            ("size_class", WalkableValue::Scalar(ScalarValue::String(self.size_class().to_string()))),
            ("pkt_len", WalkableValue::Scalar(ScalarValue::log(self.pkt_len as f64))),
            // p0f-level fields (raw numeric values)
            ("ttl", WalkableValue::Scalar(ScalarValue::Int(self.ttl as i64))),
            ("df_bit", WalkableValue::Scalar(ScalarValue::Int(self.df_bit as i64))),
        ];
        // TCP-only fields
        if self.protocol == 6 {
            items.push(("tcp_flags", WalkableValue::Scalar(ScalarValue::Int(self.tcp_flags as i64))));
            items.push(("tcp_window", WalkableValue::Scalar(ScalarValue::Int(self.tcp_window as i64))));
        }
        items
    }
    fn has_fast_visitor(&self) -> bool { true }
    fn walk_map_visitor(&self, visitor: &mut dyn FnMut(&str, WalkableRef<'_>)) {
        let src_ip_str = self.src_ip_addr().to_string();
        let dst_ip_str = self.dst_ip_addr().to_string();
        visitor("src_ip", WalkableRef::string(&src_ip_str));
        visitor("dst_ip", WalkableRef::string(&dst_ip_str));
        visitor("src_port", WalkableRef::int(self.src_port as i64));
        visitor("dst_port", WalkableRef::int(self.dst_port as i64));
        visitor("protocol", WalkableRef::int(self.protocol as i64));
        visitor("src_port_band", WalkableRef::string(self.src_port_band()));
        visitor("dst_port_band", WalkableRef::string(self.dst_port_band()));
        visitor("direction", WalkableRef::string(self.direction()));
        visitor("size_class", WalkableRef::string(self.size_class()));
        visitor("pkt_len", WalkableRef::Scalar(ScalarRef::log(self.pkt_len as f64)));
        // p0f-level fields (raw numeric values)
        visitor("ttl", WalkableRef::int(self.ttl as i64));
        visitor("df_bit", WalkableRef::int(self.df_bit as i64));
        // TCP-only fields
        if self.protocol == 6 {
            visitor("tcp_flags", WalkableRef::int(self.tcp_flags as i64));
            visitor("tcp_window", WalkableRef::int(self.tcp_window as i64));
        }
    }
}

// =============================================================================
// Legacy Rule type (kept for backward compat)
// =============================================================================

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FilterStats {
    pub total_packets: u64,
    pub passed_packets: u64,
    pub dropped_packets: u64,
    pub sampled_packets: u64,
    pub rate_limited_packets: u64,
    /// Diagnostic: DFS completions (STATS[6])
    pub dfs_completions: u64,
    /// Diagnostic: tail-call entries (STATS[7])
    pub tail_call_entries: u64,
    /// Diagnostic: eval_mode==2 entered (STATS[8])
    pub diag_eval2: u64,
    /// Diagnostic: root non-zero (STATS[9])
    pub diag_root_ok: u64,
    /// Diagnostic: got DFS state ptr (STATS[10])
    pub diag_state_ok: u64,
    /// Diagnostic: tail call attempted (STATS[11])
    pub diag_tc_attempt: u64,
    /// Diagnostic: tail call FAILED (STATS[12])
    pub diag_tc_fail: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Rule {
    pub rule_type: RuleType,
    pub value: String,
    pub action: RuleAction,
    pub rate_pps: Option<u32>,
}

impl Rule {
    pub fn drop_src_ip(ip: Ipv4Addr) -> Self {
        Self { rule_type: RuleType::SrcIp, value: ip.to_string(), action: RuleAction::Drop, rate_pps: None }
    }
    pub fn drop_dst_port(port: u16) -> Self {
        Self { rule_type: RuleType::DstPort, value: port.to_string(), action: RuleAction::Drop, rate_pps: None }
    }
    pub fn drop_src_port(port: u16) -> Self {
        Self { rule_type: RuleType::SrcPort, value: port.to_string(), action: RuleAction::Drop, rate_pps: None }
    }
    pub fn to_key(&self) -> Result<RuleKey> {
        let value = match self.rule_type {
            RuleType::SrcIp | RuleType::DstIp => {
                let ip: Ipv4Addr = self.value.parse().context("Invalid IP address")?;
                u32::from_ne_bytes(ip.octets())
            }
            RuleType::SrcPort | RuleType::DstPort => {
                let port: u16 = self.value.parse().context("Invalid port number")?;
                port as u32
            }
            RuleType::Protocol => {
                let proto: u8 = self.value.parse().context("Invalid protocol number")?;
                proto as u32
            }
        };
        Ok(RuleKey { rule_type: self.rule_type as u8, _pad: [0; 3], value })
    }
    pub fn to_value(&self) -> RuleValue {
        RuleValue {
            action: self.action.action_type(),
            _pad: [0; 3],
            rate_pps: self.rate_pps.unwrap_or(0),
            tokens: self.rate_pps.unwrap_or(0),
            last_update_ns: 0,
            match_count: 0,
        }
    }
    pub fn rate_limit_src_ip(ip: Ipv4Addr, pps: u32) -> Self {
        Self { 
            rule_type: RuleType::SrcIp, 
            value: ip.to_string(), 
            action: RuleAction::RateLimit { pps, name: None }, 
            rate_pps: Some(pps) 
        }
    }
    pub fn rate_limit_dst_port(port: u16, pps: u32) -> Self {
        Self { 
            rule_type: RuleType::DstPort, 
            value: port.to_string(), 
            action: RuleAction::RateLimit { pps, name: None }, 
            rate_pps: Some(pps) 
        }
    }
    pub fn rate_limit_src_port(port: u16, pps: u32) -> Self {
        Self { 
            rule_type: RuleType::SrcPort, 
            value: port.to_string(), 
            action: RuleAction::RateLimit { pps, name: None }, 
            rate_pps: Some(pps) 
        }
    }
}

// =============================================================================
// VethFilter - Main API
// =============================================================================

pub struct VethFilter {
    bpf: Arc<RwLock<Ebpf>>,
    interface: String,
    /// Bitmask of allocated rule bit positions (bitmask rete engine)
    allocated_bits: AtomicU64,
    /// Tree rete engine manager (blue/green)
    tree_manager: tokio::sync::Mutex<tree::TreeManager>,
    /// Keep the prog_array alive so the tail-call entry persists.
    /// Dropping this closes the map fd, which clears the prog_array entries.
    _prog_array: Option<ProgramArray<MapData>>,
}

impl VethFilter {
    pub fn new(interface: &str) -> Result<Self> {
        Self::with_flags(interface, XdpFlags::default())
    }

    pub fn with_flags(interface: &str, flags: XdpFlags) -> Result<Self> {
        info!("Loading veth-filter XDP program for {}", interface);

        #[cfg(debug_assertions)]
        let data = include_bytes_aligned!("../../filter-ebpf/target/bpfel-unknown-none/debug/veth-filter");
        #[cfg(not(debug_assertions))]
        let data = include_bytes_aligned!("../../filter-ebpf/target/bpfel-unknown-none/release/veth-filter");

        let mut bpf = Ebpf::load(data).context("Failed to load eBPF program")?;

        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            debug!("eBPF logger not available: {}", e);
        }

        let program: &mut Xdp = bpf
            .program_mut("veth_filter").context("XDP program not found")?
            .try_into().context("Program is not XDP")?;
        program.load().context("Failed to load XDP program")?;
        info!("XDP program loaded");

        let attach_result = program.attach(interface, flags);
        match attach_result {
            Ok(_) => {
                let mode = if flags.contains(XdpFlags::DRV_MODE) { "native driver" }
                    else if flags.contains(XdpFlags::SKB_MODE) { "SKB" }
                    else { "default" };
                info!("XDP program attached to {} in {} mode", interface, mode);
            }
            Err(e) if !flags.contains(XdpFlags::SKB_MODE) => {
                warn!("Requested XDP mode failed ({}), trying SKB mode", e);
                program.attach(interface, XdpFlags::SKB_MODE)
                    .context("Failed to attach XDP program in SKB mode")?;
                info!("XDP program attached to {} in SKB mode", interface);
            }
            Err(e) => { return Err(e).context("Failed to attach XDP program"); }
        }

        // Load tree_walk_step (tail-call target for tree rete DFS).
        // Load only — do NOT attach to any interface.
        {
            let tree_walk: &mut Xdp = bpf
                .program_mut("tree_walk_step")
                .context("tree_walk_step program not found")?
                .try_into()
                .context("tree_walk_step is not XDP")?;
            tree_walk.load().context("Failed to load tree_walk_step")?;
            info!("tree_walk_step loaded (tail-call target for tree DFS)");
        }

        // Set up tail-call program array: insert tree_walk_step fd at index 0.
        // IMPORTANT: We must keep the ProgramArray alive for the lifetime of VethFilter.
        // Dropping it closes the map fd, which causes the kernel to clear the entries.
        let prog_array = {
            let tree_walk_fd = {
                let prog = bpf.program("tree_walk_step")
                    .context("tree_walk_step program not found after load")?;
                prog.fd()
                    .context("tree_walk_step has no fd")?
                    .try_clone()
                    .context("Failed to clone tree_walk_step fd")?
            };
            let map = bpf.take_map("TREE_WALK_PROG")
                .context("TREE_WALK_PROG map not found")?;
            let mut prog_array = ProgramArray::try_from(map)
                .context("Failed to create ProgramArray from TREE_WALK_PROG")?;
            prog_array.set(0, &tree_walk_fd, 0)
                .context("Failed to set tree_walk_step in TREE_WALK_PROG")?;
            info!("TREE_WALK_PROG[0] = tree_walk_step fd");
            prog_array
        };

        Ok(Self {
            bpf: Arc::new(RwLock::new(bpf)),
            interface: interface.to_string(),
            allocated_bits: AtomicU64::new(0),
            tree_manager: tokio::sync::Mutex::new(tree::TreeManager::new()),
            _prog_array: Some(prog_array),
        })
    }

    pub fn interface(&self) -> &str { &self.interface }

    pub async fn stats(&self) -> Result<FilterStats> {
        let bpf = self.bpf.read().await;
        let stats: PerCpuArray<_, u64> = bpf.map("STATS").context("STATS not found")?.try_into()?;
        Ok(FilterStats {
            total_packets: stats.get(&0, 0).map(|v| sum_percpu(&v)).unwrap_or(0),
            passed_packets: stats.get(&1, 0).map(|v| sum_percpu(&v)).unwrap_or(0),
            dropped_packets: stats.get(&2, 0).map(|v| sum_percpu(&v)).unwrap_or(0),
            sampled_packets: stats.get(&4, 0).map(|v| sum_percpu(&v)).unwrap_or(0),
            rate_limited_packets: stats.get(&5, 0).map(|v| sum_percpu(&v)).unwrap_or(0),
            dfs_completions: stats.get(&6, 0).map(|v| sum_percpu(&v)).unwrap_or(0),
            tail_call_entries: stats.get(&7, 0).map(|v| sum_percpu(&v)).unwrap_or(0),
            diag_eval2: stats.get(&8, 0).map(|v| sum_percpu(&v)).unwrap_or(0),
            diag_root_ok: stats.get(&9, 0).map(|v| sum_percpu(&v)).unwrap_or(0),
            diag_state_ok: stats.get(&10, 0).map(|v| sum_percpu(&v)).unwrap_or(0),
            diag_tc_attempt: stats.get(&11, 0).map(|v| sum_percpu(&v)).unwrap_or(0),
            diag_tc_fail: stats.get(&12, 0).map(|v| sum_percpu(&v)).unwrap_or(0),
        })
    }

    pub async fn set_sample_rate(&self, rate: u32) -> Result<()> {
        let mut bpf = self.bpf.write().await;
        let mut config: PerCpuArray<_, u32> = bpf.map_mut("CONFIG").context("CONFIG not found")?.try_into()?;
        let num_cpus = aya::util::nr_cpus().map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))?;
        config.set(0, PerCpuValues::try_from(vec![rate; num_cpus])?, 0)?;
        info!("Sample rate set to {}", rate);
        Ok(())
    }

    pub async fn set_enforce_mode(&self, enforce: bool) -> Result<()> {
        let mut bpf = self.bpf.write().await;
        let mut config: PerCpuArray<_, u32> = bpf.map_mut("CONFIG").context("CONFIG not found")?.try_into()?;
        let num_cpus = aya::util::nr_cpus().map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))?;
        let val = if enforce { 1u32 } else { 0u32 };
        config.set(1, PerCpuValues::try_from(vec![val; num_cpus])?, 0)?;
        info!("Enforce mode set to {}", enforce);
        Ok(())
    }

    pub async fn set_eval_mode(&self, mode: u32) -> Result<()> {
        let mut bpf = self.bpf.write().await;
        let mut config: PerCpuArray<_, u32> = bpf.map_mut("CONFIG").context("CONFIG not found")?.try_into()?;
        let num_cpus = aya::util::nr_cpus().map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))?;
        config.set(2, PerCpuValues::try_from(vec![mode; num_cpus])?, 0)?;
        info!("Eval mode set to {} ({})", mode, match mode {
            1 => "bitmask rete",
            2 => "tree rete",
            _ => "legacy",
        });
        Ok(())
    }

    // Legacy rule management (unchanged)
    pub async fn add_rule(&self, rule: &Rule) -> Result<()> {
        let key = rule.to_key()?;
        let value = rule.to_value();
        let mut bpf = self.bpf.write().await;
        let mut rules: HashMap<_, RuleKey, RuleValue> = bpf.map_mut("RULES").context("RULES not found")?.try_into()?;
        rules.insert(key, value, 0)?;
        info!("Added legacy rule: {:?} -> {:?}", rule.rule_type, rule.action);
        Ok(())
    }

    pub async fn remove_rule(&self, rule: &Rule) -> Result<()> {
        let key = rule.to_key()?;
        let mut bpf = self.bpf.write().await;
        let mut rules: HashMap<_, RuleKey, RuleValue> = bpf.map_mut("RULES").context("RULES not found")?.try_into()?;
        rules.remove(&key)?;
        Ok(())
    }

    pub async fn list_rules(&self) -> Result<Vec<(Rule, u64)>> {
        let bpf = self.bpf.read().await;
        let rules: HashMap<_, RuleKey, RuleValue> = bpf.map("RULES").context("RULES not found")?.try_into()?;
        let mut result = Vec::new();
        for item in rules.iter() {
            if let Ok((key, value)) = item {
                let rule_type = match key.rule_type {
                    0 => RuleType::SrcIp, 1 => RuleType::DstIp, 2 => RuleType::SrcPort,
                    3 => RuleType::DstPort, 4 => RuleType::Protocol, _ => continue,
                };
                let value_str = match rule_type {
                    RuleType::SrcIp | RuleType::DstIp => Ipv4Addr::from(key.value.to_be_bytes()).to_string(),
                    RuleType::SrcPort | RuleType::DstPort => (key.value as u16).to_string(),
                    RuleType::Protocol => (key.value as u8).to_string(),
                };
                let action = match value.action {
                    0 => RuleAction::Pass,
                    1 => RuleAction::Drop,
                    2 => RuleAction::RateLimit { pps: value.rate_pps, name: None },
                    _ => continue,
                };
                result.push((Rule { rule_type, value: value_str, action, rate_pps: if value.rate_pps > 0 { Some(value.rate_pps) } else { None } }, value.match_count));
            }
        }
        Ok(result)
    }

    pub async fn clear_rules(&self) -> Result<()> {
        let rules = self.list_rules().await?;
        for (rule, _) in rules { self.remove_rule(&rule).await?; }
        info!("All legacy rules cleared");
        Ok(())
    }

    pub async fn take_perf_array(&self) -> Result<AsyncPerfEventArray<MapData>> {
        let mut bpf = self.bpf.write().await;
        let samples = bpf.take_map("SAMPLES").context("SAMPLES not found")?;
        AsyncPerfEventArray::try_from(samples).context("Failed to create perf array")
    }

    pub fn bpf(&self) -> Arc<RwLock<Ebpf>> { self.bpf.clone() }

    // =========================================================================
    // Tree Rete Engine Methods (eval_mode == 2)
    // =========================================================================

    /// Compile a set of rules into the tree engine and atomically flip.
    /// This is the primary API for the tree engine. The sidecar maintains
    /// its rule set and calls this whenever rules change.
    /// Returns the number of nodes in the compiled tree.
    pub async fn compile_and_flip_tree(&self, rules: &[RuleSpec]) -> Result<usize> {
        let mut bpf = self.bpf.write().await;
        let mut mgr = self.tree_manager.lock().await;
        mgr.compile_and_flip(rules, &mut bpf)
    }

    /// Read TREE_COUNTERS map and return (key, value) pairs
    pub async fn read_counters(&self) -> Result<Vec<(u32, u64)>> {
        use aya::maps::HashMap as AyaHashMap;
        let bpf = self.bpf.read().await;
        
        let map = bpf.map("TREE_COUNTERS")
            .ok_or_else(|| anyhow::anyhow!("TREE_COUNTERS map not found"))?;
        let counters_map = AyaHashMap::<_, u32, u64>::try_from(map)?;
        let mut results = Vec::new();
        
        for key_result in counters_map.keys() {
            if let Ok(key) = key_result {
                if let Ok(value) = counters_map.get(&key, 0) {
                    results.push((key, value));
                }
            }
        }
        
        Ok(results)
    }

    /// Read rate limiter statistics from the TREE_RATE_STATE map.
    /// Returns Vec<(bucket_id, allowed, dropped)>
    pub async fn read_rate_limit_stats(&self) -> Result<Vec<(u32, u64, u64)>> {
        use aya::maps::HashMap as AyaHashMap;
        let bpf = self.bpf.read().await;
        
        let map = bpf.map("TREE_RATE_STATE")
            .ok_or_else(|| anyhow::anyhow!("TREE_RATE_STATE map not found"))?;
        let rate_map = AyaHashMap::<_, u32, TokenBucket>::try_from(map)?;
        let mut results = Vec::new();
        
        for key_result in rate_map.keys() {
            if let Ok(key) = key_result {
                if let Ok(bucket) = rate_map.get(&key, 0) {
                    results.push((key, bucket.allowed_count, bucket.dropped_count));
                }
            }
        }
        
        Ok(results)
    }

    /// Clear both tree slots.
    pub async fn clear_tree(&self) -> Result<()> {
        let mut bpf = self.bpf.write().await;
        let mut mgr = self.tree_manager.lock().await;
        mgr.clear_all(&mut bpf)
    }

    // =========================================================================
    // Bitmask Rete Engine Methods
    // =========================================================================

    /// Allocate a free bit position for a new rule. Returns None if all 64 are used.
    fn allocate_bit(&self) -> Option<u32> {
        loop {
            let current = self.allocated_bits.load(Ordering::SeqCst);
            if current == u64::MAX { return None; } // All bits used
            // Find first zero bit
            let bit = (!current).trailing_zeros();
            if bit >= 64 { return None; }
            let new = current | (1u64 << bit);
            if self.allocated_bits.compare_exchange(current, new, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                return Some(bit);
            }
        }
    }

    /// Free a bit position
    fn free_bit(&self, bit: u32) {
        if bit < 64 {
            self.allocated_bits.fetch_and(!(1u64 << bit), Ordering::SeqCst);
        }
    }

    /// Add a rule to the bitmask Rete engine.
    /// Returns the allocated bit position (rule_id).
    pub async fn add_rete_rule(&self, spec: &RuleSpec) -> Result<u32> {
        let bit = self.allocate_bit()
            .ok_or_else(|| anyhow::anyhow!("All 64 rule slots are in use"))?;

        let rule_bit: u64 = 1u64 << bit;

        let mut bpf = self.bpf.write().await;

        // 1. Write RULE_META
        {
            let mut meta_map: Array<_, RuleMeta> = bpf
                .map_mut("RULE_META").context("RULE_META not found")?.try_into()?;
            
            // Use first action for legacy rete engine
            let first_action = spec.actions.first().unwrap_or(&RuleAction::Pass);
            meta_map.set(bit, RuleMeta {
                action: first_action.action_type(),
                _pad: [0; 3],
                rate_pps: first_action.rate_pps().unwrap_or(0),
            }, 0)?;
        }

        // 2. For each constraint, set the bit in the corresponding dispatch map
        for pred in &spec.constraints {
            let (dim, value) = pred.as_eq_dim().expect("bitmask rete requires Eq predicates");
            let map_name = dim.map_name();
            let mut dispatch: HashMap<_, u32, u64> = bpf
                .map_mut(map_name)
                .with_context(|| format!("{} not found", map_name))?
                .try_into()?;

            let existing = dispatch.get(&value, 0).unwrap_or(0u64);
            dispatch.insert(value, existing | rule_bit, 0)?;
        }

        // 3. For unconstrained dimensions, set dont_care bit
        {
            let constrained_dims: Vec<u8> = spec.constraints.iter()
                .filter_map(|p| p.as_eq_dim())
                .map(|(d, _)| d as u8)
                .collect();
            let mut dont_care_map: Array<_, u64> = bpf
                .map_mut("DONT_CARE").context("DONT_CARE not found")?.try_into()?;

            for dim in FieldDim::all() {
                if !constrained_dims.contains(&(*dim as u8)) {
                    let existing = dont_care_map.get(&(*dim as u32), 0).unwrap_or(0u64);
                    dont_care_map.set(*dim as u32, existing | rule_bit, 0)?;
                }
            }
        }

        // 4. Update ACTIVE_RULES bitmask
        {
            let mut active: Array<_, u64> = bpf
                .map_mut("ACTIVE_RULES").context("ACTIVE_RULES not found")?.try_into()?;
            let existing = active.get(&0, 0).unwrap_or(0u64);
            active.set(0, existing | rule_bit, 0)?;
        }

        // 5. Update NEEDS_PHASE2 if rule has Phase 2 constraints
        if spec.needs_phase2() {
            let mut needs_p2: Array<_, u64> = bpf
                .map_mut("NEEDS_PHASE2").context("NEEDS_PHASE2 not found")?.try_into()?;
            let existing = needs_p2.get(&0, 0).unwrap_or(0u64);
            needs_p2.set(0, existing | rule_bit, 0)?;
        }

        // 6. Create rate state if needed
        if let Some(first_action) = spec.actions.first() {
            if let Some(pps) = first_action.rate_pps() {
                let mut rate_state: HashMap<_, u32, TokenBucket> = bpf
                    .map_mut("RATE_STATE").context("RATE_STATE not found")?.try_into()?;
                rate_state.insert(bit, TokenBucket { 
                    rate_pps: pps, 
                    tokens: pps, 
                    last_update_ns: 0,
                    allowed_count: 0,
                    dropped_count: 0,
                }, 0)?;
            }
        }

        info!("Added rete rule bit={}: {}", bit, spec.describe());
        Ok(bit)
    }

    /// Remove a rule by its bit position
    pub async fn remove_rete_rule(&self, bit: u32, spec: &RuleSpec) -> Result<()> {
        if bit >= 64 {
            return Err(anyhow::anyhow!("Invalid rule bit: {}", bit));
        }
        let rule_bit: u64 = 1u64 << bit;
        let clear_mask: u64 = !rule_bit;

        let mut bpf = self.bpf.write().await;

        // 1. Clear bit from all dispatch maps that have constraints
        for pred in &spec.constraints {
            let (dim, value) = pred.as_eq_dim().expect("bitmask rete requires Eq predicates");
            let map_name = dim.map_name();
            let mut dispatch: HashMap<_, u32, u64> = bpf
                .map_mut(map_name)
                .with_context(|| format!("{} not found", map_name))?
                .try_into()?;

            if let Ok(existing) = dispatch.get(&value, 0) {
                let new_val = existing & clear_mask;
                if new_val == 0 {
                    let _ = dispatch.remove(&value);
                } else {
                    dispatch.insert(value, new_val, 0)?;
                }
            }
        }

        // 2. Clear dont_care bits
        {
            let mut dont_care_map: Array<_, u64> = bpf
                .map_mut("DONT_CARE").context("DONT_CARE not found")?.try_into()?;
            for dim in FieldDim::all() {
                let existing = dont_care_map.get(&(*dim as u32), 0).unwrap_or(0);
                dont_care_map.set(*dim as u32, existing & clear_mask, 0)?;
            }
        }

        // 3. Clear ACTIVE_RULES bit
        {
            let mut active: Array<_, u64> = bpf
                .map_mut("ACTIVE_RULES").context("ACTIVE_RULES not found")?.try_into()?;
            let existing = active.get(&0, 0).unwrap_or(0);
            active.set(0, existing & clear_mask, 0)?;
        }

        // 4. Clear NEEDS_PHASE2 bit
        {
            let mut needs_p2: Array<_, u64> = bpf
                .map_mut("NEEDS_PHASE2").context("NEEDS_PHASE2 not found")?.try_into()?;
            let existing = needs_p2.get(&0, 0).unwrap_or(0);
            needs_p2.set(0, existing & clear_mask, 0)?;
        }

        // 5. Remove rate state
        {
            let mut rate_state: HashMap<_, u32, TokenBucket> = bpf
                .map_mut("RATE_STATE").context("RATE_STATE not found")?.try_into()?;
            let _ = rate_state.remove(&bit);
        }

        // 6. Free the bit
        self.free_bit(bit);

        info!("Removed rete rule bit={}", bit);
        Ok(())
    }

    /// Clear all rete rules
    pub async fn clear_rete_rules(&self) -> Result<()> {
        self.allocated_bits.store(0, Ordering::SeqCst);

        let mut bpf = self.bpf.write().await;

        // Clear all dispatch maps
        let dispatch_map_names = [
            "DISPATCH_PROTO", "DISPATCH_SRC_IP", "DISPATCH_DST_IP",
            "DISPATCH_L4W0", "DISPATCH_L4W1",
            "DISPATCH_TCP_FLAGS", "DISPATCH_TTL", "DISPATCH_DF", "DISPATCH_TCP_WIN",
        ];
        for map_name in dispatch_map_names {
            if let Some(m) = bpf.map_mut(map_name) {
                let mut map: HashMap<_, u32, u64> = match m.try_into() { Ok(hm) => hm, Err(_) => continue };
                let keys: Vec<u32> = map.keys().filter_map(|k| k.ok()).collect();
                for key in keys { let _ = map.remove(&key); }
            }
        }

        // Clear DONT_CARE
        {
            let mut dc: Array<_, u64> = bpf.map_mut("DONT_CARE").context("DONT_CARE not found")?.try_into()?;
            for i in 0..NUM_DIMENSIONS as u32 { dc.set(i, 0u64, 0)?; }
        }

        // Clear ACTIVE_RULES
        {
            let mut ar: Array<_, u64> = bpf.map_mut("ACTIVE_RULES").context("ACTIVE_RULES not found")?.try_into()?;
            ar.set(0, 0u64, 0)?;
        }

        // Clear NEEDS_PHASE2
        {
            let mut np: Array<_, u64> = bpf.map_mut("NEEDS_PHASE2").context("NEEDS_PHASE2 not found")?.try_into()?;
            np.set(0, 0u64, 0)?;
        }

        // Clear RATE_STATE
        {
            let mut rs: HashMap<_, u32, TokenBucket> = bpf.map_mut("RATE_STATE").context("RATE_STATE not found")?.try_into()?;
            let keys: Vec<u32> = rs.keys().filter_map(|k| k.ok()).collect();
            for key in keys { let _ = rs.remove(&key); }
        }

        info!("All rete rules cleared");
        Ok(())
    }
}

impl Drop for VethFilter {
    fn drop(&mut self) {
        info!("Detaching XDP filter from {}", self.interface);
    }
}

fn sum_percpu(values: &PerCpuValues<u64>) -> u64 {
    values.iter().sum()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_key_conversion() {
        let rule = Rule::drop_src_ip(Ipv4Addr::new(10, 0, 0, 1));
        let key = rule.to_key().unwrap();
        assert_eq!(key.rule_type, RuleType::SrcIp as u8);
        assert_eq!(key.value, u32::from_ne_bytes([10, 0, 0, 1]));
    }

    #[test]
    fn test_port_rule() {
        let rule = Rule::drop_dst_port(53);
        let key = rule.to_key().unwrap();
        assert_eq!(key.rule_type, RuleType::DstPort as u8);
        assert_eq!(key.value, 53);
    }

    // =========================================================================
    // Bitmask Rete Engine Tests
    // =========================================================================

    #[test]
    fn test_rule_spec_simple() {
        let spec = RuleSpec::drop_field(FieldDim::Proto, 17);
        assert_eq!(spec.constraints.len(), 1);
        assert_eq!(spec.constraints[0], Predicate::eq(FieldDim::Proto, 17));
        assert_eq!(spec.actions.len(), 1);
        assert_eq!(spec.actions[0], RuleAction::Drop);
        assert!(!spec.needs_phase2());
    }

    #[test]
    fn test_rule_spec_compound() {
        let spec = RuleSpec::compound(
            vec![
                Predicate::eq(FieldDim::SrcIp, 0x0A000001),
                Predicate::eq(FieldDim::L4Word1, 9999),
            ],
            RuleAction::RateLimit { pps: 5000, name: None },
        );
        assert_eq!(spec.constraints.len(), 2);
        assert!(!spec.needs_phase2());
        assert_eq!(spec.actions.len(), 1);
        assert_eq!(spec.actions[0], RuleAction::RateLimit { pps: 5000, name: None });
    }

    #[test]
    fn test_rule_spec_phase2() {
        let spec = RuleSpec::compound(
            vec![
                Predicate::eq(FieldDim::SrcIp, 0x0A000001),
                Predicate::eq(FieldDim::TcpFlags, 0x02), // SYN
            ],
            RuleAction::Drop,
        );
        assert!(spec.needs_phase2());
    }

    #[test]
    fn test_rule_spec_describe() {
        let spec = RuleSpec::compound(
            vec![
                Predicate::eq(FieldDim::Proto, 6),
                Predicate::eq(FieldDim::L4Word1, 80),
            ],
            RuleAction::Drop,
        );
        let desc = spec.describe();
        assert_eq!(desc, "((and (= proto 6) (= dst-port 80)) => (drop))");
    }

    #[test]
    fn test_sexpr_single_constraint() {
        let spec = RuleSpec::drop_field(FieldDim::Proto, 17);
        assert_eq!(spec.to_sexpr(), "((= proto 17) => (drop))");
    }

    #[test]
    fn test_sexpr_rate_limit() {
        let ip = u32::from_ne_bytes([10, 0, 0, 100]);
        let spec = RuleSpec::compound(
            vec![Predicate::eq(FieldDim::SrcIp, ip), Predicate::eq(FieldDim::L4Word1, 9999)],
            RuleAction::RateLimit { pps: 1906, name: None },
        );
        assert_eq!(
            spec.to_sexpr(),
            "((and (= src-addr 10.0.0.100) (= dst-port 9999)) => (rate-limit 1906))"
        );
    }

    #[test]
    fn test_sexpr_with_priority() {
        let spec = RuleSpec::drop_field(FieldDim::TcpFlags, 0x02).with_priority(200);
        assert_eq!(
            spec.to_sexpr(),
            "((= tcp-flags 2) => (drop) :priority 200)"
        );
    }

    #[test]
    fn test_sexpr_pass() {
        let spec = RuleSpec {
            constraints: vec![],
            actions: vec![RuleAction::Pass],
            priority: 100,
            comment: None,
            label: None,
        };
        assert_eq!(spec.to_sexpr(), "(() => (pass))");
    }

    #[test]
    fn test_sexpr_pretty_compound() {
        let ip = u32::from_ne_bytes([10, 0, 0, 100]);
        let spec = RuleSpec::compound(
            vec![
                Predicate::eq(FieldDim::Proto, 17),
                Predicate::eq(FieldDim::SrcIp, ip),
                Predicate::eq(FieldDim::L4Word1, 9999),
            ],
            RuleAction::RateLimit { pps: 1906, name: None },
        );
        let pretty = spec.to_sexpr_pretty();
        assert_eq!(pretty,
            "((and (= proto 17)\n\
             \x20     (= src-addr 10.0.0.100)\n\
             \x20     (= dst-port 9999))\n\
             \x20=>\n\
             \x20(rate-limit 1906))");
    }

    #[test]
    fn test_sexpr_pretty_single() {
        let spec = RuleSpec::drop_field(FieldDim::Proto, 17);
        let pretty = spec.to_sexpr_pretty();
        assert_eq!(pretty,
            "((= proto 17)\n\
             \x20=>\n\
             \x20(drop))");
    }

    #[test]
    fn test_field_dim_properties() {
        assert!(!FieldDim::Proto.is_phase2());
        assert!(!FieldDim::SrcIp.is_phase2());
        assert!(FieldDim::TcpFlags.is_phase2());
        assert!(FieldDim::Ttl.is_phase2());
        assert!(FieldDim::DfBit.is_phase2());
        assert!(FieldDim::TcpWindow.is_phase2());
    }

    #[test]
    fn test_field_dim_format_value() {
        assert_eq!(FieldDim::Proto.format_value(6), "TCP");
        assert_eq!(FieldDim::Proto.format_value(17), "UDP");
        assert_eq!(FieldDim::L4Word1.format_value(80), "80");
        assert_eq!(FieldDim::DfBit.format_value(1), "DF");
        assert_eq!(FieldDim::TcpFlags.format_value(0x02), "0x02");
    }

    #[test]
    fn test_field_dim_all() {
        let all = FieldDim::all();
        assert_eq!(all.len(), 9);
        assert_eq!(all[0], FieldDim::Proto);
        assert_eq!(all[8], FieldDim::TcpWindow);
    }
}
