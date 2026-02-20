//! Veth Filter - Userspace loader and rule management
//!
//! Loads the XDP filter and provides an API for:
//! - Compiling rules into the tree Rete decision engine
//! - Reading statistics, counters, and rate limiter state
//! - Receiving packet samples via ring buffer

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{MapData, PerCpuArray, PerCpuValues, ProgramArray, RingBuf},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use holon::{ScalarValue, WalkType, Walkable, WalkableRef, WalkableValue, ScalarRef};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

pub mod tree;

// =============================================================================
// Rule Action Types
// =============================================================================

/// Action to take when a rule matches.
/// Note: The repr(u8) discriminants are used in eBPF for simple actions.
/// Complex actions (with names) are handled at compile time in userspace.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RuleAction {
    Pass { name: Option<(String, String)> },
    Drop { name: Option<(String, String)> },
    RateLimit { pps: u32, name: Option<(String, String)> },  // name: (namespace, name)
    Count { name: Option<(String, String)> },
}

impl RuleAction {
    /// Convenience constructor for unnamed pass
    pub fn pass() -> Self { RuleAction::Pass { name: None } }

    /// Convenience constructor for unnamed drop
    pub fn drop() -> Self { RuleAction::Drop { name: None } }

    /// Get the action type as a u8 for eBPF (matches ACT_* constants)
    pub fn action_type(&self) -> u8 {
        match self {
            RuleAction::Pass { .. } => ACT_PASS,
            RuleAction::Drop { .. } => ACT_DROP,
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
            RuleAction::Pass { name } | RuleAction::Drop { name } | RuleAction::RateLimit { name, .. } | RuleAction::Count { name } => {
                name.as_ref()
            }
        }
    }
}

// =============================================================================
// Rule Manifest (post-compilation metadata for observability)
// =============================================================================

/// Entry in the rule manifest returned from tree compilation.
/// Maps post-compilation rule_id to the original rule's action and display label.
/// This provides an authoritative mapping for all entries that may appear in
/// TREE_COUNTERS, without relying on exclusion-based inference.
#[derive(Debug, Clone)]
pub struct RuleManifestEntry {
    pub rule_id: u32,
    pub action: RuleAction,
    pub label: String,
    /// Canonical constraints from the original user rule (pre-compilation lowering)
    pub constraints: String,
    /// Full EDN expression from the original user rule (pre-compilation lowering)
    pub expression: String,
}

impl RuleManifestEntry {
    /// Human-readable action kind string for log section headers
    pub fn action_kind(&self) -> &'static str {
        match &self.action {
            RuleAction::Pass { .. } => "pass",
            RuleAction::Drop { .. } => "drop",
            RuleAction::RateLimit { .. } => "rate-limit",
            RuleAction::Count { .. } => "count",
        }
    }
}

// =============================================================================
// Field Dimension Types
// =============================================================================

/// Dispatch dimension identifiers.
///
/// Indices 0-14 are static (pre-extracted) packet header fields.
/// Indices 16-22 are dynamic custom dimensions for l4-match byte extraction.
/// Index 15 and 23-31 are reserved for future use.
///
/// The DfsState.fields array is [u32; 32], indexed by these discriminants.
/// The eBPF walker masks with `& 0x1F` to prove bounds for the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum FieldDim {
    // Phase 1: L3/L4 header fields (unconditional extraction)
    Proto = 0,
    SrcIp = 1,
    DstIp = 2,
    L4Word0 = 3,   // src_port or icmp type/code
    L4Word1 = 4,   // dst_port or icmp checksum
    // Phase 2: extended header fields (extracted alongside phase 1)
    TcpFlags = 5,
    Ttl = 6,
    DfBit = 7,
    TcpWindow = 8,
    // IPv4 header fingerprinting fields (bytes 1-7 of IP header)
    IpId = 9,        // bytes 4-5: IP Identification (u16, OS fingerprint)
    IpLen = 10,      // bytes 2-3: IP Total Length (u16, flood detection)
    Dscp = 11,       // byte 1 upper 6 bits: Differentiated Services Code Point (0-63)
    Ecn = 12,        // byte 1 lower 2 bits: Explicit Congestion Notification (0-3)
    MfBit = 13,      // byte 6 bit 13: More Fragments flag (0 or 1)
    FragOffset = 14,  // bytes 6-7 lower 13 bits: Fragment offset (0-8191, in 8-byte units)
    // Dynamic custom dimensions for l4-match (1-4 byte fan-out)
    // Gap at 15 (reserved) separates static from custom dims.
    Custom0 = 16,
    Custom1 = 17,
    Custom2 = 18,
    Custom3 = 19,
    Custom4 = 20,
    Custom5 = 21,
    Custom6 = 22,
}

impl FieldDim {
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
            FieldDim::IpId => "ip_id",
            FieldDim::IpLen => "ip_len",
            FieldDim::Dscp => "dscp",
            FieldDim::Ecn => "ecn",
            FieldDim::MfBit => "mf_bit",
            FieldDim::FragOffset => "frag_offset",
            FieldDim::Custom0 => "custom0",
            FieldDim::Custom1 => "custom1",
            FieldDim::Custom2 => "custom2",
            FieldDim::Custom3 => "custom3",
            FieldDim::Custom4 => "custom4",
            FieldDim::Custom5 => "custom5",
            FieldDim::Custom6 => "custom6",
        }
    }

    /// All static dimensions (does NOT include Custom0-6)
    pub fn all() -> &'static [FieldDim] {
        &[
            FieldDim::Proto, FieldDim::SrcIp, FieldDim::DstIp,
            FieldDim::L4Word0, FieldDim::L4Word1,
            FieldDim::TcpFlags, FieldDim::Ttl, FieldDim::DfBit, FieldDim::TcpWindow,
            FieldDim::IpId, FieldDim::IpLen, FieldDim::Dscp,
            FieldDim::Ecn, FieldDim::MfBit, FieldDim::FragOffset,
        ]
    }

    /// Check if this is a custom (dynamic) dimension
    pub fn is_custom(&self) -> bool {
        (*self as u8) >= 16
    }

    /// Get the custom dim slot index (0-6), or None if static
    pub fn custom_index(&self) -> Option<usize> {
        let idx = *self as u8;
        if idx >= 16 && idx <= 22 { Some((idx - 16) as usize) } else { None }
    }

    /// Get a custom dim from a slot index (0-6)
    pub fn from_custom_index(index: usize) -> Option<FieldDim> {
        match index {
            0 => Some(FieldDim::Custom0),
            1 => Some(FieldDim::Custom1),
            2 => Some(FieldDim::Custom2),
            3 => Some(FieldDim::Custom3),
            4 => Some(FieldDim::Custom4),
            5 => Some(FieldDim::Custom5),
            6 => Some(FieldDim::Custom6),
            _ => None,
        }
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
            FieldDim::DfBit | FieldDim::MfBit => {
                if value == 1 {
                    if matches!(self, FieldDim::DfBit) { "DF".to_string() } else { "MF".to_string() }
                } else {
                    if matches!(self, FieldDim::DfBit) { "!DF".to_string() } else { "!MF".to_string() }
                }
            }
            FieldDim::Dscp => format!("dscp:{}", value),
            FieldDim::Ecn => match value {
                0 => "not-ECT".to_string(),
                1 => "ECT(1)".to_string(),
                2 => "ECT(0)".to_string(),
                3 => "CE".to_string(),
                v => format!("{}", v),
            },
            d if d.is_custom() => format!("0x{:x}", value),
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
            FieldDim::IpId => "ip-id",
            FieldDim::IpLen => "ip-len",
            FieldDim::Dscp => "dscp",
            FieldDim::Ecn => "ecn",
            FieldDim::MfBit => "mf",
            FieldDim::FragOffset => "frag-offset",
            FieldDim::Custom0 => "custom0",
            FieldDim::Custom1 => "custom1",
            FieldDim::Custom2 => "custom2",
            FieldDim::Custom3 => "custom3",
            FieldDim::Custom4 => "custom4",
            FieldDim::Custom5 => "custom5",
            FieldDim::Custom6 => "custom6",
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
            d if d.is_custom() => format!("0x{:x}", value),
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
    /// Bytes at a transport-relative offset (offset, length 1-4 bytes)
    /// Used for l4-match predicates. Resolved to Dim(CustomN) during compilation.
    L4Byte { offset: u16, length: u8 },
}

/// A matching predicate for a single field constraint.
/// Predicates define match conditions on packet fields.
/// Each predicate maps 1:1 to a single DAG operation — no hidden expansion.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Predicate {
    /// Exact equality: field == value
    Eq(FieldRef, u32),
    /// Greater than: field > value
    Gt(FieldRef, u32),
    /// Less than: field < value
    Lt(FieldRef, u32),
    /// Greater than or equal: field >= value
    Gte(FieldRef, u32),
    /// Less than or equal: field <= value
    Lte(FieldRef, u32),
    /// Masked equality: (field_value & mask) == expected
    /// Replaces the old `Mask` variant which used `!= 0` semantics.
    MaskEq(FieldRef, u32, u32),  // (field, mask, expected)
    /// Pattern guard: byte pattern match at transport offset.
    /// Compiled form — the u32 is the pattern index into BYTE_PATTERNS map.
    /// Treated as a guard edge (RANGE_OP_PATTERN) on the specified dimension.
    PatternGuard(FieldDim, u32),  // (dimension for placement, pattern_index)
    /// Raw byte match: carries a complete BytePattern for >4 byte matches.
    /// This is an intermediate form created by the sidecar parser and consumed by
    /// the compiler's allocate_patterns() to produce PatternGuard entries.
    /// Never survives compilation — always converted to PatternGuard.
    RawByteMatch(Box<BytePattern>),
    // Future:
    // Not(Box<Predicate>),
    // Or(Vec<Predicate>),
}

impl Predicate {
    /// Convenience: create an Eq predicate on a parsed header field.
    pub fn eq(dim: FieldDim, value: u32) -> Self {
        Predicate::Eq(FieldRef::Dim(dim), value)
    }

    /// Extract (FieldDim, value) if this is an Eq on a Dim ref.
    /// Returns `None` for In, range predicates, and other variants.
    pub fn as_eq_dim(&self) -> Option<(FieldDim, u32)> {
        match self {
            Predicate::Eq(FieldRef::Dim(dim), value) => Some((*dim, *value)),
            _ => None,
        }
    }

    /// Check if this predicate constrains the given dimension (any predicate type).
    pub fn constrains_dim(&self, dim: FieldDim) -> bool {
        self.field_dim() == Some(dim)
    }

    /// If this is a guard predicate (range or mask) on the given dimension,
    /// return (guard_op, threshold/mask).
    /// Returns None for Eq, In, or predicates on other dimensions.
    /// Renamed from `as_range_on_dim` to reflect that it covers both ranges and masks.
    pub fn as_guard_on_dim(&self, dim: FieldDim) -> Option<(u8, u32)> {
        match self {
            Predicate::Gt(FieldRef::Dim(d), val) if *d == dim => Some((RANGE_OP_GT, *val)),
            Predicate::Lt(FieldRef::Dim(d), val) if *d == dim => Some((RANGE_OP_LT, *val)),
            Predicate::Gte(FieldRef::Dim(d), val) if *d == dim => Some((RANGE_OP_GTE, *val)),
            Predicate::Lte(FieldRef::Dim(d), val) if *d == dim => Some((RANGE_OP_LTE, *val)),
            Predicate::MaskEq(FieldRef::Dim(d), mask, expected) if *d == dim => {
                // Pack mask in upper 16 bits, expected in lower 16 bits
                let packed = (*mask << 16) | (*expected & 0xFFFF);
                Some((RANGE_OP_MASK_EQ, packed))
            }
            Predicate::PatternGuard(d, pattern_idx) if *d == dim => {
                Some((RANGE_OP_PATTERN, *pattern_idx))
            }
            _ => None,
        }
    }

    /// Legacy alias for as_guard_on_dim (for backwards compatibility)
    #[deprecated(note = "use as_guard_on_dim instead")]
    pub fn as_range_on_dim(&self, dim: FieldDim) -> Option<(u8, u32)> {
        self.as_guard_on_dim(dim)
    }

    /// Get the field dimension this predicate tests (works for all predicate types).
    /// Returns None for unresolved L4Byte refs (must be resolved before compilation).
    pub fn field_dim(&self) -> Option<FieldDim> {
        match self {
            Predicate::Eq(FieldRef::Dim(dim), _) 
            | Predicate::Gt(FieldRef::Dim(dim), _)
            | Predicate::Lt(FieldRef::Dim(dim), _)
            | Predicate::Gte(FieldRef::Dim(dim), _)
            | Predicate::Lte(FieldRef::Dim(dim), _)
            | Predicate::MaskEq(FieldRef::Dim(dim), _, _) => Some(*dim),
            Predicate::PatternGuard(dim, _) => Some(*dim),
            Predicate::RawByteMatch(_) => None, // Pre-compilation form, no fixed dim
            _ => None,
        }
    }
    
    /// Get the FieldRef this predicate operates on.
    /// PatternGuard/RawByteMatch returns a static Dim ref for placement dimension.
    pub fn field_ref(&self) -> &FieldRef {
        // Static refs for PatternGuard/RawByteMatch
        static PATTERN_REF: FieldRef = FieldRef::Dim(FieldDim::Proto);
        match self {
            Predicate::Eq(fr, _)
            | Predicate::Gt(fr, _)
            | Predicate::Lt(fr, _)
            | Predicate::Gte(fr, _)
            | Predicate::Lte(fr, _)
            | Predicate::MaskEq(fr, _, _) => fr,
            Predicate::PatternGuard(_, _) | Predicate::RawByteMatch(_) => &PATTERN_REF,
        }
    }

    /// Render this predicate as an s-expression clause.
    pub fn to_sexpr_clause(&self) -> String {
        match self {
            Predicate::Eq(FieldRef::Dim(dim), value) => {
                format!("(= {} {})", dim.sexpr_name(), dim.sexpr_value(*value))
            }
            Predicate::Gt(FieldRef::Dim(dim), value) => {
                format!("(> {} {})", dim.sexpr_name(), dim.sexpr_value(*value))
            }
            Predicate::Lt(FieldRef::Dim(dim), value) => {
                format!("(< {} {})", dim.sexpr_name(), dim.sexpr_value(*value))
            }
            Predicate::Gte(FieldRef::Dim(dim), value) => {
                format!("(>= {} {})", dim.sexpr_name(), dim.sexpr_value(*value))
            }
            Predicate::Lte(FieldRef::Dim(dim), value) => {
                format!("(<= {} {})", dim.sexpr_name(), dim.sexpr_value(*value))
            }
            Predicate::MaskEq(FieldRef::Dim(dim), mask, expected) => {
                format!("(mask-eq {} 0x{:x} 0x{:x})", dim.sexpr_name(), mask, expected)
            }
            // L4Byte refs (unresolved — should be resolved before display in normal flow)
            Predicate::Eq(FieldRef::L4Byte { offset, length }, value) => {
                format!("(l4-match {} 0x{:0width$x} \"FF\")", offset, value, width = (*length as usize) * 2)
            }
            Predicate::MaskEq(FieldRef::L4Byte { offset, .. }, mask, expected) => {
                format!("(l4-match {} 0x{:x} 0x{:x})", offset, expected, mask)
            }
            Predicate::PatternGuard(dim, idx) => {
                format!("(pattern-guard {} #{})", dim.sexpr_name(), idx)
            }
            Predicate::RawByteMatch(pat) => {
                let match_hex: String = pat.match_bytes[..pat.length as usize]
                    .iter().map(|b| format!("{:02x}", b)).collect();
                let mask_hex: String = pat.mask_bytes[..pat.length as usize]
                    .iter().map(|b| format!("{:02x}", b)).collect();
                format!("(l4-match {} \"{}\" \"{}\")", pat.offset, match_hex, mask_hex)
            }
            _ => format!("(unknown-predicate)")
        }
    }
}

/// Number of static (fixed) dispatch dimensions (Proto..FragOffset = 0..14)
pub const NUM_DIMENSIONS: usize = 15;

/// Maximum dimension index (0-31, fits DfsState.fields[u32; 32])
/// eBPF walker masks with `& 0x1F` to prove bounds for the verifier.
pub const MAX_DIM: u8 = 32;

/// Number of custom dimension slots available for l4-match fan-out (slots 16-22)
pub const NUM_CUSTOM_DIMS: usize = 7;

/// Token bucket state (must match eBPF struct)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TokenBucket {
    pub rate_pps: u32,
    pub tokens: u32,
    pub last_update_ns: u64,
    /// Fractional token accumulator in "nano-token" units (rate_pps * ns).
    /// Rolls over at NS_PER_SEC, producing one whole token per rollover.
    /// This preserves sub-token remainders without runtime division.
    pub credit: u64,
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

/// Range operator constants (must match eBPF)
pub const RANGE_OP_NONE: u8 = 0;
pub const RANGE_OP_GT: u8 = 1;
pub const RANGE_OP_LT: u8 = 2;
pub const RANGE_OP_GTE: u8 = 3;
pub const RANGE_OP_LTE: u8 = 4;
pub const RANGE_OP_MASK_EQ: u8 = 5;
pub const RANGE_OP_PATTERN: u8 = 6;

/// Maximum range edges per tree node
pub const MAX_RANGE_EDGES: usize = 2;

/// Node in the decision tree (must match eBPF TreeNode exactly).
///
/// Each node optionally branches on a dimension (specific edges via TREE_EDGES,
/// wildcard child, and up to MAX_RANGE_EDGES range-guarded children).
/// Range edges are evaluated at runtime: if packet_value OP threshold,
/// the range child is pushed onto the DFS stack.
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
    // Range edges (up to 2 per node)
    pub range_count: u8,
    pub range_op_0: u8,
    pub range_op_1: u8,
    pub _range_pad: u8,
    pub range_val_0: u32,
    pub range_child_0: u32,
    pub range_val_1: u32,
    pub range_child_1: u32,
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
            range_count: 0,
            range_op_0: RANGE_OP_NONE,
            range_op_1: RANGE_OP_NONE,
            _range_pad: 0,
            range_val_0: 0,
            range_child_0: 0,
            range_val_1: 0,
            range_child_1: 0,
        }
    }
}

/// Configuration for a custom dimension slot (for CUSTOM_DIM_CONFIG BPF map).
/// Each entry tells the eBPF extractor what to read at what offset.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CustomDimEntry {
    /// Offset from transport pointer
    pub offset: u16,
    /// Number of bytes to read (1, 2, or 4)
    pub length: u8,
    pub _pad: u8,
}

unsafe impl aya::Pod for CustomDimEntry {}

/// Maximum length of a byte pattern for l4-match
pub const MAX_PATTERN_LEN: usize = 64;

/// Maximum number of byte pattern entries in the BYTE_PATTERNS map.
/// 65536 entries at 132 bytes each = ~8.5 MB of BPF map memory.
/// Supports massive multi-tenant deployments with many byte match rules.
pub const MAX_BYTE_PATTERNS: u32 = 65536;

/// A byte pattern for multi-byte matching at a transport-relative offset.
/// Stored in the BYTE_PATTERNS BPF map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BytePattern {
    /// Offset from transport pointer
    pub offset: u16,
    /// Number of bytes to compare (1-64)
    pub length: u8,
    pub _pad: u8,
    /// Expected byte values (pre-masked: match_bytes[i] = expected[i] & mask[i])
    pub match_bytes: [u8; MAX_PATTERN_LEN],
    /// Mask bytes: which bits matter (1 = compare, 0 = ignore)
    pub mask_bytes: [u8; MAX_PATTERN_LEN],
}

impl Default for BytePattern {
    fn default() -> Self {
        Self {
            offset: 0,
            length: 0,
            _pad: 0,
            match_bytes: [0u8; MAX_PATTERN_LEN],
            mask_bytes: [0u8; MAX_PATTERN_LEN],
        }
    }
}

unsafe impl aya::Pod for BytePattern {}

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
/// Each constraint is a `Predicate` (Eq or In).
/// Unconstrained dimensions get wildcard traversal in the tree.
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
            actions: vec![RuleAction::drop()], 
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
                Predicate::Gt(FieldRef::Dim(dim), val) => {
                    sorted_parts.push(format!("gt-{}-{}", *dim as u8, val));
                }
                Predicate::Lt(FieldRef::Dim(dim), val) => {
                    sorted_parts.push(format!("lt-{}-{}", *dim as u8, val));
                }
                Predicate::Gte(FieldRef::Dim(dim), val) => {
                    sorted_parts.push(format!("gte-{}-{}", *dim as u8, val));
                }
                Predicate::Lte(FieldRef::Dim(dim), val) => {
                    sorted_parts.push(format!("lte-{}-{}", *dim as u8, val));
                }
                Predicate::MaskEq(FieldRef::Dim(dim), mask, expected) => {
                    sorted_parts.push(format!("maskeq-{}-{}-{}", *dim as u8, mask, expected));
                }
                // L4Byte predicates (may be pre-resolution)
                Predicate::Eq(FieldRef::L4Byte { offset, length }, val) => {
                    sorted_parts.push(format!("l4eq-{}-{}-{}", offset, length, val));
                }
                Predicate::MaskEq(FieldRef::L4Byte { offset, length }, mask, expected) => {
                    sorted_parts.push(format!("l4maskeq-{}-{}-{}-{}", offset, length, mask, expected));
                }
                Predicate::PatternGuard(dim, idx) => {
                    sorted_parts.push(format!("patguard-{}-{}", *dim as u8, idx));
                }
                Predicate::RawByteMatch(pat) => {
                    let match_hex: String = pat.match_bytes[..pat.length as usize]
                        .iter().map(|b| format!("{:02x}", b)).collect();
                    let mask_hex: String = pat.mask_bytes[..pat.length as usize]
                        .iter().map(|b| format!("{:02x}", b)).collect();
                    sorted_parts.push(format!("rawbyte-{}-{}-{}-{}", pat.offset, pat.length, match_hex, mask_hex));
                }
                _ => {
                    // Other predicate/field combos — include a generic hash
                    sorted_parts.push(format!("{:?}", pred));
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
                RuleAction::Pass { name } => {
                    let name_str = name.as_ref()
                        .map(|(ns, n)| format!("{}:{}", ns, n))
                        .unwrap_or_default();
                    format!("pass:{}", name_str)
                }
                RuleAction::Drop { name } => {
                    let name_str = name.as_ref()
                        .map(|(ns, n)| format!("{}:{}", ns, n))
                        .unwrap_or_default();
                    format!("drop:{}", name_str)
                }
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

    /// Compute the bucket key for this rule (for rate limiters, counters, and drops).
    /// 
    /// Named actions (drop, rate-limit, or count with :name ["ns" "name"]) share a bucket/counter
    /// across all rules with the same namespace and name. Unnamed actions get a stable key
    /// derived from constraints only, so bucket state persists across pps changes.
    /// 
    /// Returns the key (u32) for the first drop, rate-limit, or count action, or None if neither.
    pub fn bucket_key(&self) -> Option<u32> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        // Find first action with a bucket (pass, drop, rate-limit, or count)
        for action in &self.actions {
            match action {
                RuleAction::Pass { name } | RuleAction::Drop { name } | RuleAction::RateLimit { pps: _, name } | RuleAction::Count { name } => {
                    if let Some((namespace, name)) = name {
                        // Named bucket: hash namespace + name
                        let mut hasher = DefaultHasher::new();
                        namespace.hash(&mut hasher);
                        name.hash(&mut hasher);
                        let h = hasher.finish() as u32;
                        return Some(if h == 0 { 1 } else { h });
                    } else {
                        // Unnamed bucket: hash constraints only for stability
                        // across pps changes (preserves eBPF token bucket state)
                        return Some(self.constraints_key());
                    }
                }
            }
        }
        None
    }

    /// Stable key derived from constraints only (ignores actions/priority).
    /// Used for unnamed bucket keys so token bucket state persists when pps changes.
    fn constraints_key(&self) -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        let edn = self.constraints_to_edn();
        edn.hash(&mut hasher);
        let h = hasher.finish() as u32;
        if h == 0 { 1 } else { h }
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
                Predicate::Gt(FieldRef::Dim(dim), val) => {
                    let (dim_name, val_str) = Self::format_dim_value(*dim, *val);
                    parts.push(format!("(> {} {})", dim_name, val_str));
                }
                Predicate::Lt(FieldRef::Dim(dim), val) => {
                    let (dim_name, val_str) = Self::format_dim_value(*dim, *val);
                    parts.push(format!("(< {} {})", dim_name, val_str));
                }
                Predicate::Gte(FieldRef::Dim(dim), val) => {
                    let (dim_name, val_str) = Self::format_dim_value(*dim, *val);
                    parts.push(format!("(>= {} {})", dim_name, val_str));
                }
                Predicate::Lte(FieldRef::Dim(dim), val) => {
                    let (dim_name, val_str) = Self::format_dim_value(*dim, *val);
                    parts.push(format!("(<= {} {})", dim_name, val_str));
                }
                Predicate::MaskEq(FieldRef::Dim(dim), mask, expected) => {
                    let dim_name = Self::dim_name(*dim);
                    parts.push(format!("(mask-eq {} 0x{:x} 0x{:x})", dim_name, mask, expected));
                }
                _ => {
                    parts.push(pred.to_sexpr_clause());
                }
            }
        }
        
        format!("[{}]", parts.join(" "))
    }

    /// Helper: format dimension name
    fn dim_name(dim: FieldDim) -> &'static str {
        dim.sexpr_name()
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
            FieldDim::Ttl | FieldDim::DfBit | FieldDim::TcpWindow |
            FieldDim::IpId | FieldDim::IpLen | FieldDim::Dscp |
            FieldDim::Ecn | FieldDim::MfBit | FieldDim::FragOffset => val.to_string(),
            d if d.is_custom() => format!("0x{:x}", val),
            _ => val.to_string(),
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

    /// Human-readable description
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
            RuleAction::Pass { name: None } => "(pass)".to_string(),
            RuleAction::Pass { name: Some((ns, n)) } => {
                format!("(pass :name [\"{}\", \"{}\"])", ns, n)
            }
            RuleAction::Drop { name: None } => "(drop)".to_string(),
            RuleAction::Drop { name: Some((ns, n)) } => {
                format!("(drop :name [\"{}\", \"{}\"])", ns, n)
            }
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
        // Use sorted constraints for canonical ordering
        let mut sorted: Vec<&Predicate> = self.constraints.iter().collect();
        sorted.sort_by_key(|p| {
            p.field_dim().map(|d| d as u8).unwrap_or(255)
        });
        
        let constraints_str = if sorted.is_empty() {
            "[]".to_string()
        } else {
            let clauses: Vec<String> = sorted.iter()
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
        
        // Use sorted constraints for canonical ordering
        let mut sorted: Vec<&Predicate> = self.constraints.iter().collect();
        sorted.sort_by_key(|p| {
            p.field_dim().map(|d| d as u8).unwrap_or(255)
        });
        
        let constraints_str = if sorted.is_empty() {
            "[]".to_string()
        } else if sorted.len() == 1 {
            format!("[{}]", sorted[0].to_sexpr_clause())
        } else {
            let clauses: Vec<String> = sorted.iter()
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

pub const SAMPLE_DATA_SIZE: usize = 2048;

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
    // IPv4 header fingerprinting fields
    pub ip_id: u16,
    pub ip_len: u16,
    pub dscp: u8,
    pub ecn: u8,
    pub mf_bit: u8,
    pub _pad_fp: u8,
    pub frag_offset: u16,
    pub _pad_fp2: u16,
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

    /// Calculate the offset to L4 payload within sample.data.
    /// Returns None if the packet is too short or malformed.
    pub fn l4_payload_offset(&self) -> Option<usize> {
        const ETH_HDR_LEN: usize = 14;
        
        if self.cap_len < (ETH_HDR_LEN + 20) as u32 {
            return None; // Too short for IP header
        }

        // Parse IP header length from IHL field
        let ihl = (self.data[ETH_HDR_LEN] & 0x0F) as usize;
        let ip_hdr_len = ihl * 4;
        
        if ip_hdr_len < 20 || ip_hdr_len > 60 {
            return None; // Invalid IHL
        }

        let l4_start = ETH_HDR_LEN + ip_hdr_len;
        
        if self.cap_len < l4_start as u32 {
            return None; // Packet truncated before L4
        }

        // Parse L4 header length
        let l4_hdr_len = match self.protocol {
            6 => {
                // TCP: data offset in upper 4 bits of byte 12
                if self.cap_len < (l4_start + 13) as u32 {
                    return None;
                }
                let data_offset = (self.data[l4_start + 12] >> 4) as usize;
                data_offset * 4
            }
            17 => 8, // UDP header is always 8 bytes
            _ => return None, // Only TCP/UDP supported
        };

        let payload_start = l4_start + l4_hdr_len;
        
        if payload_start >= self.cap_len as usize {
            return None; // No payload
        }

        Some(payload_start)
    }

    /// Return the L4 header length in bytes, derived from the packet itself.
    /// TCP: parsed from data-offset field (min 20). UDP: 8. Returns None for other protos.
    pub fn l4_header_len(&self) -> Option<usize> {
        const ETH_HDR_LEN: usize = 14;
        if self.cap_len < (ETH_HDR_LEN + 20) as u32 {
            return None;
        }
        let ihl = (self.data[ETH_HDR_LEN] & 0x0F) as usize;
        let ip_hdr_len = ihl * 4;
        if ip_hdr_len < 20 || ip_hdr_len > 60 {
            return None;
        }
        let l4_start = ETH_HDR_LEN + ip_hdr_len;
        match self.protocol {
            6 => {
                if self.cap_len < (l4_start + 13) as u32 { return None; }
                let data_offset = (self.data[l4_start + 12] >> 4) as usize;
                if data_offset < 5 { return None; }
                Some(data_offset * 4)
            }
            17 => Some(8),
            _ => None,
        }
    }

    /// Get L4 payload slice from sample data.
    /// Returns empty slice if no payload is available.
    pub fn l4_payload(&self) -> &[u8] {
        self.l4_payload_offset()
            .map(|offset| {
                let end = std::cmp::min(self.cap_len as usize, SAMPLE_DATA_SIZE);
                &self.data[offset..end]
            })
            .unwrap_or(&[])
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
            // p0f-level fields: TTL stays discrete (64 vs 128 vs 255 are strong OS/attack
            // indicators — log-scale compresses exactly the signal we need for detection).
            ("ttl", WalkableValue::Scalar(ScalarValue::Int(self.ttl as i64))),
            ("df_bit", WalkableValue::Scalar(ScalarValue::Int(self.df_bit as i64))),
            // IPv4 header fingerprinting fields
            ("ip_id", WalkableValue::Scalar(ScalarValue::Int(self.ip_id as i64))),
            ("ip_len", WalkableValue::Scalar(ScalarValue::log(self.ip_len as f64))),
            ("dscp", WalkableValue::Scalar(ScalarValue::Int(self.dscp as i64))),
            ("ecn", WalkableValue::Scalar(ScalarValue::Int(self.ecn as i64))),
            ("mf_bit", WalkableValue::Scalar(ScalarValue::Int(self.mf_bit as i64))),
            ("frag_offset", WalkableValue::Scalar(ScalarValue::Int(self.frag_offset as i64))),
        ];
        // TCP-only fields
        if self.protocol == 6 {
            items.push(("tcp_flags", WalkableValue::Scalar(ScalarValue::Int(self.tcp_flags as i64))));
            items.push(("tcp_window", WalkableValue::Scalar(ScalarValue::log(self.tcp_window.max(1) as f64))));
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
        // p0f-level fields: TTL stays discrete (64 vs 128 vs 255 are strong OS/attack
        // indicators — log-scale compresses exactly the signal we need for detection).
        visitor("ttl", WalkableRef::int(self.ttl as i64));
        visitor("df_bit", WalkableRef::int(self.df_bit as i64));
        // IPv4 header fingerprinting fields
        visitor("ip_id", WalkableRef::int(self.ip_id as i64));
        visitor("ip_len", WalkableRef::Scalar(ScalarRef::log(self.ip_len as f64)));
        visitor("dscp", WalkableRef::int(self.dscp as i64));
        visitor("ecn", WalkableRef::int(self.ecn as i64));
        visitor("mf_bit", WalkableRef::int(self.mf_bit as i64));
        visitor("frag_offset", WalkableRef::int(self.frag_offset as i64));
        // TCP-only fields
        if self.protocol == 6 {
            visitor("tcp_flags", WalkableRef::int(self.tcp_flags as i64));
            visitor("tcp_window", WalkableRef::Scalar(ScalarRef::log(self.tcp_window.max(1) as f64)));
        }
    }
}

// =============================================================================
// Statistics
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
    /// Diagnostic: tree eval entered (STATS[8])
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

// =============================================================================
// VethFilter - Main API
// =============================================================================

pub struct VethFilter {
    bpf: Arc<RwLock<Ebpf>>,
    interface: String,
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

    pub async fn take_ring_buf(&self) -> Result<RingBuf<MapData>> {
        let mut bpf = self.bpf.write().await;
        let samples = bpf.take_map("SAMPLE_RING").context("SAMPLE_RING not found")?;
        RingBuf::try_from(samples).context("Failed to create ring buffer")
    }

    pub fn bpf(&self) -> Arc<RwLock<Ebpf>> { self.bpf.clone() }

    // =========================================================================
    // Tree Rete Engine Methods
    // =========================================================================

    /// Compile a set of rules into the tree engine and atomically flip.
    /// This is the primary API for the tree engine. The sidecar maintains
    /// its rule set and calls this whenever rules change.
    /// Returns the number of nodes in the compiled tree.
    pub async fn compile_and_flip_tree(&self, rules: &[RuleSpec]) -> Result<(usize, Vec<RuleManifestEntry>, Vec<(u32, u64)>)> {
        let mut bpf = self.bpf.write().await;
        let mut mgr = self.tree_manager.lock().await;
        mgr.compile_and_flip(rules, &mut bpf)
    }

    /// Serialize the last compiled DAG for visualization
    pub async fn serialize_dag(&self) -> Vec<tree::SerializableDagNode> {
        let mgr = self.tree_manager.lock().await;
        mgr.get_dag()
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
    fn test_rule_spec_simple() {
        let spec = RuleSpec::drop_field(FieldDim::Proto, 17);
        assert_eq!(spec.constraints.len(), 1);
        assert_eq!(spec.constraints[0], Predicate::eq(FieldDim::Proto, 17));
        assert_eq!(spec.actions.len(), 1);
        assert_eq!(spec.actions[0], RuleAction::drop());
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
        assert_eq!(spec.actions.len(), 1);
        assert_eq!(spec.actions[0], RuleAction::RateLimit { pps: 5000, name: None });
    }

    #[test]
    fn test_rule_spec_describe() {
        let spec = RuleSpec::compound(
            vec![
                Predicate::eq(FieldDim::Proto, 6),
                Predicate::eq(FieldDim::L4Word1, 80),
            ],
            RuleAction::drop(),
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
            actions: vec![RuleAction::pass()],
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
        assert_eq!(all.len(), 15);
        assert_eq!(all[0], FieldDim::Proto);
        assert_eq!(all[8], FieldDim::TcpWindow);
        assert_eq!(all[9], FieldDim::IpId);
        assert_eq!(all[14], FieldDim::FragOffset);
    }

    // =========================================================================
    // TokenBucket credit accumulator math
    // =========================================================================
    //
    // Pure-Rust mirror of the eBPF apply_tree_token_bucket logic.
    // This lets us verify the nano-token credit math without needing
    // eBPF infrastructure.

    const NS_PER_SEC: u64 = 1_000_000_000;

    /// Simulate a single packet arrival at `now_ns`.
    /// Returns true if the packet is ALLOWED, false if DROPPED.
    fn bucket_arrive(bucket: &mut TokenBucket, now_ns: u64) -> bool {
        if bucket.last_update_ns == 0 {
            bucket.last_update_ns = now_ns;
            bucket.tokens = bucket.rate_pps;
        }

        let elapsed_ns = now_ns.saturating_sub(bucket.last_update_ns);
        bucket.last_update_ns = now_ns;

        if bucket.rate_pps > 0 && elapsed_ns > 0 {
            let capped = if elapsed_ns > 2 * NS_PER_SEC {
                2 * NS_PER_SEC
            } else {
                elapsed_ns
            };
            bucket.credit += capped * bucket.rate_pps as u64;
            let tokens_to_add = (bucket.credit / NS_PER_SEC) as u32;
            if tokens_to_add > 0 {
                bucket.credit -= tokens_to_add as u64 * NS_PER_SEC;
                let new_tokens = bucket.tokens.saturating_add(tokens_to_add);
                bucket.tokens = if new_tokens > bucket.rate_pps {
                    bucket.rate_pps
                } else {
                    new_tokens
                };
            }
        }

        if bucket.tokens > 0 {
            bucket.tokens -= 1;
            bucket.allowed_count += 1;
            true
        } else {
            bucket.dropped_count += 1;
            false
        }
    }

    fn new_bucket(rate_pps: u32) -> TokenBucket {
        TokenBucket {
            rate_pps,
            tokens: 0,
            last_update_ns: 0,
            credit: 0,
            allowed_count: 0,
            dropped_count: 0,
        }
    }

    #[test]
    fn test_token_bucket_initial_burst() {
        // First packet initializes tokens to rate_pps.
        let mut b = new_bucket(1000);
        let allowed = bucket_arrive(&mut b, 1_000_000);
        assert!(allowed, "first packet should be allowed (initial burst)");
        assert_eq!(b.tokens, 999, "tokens should be rate_pps - 1 after first packet");
        assert_eq!(b.allowed_count, 1);
        assert_eq!(b.dropped_count, 0);
    }

    #[test]
    fn test_token_bucket_drain_and_refill() {
        // Drain all tokens, verify drops, then refill after 1 second.
        let mut b = new_bucket(10);
        let t0 = 1_000_000_000u64; // 1s

        // First packet initializes
        assert!(bucket_arrive(&mut b, t0));
        // Drain remaining 9
        for _ in 0..9 {
            assert!(bucket_arrive(&mut b, t0));
        }
        assert_eq!(b.tokens, 0);
        assert_eq!(b.allowed_count, 10);

        // Next packet at same time → drop
        assert!(!bucket_arrive(&mut b, t0));
        assert_eq!(b.dropped_count, 1);

        // 1 second later → refill to rate_pps (10)
        let t1 = t0 + NS_PER_SEC;
        assert!(bucket_arrive(&mut b, t1));
        // Should have refilled 10 tokens, consumed 1
        assert_eq!(b.tokens, 9);
        assert_eq!(b.allowed_count, 11);
    }

    #[test]
    fn test_token_bucket_fractional_preservation() {
        // With rate_pps=3, each packet needs 333.33ms of credit.
        // Send packets every 300ms — credit should accumulate across calls
        // and not be lost.
        let mut b = new_bucket(3);
        let t0 = NS_PER_SEC;

        // Initialize
        assert!(bucket_arrive(&mut b, t0));
        // Drain initial burst
        assert!(bucket_arrive(&mut b, t0));
        assert!(bucket_arrive(&mut b, t0));
        assert_eq!(b.tokens, 0);

        // 300ms later: 300ms * 3 = 900M credit. < 1B → no token yet.
        let t1 = t0 + 300_000_000;
        assert!(!bucket_arrive(&mut b, t1), "300ms: not enough for a token");
        assert_eq!(b.credit, 900_000_000);

        // Another 100ms later (400ms total from drain):
        // credit += 100ms * 3 = 300M → total 1.2B → 1 token, remainder 200M
        let t2 = t1 + 100_000_000;
        assert!(bucket_arrive(&mut b, t2), "400ms: exactly 1 token available");
        assert_eq!(b.credit, 200_000_000);
        assert_eq!(b.tokens, 0); // consumed the token immediately

        // Another 300ms: credit = 200M + 900M = 1.1B → 1 token, remainder 100M
        let t3 = t2 + 300_000_000;
        assert!(bucket_arrive(&mut b, t3), "700ms: another token from carryover");
        assert_eq!(b.credit, 100_000_000);
    }

    #[test]
    fn test_token_bucket_high_rate_precision() {
        // With rate_pps=20000, send 20000 packets over exactly 1 second
        // (50µs apart). All 20000 should be allowed if we include the
        // initial burst. Actually: initial burst = 20000, so first 20000
        // at t0 all pass. Then at t0+1s, another 20000 should pass.
        let rate = 20_000u32;
        let mut b = new_bucket(rate);
        let t0 = NS_PER_SEC;
        let interval_ns = NS_PER_SEC / rate as u64; // 50µs

        // Initialize and drain initial burst
        for i in 0..rate {
            let allowed = bucket_arrive(&mut b, t0 + i as u64); // all at ~t0
            assert!(allowed, "initial burst packet {i} should pass");
        }
        assert_eq!(b.allowed_count, rate as u64);
        assert_eq!(b.tokens, 0);

        // Now send 20000 packets evenly over the next second
        let mut allowed_in_second = 0u64;
        let mut dropped_in_second = 0u64;
        for i in 0..rate {
            let t = t0 + (i as u64 + 1) * interval_ns;
            if bucket_arrive(&mut b, t) {
                allowed_in_second += 1;
            } else {
                dropped_in_second += 1;
            }
        }

        // At exactly rate_pps packets/s, we should allow very close to all
        // (small rounding may cause 1-2 drops at boundaries).
        let tolerance = 2u64;
        assert!(
            allowed_in_second >= rate as u64 - tolerance,
            "expected ~{rate} allowed in 1s, got {allowed_in_second} (dropped {dropped_in_second})"
        );
    }

    #[test]
    fn test_token_bucket_overflow_cap() {
        // Elapsed > 2s should be capped to prevent u64 overflow.
        let mut b = new_bucket(1000);
        let t0 = NS_PER_SEC;
        bucket_arrive(&mut b, t0); // initialize
        // Drain all
        for _ in 0..999 {
            bucket_arrive(&mut b, t0);
        }

        // Jump forward 100 seconds — should cap refill at rate_pps (1000)
        let t1 = t0 + 100 * NS_PER_SEC;
        assert!(bucket_arrive(&mut b, t1));
        // Tokens should be capped at rate_pps, minus 1 for the packet we just sent
        assert_eq!(b.tokens, 999, "tokens capped at rate_pps after long gap");
    }

    #[test]
    fn test_token_bucket_zero_rate() {
        // rate_pps=0 → no tokens ever refilled, initial burst = 0 → all drops
        let mut b = new_bucket(0);
        assert!(!bucket_arrive(&mut b, NS_PER_SEC));
        assert!(!bucket_arrive(&mut b, 2 * NS_PER_SEC));
        assert_eq!(b.dropped_count, 2);
        assert_eq!(b.allowed_count, 0);
    }

    #[test]
    fn test_token_bucket_one_pps_exact() {
        // 1 pps: exactly 1 token per second.
        let mut b = new_bucket(1);
        let t0 = NS_PER_SEC;

        // Initialize → 1 token
        assert!(bucket_arrive(&mut b, t0));
        assert_eq!(b.tokens, 0);

        // 500ms later → no token (0.5 credit)
        assert!(!bucket_arrive(&mut b, t0 + 500_000_000));

        // Another 500ms (1s total) → 1 token
        assert!(bucket_arrive(&mut b, t0 + NS_PER_SEC));
        assert_eq!(b.tokens, 0);

        // 999ms later → no token
        assert!(!bucket_arrive(&mut b, t0 + NS_PER_SEC + 999_000_000));

        // 1ms more (2s total) → 1 token
        assert!(bucket_arrive(&mut b, t0 + 2 * NS_PER_SEC));
    }

    #[test]
    fn test_token_bucket_credit_rollover_exact() {
        // Verify that credit accumulates exactly and rolls over correctly.
        // rate_pps=7, NS_PER_SEC/7 ≈ 142857142.857ns per token.
        // After exactly 142857142ns, credit = 142857142 * 7 = 999999994 < 1B → no token.
        // After 142857143ns from last_update, credit += 1*7 = 999999994+7 = 1000000001 → 1 token,
        //   remainder = 1000000001 - 1000000000 = 1.
        let mut b = new_bucket(7);
        let t0 = NS_PER_SEC;

        // Initialize and drain
        for _ in 0..7 { bucket_arrive(&mut b, t0); }
        assert_eq!(b.tokens, 0);

        // Sub-token interval
        let almost = NS_PER_SEC / 7; // 142857142ns
        assert!(!bucket_arrive(&mut b, t0 + almost));
        assert_eq!(b.credit, almost * 7); // 999999994

        // One more nanosecond
        assert!(bucket_arrive(&mut b, t0 + almost + 1));
        assert_eq!(b.credit, 1, "remainder should be exactly 1 nano-token");
    }
}
