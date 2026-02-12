//! Veth Filter - Userspace loader and rule management
//!
//! Loads the XDP filter and provides an API for:
//! - Managing drop/rate-limit rules via bitmask Rete engine
//! - Reading statistics
//! - Receiving packet samples via ring buffer

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap, MapData, PerCpuArray, PerCpuValues, AsyncPerfEventArray},
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum RuleAction {
    Pass = 0,
    Drop = 1,
    RateLimit = 2,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

    /// Format a value as an s-expression atom (lower-case symbols where appropriate)
    pub fn sexpr_value(&self, value: u32) -> String {
        match self {
            FieldDim::SrcIp | FieldDim::DstIp => {
                let bytes = value.to_ne_bytes();
                format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
            }
            FieldDim::Proto => match value {
                1 => "icmp".to_string(),
                6 => "tcp".to_string(),
                17 => "udp".to_string(),
                v => format!("{}", v),
            },
            FieldDim::TcpFlags => format!("0x{:02x}", value),
            FieldDim::DfBit => if value == 1 { "true".to_string() } else { "false".to_string() },
            _ => format!("{}", value),
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
}

unsafe impl aya::Pod for TokenBucket {}

// =============================================================================
// Tree Rete Engine Types (must match eBPF structs exactly)
// =============================================================================

/// Blue/green slot size: max nodes per slot
pub const TREE_SLOT_SIZE: u32 = 250_000;

/// Sentinel: dimension value meaning "this is a leaf node"
pub const DIM_LEAF: u8 = 0xFF;

/// Action constants (must match eBPF)
pub const ACT_PASS: u8 = 0;
pub const ACT_DROP: u8 = 1;
pub const ACT_RATE_LIMIT: u8 = 2;

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

/// A rule specification: set of constraints + action.
/// Each constraint is (dimension, value) meaning "this field must equal this value".
/// Unconstrained dimensions get dont_care bits set.
#[derive(Debug, Clone)]
pub struct RuleSpec {
    /// Constraints: (dimension, expected_value). Unconstrained dims get dont_care.
    pub constraints: Vec<(FieldDim, u32)>,
    /// Action to take when all constraints match
    pub action: RuleAction,
    /// Rate limit PPS (only for RateLimit action)
    pub rate_pps: Option<u32>,
    /// Priority (0-255, higher = more important). Default 100.
    pub priority: u8,
}

impl RuleSpec {
    /// Create a simple single-field drop rule
    pub fn drop_field(dim: FieldDim, value: u32) -> Self {
        Self { constraints: vec![(dim, value)], action: RuleAction::Drop, rate_pps: None, priority: 100 }
    }

    /// Create a simple single-field rate limit rule
    pub fn rate_limit_field(dim: FieldDim, value: u32, pps: u32) -> Self {
        Self { constraints: vec![(dim, value)], action: RuleAction::RateLimit, rate_pps: Some(pps), priority: 100 }
    }

    /// Create a compound rule with multiple constraints (all must match)
    pub fn compound(constraints: Vec<(FieldDim, u32)>, action: RuleAction, rate_pps: Option<u32>) -> Self {
        Self { constraints, action, rate_pps, priority: 100 }
    }

    /// Create a rule with explicit priority
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Compute a stable canonical hash for this rule (for deduplication and rate state keying).
    /// Excludes rate_pps so the same logical rule with different rates deduplicates.
    pub fn canonical_hash(&self) -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        // Sort constraints for canonical ordering
        let mut sorted: Vec<(u8, u32)> = self.constraints.iter()
            .map(|(d, v)| (*d as u8, *v))
            .collect();
        sorted.sort();
        for (dim, val) in &sorted {
            dim.hash(&mut hasher);
            val.hash(&mut hasher);
        }
        (self.action as u8).hash(&mut hasher);
        // Truncate to u32 (non-zero)
        let h = hasher.finish() as u32;
        if h == 0 { 1 } else { h }
    }

    /// Whether this rule needs Phase 2 fields
    pub fn needs_phase2(&self) -> bool {
        self.constraints.iter().any(|(dim, _)| dim.is_phase2())
    }

    /// Human-readable description (legacy format)
    pub fn describe(&self) -> String {
        self.to_sexpr()
    }

    /// Emit rule as an s-expression in Clara-style LHS => RHS form.
    ///
    /// Single constraint:  `((= src-addr 10.0.0.100) => (drop))`
    /// Compound:           `((and (= proto udp) (= src-port 53)) => (rate-limit 1906))`
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
    /// ((and (= proto udp)
    ///       (= src-port 53))
    ///  =>
    ///  (rate-limit 1234))
    /// ```
    pub fn to_sexpr_pretty(&self) -> String {
        let (lhs, rhs, prio) = self.sexpr_parts();

        // For compound rules, break clauses across lines aligned after `(and `
        let lhs_pretty = if self.constraints.len() > 1 {
            let clauses: Vec<String> = self.constraints.iter()
                .map(|(dim, val)| format!("(= {} {})", dim.sexpr_name(), dim.sexpr_value(*val)))
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
            let (dim, val) = &self.constraints[0];
            format!("(= {} {})", dim.sexpr_name(), dim.sexpr_value(*val))
        } else {
            let clauses: Vec<String> = self.constraints.iter()
                .map(|(dim, val)| format!("(= {} {})", dim.sexpr_name(), dim.sexpr_value(*val)))
                .collect();
            format!("(and {})", clauses.join(" "))
        };

        let rhs = match self.action {
            RuleAction::Pass => "(pass)".to_string(),
            RuleAction::Drop => "(drop)".to_string(),
            RuleAction::RateLimit => format!("(rate-limit {})", self.rate_pps.unwrap_or(0)),
        };

        let prio = if self.priority != 100 { Some(self.priority) } else { None };
        (lhs, rhs, prio)
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
    pub _pad: u8,
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
}

impl Walkable for PacketSample {
    fn walk_type(&self) -> WalkType { WalkType::Map }
    fn walk_map_items(&self) -> Vec<(&str, WalkableValue)> {
        vec![
            ("src_ip", WalkableValue::Scalar(ScalarValue::String(self.src_ip_addr().to_string()))),
            ("dst_ip", WalkableValue::Scalar(ScalarValue::String(self.dst_ip_addr().to_string()))),
            ("src_port", WalkableValue::Scalar(ScalarValue::Int(self.src_port as i64))),
            ("dst_port", WalkableValue::Scalar(ScalarValue::Int(self.dst_port as i64))),
            ("protocol", WalkableValue::Scalar(ScalarValue::String(self.protocol_name().to_string()))),
            ("src_port_band", WalkableValue::Scalar(ScalarValue::String(self.src_port_band().to_string()))),
            ("dst_port_band", WalkableValue::Scalar(ScalarValue::String(self.dst_port_band().to_string()))),
            ("direction", WalkableValue::Scalar(ScalarValue::String(self.direction().to_string()))),
            ("size_class", WalkableValue::Scalar(ScalarValue::String(self.size_class().to_string()))),
            ("pkt_len", WalkableValue::Scalar(ScalarValue::log(self.pkt_len as f64))),
        ]
    }
    fn has_fast_visitor(&self) -> bool { true }
    fn walk_map_visitor(&self, visitor: &mut dyn FnMut(&str, WalkableRef<'_>)) {
        let src_ip_str = self.src_ip_addr().to_string();
        let dst_ip_str = self.dst_ip_addr().to_string();
        visitor("src_ip", WalkableRef::string(&src_ip_str));
        visitor("dst_ip", WalkableRef::string(&dst_ip_str));
        visitor("src_port", WalkableRef::int(self.src_port as i64));
        visitor("dst_port", WalkableRef::int(self.dst_port as i64));
        visitor("protocol", WalkableRef::string(self.protocol_name()));
        visitor("src_port_band", WalkableRef::string(self.src_port_band()));
        visitor("dst_port_band", WalkableRef::string(self.dst_port_band()));
        visitor("direction", WalkableRef::string(self.direction()));
        visitor("size_class", WalkableRef::string(self.size_class()));
        visitor("pkt_len", WalkableRef::Scalar(ScalarRef::log(self.pkt_len as f64)));
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
            action: self.action as u8, _pad: [0; 3],
            rate_pps: self.rate_pps.unwrap_or(0),
            tokens: self.rate_pps.unwrap_or(0),
            last_update_ns: 0, match_count: 0,
        }
    }
    pub fn rate_limit_src_ip(ip: Ipv4Addr, pps: u32) -> Self {
        Self { rule_type: RuleType::SrcIp, value: ip.to_string(), action: RuleAction::RateLimit, rate_pps: Some(pps) }
    }
    pub fn rate_limit_dst_port(port: u16, pps: u32) -> Self {
        Self { rule_type: RuleType::DstPort, value: port.to_string(), action: RuleAction::RateLimit, rate_pps: Some(pps) }
    }
    pub fn rate_limit_src_port(port: u16, pps: u32) -> Self {
        Self { rule_type: RuleType::SrcPort, value: port.to_string(), action: RuleAction::RateLimit, rate_pps: Some(pps) }
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

        Ok(Self {
            bpf: Arc::new(RwLock::new(bpf)),
            interface: interface.to_string(),
            allocated_bits: AtomicU64::new(0),
            tree_manager: tokio::sync::Mutex::new(tree::TreeManager::new()),
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
                    0 => RuleAction::Pass, 1 => RuleAction::Drop, 2 => RuleAction::RateLimit, _ => continue,
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
            meta_map.set(bit, RuleMeta {
                action: spec.action as u8,
                _pad: [0; 3],
                rate_pps: spec.rate_pps.unwrap_or(0),
            }, 0)?;
        }

        // 2. For each constraint, set the bit in the corresponding dispatch map
        for &(dim, value) in &spec.constraints {
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
            let constrained_dims: Vec<u8> = spec.constraints.iter().map(|(d, _)| *d as u8).collect();
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
        if spec.action == RuleAction::RateLimit {
            if let Some(pps) = spec.rate_pps {
                let mut rate_state: HashMap<_, u32, TokenBucket> = bpf
                    .map_mut("RATE_STATE").context("RATE_STATE not found")?.try_into()?;
                rate_state.insert(bit, TokenBucket { rate_pps: pps, tokens: pps, last_update_ns: 0 }, 0)?;
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
        for &(dim, value) in &spec.constraints {
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
        assert_eq!(spec.constraints[0], (FieldDim::Proto, 17));
        assert_eq!(spec.action, RuleAction::Drop);
        assert!(!spec.needs_phase2());
    }

    #[test]
    fn test_rule_spec_compound() {
        let spec = RuleSpec::compound(
            vec![
                (FieldDim::SrcIp, 0x0A000001),
                (FieldDim::L4Word1, 9999),
            ],
            RuleAction::RateLimit,
            Some(5000),
        );
        assert_eq!(spec.constraints.len(), 2);
        assert!(!spec.needs_phase2());
        assert_eq!(spec.action, RuleAction::RateLimit);
        assert_eq!(spec.rate_pps, Some(5000));
    }

    #[test]
    fn test_rule_spec_phase2() {
        let spec = RuleSpec::compound(
            vec![
                (FieldDim::SrcIp, 0x0A000001),
                (FieldDim::TcpFlags, 0x02), // SYN
            ],
            RuleAction::Drop,
            None,
        );
        assert!(spec.needs_phase2());
    }

    #[test]
    fn test_rule_spec_describe() {
        let spec = RuleSpec::compound(
            vec![
                (FieldDim::Proto, 6),
                (FieldDim::L4Word1, 80),
            ],
            RuleAction::Drop,
            None,
        );
        let desc = spec.describe();
        assert_eq!(desc, "((and (= proto tcp) (= dst-port 80)) => (drop))");
    }

    #[test]
    fn test_sexpr_single_constraint() {
        let spec = RuleSpec::drop_field(FieldDim::Proto, 17);
        assert_eq!(spec.to_sexpr(), "((= proto udp) => (drop))");
    }

    #[test]
    fn test_sexpr_rate_limit() {
        let ip = u32::from_ne_bytes([10, 0, 0, 100]);
        let spec = RuleSpec::compound(
            vec![(FieldDim::SrcIp, ip), (FieldDim::L4Word1, 9999)],
            RuleAction::RateLimit,
            Some(1906),
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
            "((= tcp-flags 0x02) => (drop) :priority 200)"
        );
    }

    #[test]
    fn test_sexpr_pass() {
        let spec = RuleSpec {
            constraints: vec![],
            action: RuleAction::Pass,
            rate_pps: None,
            priority: 100,
        };
        assert_eq!(spec.to_sexpr(), "(() => (pass))");
    }

    #[test]
    fn test_sexpr_pretty_compound() {
        let ip = u32::from_ne_bytes([10, 0, 0, 100]);
        let spec = RuleSpec::compound(
            vec![
                (FieldDim::Proto, 17),
                (FieldDim::SrcIp, ip),
                (FieldDim::L4Word1, 9999),
            ],
            RuleAction::RateLimit,
            Some(1906),
        );
        let pretty = spec.to_sexpr_pretty();
        assert_eq!(pretty,
            "((and (= proto udp)\n\
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
            "((= proto udp)\n\
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
