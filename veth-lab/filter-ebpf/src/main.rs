//! Veth Lab XDP Filter - Bitmask Rete Engine
//!
//! XDP program with bitmask-based Rete discrimination network.
//! Rules are managed by the userspace sidecar based on Holon detection.
//!
//! Architecture:
//! - Dispatch maps store u64 bitmasks (one bit per rule, up to 64 rules)
//! - DONT_CARE masks indicate which fields a rule ignores
//! - Evaluation: AND all dispatch results with dont_care fallbacks
//! - First set bit = matched rule -> look up action in RULE_META
//!
//! Features:
//! - Phase 1: proto, src/dst IP, L4 ports (unconditional)
//! - Phase 2: TCP flags, TTL, DF bit, TCP window (on-demand)
//! - DROP/RATE_LIMIT/PASS actions with token bucket rate limiting
//! - Packet sampling to userspace for Holon analysis
//! - Legacy flat rule path preserved for backward compatibility

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{Array, HashMap, PerCpuArray, PerfEventArray},
    programs::XdpContext,
};

// =============================================================================
// Legacy Rule Types (kept for backward compatibility)
// =============================================================================

#[repr(u8)]
pub enum RuleType {
    SrcIp = 0,
    DstIp = 1,
    SrcPort = 2,
    DstPort = 3,
    Protocol = 4,
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
pub enum RuleAction {
    Pass = 0,
    Drop = 1,
    RateLimit = 2,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleKey {
    pub rule_type: u8,
    pub _pad: [u8; 3],
    pub value: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleValue {
    pub action: u8,
    pub _pad: [u8; 3],
    pub rate_pps: u32,
    pub tokens: u32,
    pub last_update_ns: u64,
    pub match_count: u64,
}

// =============================================================================
// Bitmask Rete Engine Types
// =============================================================================

// Action constants
const ACT_PASS: u8 = 0;
const ACT_DROP: u8 = 1;
const ACT_RATE_LIMIT: u8 = 2;

/// Rule metadata: action + rate limit config. Indexed by bit position (0-63).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleMeta {
    pub action: u8,
    pub _pad: [u8; 3],
    pub rate_pps: u32,
}

/// Token bucket state for rate limiting
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TokenBucket {
    pub rate_pps: u32,
    pub tokens: u32,
    pub last_update_ns: u64,
}

// =============================================================================
// Tree Rete Engine Types
// =============================================================================

/// Number of field dimensions (Proto..TcpWindow = 0..8)
const NUM_DIMS: u8 = 9;

/// Sentinel: dimension value meaning "this is a leaf node, no more branching"
const DIM_LEAF: u8 = 0xFF;

/// Node in the decision tree. Stored in TREE_NODES array.
/// Each node optionally carries an action (match point) and optionally
/// branches on a dimension (specific edges in TREE_EDGES + wildcard child).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TreeNode {
    /// Which dimension to branch on (0-8), or DIM_LEAF (0xFF) = pure leaf.
    pub dimension: u8,
    /// 1 = this node has a match action
    pub has_action: u8,
    /// Action: ACT_PASS / ACT_DROP / ACT_RATE_LIMIT
    pub action: u8,
    /// Rule priority (higher = more important, 0-255)
    pub priority: u8,
    /// Rate limit PPS (for ACT_RATE_LIMIT)
    pub rate_pps: u32,
    /// Node ID for "any value" wildcard path (0 = none)
    pub wildcard_child: u32,
    /// Stable rule ID for rate state lookup (0 = no rule)
    pub rule_id: u32,
}

/// Edge key: (parent_node_id, field_value) -> child_node_id
/// Used as HashMap key for TREE_EDGES.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EdgeKey {
    pub parent: u32,
    pub value: u32,
}

/// Packet facts extracted in Phase 1 (lives on stack)
struct PktFacts {
    proto: u8,
    src_ip: u32,
    dst_ip: u32,
    l4_word0: u16,
    l4_word1: u16,
}

/// Phase 2 facts extracted on-demand
struct PktFacts2 {
    tcp_flags: u8,
    ttl: u8,
    df_bit: u8,
    tcp_window: u16,
}

// =============================================================================
// BPF Maps
// =============================================================================

/// Legacy rules map
#[map]
static RULES: HashMap<RuleKey, RuleValue> = HashMap::with_max_entries(1024, 0);

/// Stats counters (per-CPU)
/// 0: total, 1: passed, 2: dropped, 3: matched, 4: sampled, 5: rate_limited
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(8, 0);

/// Configuration
/// 0: sample_rate, 1: enforce_mode, 2: eval_mode (0=legacy, 1=bitmask rete)
#[map]
static CONFIG: PerCpuArray<u32> = PerCpuArray::with_max_entries(4, 0);

/// Perf event array for packet samples
#[map]
static SAMPLES: PerfEventArray<PacketSample> = PerfEventArray::new(0);

// =============================================================================
// Bitmask Rete Engine Maps
// =============================================================================

// Phase 1 dispatch maps: HashMap<u32, u64> - key is field value, value is rule bitmask
#[map]
static DISPATCH_PROTO: HashMap<u32, u64> = HashMap::with_max_entries(256, 0);
#[map]
static DISPATCH_SRC_IP: HashMap<u32, u64> = HashMap::with_max_entries(131072, 0);
#[map]
static DISPATCH_DST_IP: HashMap<u32, u64> = HashMap::with_max_entries(131072, 0);
#[map]
static DISPATCH_L4W0: HashMap<u32, u64> = HashMap::with_max_entries(65536, 0);
#[map]
static DISPATCH_L4W1: HashMap<u32, u64> = HashMap::with_max_entries(65536, 0);

// Phase 2 dispatch maps
#[map]
static DISPATCH_TCP_FLAGS: HashMap<u32, u64> = HashMap::with_max_entries(256, 0);
#[map]
static DISPATCH_TTL: HashMap<u32, u64> = HashMap::with_max_entries(256, 0);
#[map]
static DISPATCH_DF: HashMap<u32, u64> = HashMap::with_max_entries(4, 0);
#[map]
static DISPATCH_TCP_WIN: HashMap<u32, u64> = HashMap::with_max_entries(65536, 0);

/// Don't-care masks: Array<u64> indexed by dimension (0-8).
/// Bit set = rule does NOT constrain this dimension.
#[map]
static DONT_CARE: Array<u64> = Array::with_max_entries(16, 0);

/// Active rules bitmask (single entry at index 0)
#[map]
static ACTIVE_RULES: Array<u64> = Array::with_max_entries(1, 0);

/// Bitmask of rules that need Phase 2 evaluation (single entry at index 0)
#[map]
static NEEDS_PHASE2: Array<u64> = Array::with_max_entries(1, 0);

/// Rule metadata: Array<RuleMeta> indexed by bit position (0-63)
#[map]
static RULE_META: Array<RuleMeta> = Array::with_max_entries(64, 0);

/// Rate limit state for rules (keyed by rule bit position)
#[map]
static RATE_STATE: HashMap<u32, TokenBucket> = HashMap::with_max_entries(64, 0);

// =============================================================================
// Tree Rete Engine Maps (blue/green double-buffered)
// =============================================================================

/// Tree node pool: 2 slots × 250K = 500K entries.
/// Slot 0: nodes 1..250_000, Slot 1: nodes 250_001..500_000.
/// Node 0 is reserved as NULL sentinel.
#[map]
static TREE_NODES: Array<TreeNode> = Array::with_max_entries(500_000, 0);

/// Tree edges: (parent_node_id, field_value) -> child_node_id.
/// Both slots' edges coexist; they're namespaced by parent node ID range.
#[map]
static TREE_EDGES: HashMap<EdgeKey, u32> = HashMap::with_max_entries(1_000_000, 0);

/// Active root node ID (single entry at index 0).
/// 0 = no tree loaded (pass everything).
/// Points to root of currently active slot's tree.
#[map]
static TREE_ROOT: Array<u32> = Array::with_max_entries(1, 0);

/// Rate limit state for tree rules (keyed by stable rule_id, survives flips).
#[map]
static TREE_RATE_STATE: HashMap<u32, TokenBucket> = HashMap::with_max_entries(500_000, 0);

// =============================================================================
// Packet Sample Structure
// =============================================================================

const SAMPLE_DATA_SIZE: usize = 128;

#[repr(C)]
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

// =============================================================================
// Constants
// =============================================================================

const ETH_HDR_LEN: usize = 14;
const IP_HDR_MIN_LEN: usize = 20;
const ETH_P_IP: u16 = 0x0800;
const MS_PER_SEC: u64 = 1000;
const NS_PER_MS: u64 = 1_000_000;

// =============================================================================
// XDP Program
// =============================================================================

#[xdp]
pub fn veth_filter(ctx: XdpContext) -> u32 {
    match try_veth_filter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_veth_filter(ctx: XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = (data_end - data) as u32;

    // Increment total counter
    if let Some(total) = STATS.get_ptr_mut(0) {
        unsafe { *total += 1; }
    }

    // Bounds check for Ethernet header
    if data + ETH_HDR_LEN > data_end {
        return pass_packet();
    }

    // Check EtherType
    let ethertype = unsafe { u16::from_be(*((data + 12) as *const u16)) };
    if ethertype != ETH_P_IP {
        return pass_packet();
    }

    // Bounds check for IP header
    if data + ETH_HDR_LEN + IP_HDR_MIN_LEN > data_end {
        return pass_packet();
    }

    // Parse IP header
    let ip_hdr = data + ETH_HDR_LEN;
    let version_ihl = unsafe { *(ip_hdr as *const u8) };
    let ihl = ((version_ihl & 0x0F) as usize) * 4;

    if ihl < IP_HDR_MIN_LEN {
        return pass_packet();
    }

    if data + ETH_HDR_LEN + ihl > data_end {
        return pass_packet();
    }

    let protocol = unsafe { *((ip_hdr + 9) as *const u8) };
    let src_ip = unsafe { *((ip_hdr + 12) as *const u32) };
    let dst_ip = unsafe { *((ip_hdr + 16) as *const u32) };

    // Dual evaluation path
    let eval_mode = CONFIG.get(2).copied().unwrap_or(0);

    let (matched, action, should_drop, src_port, dst_port) = if eval_mode == 2 {
        // Tree Rete evaluation path (blue/green decision tree)
        let facts = extract_phase1(data_end, ip_hdr, ihl, protocol, src_ip, dst_ip);
        let sp = if protocol == 6 || protocol == 17 { facts.l4_word0 } else { 0 };
        let dp = if protocol == 6 || protocol == 17 { facts.l4_word1 } else { 0 };
        let (m, a, sd) = check_tree_rules(data_end, ip_hdr, ihl, &facts);
        (m, a, sd, sp, dp)
    } else if eval_mode == 1 {
        // Bitmask Rete evaluation path
        let facts = extract_phase1(data_end, ip_hdr, ihl, protocol, src_ip, dst_ip);
        let sp = if protocol == 6 || protocol == 17 { facts.l4_word0 } else { 0 };
        let dp = if protocol == 6 || protocol == 17 { facts.l4_word1 } else { 0 };
        let (m, a, sd) = check_rete_rules(data_end, ip_hdr, ihl, &facts);
        (m, a, sd, sp, dp)
    } else {
        // Legacy flat rules path
        let (sp, dp) = parse_ports(data_end, ip_hdr, ihl, protocol);
        let (m, a, sd) = check_rules_with_rate_limit(src_ip, dst_ip, sp, dp, protocol);
        (m, a, sd, sp, dp)
    };

    // Update matched counter
    if matched {
        if let Some(matched_cnt) = STATS.get_ptr_mut(3) {
            unsafe { *matched_cnt += 1; }
        }
    }

    // Sample the packet
    let sample_rate = CONFIG.get(0).copied().unwrap_or(0);
    let total_count = STATS.get(0).copied().unwrap_or(0);
    let should_sample = sample_rate > 0 && (total_count % sample_rate as u64 == 0);

    if should_sample {
        // Extract Phase 2 fields only for sampled packets (cheap at 1:N rate)
        let p2 = extract_phase2(data_end, ip_hdr, ihl, protocol);
        sample_packet(
            &ctx, pkt_len, src_ip, dst_ip, src_port, dst_port,
            protocol, matched, action, data, data_end,
            p2.tcp_flags, p2.ttl, p2.df_bit, p2.tcp_window,
        );
    }

    // Apply action
    let enforce = CONFIG.get(1).copied().unwrap_or(0) == 1;

    if matched && should_drop && enforce {
        if action == RuleAction::Drop as u8 {
            if let Some(dropped) = STATS.get_ptr_mut(2) {
                unsafe { *dropped += 1; }
            }
        } else if action == RuleAction::RateLimit as u8 {
            if let Some(rate_limited) = STATS.get_ptr_mut(5) {
                unsafe { *rate_limited += 1; }
            }
            if let Some(dropped) = STATS.get_ptr_mut(2) {
                unsafe { *dropped += 1; }
            }
        }
        return Ok(xdp_action::XDP_DROP);
    }

    pass_packet()
}

#[inline(always)]
fn pass_packet() -> Result<u32, ()> {
    if let Some(passed) = STATS.get_ptr_mut(1) {
        unsafe { *passed += 1; }
    }
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn parse_ports(data_end: usize, ip_hdr: usize, ihl: usize, protocol: u8) -> (u16, u16) {
    let transport = ip_hdr + ihl;
    if (protocol == 6 || protocol == 17) && transport + 4 <= data_end {
        let src_port = unsafe { u16::from_be(*((transport) as *const u16)) };
        let dst_port = unsafe { u16::from_be(*((transport + 2) as *const u16)) };
        (src_port, dst_port)
    } else {
        (0, 0)
    }
}

// =============================================================================
// Legacy flat rule evaluation (unchanged)
// =============================================================================

#[inline(always)]
fn check_rules_with_rate_limit(
    src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8,
) -> (bool, u8, bool) {
    let key = RuleKey { rule_type: RuleType::SrcIp as u8, _pad: [0; 3], value: src_ip };
    if let Some(should_drop) = check_single_rule(&key) {
        let action = unsafe { RULES.get(&key).map(|r| r.action).unwrap_or(0) };
        return (true, action, should_drop);
    }
    let key = RuleKey { rule_type: RuleType::DstIp as u8, _pad: [0; 3], value: dst_ip };
    if let Some(should_drop) = check_single_rule(&key) {
        let action = unsafe { RULES.get(&key).map(|r| r.action).unwrap_or(0) };
        return (true, action, should_drop);
    }
    if src_port != 0 {
        let key = RuleKey { rule_type: RuleType::SrcPort as u8, _pad: [0; 3], value: src_port as u32 };
        if let Some(should_drop) = check_single_rule(&key) {
            let action = unsafe { RULES.get(&key).map(|r| r.action).unwrap_or(0) };
            return (true, action, should_drop);
        }
    }
    if dst_port != 0 {
        let key = RuleKey { rule_type: RuleType::DstPort as u8, _pad: [0; 3], value: dst_port as u32 };
        if let Some(should_drop) = check_single_rule(&key) {
            let action = unsafe { RULES.get(&key).map(|r| r.action).unwrap_or(0) };
            return (true, action, should_drop);
        }
    }
    let key = RuleKey { rule_type: RuleType::Protocol as u8, _pad: [0; 3], value: protocol as u32 };
    if let Some(should_drop) = check_single_rule(&key) {
        let action = unsafe { RULES.get(&key).map(|r| r.action).unwrap_or(0) };
        return (true, action, should_drop);
    }
    (false, RuleAction::Pass as u8, false)
}

#[inline(always)]
fn check_single_rule(key: &RuleKey) -> Option<bool> {
    match RULES.get_ptr_mut(key) {
        Some(ptr) => {
            let rule = unsafe { &mut *ptr };
            rule.match_count = rule.match_count.wrapping_add(1);
            match rule.action {
                a if a == RuleAction::Pass as u8 => Some(false),
                a if a == RuleAction::Drop as u8 => Some(true),
                a if a == RuleAction::RateLimit as u8 => Some(apply_token_bucket(rule)),
                _ => Some(false),
            }
        }
        None => None,
    }
}

#[inline(always)]
fn apply_token_bucket(rule: &mut RuleValue) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    let rate_pps = rule.rate_pps;
    if rule.last_update_ns == 0 {
        rule.last_update_ns = now;
        rule.tokens = rate_pps;
    }
    let elapsed_ns = now.saturating_sub(rule.last_update_ns);
    let elapsed_ms = elapsed_ns / NS_PER_MS;
    if elapsed_ms > 0 && rate_pps > 0 {
        let tokens_to_add = ((elapsed_ms * rate_pps as u64) / MS_PER_SEC) as u32;
        if tokens_to_add > 0 {
            let new_tokens = rule.tokens.saturating_add(tokens_to_add);
            rule.tokens = if new_tokens > rate_pps { rate_pps } else { new_tokens };
            rule.last_update_ns = now;
        }
    }
    if rule.tokens > 0 { rule.tokens -= 1; false } else { true }
}

// =============================================================================
// Sampling (unchanged)
// =============================================================================

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn sample_packet(
    ctx: &XdpContext, pkt_len: u32, src_ip: u32, dst_ip: u32,
    src_port: u16, dst_port: u16, protocol: u8,
    matched: bool, action: u8, data: usize, data_end: usize,
    tcp_flags: u8, ttl: u8, df_bit: u8, tcp_window: u16,
) {
    let cap_len = if pkt_len as usize > SAMPLE_DATA_SIZE { SAMPLE_DATA_SIZE } else { pkt_len as usize };
    let mut sample = PacketSample {
        pkt_len, cap_len: cap_len as u32, src_ip, dst_ip, src_port, dst_port,
        protocol, matched_rule: if matched { 1 } else { 0 }, action_taken: action,
        tcp_flags, ttl, df_bit, tcp_window,
        data: [0u8; SAMPLE_DATA_SIZE],
    };
    let src = data as *const u8;
    for i in 0..SAMPLE_DATA_SIZE {
        if data + i < data_end { sample.data[i] = unsafe { *src.add(i) }; } else { break; }
    }
    let _ = SAMPLES.output(ctx, &sample, 0);
    if let Some(sampled) = STATS.get_ptr_mut(4) { unsafe { *sampled += 1; } }
}

// =============================================================================
// Bitmask Rete Engine
// =============================================================================

/// Phase 1 fact extraction - unconditional read of L3/L4 header fields
#[inline(always)]
fn extract_phase1(
    data_end: usize, ip_hdr: usize, ihl: usize,
    proto: u8, src_ip: u32, dst_ip: u32,
) -> PktFacts {
    let transport = ip_hdr + ihl;
    let (l4_word0, l4_word1) = if transport + 4 <= data_end {
        let w0 = unsafe { u16::from_be(*((transport) as *const u16)) };
        let w1 = unsafe { u16::from_be(*((transport + 2) as *const u16)) };
        (w0, w1)
    } else {
        (0, 0)
    };
    PktFacts { proto, src_ip, dst_ip, l4_word0, l4_word1 }
}

/// Phase 2 fact extraction - TCP flags, TTL, DF bit, TCP window
#[inline(always)]
fn extract_phase2(data_end: usize, ip_hdr: usize, ihl: usize, proto: u8) -> PktFacts2 {
    // TTL is always at IP+8
    let ttl = unsafe { *((ip_hdr + 8) as *const u8) };

    // DF bit is in IP flags at offset 6 (bit 6 of the flags/fragment field)
    let flags_frag = unsafe { u16::from_be(*((ip_hdr + 6) as *const u16)) };
    let df_bit = if (flags_frag & 0x4000) != 0 { 1u8 } else { 0u8 };

    // TCP-specific fields
    let transport = ip_hdr + ihl;
    let (tcp_flags, tcp_window) = if proto == 6 && transport + 20 <= data_end {
        // TCP flags at offset 13, window at offset 14
        let flags = unsafe { *((transport + 13) as *const u8) };
        let window = unsafe { u16::from_be(*((transport + 14) as *const u16)) };
        (flags, window)
    } else {
        (0, 0)
    };

    PktFacts2 { tcp_flags, ttl, df_bit, tcp_window }
}

/// Helper: look up a dispatch map and return the bitmask (0 if not found)
#[inline(always)]
fn dispatch_lookup(map: &HashMap<u32, u64>, key: u32) -> u64 {
    match unsafe { map.get(&key) } {
        Some(mask) => *mask,
        None => 0,
    }
}

/// Helper: get a dont_care mask for a dimension (returns 0 if not found)
#[inline(always)]
fn get_dont_care(dim: u32) -> u64 {
    DONT_CARE.get(dim).copied().unwrap_or(0)
}

/// Bitmask Rete evaluation: dispatch all dimensions, AND results, find match.
/// Returns (matched, action, should_drop).
#[inline(always)]
fn check_rete_rules(data_end: usize, ip_hdr: usize, ihl: usize, facts: &PktFacts) -> (bool, u8, bool) {
    // Start with all active rules
    let mut matched = ACTIVE_RULES.get(0).copied().unwrap_or(0);
    if matched == 0 {
        return (false, ACT_PASS, false);
    }

    // Phase 1 dispatch: narrow by each dimension
    // For each field: matched &= (dispatch_result | dont_care_for_this_dimension)
    matched &= dispatch_lookup(&DISPATCH_PROTO, facts.proto as u32) | get_dont_care(0);
    if matched == 0 { return (false, ACT_PASS, false); }

    matched &= dispatch_lookup(&DISPATCH_SRC_IP, facts.src_ip) | get_dont_care(1);
    if matched == 0 { return (false, ACT_PASS, false); }

    matched &= dispatch_lookup(&DISPATCH_DST_IP, facts.dst_ip) | get_dont_care(2);
    if matched == 0 { return (false, ACT_PASS, false); }

    matched &= dispatch_lookup(&DISPATCH_L4W0, facts.l4_word0 as u32) | get_dont_care(3);
    if matched == 0 { return (false, ACT_PASS, false); }

    matched &= dispatch_lookup(&DISPATCH_L4W1, facts.l4_word1 as u32) | get_dont_care(4);
    if matched == 0 { return (false, ACT_PASS, false); }

    // Check if any remaining candidates need Phase 2
    let needs_p2 = NEEDS_PHASE2.get(0).copied().unwrap_or(0);
    if matched & needs_p2 != 0 {
        // Phase 2 extraction (on-demand)
        let facts2 = extract_phase2(data_end, ip_hdr, ihl, facts.proto);

        matched &= dispatch_lookup(&DISPATCH_TCP_FLAGS, facts2.tcp_flags as u32) | get_dont_care(5);
        if matched == 0 { return (false, ACT_PASS, false); }

        matched &= dispatch_lookup(&DISPATCH_TTL, facts2.ttl as u32) | get_dont_care(6);
        if matched == 0 { return (false, ACT_PASS, false); }

        matched &= dispatch_lookup(&DISPATCH_DF, facts2.df_bit as u32) | get_dont_care(7);
        if matched == 0 { return (false, ACT_PASS, false); }

        matched &= dispatch_lookup(&DISPATCH_TCP_WIN, facts2.tcp_window as u32) | get_dont_care(8);
        if matched == 0 { return (false, ACT_PASS, false); }
    }

    // Find first matching rule: lowest set bit
    // In eBPF we can't use ctz() directly, so we check bits 0-7 explicitly
    // (covers the common case of <8 active rules; for more, extend)
    let rule_bit = find_first_set_bit(matched);
    if rule_bit >= 64 {
        return (false, ACT_PASS, false);
    }

    // Look up rule metadata
    let meta = match RULE_META.get(rule_bit) {
        Some(m) => *m,
        None => return (false, ACT_PASS, false),
    };

    let should_drop = if meta.action == ACT_PASS {
        false
    } else if meta.action == ACT_DROP {
        true
    } else if meta.action == ACT_RATE_LIMIT {
        apply_rete_token_bucket(rule_bit)
    } else {
        false
    };

    (true, meta.action, should_drop)
}

/// Find the lowest set bit in a u64. Returns 64 if no bits set.
/// Uses cascading checks for BPF verifier compatibility.
#[inline(always)]
fn find_first_set_bit(v: u64) -> u32 {
    if v == 0 { return 64; }
    // Check byte by byte to find which byte has a set bit
    if v & 0xFF != 0 {
        // Bit is in byte 0 (bits 0-7)
        if v & 1 != 0 { return 0; }
        if v & 2 != 0 { return 1; }
        if v & 4 != 0 { return 2; }
        if v & 8 != 0 { return 3; }
        if v & 16 != 0 { return 4; }
        if v & 32 != 0 { return 5; }
        if v & 64 != 0 { return 6; }
        return 7;
    }
    if v & 0xFF00 != 0 {
        if v & (1 << 8) != 0 { return 8; }
        if v & (1 << 9) != 0 { return 9; }
        if v & (1 << 10) != 0 { return 10; }
        if v & (1 << 11) != 0 { return 11; }
        if v & (1 << 12) != 0 { return 12; }
        if v & (1 << 13) != 0 { return 13; }
        if v & (1 << 14) != 0 { return 14; }
        return 15;
    }
    if v & 0xFF_0000 != 0 {
        if v & (1 << 16) != 0 { return 16; }
        if v & (1 << 17) != 0 { return 17; }
        if v & (1 << 18) != 0 { return 18; }
        if v & (1 << 19) != 0 { return 19; }
        if v & (1 << 20) != 0 { return 20; }
        if v & (1 << 21) != 0 { return 21; }
        if v & (1 << 22) != 0 { return 22; }
        return 23;
    }
    if v & 0xFF00_0000 != 0 {
        if v & (1 << 24) != 0 { return 24; }
        if v & (1 << 25) != 0 { return 25; }
        if v & (1 << 26) != 0 { return 26; }
        if v & (1 << 27) != 0 { return 27; }
        if v & (1 << 28) != 0 { return 28; }
        if v & (1 << 29) != 0 { return 29; }
        if v & (1 << 30) != 0 { return 30; }
        return 31;
    }
    // Bits 32-63 (extend as needed)
    if v & 0xFF_0000_0000 != 0 {
        if v & (1u64 << 32) != 0 { return 32; }
        if v & (1u64 << 33) != 0 { return 33; }
        if v & (1u64 << 34) != 0 { return 34; }
        if v & (1u64 << 35) != 0 { return 35; }
        if v & (1u64 << 36) != 0 { return 36; }
        if v & (1u64 << 37) != 0 { return 37; }
        if v & (1u64 << 38) != 0 { return 38; }
        return 39;
    }
    // For simplicity, handle up to bit 63 with a fallback
    // In practice, we'll rarely have >40 rules active
    let mut bit = 40u32;
    while bit < 64 {
        if v & (1u64 << bit) != 0 { return bit; }
        bit += 1;
    }
    64
}

/// Token bucket rate limiting for Rete rules
#[inline(always)]
fn apply_rete_token_bucket(rule_bit: u32) -> bool {
    match RATE_STATE.get_ptr_mut(&rule_bit) {
        Some(ptr) => {
            let bucket = unsafe { &mut *ptr };
            let now = unsafe { bpf_ktime_get_ns() };
            if bucket.last_update_ns == 0 {
                bucket.last_update_ns = now;
                bucket.tokens = bucket.rate_pps;
            }
            let elapsed_ns = now.saturating_sub(bucket.last_update_ns);
            let elapsed_ms = elapsed_ns / NS_PER_MS;
            if elapsed_ms > 0 && bucket.rate_pps > 0 {
                let tokens_to_add = ((elapsed_ms * bucket.rate_pps as u64) / MS_PER_SEC) as u32;
                if tokens_to_add > 0 {
                    let new_tokens = bucket.tokens.saturating_add(tokens_to_add);
                    bucket.tokens = if new_tokens > bucket.rate_pps { bucket.rate_pps } else { new_tokens };
                    bucket.last_update_ns = now;
                }
            }
            if bucket.tokens > 0 { bucket.tokens -= 1; false } else { true }
        }
        None => false,
    }
}

// =============================================================================
// Tree Rete Engine (eval_mode == 2)
// =============================================================================

/// Extract the packet field value for a given dimension.
#[inline(always)]
fn get_field(facts: &PktFacts, facts2: &PktFacts2, dim: u8) -> u32 {
    if dim == 0 { facts.proto as u32 }
    else if dim == 1 { facts.src_ip }
    else if dim == 2 { facts.dst_ip }
    else if dim == 3 { facts.l4_word0 as u32 }
    else if dim == 4 { facts.l4_word1 as u32 }
    else if dim == 5 { facts2.tcp_flags as u32 }
    else if dim == 6 { facts2.ttl as u32 }
    else if dim == 7 { facts2.df_bit as u32 }
    else if dim == 8 { facts2.tcp_window as u32 }
    else { 0 }
}

/// Apply the tree match result: determine if we should drop the packet.
#[inline(always)]
fn tree_result(matched: bool, action: u8, rule_id: u32) -> (bool, u8, bool) {
    if !matched {
        return (false, ACT_PASS, false);
    }
    if action == ACT_DROP {
        (true, ACT_DROP, true)
    } else if action == ACT_RATE_LIMIT {
        (true, ACT_RATE_LIMIT, apply_tree_token_bucket(rule_id))
    } else {
        (true, ACT_PASS, false)
    }
}

/// Token bucket rate limiting for tree rules (keyed by stable rule_id).
#[inline(always)]
fn apply_tree_token_bucket(rule_id: u32) -> bool {
    match TREE_RATE_STATE.get_ptr_mut(&rule_id) {
        Some(ptr) => {
            let bucket = unsafe { &mut *ptr };
            let now = unsafe { bpf_ktime_get_ns() };
            if bucket.last_update_ns == 0 {
                bucket.last_update_ns = now;
                bucket.tokens = bucket.rate_pps;
            }
            let elapsed_ns = now.saturating_sub(bucket.last_update_ns);
            let elapsed_ms = elapsed_ns / NS_PER_MS;
            if elapsed_ms > 0 && bucket.rate_pps > 0 {
                let tokens_to_add = ((elapsed_ms * bucket.rate_pps as u64) / MS_PER_SEC) as u32;
                if tokens_to_add > 0 {
                    let new_tokens = bucket.tokens.saturating_add(tokens_to_add);
                    bucket.tokens = if new_tokens > bucket.rate_pps { bucket.rate_pps } else { new_tokens };
                    bucket.last_update_ns = now;
                }
            }
            if bucket.tokens > 0 { bucket.tokens -= 1; false } else { true }
        }
        None => false,
    }
}

/// Walk one level of the tree: read node, update best match, follow edge.
/// Returns the next node_id to visit, or 0 if we should stop.
macro_rules! tree_walk_level {
    ($node_id:expr, $facts:expr, $facts2:expr, $p2_done:expr,
     $matched:expr, $best_action:expr, $best_rule_id:expr,
     $data_end:expr, $ip_hdr:expr, $ihl:expr) => {{
        let nptr = TREE_NODES.get($node_id);
        if nptr.is_none() {
            0u32
        } else {
            let node = *nptr.unwrap();
            if node.has_action != 0 {
                $matched = true;
                $best_action = node.action;
                $best_rule_id = node.rule_id;
            }
            if node.dimension == DIM_LEAF || node.dimension >= NUM_DIMS {
                0u32 // stop: leaf node
            } else {
                // Lazy Phase 2 extraction
                if node.dimension >= 5 && !$p2_done {
                    $facts2 = extract_phase2($data_end, $ip_hdr, $ihl, $facts.proto);
                    $p2_done = true;
                }
                let fv = get_field($facts, &$facts2, node.dimension);
                let key = EdgeKey { parent: $node_id, value: fv };
                match unsafe { TREE_EDGES.get(&key) } {
                    Some(&child) => child,
                    None => {
                        if node.wildcard_child != 0 { node.wildcard_child }
                        else { 0u32 } // stop: no matching edge
                    }
                }
            }
        }
    }};
}

/// Tree Rete evaluation: walk the decision tree from TREE_ROOT.
/// Single-path walk, max 9 levels (one per dimension).
/// Returns (matched, action, should_drop).
#[inline(always)]
fn check_tree_rules(data_end: usize, ip_hdr: usize, ihl: usize, facts: &PktFacts) -> (bool, u8, bool) {
    let root = match TREE_ROOT.get(0) {
        Some(r) => *r,
        None => return (false, ACT_PASS, false),
    };
    if root == 0 {
        return (false, ACT_PASS, false);
    }

    let mut matched = false;
    let mut best_action = ACT_PASS;
    let mut best_rule_id = 0u32;
    let mut p2_done = false;
    let mut facts2 = PktFacts2 { tcp_flags: 0, ttl: 0, df_bit: 0, tcp_window: 0 };

    // Unrolled walk: 9 levels maximum (one per dimension)
    // Level 0
    let nid = root;
    let nid = tree_walk_level!(nid, facts, facts2, p2_done, matched, best_action, best_rule_id, data_end, ip_hdr, ihl);
    if nid == 0 { return tree_result(matched, best_action, best_rule_id); }

    // Level 1
    let nid = tree_walk_level!(nid, facts, facts2, p2_done, matched, best_action, best_rule_id, data_end, ip_hdr, ihl);
    if nid == 0 { return tree_result(matched, best_action, best_rule_id); }

    // Level 2
    let nid = tree_walk_level!(nid, facts, facts2, p2_done, matched, best_action, best_rule_id, data_end, ip_hdr, ihl);
    if nid == 0 { return tree_result(matched, best_action, best_rule_id); }

    // Level 3
    let nid = tree_walk_level!(nid, facts, facts2, p2_done, matched, best_action, best_rule_id, data_end, ip_hdr, ihl);
    if nid == 0 { return tree_result(matched, best_action, best_rule_id); }

    // Level 4
    let nid = tree_walk_level!(nid, facts, facts2, p2_done, matched, best_action, best_rule_id, data_end, ip_hdr, ihl);
    if nid == 0 { return tree_result(matched, best_action, best_rule_id); }

    // Level 5
    let nid = tree_walk_level!(nid, facts, facts2, p2_done, matched, best_action, best_rule_id, data_end, ip_hdr, ihl);
    if nid == 0 { return tree_result(matched, best_action, best_rule_id); }

    // Level 6
    let nid = tree_walk_level!(nid, facts, facts2, p2_done, matched, best_action, best_rule_id, data_end, ip_hdr, ihl);
    if nid == 0 { return tree_result(matched, best_action, best_rule_id); }

    // Level 7
    let nid = tree_walk_level!(nid, facts, facts2, p2_done, matched, best_action, best_rule_id, data_end, ip_hdr, ihl);
    if nid == 0 { return tree_result(matched, best_action, best_rule_id); }

    // Level 8 (last possible level)
    let nid = tree_walk_level!(nid, facts, facts2, p2_done, matched, best_action, best_rule_id, data_end, ip_hdr, ihl);
    let _ = nid; // no more levels

    tree_result(matched, best_action, best_rule_id)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
