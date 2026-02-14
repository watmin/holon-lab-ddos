//! Veth Lab XDP Filter - Tree Rete Engine
//!
//! XDP program with tree-based Rete discrimination network.
//! Rules are managed by the userspace sidecar based on Holon detection.
//!
//! Architecture:
//! - Decision tree with stack-based DFS trie walker that explores all
//!   matching paths (specific + wildcard) and picks the highest-priority
//!   terminal node.
//! - Blue/green double-buffered tree for zero-downtime rule updates.
//!
//! Features:
//! - Phase 1: proto, src/dst IP, L4 ports (unconditional)
//! - Phase 2: TCP flags, TTL, DF bit, TCP window (on-demand)
//! - DROP/RATE_LIMIT/PASS/COUNT actions with token bucket rate limiting
//! - Packet sampling to userspace for Holon analysis

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{Array, HashMap, PerCpuArray, PerfEventArray, ProgramArray},
    programs::XdpContext,
};

// =============================================================================
// Action and Rate-Limit Types
// =============================================================================

// Action constants
const ACT_PASS: u8 = 0;
const ACT_DROP: u8 = 1;
const ACT_RATE_LIMIT: u8 = 2;
const ACT_COUNT: u8 = 3;

// Range operator constants (must match userspace)
const RANGE_OP_GT: u8 = 1;
const RANGE_OP_LT: u8 = 2;
const RANGE_OP_GTE: u8 = 3;
const RANGE_OP_LTE: u8 = 4;
const RANGE_OP_MASK_EQ: u8 = 5;
const RANGE_OP_PATTERN: u8 = 6;

/// Token bucket state for rate limiting
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TokenBucket {
    pub rate_pps: u32,
    pub tokens: u32,
    pub last_update_ns: u64,
    pub allowed_count: u64,
    pub dropped_count: u64,
}

// =============================================================================
// Tree Rete Engine Types
// =============================================================================

/// Number of static field dimensions (Proto..TcpWindow = 0..8)
const NUM_DIMS: u8 = 9;

/// Maximum dimension index (0-15, includes 7 custom slots)
const MAX_DIM: u8 = 16;

/// Sentinel: dimension value meaning "this is a leaf node, no more branching"
const DIM_LEAF: u8 = 0xFF;

/// Node in the decision tree. Stored in TREE_NODES array.
/// Each node optionally carries an action (match point) and optionally
/// branches on a dimension (specific edges in TREE_EDGES + wildcard child +
/// up to 2 range-guarded children).
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
    // --- Range edges (up to 2 per node) ---
    /// Number of active range edges (0-2)
    pub range_count: u8,
    /// Range operator for edge 0 (RANGE_OP_GT/LT/GTE/LTE, 0 = none)
    pub range_op_0: u8,
    /// Range operator for edge 1
    pub range_op_1: u8,
    pub _range_pad: u8,
    /// Threshold value for range edge 0
    pub range_val_0: u32,
    /// Child node ID for range edge 0
    pub range_child_0: u32,
    /// Threshold value for range edge 1
    pub range_val_1: u32,
    /// Child node ID for range edge 1
    pub range_child_1: u32,
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

/// Stats counters (per-CPU)
/// 0: total, 1: passed, 2: dropped, 3: matched, 4: sampled, 5: rate_limited
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(16, 0);

/// Configuration
/// 0: sample_rate, 1: enforce_mode
#[map]
static CONFIG: PerCpuArray<u32> = PerCpuArray::with_max_entries(4, 0);

/// Perf event array for packet samples
#[map]
static SAMPLES: PerfEventArray<PacketSample> = PerfEventArray::new(0);

// =============================================================================
// Tree Rete Engine Maps (blue/green double-buffered)
// =============================================================================

/// Tree node pool: 2 slots × 250K = 500K entries.
/// Slot 0: nodes 1..500_000, Slot 1: nodes 500_001..1_000_000.
/// Node 0 is reserved as NULL sentinel.
#[map]
static TREE_NODES: Array<TreeNode> = Array::with_max_entries(5_000_000, 0);

/// Tree edges: (parent_node_id, field_value) -> child_node_id.
/// Both slots' edges coexist; they're namespaced by parent node ID range.
#[map]
static TREE_EDGES: HashMap<EdgeKey, u32> = HashMap::with_max_entries(5_000_000, 0);

/// Active root node ID (single entry at index 0).
/// 0 = no tree loaded (pass everything).
/// Points to root of currently active slot's tree.
#[map]
static TREE_ROOT: Array<u32> = Array::with_max_entries(1, 0);

/// Rate limit state for tree rules (keyed by stable rule_id, survives flips).
#[map]
static TREE_RATE_STATE: HashMap<u32, TokenBucket> = HashMap::with_max_entries(2_000_000, 0);

/// Per-counter packet counts for Count actions (keyed by counter name hash)
#[map]
static TREE_COUNTERS: HashMap<u32, u64> = HashMap::with_max_entries(100_000, 0);

/// Maximum byte pattern length for multi-byte matching
const MAX_PATTERN_LEN: usize = 64;

/// Byte pattern for multi-byte matching at transport-relative offsets.
/// Stored in BYTE_PATTERNS map, referenced by RANGE_OP_PATTERN guard edges.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BytePattern {
    pub offset: u16,
    pub length: u8,
    pub _pad: u8,
    pub match_bytes: [u8; MAX_PATTERN_LEN],
    pub mask_bytes: [u8; MAX_PATTERN_LEN],
}

/// Byte patterns for multi-byte matching (l4-match 5-64 byte patterns)
#[map]
static BYTE_PATTERNS: Array<BytePattern> = Array::with_max_entries(4096, 0);

/// Custom dimension config: 7 slots for l4-match byte extraction.
/// Each entry is a CustomDimEntry { offset: u16, length: u8, _pad: u8 }.
/// Stored as u32 for simplicity (offset in lower 16 bits, length in bits 16-23).
#[map]
static CUSTOM_DIM_CONFIG: Array<u32> = Array::with_max_entries(7, 0);

// =============================================================================
// Tree Rete Tail-Call DFS Maps
// =============================================================================

/// DFS state shared between tail calls via per-CPU scratch map.
/// Written by veth_filter (main), read/updated by tree_walk_step.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DfsState {
    /// DFS node stack
    pub stack: [u32; 16],
    /// Stack top (number of entries)
    pub top: u32,
    /// Pre-extracted packet field values indexed by dimension (0-8), padded to 16
    pub fields: [u32; 16],
    /// 1 if any rule matched so far
    pub matched: u8,
    /// Best matching action
    pub best_action: u8,
    /// Best matching priority
    pub best_prio: u8,
    pub _pad0: u8,
    /// Best matching rule ID (for rate limiting)
    pub best_rule_id: u32,
    /// Packet metadata for post-DFS processing (sampling, stats)
    pub pkt_len: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub should_sample: u8,
    pub enforce: u8,
    pub _pad1: u8,
    pub tcp_flags: u8,
    pub ttl: u8,
    pub df_bit: u8,
    pub _pad2: u8,
    pub tcp_window: u16,
    /// Offset from packet start to transport (L4) header, for pattern matching
    pub transport_offset: u16,
    /// Pre-copied transport payload bytes for pattern matching.
    /// Copied from the packet in veth_filter (which has verified packet access)
    /// so tree_walk_step can compare without packet pointer issues.
    pub pattern_data: [u8; MAX_PATTERN_LEN],
}

/// Per-CPU scratch for DFS state between tail calls.
/// eBPF programs don't migrate CPUs between tail calls, so this is safe.
#[map]
static TREE_DFS_STATE: PerCpuArray<DfsState> = PerCpuArray::with_max_entries(1, 0);

/// Program array for tail-call DFS. Index 0 = tree_walk_step.
/// The main program tail-calls to index 0, and tree_walk_step tail-calls
/// itself at index 0 for each DFS iteration.
#[map]
static TREE_WALK_PROG: ProgramArray = ProgramArray::with_max_entries(1, 0);

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

    // Tree Rete evaluation.
    // Sampling happens HERE (before tail call) because tree_walk_step
    // can't access raw packet data — the verifier requires bounds checks
    // that only veth_filter has established. Sidecar anomaly detection
    // uses only structured fields (IPs, ports, p0f), not matched/action.
    // tree_walk_step handles stats counters and the drop/pass decision.

    // DIAG: reached tree eval
    if let Some(cnt) = STATS.get_ptr_mut(8) { unsafe { *cnt += 1; } }

    let facts = extract_phase1(data_end, ip_hdr, ihl, protocol, src_ip, dst_ip);
    let sp = if protocol == 6 || protocol == 17 { facts.l4_word0 } else { 0 };
    let dp = if protocol == 6 || protocol == 17 { facts.l4_word1 } else { 0 };

    // Sample BEFORE the tail call (packet data is accessible here)
    let sample_rate = CONFIG.get(0).copied().unwrap_or(0);
    let total_count = STATS.get(0).copied().unwrap_or(0);
    let should_sample = sample_rate > 0 && (total_count % sample_rate as u64 == 0);
    if should_sample {
        let p2 = extract_phase2(data_end, ip_hdr, ihl, protocol);
        sample_packet(
            &ctx, pkt_len, src_ip, dst_ip, sp, dp,
            protocol, false, ACT_PASS, data, data_end,
            p2.tcp_flags, p2.ttl, p2.df_bit, p2.tcp_window,
        );
    }

    let root = TREE_ROOT.get(0).copied().unwrap_or(0);
    if root != 0 {
        // DIAG: root is non-zero
        if let Some(cnt) = STATS.get_ptr_mut(9) { unsafe { *cnt += 1; } }

        if let Some(state_ptr) = TREE_DFS_STATE.get_ptr_mut(0) {
            // DIAG: got DFS state pointer
            if let Some(cnt) = STATS.get_ptr_mut(10) { unsafe { *cnt += 1; } }

            let state = unsafe { &mut *state_ptr };
            let fields = extract_all_fields(data_end, ip_hdr, ihl, &facts);
            let enforce = CONFIG.get(1).copied().unwrap_or(0) == 1;

            // Write DfsState field-by-field (no bulk array ops — those
            // generate memset subprograms that blow up verifier state).
            state.stack[0] = root;
            state.top = 1;
            // Fields: individual u32 writes (0-8 = static dims, 9-15 = custom dims)
            state.fields[0] = fields[0];
            state.fields[1] = fields[1];
            state.fields[2] = fields[2];
            state.fields[3] = fields[3];
            state.fields[4] = fields[4];
            state.fields[5] = fields[5];
            state.fields[6] = fields[6];
            state.fields[7] = fields[7];
            state.fields[8] = fields[8];
            // Custom dims (9-15) extracted from pattern_data below
            // Match state
            state.matched = 0;
            state.best_action = ACT_PASS;
            state.best_prio = 0;
            state._pad0 = 0;
            state.best_rule_id = 0;
            // Packet metadata (for stats/action in tree_walk_step)
            state.pkt_len = pkt_len;
            state.src_ip = src_ip;
            state.dst_ip = dst_ip;
            state.src_port = sp;
            state.dst_port = dp;
            state.protocol = protocol;
            state.should_sample = 0; // sampling already done above
            state.enforce = if enforce { 1 } else { 0 };
            state._pad1 = 0;
            state._pad2 = 0;
            state.transport_offset = (ETH_HDR_LEN + ihl) as u16;
            state.tcp_flags = 0;
            state.ttl = 0;
            state.df_bit = 0;
            state.tcp_window = 0;

            // Pre-copy up to 64 bytes of transport payload for pattern matching.
            // tree_walk_step can't access raw packet data (verifier loses range
            // through stack spills), so we snapshot the bytes here while we have
            // verified packet access.
            {
                let tp = data + ETH_HDR_LEN + ihl;
                let avail = if data_end > tp { data_end - tp } else { 0 };
                let copy_len = if avail > MAX_PATTERN_LEN { MAX_PATTERN_LEN } else { avail };
                state.pattern_data = [0u8; MAX_PATTERN_LEN];
                let mut k = 0usize;
                while k < MAX_PATTERN_LEN {
                    if k >= copy_len { break; }
                    if tp + k + 1 > data_end { break; }
                    state.pattern_data[k] = unsafe { *((tp + k) as *const u8) };
                    k += 1;
                }
            }

            // Extract custom dimension values from pattern_data (not from
            // packet pointers — variable-offset packet access fails verifier).
            extract_custom_dim_from_data(state, 0);
            extract_custom_dim_from_data(state, 1);
            extract_custom_dim_from_data(state, 2);
            extract_custom_dim_from_data(state, 3);
            extract_custom_dim_from_data(state, 4);
            extract_custom_dim_from_data(state, 5);
            extract_custom_dim_from_data(state, 6);

            // DIAG: about to attempt tail call
            if let Some(cnt) = STATS.get_ptr_mut(11) { unsafe { *cnt += 1; } }

            // Tail-call to tree_walk_step — never returns on success
            unsafe { let _ = TREE_WALK_PROG.tail_call(&ctx, 0); }

            // DIAG: tail call FAILED (returned)
            if let Some(cnt) = STATS.get_ptr_mut(12) { unsafe { *cnt += 1; } }
        }
    }
    // Tail call failed or root == 0: pass the packet
    pass_packet()
}

#[inline(always)]
fn pass_packet() -> Result<u32, ()> {
    if let Some(passed) = STATS.get_ptr_mut(1) {
        unsafe { *passed += 1; }
    }
    Ok(xdp_action::XDP_PASS)
}

// =============================================================================
// Sampling
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
// Packet Fact Extraction
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

// =============================================================================
// Tree Rete Engine
// =============================================================================

/// Extract static packet field values into a flat array indexed by dimension.
/// Custom dimensions (9-15) are extracted separately from pattern_data after
/// the transport payload has been pre-copied, avoiding variable-offset packet
/// pointer arithmetic that the verifier rejects.
#[inline(always)]
fn extract_all_fields(
    data_end: usize, ip_hdr: usize, ihl: usize, facts: &PktFacts,
) -> [u32; 16] {
    let facts2 = extract_phase2(data_end, ip_hdr, ihl, facts.proto);
    let mut f = [0u32; 16];
    f[0] = facts.proto as u32;
    f[1] = facts.src_ip;
    f[2] = facts.dst_ip;
    f[3] = facts.l4_word0 as u32;
    f[4] = facts.l4_word1 as u32;
    f[5] = facts2.tcp_flags as u32;
    f[6] = facts2.ttl as u32;
    f[7] = facts2.df_bit as u32;
    f[8] = facts2.tcp_window as u32;
    // f[9..15] = custom dims, populated later from pattern_data
    f
}

/// Extract a single custom dimension value from pre-copied pattern_data.
/// Reads from the map-value byte buffer instead of the packet, so the
/// verifier can prove all accesses are in-bounds.
#[inline(always)]
fn extract_custom_dim_from_data(state: &mut DfsState, index: u32) {
    if let Some(&cfg) = CUSTOM_DIM_CONFIG.get(index) {
        let offset = (cfg & 0xFFFF) as usize;
        let length = ((cfg >> 16) & 0xFF) as usize;
        if offset > 0 && length > 0 {
            // Mask offset to pattern_data bounds (0..63)
            let off = offset & 0x3F;
            let val = match length {
                1 => {
                    if off < MAX_PATTERN_LEN {
                        state.pattern_data[off] as u32
                    } else { 0 }
                }
                2 => {
                    if off + 1 < MAX_PATTERN_LEN {
                        ((state.pattern_data[off] as u32) << 8)
                            | (state.pattern_data[off + 1] as u32)
                    } else { 0 }
                }
                4 => {
                    if off + 3 < MAX_PATTERN_LEN {
                        ((state.pattern_data[off] as u32) << 24)
                            | ((state.pattern_data[off + 1] as u32) << 16)
                            | ((state.pattern_data[off + 2] as u32) << 8)
                            | (state.pattern_data[off + 3] as u32)
                    } else { 0 }
                }
                _ => 0,
            };
            state.fields[(9 + index as usize) & 0xF] = val;
        }
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
            
            // Token check and enforcement stats
            if bucket.tokens > 0 {
                bucket.tokens -= 1;
                bucket.allowed_count += 1;
                false  // Allow packet
            } else {
                bucket.dropped_count += 1;
                true   // Drop packet
            }
        }
        None => false,
    }
}

// =============================================================================
// Tree Rete Tail-Call DFS Walker
// =============================================================================

/// tree_walk_step: XDP program invoked via tail call from veth_filter.
///
/// Performs ONE DFS iteration per invocation:
///   1. Read DfsState from per-CPU scratch
///   2. If stack empty → apply best match result (drop/pass/rate-limit)
///   3. Pop one node, check its action, push children (specific + wildcard)
///   4. Write updated state back, tail-call self for next iteration
///
/// The BPF verifier sees this as a ~100-instruction straight-line program with
/// 2-3 map lookups and no loops. The kernel enforces a max of 33 tail calls,
/// giving us up to 32 DFS steps — plenty for trees with 9 dimensions.
#[xdp]
pub fn tree_walk_step(ctx: XdpContext) -> u32 {
    match try_tree_walk_step(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_tree_walk_step(ctx: &XdpContext) -> Result<u32, ()> {
    // Diagnostic: count tail-call entries (STATS[7])
    if let Some(cnt) = STATS.get_ptr_mut(7) {
        unsafe { *cnt += 1; }
    }

    // Read DFS state from per-CPU scratch
    let state_ptr = match TREE_DFS_STATE.get_ptr_mut(0) {
        Some(p) => p,
        None => return pass_packet(),
    };
    let state = unsafe { &mut *state_ptr };

    // ---------------------------------------------------------------
    // DFS complete: stack is empty → apply best result
    // ---------------------------------------------------------------
    if state.top == 0 {
        return apply_dfs_result(ctx, state);
    }

    // ---------------------------------------------------------------
    // Pop one node from the stack
    // ---------------------------------------------------------------
    state.top -= 1;
    let nid = state.stack[(state.top & 0xF) as usize];

    // Read the tree node
    let node = match TREE_NODES.get(nid) {
        Some(n) => *n,
        None => {
            // Invalid node ID — skip this entry, tail-call self for next
            unsafe { let _ = TREE_WALK_PROG.tail_call(ctx, 0); }
            return pass_packet();
        }
    };

    // ---------------------------------------------------------------
    // Check if this node carries an action (priority-based best match)
    // ---------------------------------------------------------------
    if node.has_action != 0 {
        // ACT_COUNT is non-terminating: increment counter and continue
        if node.action == ACT_COUNT {
            // Increment counter for this rule_id
            match TREE_COUNTERS.get_ptr_mut(&node.rule_id) {
                Some(ptr) => {
                    let count = unsafe { &mut *ptr };
                    *count += 1;
                }
                None => {
                    // First packet for this counter - initialize to 1
                    let _ = TREE_COUNTERS.insert(&node.rule_id, &1, 0);
                }
            }
            // Don't update best_action - continue walking
        } else if node.priority >= state.best_prio {
            // Terminating actions (PASS, DROP, RATE_LIMIT) compete on priority
            state.matched = 1;
            state.best_prio = node.priority;
            state.best_action = node.action;
            state.best_rule_id = node.rule_id;
        }
    }

    // ---------------------------------------------------------------
    // If this is a leaf node, skip to next iteration (no children)
    // ---------------------------------------------------------------
    if node.dimension == DIM_LEAF || node.dimension >= MAX_DIM {
        unsafe { let _ = TREE_WALK_PROG.tail_call(ctx, 0); }
        return pass_packet();
    }

    // ---------------------------------------------------------------
    // Look up packet field value for this dimension
    // Masked index into pre-extracted fields array
    // ---------------------------------------------------------------
    let fv = state.fields[(node.dimension as usize) & 0xF];

    // Push wildcard child FIRST (lowest priority in LIFO order)
    if node.wildcard_child != 0 && state.top < 16 {
        state.stack[(state.top & 0xF) as usize] = node.wildcard_child;
        state.top += 1;
    }

    // Push range-guarded children (evaluated at runtime against packet value)
    // Range edge 1 pushed before edge 0 so edge 0 is popped first (LIFO)
    if node.range_count > 1 && node.range_op_1 != 0 && node.range_child_1 != 0 {
        let passes = match node.range_op_1 {
            RANGE_OP_GT  => fv > node.range_val_1,
            RANGE_OP_LT  => fv < node.range_val_1,
            RANGE_OP_GTE => fv >= node.range_val_1,
            RANGE_OP_LTE => fv <= node.range_val_1,
            RANGE_OP_MASK_EQ => {
                let mask = node.range_val_1 >> 16;
                let expected = node.range_val_1 & 0xFFFF;
                (fv & mask) == expected
            }
            RANGE_OP_PATTERN => check_byte_pattern(state, node.range_val_1),
            _ => false,
        };
        if passes && state.top < 16 {
            state.stack[(state.top & 0xF) as usize] = node.range_child_1;
            state.top += 1;
        }
    }
    if node.range_count > 0 && node.range_op_0 != 0 && node.range_child_0 != 0 {
        let passes = match node.range_op_0 {
            RANGE_OP_GT  => fv > node.range_val_0,
            RANGE_OP_LT  => fv < node.range_val_0,
            RANGE_OP_GTE => fv >= node.range_val_0,
            RANGE_OP_LTE => fv <= node.range_val_0,
            RANGE_OP_MASK_EQ => {
                let mask = node.range_val_0 >> 16;
                let expected = node.range_val_0 & 0xFFFF;
                (fv & mask) == expected
            }
            RANGE_OP_PATTERN => check_byte_pattern(state, node.range_val_0),
            _ => false,
        };
        if passes && state.top < 16 {
            state.stack[(state.top & 0xF) as usize] = node.range_child_0;
            state.top += 1;
        }
    }

    // Push specific child (popped first due to LIFO — most discriminating path)
    let key = EdgeKey { parent: nid, value: fv };
    if let Some(&child) = unsafe { TREE_EDGES.get(&key) } {
        if state.top < 16 {
            state.stack[(state.top & 0xF) as usize] = child;
            state.top += 1;
        }
    }

    // ---------------------------------------------------------------
    // Tail-call self for next DFS step
    // ---------------------------------------------------------------
    unsafe { let _ = TREE_WALK_PROG.tail_call(ctx, 0); }

    // Tail call failed (33-call limit reached) — apply what we have
    apply_dfs_result(ctx, state)
}

/// Check a byte pattern against pre-copied transport payload bytes.
/// `pattern_idx` is the index into BYTE_PATTERNS map.
/// Returns true if the pattern matches.
///
/// The actual packet bytes are pre-copied into `state.pattern_data` by
/// `veth_filter` (which has verified packet access). This avoids packet
/// pointer issues in tree_walk_step — the verifier loses range tracking
/// when the compiler spills packet pointers to the stack.
///
/// The match/mask arrays in BytePattern are "pre-shifted" by the compiler:
/// match_bytes[i] and mask_bytes[i] correspond to pattern_data[i] directly.
/// Bytes outside the pattern range have mask=0 so `(any & 0) == 0` always
/// passes. This eliminates all runtime offset arithmetic, avoiding verifier
/// issues with unbounded map value accesses.
#[inline(always)]
fn check_byte_pattern(state: &DfsState, pattern_idx: u32) -> bool {
    let pat = match BYTE_PATTERNS.get(pattern_idx) {
        Some(p) => p,
        None => return false,
    };

    // Straight 64-byte comparison — no offset arithmetic.
    // The verifier tracks j ∈ [0, 63], and both pattern_data[j] (at map
    // offset 168+j within 232-byte DfsState) and mask/match_bytes[j]
    // (within 132-byte BytePattern) are provably in-bounds.
    let mut j = 0usize;
    while j < MAX_PATTERN_LEN {
        if (state.pattern_data[j] & pat.mask_bytes[j]) != pat.match_bytes[j] {
            return false;
        }
        j += 1;
    }
    true
}

/// Apply the final DFS result: update stats, return XDP action.
/// Called when the DFS stack is empty or the tail-call chain is exhausted.
/// NOTE: Sampling is done in veth_filter BEFORE the tail call, because
/// tree_walk_step cannot access raw packet data (verifier bounds issue).
#[inline(always)]
fn apply_dfs_result(_ctx: &XdpContext, state: &mut DfsState) -> Result<u32, ()> {
    // Diagnostic: count DFS completions (STATS[6])
    if let Some(cnt) = STATS.get_ptr_mut(6) {
        unsafe { *cnt += 1; }
    }

    let matched = state.matched != 0;
    let action = state.best_action;
    let rule_id = state.best_rule_id;

    // Determine the drop decision
    let should_drop = if !matched {
        false
    } else if action == ACT_DROP {
        true
    } else if action == ACT_RATE_LIMIT {
        apply_tree_token_bucket(rule_id)
    } else {
        false
    };

    // Update matched counter
    if matched {
        if let Some(matched_cnt) = STATS.get_ptr_mut(3) {
            unsafe { *matched_cnt += 1; }
        }
    }

    // Apply action
    if matched && should_drop && state.enforce != 0 {
        if action == ACT_DROP {
            if let Some(dropped) = STATS.get_ptr_mut(2) {
                unsafe { *dropped += 1; }
            }
            // Per-rule drop counter (same map as COUNT actions)
            match TREE_COUNTERS.get_ptr_mut(&rule_id) {
                Some(ptr) => { unsafe { *ptr += 1; } }
                None => { let _ = TREE_COUNTERS.insert(&rule_id, &1, 0); }
            }
        } else if action == ACT_RATE_LIMIT {
            if let Some(rate_limited) = STATS.get_ptr_mut(5) {
                unsafe { *rate_limited += 1; }
            }
        }
        return Ok(xdp_action::XDP_DROP);
    }

    // Per-rule pass counter (for named pass rules showing up in metrics)
    if matched && action == ACT_PASS {
        match TREE_COUNTERS.get_ptr_mut(&rule_id) {
            Some(ptr) => { unsafe { *ptr += 1; } }
            None => { let _ = TREE_COUNTERS.insert(&rule_id, &1, 0); }
        }
    }

    pass_packet()
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
