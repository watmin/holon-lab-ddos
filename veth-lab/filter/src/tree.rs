//! Tree Rete Compiler - Compiles rule sets into an eBPF-friendly decision tree.
//!
//! The compiler builds a trie keyed by packet field values. Each node branches
//! on one dimension (proto, src_ip, dst_ip, etc.) and optionally carries an action.
//!
//! Key properties:
//! - **Pure DAG**: wildcard rules live only in wildcard_child links — no replication.
//!   The eBPF walker uses a stack-based DFS that explores all matching paths
//!   (specific + wildcard) at each node, collecting the highest-priority match.
//! - **Blue/green double buffering**: two tree slots share the same eBPF maps
//!   via node ID offset. Atomic root-pointer flip for zero-downtime updates.
//! - **Idempotent**: rule identity is based on canonical hash, not insertion order.

use std::collections::HashMap as StdHashMap;
use std::rc::Rc;
use anyhow::{Context, Result};
use aya::maps::{Array, HashMap as AyaHashMap};
use aya::Ebpf;
use tracing::info;

use crate::{
    EdgeKey, FieldDim, RuleSpec, TokenBucket, TreeNode,
    ACT_PASS, ACT_RATE_LIMIT, DIM_LEAF, NUM_DIMENSIONS, TREE_SLOT_SIZE,
};

// =============================================================================
// Dimension ordering (fixed traversal order for the tree)
// =============================================================================

/// The fixed dimension order for tree levels.
/// Proto -> SrcIp -> DstIp -> L4Word0 -> L4Word1 -> TcpFlags -> Ttl -> DfBit -> TcpWindow
const DIM_ORDER: [FieldDim; NUM_DIMENSIONS] = [
    FieldDim::Proto,
    FieldDim::SrcIp,
    FieldDim::DstIp,
    FieldDim::L4Word0,
    FieldDim::L4Word1,
    FieldDim::TcpFlags,
    FieldDim::Ttl,
    FieldDim::DfBit,
    FieldDim::TcpWindow,
];

// =============================================================================
// Shadow tree (in-memory representation for compilation)
// =============================================================================

/// A node in the shadow tree (userspace-only, not written to eBPF).
/// Used during compilation, then flattened into eBPF maps.
/// Children are Rc-wrapped so that compile-level memoization shares
/// subtrees by reference count instead of deep-copying.
#[derive(Debug, Clone)]
struct ShadowNode {
    /// Which dimension this node branches on (index into DIM_ORDER)
    dim_index: usize,
    /// Optional action at this node (from the highest-priority terminating rule)
    action: Option<ShadowAction>,
    /// Specific-value children: field_value -> subtree (Rc for cheap sharing)
    children: StdHashMap<u32, Rc<ShadowNode>>,
    /// Wildcard child: subtree for rules that don't constrain this dimension
    wildcard: Option<Rc<ShadowNode>>,
}

#[derive(Debug, Clone)]
struct ShadowAction {
    action: u8,
    priority: u8,
    rate_pps: u32,
    rule_id: u32,
}

// =============================================================================
// Tree compiler
// =============================================================================

/// Compiles a set of RuleSpecs into a shadow DAG (no replication).
/// Wildcard rules live only in the wildcard_child branch.
/// The eBPF walker explores both specific and wildcard paths via DFS.
fn compile_tree(rules: &[RuleSpec]) -> Rc<ShadowNode> {
    compile_recursive(rules, 0)
}

fn compile_recursive(rules: &[RuleSpec], dim_idx: usize) -> Rc<ShadowNode> {
    // Base case: no more dimensions to branch on
    if dim_idx >= NUM_DIMENSIONS || rules.is_empty() {
        let mut node = ShadowNode {
            dim_index: dim_idx,
            action: None,
            children: StdHashMap::new(),
            wildcard: None,
        };
        // Pick the highest-priority rule as this leaf's action
        if let Some(best) = rules.iter().max_by_key(|r| r.priority) {
            // Use first action for tree node
            if let Some(first_action) = best.actions.first() {
                node.action = Some(ShadowAction {
                    action: first_action.action_type(),
                    priority: best.priority,
                    rate_pps: first_action.rate_pps().unwrap_or(0),
                    rule_id: best.bucket_key().unwrap_or_else(|| best.canonical_hash()),
                });
            }
        }
        return Rc::new(node);
    }

    let dim = DIM_ORDER[dim_idx];

    // Check if ANY rule constrains this dimension
    let any_constrains = rules.iter().any(|r| {
        r.constraints.iter().any(|p| p.as_eq_dim().map_or(false, |(d, _)| d == dim))
    });

    // If no rule constrains this dimension, skip it entirely
    if !any_constrains {
        return compile_recursive(rules, dim_idx + 1);
    }

    // Partition rules: specific (constrain this dim) vs wildcard (don't)
    let mut specific: StdHashMap<u32, Vec<&RuleSpec>> = StdHashMap::new();
    let mut wildcard: Vec<&RuleSpec> = Vec::new();

    for rule in rules {
        let eq_value = rule.constraints.iter()
            .find_map(|p| p.as_eq_dim().filter(|(d, _)| *d == dim).map(|(_, v)| v));
        if let Some(value) = eq_value {
            specific.entry(value).or_default().push(rule);
        } else {
            wildcard.push(rule);
        }
    }

    let mut node = ShadowNode {
        dim_index: dim_idx,
        action: None,
        children: StdHashMap::new(),
        wildcard: None,
    };

    // Rules that terminate at or above this level (don't constrain this dim or any below)
    let remaining_dims: Vec<FieldDim> = DIM_ORDER[dim_idx..].to_vec();
    let terminating: Vec<&RuleSpec> = rules.iter()
        .filter(|r| !r.constraints.iter().any(|p| {
            p.as_eq_dim().map_or(false, |(d, _)| remaining_dims.contains(&d))
        }))
        .collect();
    if let Some(best) = terminating.iter().max_by_key(|r| r.priority) {
        // Use first action for tree node
        if let Some(first_action) = best.actions.first() {
            node.action = Some(ShadowAction {
                action: first_action.action_type(),
                priority: best.priority,
                rate_pps: first_action.rate_pps().unwrap_or(0),
                rule_id: best.bucket_key().unwrap_or_else(|| best.canonical_hash()),
            });
        }
    }

    // Build specific children: ONLY their own rules (no replication here).
    // Replication happens during flatten via merge_flatten.
    for (value, specific_rules) in &specific {
        let owned: Vec<RuleSpec> = specific_rules.iter().map(|r| (*r).clone()).collect();
        node.children.insert(*value, compile_recursive(&owned, dim_idx + 1));
    }

    // Build wildcard child: only wildcard rules
    if !wildcard.is_empty() {
        let owned: Vec<RuleSpec> = wildcard.iter().map(|r| (*r).clone()).collect();
        node.wildcard = Some(compile_recursive(&owned, dim_idx + 1));
    }

    Rc::new(node)
}

// =============================================================================
// Flatten shadow DAG into eBPF map entries (with lazy replication)
// =============================================================================

/// Result of flattening: ready to write to eBPF maps.
pub struct FlatTree {
    pub nodes: Vec<(u32, TreeNode)>,       // (node_id, node)
    pub edges: Vec<(EdgeKey, u32)>,         // (edge_key, child_id)
    pub rate_buckets: Vec<(u32, TokenBucket)>, // (rule_id, bucket)
    pub root_id: u32,
}

/// Flatten a shadow DAG directly into eBPF map entries with no replication.
/// The DAG is walked once, and each unique Rc node gets a unique flat ID.
/// Wildcard rules are NOT replicated into specific subtrees; the eBPF
/// walker's stack-based DFS explores both specific and wildcard paths.
fn flatten_tree(shadow: &Rc<ShadowNode>, base_id: u32) -> FlatTree {
    let mut alloc = NodeAllocator::new(base_id);
    let mut flat = FlatTree {
        nodes: Vec::new(),
        edges: Vec::new(),
        rate_buckets: Vec::new(),
        root_id: 0,
    };
    let mut dedup: StdHashMap<usize, u32> = StdHashMap::new(); // Rc ptr -> flat node_id

    flat.root_id = flatten_recursive(shadow, &mut alloc, &mut flat, &mut dedup);
    flat
}

struct NodeAllocator {
    next_id: u32,
}

impl NodeAllocator {
    fn new(base: u32) -> Self {
        Self { next_id: if base == 0 { 1 } else { base } }
    }

    fn alloc(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

fn flatten_recursive(
    shadow: &Rc<ShadowNode>,
    alloc: &mut NodeAllocator,
    flat: &mut FlatTree,
    dedup: &mut StdHashMap<usize, u32>,
) -> u32 {
    let ptr = Rc::as_ptr(shadow) as usize;
    if let Some(&existing) = dedup.get(&ptr) {
        return existing;
    }

    let my_id = alloc.alloc();
    dedup.insert(ptr, my_id);

    // Flatten wildcard child
    let wildcard_child = if let Some(wc) = &shadow.wildcard {
        flatten_recursive(wc, alloc, flat, dedup)
    } else {
        0
    };

    // Flatten specific children
    for (&value, child) in &shadow.children {
        let child_id = flatten_recursive(child, alloc, flat, dedup);
        flat.edges.push((EdgeKey { parent: my_id, value }, child_id));
    }

    let dimension = if shadow.children.is_empty() && shadow.wildcard.is_none() {
        DIM_LEAF
    } else if shadow.dim_index < NUM_DIMENSIONS {
        DIM_ORDER[shadow.dim_index] as u8
    } else {
        DIM_LEAF
    };

    let (has_action, action, priority, rate_pps, rule_id) = if let Some(a) = &shadow.action {
        if a.action == ACT_RATE_LIMIT && a.rate_pps > 0 {
            // Check if bucket already exists (for named buckets shared across rules)
            if let Some(existing) = flat.rate_buckets.iter_mut().find(|(id, _)| *id == a.rule_id) {
                // Bucket exists - update with latest PPS (last definer wins)
                if existing.1.rate_pps != a.rate_pps {
                    eprintln!("WARN: Named bucket {} has conflicting PPS: {} -> {}. Using last-defined: {}",
                              a.rule_id, existing.1.rate_pps, a.rate_pps, a.rate_pps);
                    // Last definer wins
                    existing.1.rate_pps = a.rate_pps;
                    existing.1.tokens = a.rate_pps;
                }
            } else {
                // New bucket - insert it
                flat.rate_buckets.push((a.rule_id, TokenBucket {
                    rate_pps: a.rate_pps,
                    tokens: a.rate_pps,
                    last_update_ns: 0,
                    allowed_count: 0,
                    dropped_count: 0,
                }));
            }
        }
        (1u8, a.action, a.priority, a.rate_pps, a.rule_id)
    } else {
        (0u8, ACT_PASS, 0u8, 0u32, 0u32)
    };

    flat.nodes.push((my_id, TreeNode {
        dimension,
        has_action,
        action,
        priority,
        rate_pps,
        wildcard_child,
        rule_id,
    }));

    my_id
}


// =============================================================================
// Blue/Green Tree Manager
// =============================================================================

/// Manages the blue/green tree slots and writes compiled trees to eBPF maps.
pub struct TreeManager {
    /// Which slot is currently active (0 or 1)
    active_slot: u32,
    /// Edge keys written to each slot during the last compilation.
    /// Used to clean up stale edges before rewriting a slot.
    prev_edge_keys: [Vec<EdgeKey>; 2],
}

impl TreeManager {
    pub fn new() -> Self {
        Self {
            active_slot: 0,
            prev_edge_keys: [Vec::new(), Vec::new()],
        }
    }

    /// Which slot is currently active
    pub fn active_slot(&self) -> u32 {
        self.active_slot
    }

    /// The node ID base for the inactive (staging) slot
    fn staging_base(&self) -> u32 {
        if self.active_slot == 0 {
            TREE_SLOT_SIZE + 1 // Slot 1 starts at SLOT_SIZE+1
        } else {
            1 // Slot 0 starts at 1 (0 is NULL)
        }
    }

    /// Compile rules, write to staging slot, and atomically flip.
    /// Returns the number of nodes in the compiled tree.
    pub fn compile_and_flip(
        &mut self,
        rules: &[RuleSpec],
        bpf: &mut Ebpf,
    ) -> Result<usize> {
        let base = self.staging_base();

        // 1. Compile the tree
        let shadow = compile_tree(rules);

        // 2. Flatten into map entries
        let flat = flatten_tree(&shadow, base);
        let node_count = flat.nodes.len();
        let edge_count = flat.edges.len();

        info!(
            "Tree compiled: {} nodes, {} edges, {} rate buckets (slot {} -> {})",
            node_count, edge_count, flat.rate_buckets.len(),
            self.active_slot, 1 - self.active_slot,
        );

        if node_count == 0 {
            // Empty tree: just set root to 0 (no match)
            let mut root_map: Array<_, u32> = bpf
                .map_mut("TREE_ROOT").context("TREE_ROOT not found")?
                .try_into()?;
            root_map.set(0, 0u32, 0)?;
            self.active_slot = 1 - self.active_slot;
            return Ok(0);
        }

        // 3. Write nodes to TREE_NODES array
        {
            let mut nodes_map: Array<_, TreeNode> = bpf
                .map_mut("TREE_NODES").context("TREE_NODES not found")?
                .try_into()?;
            for &(node_id, ref node) in &flat.nodes {
                nodes_map.set(node_id, *node, 0)?;
            }
        }

        // 4. Write edges to TREE_EDGES hashmap
        //    First, clean up stale edges from previous compilation to this slot.
        //    Node IDs change between compilations (DFS order shifts when rules change),
        //    so old edge keys won't be overwritten — they accumulate as stale entries.
        {
            let staging_idx = (1 - self.active_slot) as usize;
            let mut edges_map: AyaHashMap<_, EdgeKey, u32> = bpf
                .map_mut("TREE_EDGES").context("TREE_EDGES not found")?
                .try_into()?;

            // Remove stale edges from previous compilation to this slot
            for key in &self.prev_edge_keys[staging_idx] {
                let _ = edges_map.remove(key);
            }

            // Write new edges
            for &(ref key, child_id) in &flat.edges {
                edges_map.insert(*key, child_id, 0)?;
            }

            // Track these edge keys for cleanup next time
            self.prev_edge_keys[staging_idx] = flat.edges.iter().map(|(k, _)| *k).collect();
        }

        // 5. Write rate buckets to TREE_RATE_STATE
        // Only write NEW buckets (don't overwrite existing state to preserve tokens)
        {
            let mut rate_map: AyaHashMap<_, u32, TokenBucket> = bpf
                .map_mut("TREE_RATE_STATE").context("TREE_RATE_STATE not found")?
                .try_into()?;
            for &(rule_id, ref bucket) in &flat.rate_buckets {
                // Only insert if not already present (preserves token state across flips)
                if rate_map.get(&rule_id, 0).is_err() {
                    rate_map.insert(rule_id, *bucket, 0)?;
                }
            }
        }

        // 6. ATOMIC FLIP: update TREE_ROOT to point to new tree's root
        {
            let mut root_map: Array<_, u32> = bpf
                .map_mut("TREE_ROOT").context("TREE_ROOT not found")?
                .try_into()?;
            root_map.set(0, flat.root_id, 0)?;
        }

        info!("Tree flip complete: root={} (slot {})", flat.root_id, 1 - self.active_slot);
        self.active_slot = 1 - self.active_slot;

        Ok(node_count)
    }

    /// Clean up the old (now-inactive) slot's entries from the edge HashMap.
    /// Call this after flipping, once enough time has passed for in-flight packets.
    pub fn cleanup_old_slot(
        &self,
        old_flat: &FlatTree,
        bpf: &mut Ebpf,
    ) -> Result<()> {
        // Remove old edges
        let mut edges_map: AyaHashMap<_, EdgeKey, u32> = bpf
            .map_mut("TREE_EDGES").context("TREE_EDGES not found")?
            .try_into()?;
        for &(ref key, _) in &old_flat.edges {
            let _ = edges_map.remove(key);
        }
        Ok(())
    }

    /// Clear both tree slots completely.
    pub fn clear_all(&mut self, bpf: &mut Ebpf) -> Result<()> {
        // Set root to 0 (no tree)
        {
            let mut root_map: Array<_, u32> = bpf
                .map_mut("TREE_ROOT").context("TREE_ROOT not found")?
                .try_into()?;
            root_map.set(0, 0u32, 0)?;
        }

        // Clear all edges
        {
            let mut edges_map: AyaHashMap<_, EdgeKey, u32> = bpf
                .map_mut("TREE_EDGES").context("TREE_EDGES not found")?
                .try_into()?;
            let keys: Vec<EdgeKey> = edges_map.keys().filter_map(|k| k.ok()).collect();
            for key in keys {
                let _ = edges_map.remove(&key);
            }
        }

        // Clear all rate state
        {
            let mut rate_map: AyaHashMap<_, u32, TokenBucket> = bpf
                .map_mut("TREE_RATE_STATE").context("TREE_RATE_STATE not found")?
                .try_into()?;
            let keys: Vec<u32> = rate_map.keys().filter_map(|k| k.ok()).collect();
            for key in keys {
                let _ = rate_map.remove(&key);
            }
        }

        self.active_slot = 0;
        self.prev_edge_keys = [Vec::new(), Vec::new()];
        info!("Tree cleared (both slots)");
        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FieldDim, Predicate, RuleAction, RuleSpec};

    #[test]
    fn test_empty_rules() {
        let tree = compile_tree(&[]);
        let flat = flatten_tree(&tree, 1);
        // Empty rules should produce a minimal tree (root node, no action)
        assert!(flat.nodes.len() <= 1);
    }

    #[test]
    fn test_single_rule() {
        let rules = vec![
            RuleSpec::drop_field(FieldDim::Proto, 17),
        ];
        let tree = compile_tree(&rules);
        let flat = flatten_tree(&tree, 1);

        // Should have root + at least 1 child/leaf
        assert!(flat.nodes.len() >= 2, "Expected >= 2 nodes, got {}", flat.nodes.len());
        assert!(flat.root_id > 0);

        // Root should branch on Proto (dimension 0)
        let root = flat.nodes.iter().find(|(id, _)| *id == flat.root_id).unwrap();
        assert_eq!(root.1.dimension, FieldDim::Proto as u8);
    }

    #[test]
    fn test_two_rules_same_dimension() {
        // DNS reflection + NTP reflection
        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::eq(FieldDim::Proto, 17), Predicate::eq(FieldDim::L4Word0, 53)],
                RuleAction::Drop,
            ),
            RuleSpec::compound(
                vec![Predicate::eq(FieldDim::Proto, 17), Predicate::eq(FieldDim::L4Word0, 123)],
                RuleAction::Drop,
            ),
        ];
        let tree = compile_tree(&rules);
        let flat = flatten_tree(&tree, 1);

        // Should have edges for proto=17, src_port=53, src_port=123
        assert!(flat.edges.len() >= 2, "Expected >= 2 edges, got {}", flat.edges.len());
    }

    #[test]
    fn test_priority_dual_cursor() {
        // Rule A: proto=17 -> RATE_LIMIT (prio 5)
        // Rule B: proto=17, src_port=53 -> DROP (prio 10)
        // eBPF dual-cursor walk: nid follows proto=17 -> src_port=53 -> DROP (prio 10)
        //                        wid follows wildcard_child -> RATE_LIMIT (prio 5)
        // Highest priority (DROP, 10) wins.
        // A packet matching proto=17, src_port=999: nid dead-ends, wid finds RATE_LIMIT
        let rules = vec![
            RuleSpec::rate_limit_field(FieldDim::Proto, 17, 1000).with_priority(5),
            RuleSpec::compound(
                vec![Predicate::eq(FieldDim::Proto, 17), Predicate::eq(FieldDim::L4Word0, 53)],
                RuleAction::Drop,
            ).with_priority(10),
        ];
        let tree = compile_tree(&rules);
        let flat = flatten_tree(&tree, 1);

        // The DAG should have:
        // - Root branches on Proto
        // - proto=17 node branches on L4Word0
        // - src_port=53 -> DROP (prio 10) [specific child]
        // - wildcard -> RATE_LIMIT (prio 5) [shared wildcard subtree]

        // Find the leaf nodes with actions
        let action_nodes: Vec<_> = flat.nodes.iter()
            .filter(|(_, n)| n.has_action != 0)
            .collect();

        // Should have at least 2 nodes with actions
        assert!(action_nodes.len() >= 2,
            "Expected >= 2 action nodes, got {}. Nodes: {:?}",
            action_nodes.len(), flat.nodes);

        // One should be DROP, another RATE_LIMIT
        let has_drop = action_nodes.iter().any(|(_, n)| n.action == ACT_DROP);
        let has_rate = action_nodes.iter().any(|(_, n)| n.action == ACT_RATE_LIMIT);
        assert!(has_drop, "Expected a DROP action node");
        assert!(has_rate, "Expected a RATE_LIMIT action node");
    }

    #[test]
    fn test_dimension_skipping() {
        // Rule that only constrains TcpFlags (dimension 5)
        // Should skip Proto, SrcIp, DstIp, L4Word0, L4Word1
        let rules = vec![
            RuleSpec::drop_field(FieldDim::TcpFlags, 0x02), // SYN
        ];
        let tree = compile_tree(&rules);

        // The tree should go directly to TcpFlags dimension
        // (skipping dimensions 0-4 that no rule constrains)
        assert_eq!(tree.dim_index, 5, "Should skip to TcpFlags dimension (index 5)");
    }

    #[test]
    fn test_blue_green_offsets() {
        let rules = vec![
            RuleSpec::drop_field(FieldDim::Proto, 17),
        ];

        // Slot 0: base=1
        let flat0 = flatten_tree(&compile_tree(&rules), 1);
        assert!(flat0.root_id >= 1 && flat0.root_id < TREE_SLOT_SIZE);

        // Slot 1: base=TREE_SLOT_SIZE+1
        let flat1 = flatten_tree(&compile_tree(&rules), TREE_SLOT_SIZE + 1);
        assert!(flat1.root_id > TREE_SLOT_SIZE);

        // No overlap in node IDs
        let ids0: Vec<u32> = flat0.nodes.iter().map(|(id, _)| *id).collect();
        let ids1: Vec<u32> = flat1.nodes.iter().map(|(id, _)| *id).collect();
        for id in &ids0 {
            assert!(!ids1.contains(id), "Node ID overlap: {}", id);
        }
    }

    #[test]
    fn test_canonical_hash_idempotent() {
        let spec1 = RuleSpec::compound(
            vec![Predicate::eq(FieldDim::Proto, 17), Predicate::eq(FieldDim::L4Word0, 53)],
            RuleAction::Drop,
        );
        let spec2 = RuleSpec::compound(
            // Same constraints in different order
            vec![Predicate::eq(FieldDim::L4Word0, 53), Predicate::eq(FieldDim::Proto, 17)],
            RuleAction::Drop,
        );
        assert_eq!(spec1.canonical_hash(), spec2.canonical_hash());
    }

    // =========================================================================
    // Multi-Cursor Walk Simulation (userspace correctness proof)
    // =========================================================================

    /// Simulate the eBPF multi-cursor walk in userspace against a FlatTree.
    /// This mirrors the eBPF walker: at each level, every active cursor is
    /// checked for an action, then advanced. If a cursor takes a specific
    /// edge and has a wildcard_child, the wildcard_child becomes a NEW
    /// cursor, ensuring no wildcard subtrees are lost.
    ///
    /// The userspace version uses Vec (unbounded) for correctness proof.
    /// The eBPF version uses a bounded array (MAX_CURSORS).
    /// Returns (matched, action, priority, rule_id).
    fn simulate_dual_walk(
        flat: &FlatTree,
        packet: &[(FieldDim, u32)], // list of (dimension, value) for the packet
    ) -> (bool, u8, u8, u32) {
        simulate_walk_inner(flat, packet, false)
    }

    /// Inner walk with optional tracing.
    fn simulate_walk_inner(
        flat: &FlatTree,
        packet: &[(FieldDim, u32)],
        trace: bool,
    ) -> (bool, u8, u8, u32) {
        use std::collections::HashMap as Map;

        // Build lookup structures from the flat tree
        let nodes: Map<u32, &TreeNode> = flat.nodes.iter().map(|(id, n)| (*id, n)).collect();
        let edges: Map<(u32, u32), u32> = flat.edges.iter().map(|&(ref ek, cid)| ((ek.parent, ek.value), cid)).collect();

        // Packet field values indexed by dimension
        let pkt: Map<u8, u32> = packet.iter().map(|(d, v)| (*d as u8, *v)).collect();

        let mut matched = false;
        let mut best_prio: u8 = 0;
        let mut best_action: u8 = ACT_PASS;
        let mut best_rule_id: u32 = 0;

        // Multi-cursor state: unbounded for correctness proof
        let mut cursors: Vec<u32> = vec![flat.root_id];

        for level in 0..NUM_DIMENSIONS {
            if cursors.is_empty() { break; }

            if trace {
                eprintln!("  Level {}: {} cursors: {:?}", level, cursors.len(), &cursors[..cursors.len().min(20)]);
            }

            let mut next_cursors: Vec<u32> = Vec::new();

            for &cid in &cursors {
                if cid == 0 { continue; }

                let node = match nodes.get(&cid) {
                    Some(n) => *n,
                    None => { if trace { eprintln!("    cid={}: NOT FOUND", cid); } continue; },
                };

                // Check action, update best match by priority
                if node.has_action != 0 && node.priority >= best_prio {
                    if trace {
                        eprintln!("    cid={}: HIT action={} prio={}", cid, node.action, node.priority);
                    }
                    matched = true;
                    best_prio = node.priority;
                    best_action = node.action;
                    best_rule_id = node.rule_id;
                }

                // If leaf, cursor dies
                if node.dimension == DIM_LEAF || node.dimension >= NUM_DIMENSIONS as u8 {
                    if trace { eprintln!("    cid={}: LEAF (dim={})", cid, node.dimension); }
                    continue;
                }

                // Advance cursor: look up specific edge for packet field value
                let fv = pkt.get(&node.dimension).copied().unwrap_or(0);
                let edge_key = (cid, fv);
                match edges.get(&edge_key) {
                    Some(&child) => {
                        if trace {
                            eprintln!("    cid={}: dim={} val={} -> specific child={}, wc={}",
                                cid, node.dimension, fv, child, node.wildcard_child);
                        }
                        // Took a specific edge
                        next_cursors.push(child);
                        // Spawn wildcard_child as separate cursor (if different from child)
                        if node.wildcard_child != 0 && node.wildcard_child != child {
                            next_cursors.push(node.wildcard_child);
                        }
                    }
                    None => {
                        if trace {
                            eprintln!("    cid={}: dim={} val={} -> NO EDGE, wc={}",
                                cid, node.dimension, fv, node.wildcard_child);
                        }
                        // No specific edge — fall to wildcard child
                        if node.wildcard_child != 0 {
                            next_cursors.push(node.wildcard_child);
                        }
                    }
                }
            }

            // Deduplicate cursors to avoid redundant work
            next_cursors.sort_unstable();
            next_cursors.dedup();
            cursors = next_cursors;
        }

        // Final pass: check any remaining cursors' actions (leaf nodes from last advance)
        for &cid in &cursors {
            if cid == 0 { continue; }
            if let Some(node) = nodes.get(&cid) {
                if node.has_action != 0 && node.priority >= best_prio {
                    if trace {
                        eprintln!("  FINAL cid={}: HIT action={} prio={}", cid, node.action, node.priority);
                    }
                    matched = true;
                    best_prio = node.priority;
                    best_action = node.action;
                    best_rule_id = node.rule_id;
                }
            }
        }

        if trace {
            eprintln!("  RESULT: matched={} action={} prio={}", matched, best_action, best_prio);
        }

        (matched, best_action, best_prio, best_rule_id)
    }

    /// Simulate the eBPF stack-based DFS trie walk in userspace against a FlatTree.
    ///
    /// Mirrors the eBPF walker exactly: at each node, push both the specific
    /// child (if the packet's field value matches an edge) and the wildcard
    /// child onto a fixed-size stack. Process until stack is empty or the
    /// iteration budget (64) is exhausted. Highest-priority terminal node wins.
    ///
    /// This replaces the old single-cursor + probe_wildcard_chain approach.
    /// Returns (matched, action, priority, rule_id).
    fn simulate_single_walk(
        flat: &FlatTree,
        packet: &[(FieldDim, u32)],
    ) -> (bool, u8, u8, u32) {
        simulate_single_walk_inner(flat, packet, false)
    }

    fn simulate_single_walk_inner(
        flat: &FlatTree,
        packet: &[(FieldDim, u32)],
        trace: bool,
    ) -> (bool, u8, u8, u32) {
        use std::collections::HashMap as Map;

        let nodes: Map<u32, &TreeNode> = flat.nodes.iter().map(|(id, n)| (*id, n)).collect();
        let edges: Map<(u32, u32), u32> = flat.edges.iter().map(|&(ref ek, cid)| ((ek.parent, ek.value), cid)).collect();
        let pkt: Map<u8, u32> = packet.iter().map(|(d, v)| (*d as u8, *v)).collect();

        let mut matched = false;
        let mut best_prio: u8 = 0;
        let mut best_action: u8 = ACT_PASS;
        let mut best_rule_id: u32 = 0;

        // Fixed-size stack for DFS (mirrors eBPF stack[16])
        let mut stack: [u32; 16] = [0u32; 16];

        // Push root
        stack[0] = flat.root_id;
        let mut top: usize = 1;

        // Bounded DFS: explore all matching paths, collect highest-priority match
        for _iter in 0..64u32 {
            if top == 0 { break; }

            // Pop
            top -= 1;
            let nid = stack[top];

            // Read node
            let node = match nodes.get(&nid) {
                Some(n) => *n,
                None => {
                    if trace { eprintln!("  iter={}: nid={} NOT FOUND", _iter, nid); }
                    continue;
                }
            };

            // Check action (priority-based best match)
            if node.has_action != 0 && node.priority >= best_prio {
                if trace {
                    eprintln!("  iter={}: nid={} HIT action={} prio={}", _iter, nid, node.action, node.priority);
                }
                matched = true;
                best_prio = node.priority;
                best_action = node.action;
                best_rule_id = node.rule_id;
            }

            // Leaf node — no children to explore
            if node.dimension == DIM_LEAF || node.dimension >= NUM_DIMENSIONS as u8 {
                if trace { eprintln!("  iter={}: nid={} LEAF", _iter, nid); }
                continue;
            }

            // Get packet field value for this dimension
            let fv = pkt.get(&node.dimension).copied().unwrap_or(0);

            // Push wildcard child FIRST (so specific is popped first — DFS
            // prefers the more-discriminating specific path)
            if node.wildcard_child != 0 && top < 16 {
                if trace {
                    eprintln!("  iter={}: nid={} dim={} PUSH wildcard_child={}", _iter, nid, node.dimension, node.wildcard_child);
                }
                stack[top] = node.wildcard_child;
                top += 1;
            }

            // Push specific child (popped first due to LIFO)
            let edge_key = (nid, fv);
            match edges.get(&edge_key) {
                Some(&child) => {
                    if top < 16 {
                        if trace {
                            eprintln!("  iter={}: nid={} dim={} val={} PUSH specific child={}", _iter, nid, node.dimension, fv, child);
                        }
                        stack[top] = child;
                        top += 1;
                    }
                }
                None => {
                    if trace {
                        eprintln!("  iter={}: nid={} dim={} val={} NO specific edge", _iter, nid, node.dimension, fv);
                    }
                }
            }
        }

        if trace {
            eprintln!("  RESULT: matched={} action={} prio={}", matched, best_action, best_prio);
        }

        (matched, best_action, best_prio, best_rule_id)
    }

    #[test]
    fn test_single_walk_specific_only() {
        // Rule: proto=17, src_port=53 -> DROP (prio 10)
        // Packet matches exactly -> should get DROP
        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::eq(FieldDim::Proto, 17), Predicate::eq(FieldDim::L4Word0, 53)],
                RuleAction::Drop,
            ).with_priority(10),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);

        // Single-cursor walk
        let (matched, action, prio, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::L4Word0, 53),
        ]);
        assert!(matched, "Should match");
        assert_eq!(action, ACT_DROP);
        assert_eq!(prio, 10);

        // Multi-cursor walk (theoretical reference)
        let (matched, action, prio, _) = simulate_dual_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::L4Word0, 53),
        ]);
        assert!(matched, "Should match (multi-cursor)");
        assert_eq!(action, ACT_DROP);
        assert_eq!(prio, 10);
    }

    #[test]
    fn test_single_walk_wildcard_wins() {
        // Rule A: proto=17 -> RATE_LIMIT (prio 20)  [wildcard on deeper dims]
        // Rule B: proto=17, src_port=53 -> DROP (prio 5)
        // Packet: proto=17, src_port=53
        // Both match, but A has higher priority -> RATE_LIMIT wins
        // With replication, rule A is copied into the specific child for proto=17,
        // so the single-cursor walk finds it on the same path as B.
        let rules = vec![
            RuleSpec::rate_limit_field(FieldDim::Proto, 17, 1000).with_priority(20),
            RuleSpec::compound(
                vec![Predicate::eq(FieldDim::Proto, 17), Predicate::eq(FieldDim::L4Word0, 53)],
                RuleAction::Drop,
            ).with_priority(5),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);
        let (matched, action, prio, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::L4Word0, 53),
        ]);
        assert!(matched, "Should match");
        assert_eq!(action, ACT_RATE_LIMIT, "Higher-prio wildcard should win");
        assert_eq!(prio, 20);
    }

    #[test]
    fn test_single_walk_specific_wins() {
        // Rule A: proto=17 -> RATE_LIMIT (prio 5)  [wildcard on deeper dims]
        // Rule B: proto=17, src_port=53 -> DROP (prio 10)
        // Packet: proto=17, src_port=53
        // Both match, but B has higher priority -> DROP wins
        let rules = vec![
            RuleSpec::rate_limit_field(FieldDim::Proto, 17, 1000).with_priority(5),
            RuleSpec::compound(
                vec![Predicate::eq(FieldDim::Proto, 17), Predicate::eq(FieldDim::L4Word0, 53)],
                RuleAction::Drop,
            ).with_priority(10),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);
        let (matched, action, prio, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::L4Word0, 53),
        ]);
        assert!(matched, "Should match");
        assert_eq!(action, ACT_DROP, "Higher-prio specific should win");
        assert_eq!(prio, 10);
    }

    #[test]
    fn test_single_walk_wildcard_no_specific() {
        // Rule A: proto=17 -> RATE_LIMIT (prio 5)
        // Packet: proto=17, src_port=999 (no specific rule for this port)
        // Only the wildcard matches -> RATE_LIMIT
        // With replication, the single-cursor falls to wildcard_child at the
        // L4Word0 level and still finds rule A's action.
        let rules = vec![
            RuleSpec::rate_limit_field(FieldDim::Proto, 17, 1000).with_priority(5),
            RuleSpec::compound(
                vec![Predicate::eq(FieldDim::Proto, 17), Predicate::eq(FieldDim::L4Word0, 53)],
                RuleAction::Drop,
            ).with_priority(10),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);
        let (matched, action, _, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::L4Word0, 999),
        ]);
        assert!(matched, "Wildcard rule should still match");
        assert_eq!(action, ACT_RATE_LIMIT);
    }

    #[test]
    fn test_single_walk_no_match() {
        // Rule: proto=17, src_port=53 -> DROP
        // Packet: proto=6 (TCP, doesn't match any rule)
        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::eq(FieldDim::Proto, 17), Predicate::eq(FieldDim::L4Word0, 53)],
                RuleAction::Drop,
            ).with_priority(10),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);
        let (matched, _, _, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 6), (FieldDim::L4Word0, 80),
        ]);
        assert!(!matched, "Should not match any rule");
    }

    #[test]
    fn test_single_walk_sentinel_with_background() {
        // Simulates the real 50K scenario in miniature:
        // 4 sentinels + 100 background rules with unique src_addr
        //
        // Sentinel S1: proto=17, src_port=53 -> rate-limit (prio 200)
        // Sentinel S2: proto=6, tcp_flags=2, dst_port=9999 -> rate-limit (prio 210)
        // Background: proto=17, src_addr=10.0.0.X, dst_port=Y -> drop (prio 100)
        //
        // Test packets:
        //   1. proto=17, src_addr=10.0.0.1, src_port=53 -> S1 (prio 200) wins over background
        //   2. proto=17, src_addr=10.0.0.1, dst_port=8000 -> background (prio 100) matches
        //   3. proto=6, tcp_flags=2, dst_port=9999 -> S2 (prio 210)
        //   4. proto=17, src_addr=10.0.0.99, src_port=53 -> S1 (prio 200, no background match)
        //   5. proto=17, src_addr=10.0.0.99, dst_port=1234 -> no match

        let mut rules = Vec::new();

        // Sentinels
        rules.push(RuleSpec::compound(
            vec![Predicate::eq(FieldDim::Proto, 17), Predicate::eq(FieldDim::L4Word0, 53)],
            RuleAction::RateLimit { pps: 500, name: None },
        ).with_priority(200));
        rules.push(RuleSpec::compound(
            vec![
                Predicate::eq(FieldDim::Proto, 6),
                Predicate::eq(FieldDim::TcpFlags, 2),
                Predicate::eq(FieldDim::L4Word1, 9999),
            ],
            RuleAction::RateLimit { pps: 100, name: None },
        ).with_priority(210));

        // Background rules: 100 unique (proto=17, src_addr, dst_port) combos
        for i in 0..100u32 {
            let ip = u32::from_ne_bytes([10, 0, 0, (i + 1) as u8]);
            rules.push(RuleSpec::compound(
                vec![
                    Predicate::eq(FieldDim::Proto, 17),
                    Predicate::eq(FieldDim::SrcIp, ip),
                    Predicate::eq(FieldDim::L4Word1, 8000 + i),
                ],
                RuleAction::Drop,
            ).with_priority(100));
        }

        let tree = compile_tree(&rules);
        let flat = flatten_tree(&tree, 1);

        eprintln!("sentinel+bg test: {} rules -> {} nodes, {} edges",
            rules.len(), flat.nodes.len(), flat.edges.len());

        let ip1 = u32::from_ne_bytes([10, 0, 0, 1]);
        let ip99 = u32::from_ne_bytes([10, 0, 0, 99]);

        // Test 1: S1 should win over background (prio 200 > 100)
        let (m, a, p, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::SrcIp, ip1),
            (FieldDim::L4Word0, 53), (FieldDim::L4Word1, 8000),
        ]);
        assert!(m, "Test 1: should match");
        assert_eq!(a, ACT_RATE_LIMIT, "Test 1: S1 (rate-limit) should win over background (drop)");
        assert_eq!(p, 200, "Test 1: priority should be 200");

        // Test 2: Only background matches (no sentinel for this port)
        let (m, a, p, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::SrcIp, ip1),
            (FieldDim::L4Word0, 999), (FieldDim::L4Word1, 8000),
        ]);
        assert!(m, "Test 2: should match background");
        assert_eq!(a, ACT_DROP, "Test 2: background drop");
        assert_eq!(p, 100);

        // Test 3: S2 matches TCP SYN flood
        let (m, a, p, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 6), (FieldDim::TcpFlags, 2),
            (FieldDim::L4Word1, 9999),
        ]);
        assert!(m, "Test 3: S2 should match");
        assert_eq!(a, ACT_RATE_LIMIT, "Test 3: S2 rate-limit");
        assert_eq!(p, 210);

        // Test 4: S1 matches (no background for ip99+port53 combo)
        let (m, a, p, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::SrcIp, ip99),
            (FieldDim::L4Word0, 53),
        ]);
        assert!(m, "Test 4: S1 should match via replicated wildcard");
        assert_eq!(a, ACT_RATE_LIMIT, "Test 4: S1 rate-limit");
        assert_eq!(p, 200);

        // Test 5: No match (ip99 with unknown port, no sentinel)
        let (m, _, _, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::SrcIp, ip99),
            (FieldDim::L4Word0, 999), (FieldDim::L4Word1, 1234),
        ]);
        assert!(!m, "Test 5: no rule should match");
    }

    #[test]
    fn test_single_walk_distant_wildcards() {
        // Two single-constraint rules on dimensions far apart,
        // plus a dense background creating a complex tree.
        //
        // Rule A: L4Word1=7 -> DROP (prio 21)
        // Rule B: TcpWindow=11 -> RATE_LIMIT (prio 61)
        // Background: 50 rules with Proto + SrcIp + DstIp constraints
        //
        // With replication, both A and B are replicated into all specific subtrees.
        // Single-cursor walk finds both on the same path.
        let mut rules = vec![
            RuleSpec::compound(
                vec![Predicate::eq(FieldDim::L4Word1, 7)],
                RuleAction::Drop,
            ).with_priority(21),
            RuleSpec::compound(
                vec![Predicate::eq(FieldDim::TcpWindow, 11)],
                RuleAction::RateLimit { pps: 1000, name: None },
            ).with_priority(61),
        ];
        // Dense background
        for i in 0..50u32 {
            rules.push(RuleSpec::compound(
                vec![
                    Predicate::eq(FieldDim::Proto, i % 5),
                    Predicate::eq(FieldDim::SrcIp, i),
                    Predicate::eq(FieldDim::DstIp, i + 100),
                ],
                RuleAction::Drop,
            ).with_priority(10));
        }

        let tree = compile_tree(&rules);
        let flat = flatten_tree(&tree, 1);
        eprintln!("distant_wildcards: {} rules -> {} nodes, {} edges",
            rules.len(), flat.nodes.len(), flat.edges.len());

        // Packet matches A (L4Word1=7) and B (TcpWindow=11)
        // B should win (prio 61 > 21)
        let (m, a, p, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 13), // no background match
            (FieldDim::SrcIp, 4),
            (FieldDim::DstIp, 5),
            (FieldDim::L4Word0, 9),
            (FieldDim::L4Word1, 7),
            (FieldDim::TcpFlags, 14),
            (FieldDim::Ttl, 17),
            (FieldDim::DfBit, 3),
            (FieldDim::TcpWindow, 11),
        ]);
        assert!(m, "Should match");
        assert_eq!(p, 61, "B (prio 61) should beat A (prio 21)");
        assert_eq!(a, ACT_RATE_LIMIT);
    }

    #[test]
    fn test_single_walk_deep_wildcard() {
        // Wildcard rule that constrains only a deep dimension (TcpFlags at dim_index 5).
        // Background rules constrain Proto + SrcIp.
        // With replication, rule A is replicated into the specific subtree for
        // proto=6, src_ip=10.0.0.1, so the single-cursor finds it.
        //
        // Rule A: tcp_flags=2 -> DROP (prio 150)
        // Rule B: proto=6, src_ip=10.0.0.1 -> RATE_LIMIT (prio 100)
        //
        // Packet: proto=6, src_ip=10.0.0.1, tcp_flags=2
        // Both match. A has higher priority -> DROP
        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::eq(FieldDim::TcpFlags, 2)],
                RuleAction::Drop,
            ).with_priority(150),
            RuleSpec::compound(
                vec![
                    Predicate::eq(FieldDim::Proto, 6),
                    Predicate::eq(FieldDim::SrcIp, u32::from_ne_bytes([10, 0, 0, 1])),
                ],
                RuleAction::RateLimit { pps: 1000, name: None },
            ).with_priority(100),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);

        let (m, a, p, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 6),
            (FieldDim::SrcIp, u32::from_ne_bytes([10, 0, 0, 1])),
            (FieldDim::TcpFlags, 2),
        ]);
        assert!(m, "Should match");
        assert_eq!(a, ACT_DROP, "Replicated wildcard (prio 150) should beat specific (prio 100)");
        assert_eq!(p, 150);
    }

    // =========================================================================
    // Structural Deduplication effectiveness test
    // =========================================================================

    #[test]
    fn test_dedup_reduces_node_count() {
        // 50 rules constraining proto + src_ip + dst_port (specific on 3 dims).
        // Plus 5 wildcard rules constraining only proto (wildcard on deeper dims).
        // The wildcard rules are replicated into all 50 specific subtrees,
        // but structural dedup should make most of those subtrees share nodes.
        let mut rules: Vec<RuleSpec> = Vec::new();

        // 5 wildcard-ish rules (only constrain proto)
        for i in 0..5u32 {
            rules.push(
                RuleSpec::rate_limit_field(FieldDim::Proto, 17, 500 + i)
                    .with_priority((50 + i) as u8)
            );
        }

        // 50 specific rules: proto=17, src_ip, dst_port
        for i in 0..50u32 {
            rules.push(
                RuleSpec::compound(
                    vec![
                        Predicate::eq(FieldDim::Proto, 17),
                        Predicate::eq(FieldDim::SrcIp, make_ip(i)),
                        Predicate::eq(FieldDim::L4Word1, 8000 + i),
                    ],
                    RuleAction::Drop,
                ).with_priority(100)
            );
        }

        let tree = compile_tree(&rules);

        // Flatten WITH dedup (normal path)
        let flat_dedup = flatten_tree(&tree, 1);

        eprintln!(
            "dedup test: {} rules -> {} flat nodes, {} edges",
            rules.len(), flat_dedup.nodes.len(), flat_dedup.edges.len(),
        );

        // With lazy merge-flatten, the node count should be well-bounded:
        // fewer than rules * 10 (no exponential blowup)
        assert!(
            flat_dedup.nodes.len() < rules.len() * 10,
            "Node count {} too high for {} rules",
            flat_dedup.nodes.len(), rules.len(),
        );

        // Verify correctness: all original test packets still work
        let (m, _, p, _) = simulate_single_walk(&flat_dedup, &[
            (FieldDim::Proto, 17), (FieldDim::SrcIp, make_ip(0)),
            (FieldDim::L4Word1, 8000),
        ]);
        assert!(m, "Should match specific+wildcard");
        assert_eq!(p, 100, "Specific rule prio should win");
    }

    // =========================================================================
    // Randomized A/B correctness test: walk vs brute-force reference
    // =========================================================================

    /// Brute-force reference: scan all rules, pick the highest-priority match.
    /// This is the O(n) "obviously correct" implementation.
    fn brute_force_match(
        rules: &[RuleSpec],
        packet: &[(FieldDim, u32)],
    ) -> (bool, u8, u8) {
        let pkt: std::collections::HashMap<FieldDim, u32> = packet.iter().cloned().collect();
        let mut matched = false;
        let mut best_prio: u8 = 0;
        let mut best_action: u8 = ACT_PASS;

        for rule in rules {
            // Check if all constraints match
            let all_match = rule.constraints.iter().all(|pred| {
                match pred {
                    Predicate::Eq(field_ref, value) => {
                        match field_ref {
                            crate::FieldRef::Dim(dim) => {
                                pkt.get(dim).copied() == Some(*value)
                            }
                        }
                    }
                }
            });
            if all_match && rule.priority >= best_prio {
                matched = true;
                best_prio = rule.priority;
                best_action = rule.actions.first().map(|a| a.action_type()).unwrap_or(ACT_PASS);
            }
        }
        (matched, best_action, best_prio)
    }

    #[test]
    fn test_dual_cursor_randomized_ab() {
        // Randomized A/B test: generate random rulesets and packets,
        // verify DAG dual-cursor walk matches brute-force for every packet.
        use rand::Rng;

        let all_dims = [
            FieldDim::Proto, FieldDim::SrcIp, FieldDim::DstIp,
            FieldDim::L4Word0, FieldDim::L4Word1,
            FieldDim::TcpFlags, FieldDim::Ttl, FieldDim::DfBit, FieldDim::TcpWindow,
        ];
        let actions = [
            RuleAction::Drop, 
            RuleAction::RateLimit { pps: 1000, name: None }, 
            RuleAction::Pass
        ];

        let mut rng = rand::thread_rng();
        let num_iterations = 50; // 50 random rulesets
        let rules_per_set = 100; // 100 rules each
        let packets_per_set = 200; // 200 random packets per set

        let mut total_checks = 0u64;
        let mut total_matches = 0u64;

        for iter in 0..num_iterations {
            // Generate random rules with 1-4 constraints each
            let mut rules = Vec::new();
            for _ in 0..rules_per_set {
                let num_constraints = rng.gen_range(1..=4);
                let mut used_dims = std::collections::HashSet::new();
                let mut constraints = Vec::new();
                for _ in 0..num_constraints {
                    // Pick a unique dimension
                    let dim = loop {
                        let d = all_dims[rng.gen_range(0..all_dims.len())];
                        if !used_dims.contains(&d) {
                            used_dims.insert(d);
                            break d;
                        }
                        if used_dims.len() == all_dims.len() { break d; }
                    };
                    // Random value (small range to encourage collisions)
                    let val = rng.gen_range(0..20u32);
                    constraints.push(Predicate::eq(dim, val));
                }
                let action = actions[rng.gen_range(0..actions.len())].clone();
                let prio = rng.gen_range(1..=255u8);
                rules.push(RuleSpec::compound(constraints, action).with_priority(prio));
            }

            let tree = compile_tree(&rules);
            let flat = flatten_tree(&tree, 1);

            // Generate random packets
            for _ in 0..packets_per_set {
                let packet: Vec<(FieldDim, u32)> = all_dims.iter()
                    .map(|d| (*d, rng.gen_range(0..20u32)))
                    .collect();

                let (dag_m, dag_a, dag_p, _) = simulate_dual_walk(&flat, &packet);
                let (bf_m, bf_a, bf_p) = brute_force_match(&rules, &packet);

                total_checks += 1;
                if bf_m { total_matches += 1; }

                // Check match agreement
                assert_eq!(dag_m, bf_m, "Iter {}: match mismatch. DAG={}, BF={}. Packet: {:?}",
                    iter, dag_m, bf_m, packet);

                if bf_m {
                    // Priority must always agree
                    if dag_p != bf_p {
                        let pkt_map: std::collections::HashMap<FieldDim, u32> = packet.iter().cloned().collect();
                        let matching: Vec<_> = rules.iter().enumerate().filter(|(_, r)| {
                            r.constraints.iter().all(|pred| match pred {
                                Predicate::Eq(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).copied() == Some(*val),
                            })
                        }).collect();
                        eprintln!("FAIL iter={}, packet={:?}", iter, packet);
                        for (i, r) in &matching {
                            eprintln!("  rule[{}] prio={} action={:?} constraints={:?}", i, r.priority, r.actions, r.constraints);
                        }
                        // Re-run with tracing
                        simulate_walk_inner(&flat, &packet, true);
                    }
                    assert_eq!(dag_p, bf_p, "Iter {}: priority mismatch. DAG={}, BF={}",
                        iter, dag_p, bf_p);

                    // When priorities tie, action may differ based on visit order.
                    // Only assert action when priority is unique among matching rules.
                    let pkt_map: std::collections::HashMap<FieldDim, u32> = packet.iter().cloned().collect();
                    let top_prio_count = rules.iter().filter(|r| {
                        r.priority == bf_p && r.constraints.iter().all(|pred| match pred {
                            Predicate::Eq(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).copied() == Some(*val),
                        })
                    }).count();
                    if top_prio_count == 1 {
                        assert_eq!(dag_a, bf_a,
                            "Iter {}: action mismatch (unique prio). DAG={}, BF={}", iter, dag_a, bf_a);
                    }
                }
            }
        }

        eprintln!("Randomized A/B (multi-cursor): {} checks, {} matches ({:.1}% hit rate) — ALL CORRECT",
            total_checks, total_matches, (total_matches as f64 / total_checks as f64) * 100.0);
    }

    #[test]
    fn test_single_walk_randomized_ab() {
        // Randomized A/B test: single-cursor walk (replication + dedup) vs brute-force.
        // This proves the replication+dedup approach is correct with a single-cursor walker.
        use rand::Rng;

        let all_dims = [
            FieldDim::Proto, FieldDim::SrcIp, FieldDim::DstIp,
            FieldDim::L4Word0, FieldDim::L4Word1,
            FieldDim::TcpFlags, FieldDim::Ttl, FieldDim::DfBit, FieldDim::TcpWindow,
        ];
        let actions = [
            RuleAction::Drop, 
            RuleAction::RateLimit { pps: 1000, name: None }, 
            RuleAction::Pass
        ];

        let mut rng = rand::thread_rng();
        let num_iterations = 50;
        let rules_per_set = 100;
        let packets_per_set = 200;

        let mut total_checks = 0u64;
        let mut total_matches = 0u64;

        for iter in 0..num_iterations {
            let mut rules = Vec::new();
            for _ in 0..rules_per_set {
                let num_constraints = rng.gen_range(1..=4);
                let mut used_dims = std::collections::HashSet::new();
                let mut constraints = Vec::new();
                for _ in 0..num_constraints {
                    let dim = loop {
                        let d = all_dims[rng.gen_range(0..all_dims.len())];
                        if !used_dims.contains(&d) {
                            used_dims.insert(d);
                            break d;
                        }
                        if used_dims.len() == all_dims.len() { break d; }
                    };
                    let val = rng.gen_range(0..20u32);
                    constraints.push(Predicate::eq(dim, val));
                }
                let action = actions[rng.gen_range(0..actions.len())].clone();
                let prio = rng.gen_range(1..=255u8);
                rules.push(RuleSpec::compound(constraints, action).with_priority(prio));
            }

            let tree = compile_tree(&rules);
            let flat = flatten_tree(&tree, 1);

            for _ in 0..packets_per_set {
                let packet: Vec<(FieldDim, u32)> = all_dims.iter()
                    .map(|d| (*d, rng.gen_range(0..20u32)))
                    .collect();

                let (sw_m, sw_a, sw_p, _) = simulate_single_walk(&flat, &packet);
                let (bf_m, bf_a, bf_p) = brute_force_match(&rules, &packet);

                total_checks += 1;
                if bf_m { total_matches += 1; }

                assert_eq!(sw_m, bf_m,
                    "Iter {}: match mismatch. single_walk={}, brute_force={}. Packet: {:?}",
                    iter, sw_m, bf_m, packet);

                if bf_m {
                    if sw_p != bf_p {
                        let pkt_map: std::collections::HashMap<FieldDim, u32> = packet.iter().cloned().collect();
                        let matching: Vec<_> = rules.iter().enumerate().filter(|(_, r)| {
                            r.constraints.iter().all(|pred| match pred {
                                Predicate::Eq(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).copied() == Some(*val),
                            })
                        }).collect();
                        eprintln!("FAIL iter={}, packet={:?}", iter, packet);
                        for (i, r) in &matching {
                            eprintln!("  rule[{}] prio={} action={:?} constraints={:?}", i, r.priority, r.actions, r.constraints);
                        }
                        simulate_single_walk_inner(&flat, &packet, true);
                    }
                    assert_eq!(sw_p, bf_p,
                        "Iter {}: priority mismatch. single_walk={}, brute_force={}",
                        iter, sw_p, bf_p);

                    // When priorities tie, action may differ based on visit order.
                    let pkt_map: std::collections::HashMap<FieldDim, u32> = packet.iter().cloned().collect();
                    let top_prio_count = rules.iter().filter(|r| {
                        r.priority == bf_p && r.constraints.iter().all(|pred| match pred {
                            Predicate::Eq(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).copied() == Some(*val),
                        })
                    }).count();
                    if top_prio_count == 1 {
                        assert_eq!(sw_a, bf_a,
                            "Iter {}: action mismatch (unique prio). single_walk={}, brute_force={}",
                            iter, sw_a, bf_a);
                    }
                }
            }
        }

        eprintln!("Randomized A/B (single-walk): {} checks, {} matches ({:.1}% hit rate) — ALL CORRECT",
            total_checks, total_matches, (total_matches as f64 / total_checks as f64) * 100.0);
    }

    // =========================================================================
    // Stress Tests: push tree capacity limits
    // =========================================================================

    /// Helper: generate a unique IP from a counter (10.a.b.c)
    fn make_ip(i: u32) -> u32 {
        let a = ((i >> 16) & 0xFF) as u8;
        let b = ((i >> 8) & 0xFF) as u8;
        let c = (i & 0xFF) as u8;
        u32::from_ne_bytes([10, a, b, c])
    }

    /// Helper: compile + flatten, print stats, assert within eBPF map limits
    fn stress_compile(label: &str, rules: &[RuleSpec]) -> FlatTree {
        let start = std::time::Instant::now();
        let tree = compile_tree(rules);
        let compile_time = start.elapsed();

        let start2 = std::time::Instant::now();
        let flat = flatten_tree(&tree, 1);
        let flatten_time = start2.elapsed();

        eprintln!(
            "STRESS [{}]: {} rules -> {} nodes, {} edges, {} rate_buckets | compile: {:?}, flatten: {:?}",
            label, rules.len(), flat.nodes.len(), flat.edges.len(),
            flat.rate_buckets.len(), compile_time, flatten_time,
        );

        assert!(
            flat.nodes.len() < TREE_SLOT_SIZE as usize,
            "{}: node count {} exceeds slot size {}",
            label, flat.nodes.len(), TREE_SLOT_SIZE,
        );
        assert!(
            flat.edges.len() < 1_000_000,
            "{}: edge count {} exceeds 1M limit",
            label, flat.edges.len(),
        );

        flat
    }

    #[test]
    fn test_stress_scale_100() {
        // 100 rules, each on a unique (src_ip, dst_port) pair
        let rules: Vec<RuleSpec> = (0..100).map(|i| {
            RuleSpec::compound(
                vec![
                    Predicate::eq(FieldDim::SrcIp, make_ip(i)),
                    Predicate::eq(FieldDim::L4Word1, 10000 + i),
                ],
                RuleAction::RateLimit { pps: 1000, name: None },
            )
        }).collect();
        let flat = stress_compile("scale_100", &rules);
        assert!(flat.root_id > 0);
    }

    #[test]
    fn test_stress_scale_1k() {
        let rules: Vec<RuleSpec> = (0..1_000).map(|i| {
            RuleSpec::compound(
                vec![
                    Predicate::eq(FieldDim::SrcIp, make_ip(i)),
                    Predicate::eq(FieldDim::L4Word1, 10000 + (i % 55000)),
                ],
                RuleAction::RateLimit { pps: 1000, name: None },
            )
        }).collect();
        stress_compile("scale_1k", &rules);
    }

    #[test]
    fn test_stress_scale_10k() {
        let rules: Vec<RuleSpec> = (0..10_000).map(|i| {
            RuleSpec::compound(
                vec![
                    Predicate::eq(FieldDim::SrcIp, make_ip(i)),
                    Predicate::eq(FieldDim::L4Word1, 10000 + (i % 55000)),
                ],
                RuleAction::RateLimit { pps: 1000, name: None },
            )
        }).collect();
        stress_compile("scale_10k", &rules);
    }

    #[test]
    #[ignore] // Takes significant time/memory at 100K rules
    fn test_stress_scale_100k() {
        let rules: Vec<RuleSpec> = (0..100_000).map(|i| {
            RuleSpec::compound(
                vec![
                    Predicate::eq(FieldDim::SrcIp, make_ip(i)),
                    Predicate::eq(FieldDim::L4Word1, 10000 + (i % 55000)),
                ],
                RuleAction::RateLimit { pps: 1000, name: None },
            )
        }).collect();
        stress_compile("scale_100k", &rules);
    }

    #[test]
    fn test_stress_fanout() {
        // 1000 rules all varying only src_port -- single dimension, 1000 edges
        let rules: Vec<RuleSpec> = (0..1_000).map(|i| {
            RuleSpec::drop_field(FieldDim::L4Word0, 1000 + i)
        }).collect();
        let flat = stress_compile("fanout_1k", &rules);
        assert!(flat.edges.len() >= 1000,
            "Expected >= 1000 edges for 1000 unique src_port values, got {}", flat.edges.len());
    }

    #[test]
    fn test_stress_replication_bomb() {
        // 50 wildcard-heavy rules (only constrain proto) + 50 specific rules (proto + src_ip).
        // The specific rules cause replication of wildcard rules into their subtrees.
        let mut rules: Vec<RuleSpec> = Vec::new();

        // 50 wildcard rules: different proto values, no other constraints
        for i in 0..50u32 {
            rules.push(
                RuleSpec::rate_limit_field(FieldDim::Proto, i % 256, 500 + i)
                    .with_priority((50 + i) as u8)
            );
        }

        // 50 specific rules: constrain proto AND src_ip
        for i in 0..50u32 {
            rules.push(
                RuleSpec::compound(
                    vec![
                        Predicate::eq(FieldDim::Proto, 17),
                        Predicate::eq(FieldDim::SrcIp, make_ip(i)),
                    ],
                    RuleAction::Drop,
                ).with_priority((100 + i) as u8)
            );
        }

        stress_compile("replication_bomb", &rules);
    }

    #[test]
    fn test_stress_full_depth() {
        // 100 rules touching all 9 dimensions simultaneously
        let rules: Vec<RuleSpec> = (0..100).map(|i| {
            RuleSpec::compound(
                vec![
                    Predicate::eq(FieldDim::Proto, 6),
                    Predicate::eq(FieldDim::SrcIp, make_ip(i)),
                    Predicate::eq(FieldDim::DstIp, make_ip(1000 + i)),
                    Predicate::eq(FieldDim::L4Word0, 40000 + i),
                    Predicate::eq(FieldDim::L4Word1, 80),
                    Predicate::eq(FieldDim::TcpFlags, 0x02),
                    Predicate::eq(FieldDim::Ttl, 128),
                    Predicate::eq(FieldDim::DfBit, 1),
                    Predicate::eq(FieldDim::TcpWindow, 65535),
                ],
                RuleAction::Drop,
            )
        }).collect();
        let flat = stress_compile("full_depth_100", &rules);
        assert!(flat.nodes.len() >= 100, "Expected >= 100 nodes for 100 full-depth rules");
    }

    #[test]
    fn test_stress_realistic() {
        // 500 rules with 2-4 constraints each, mixed dimensions, varying priorities.
        // Simulates what the sidecar actually produces.
        let mut rules: Vec<RuleSpec> = Vec::new();

        for i in 0u32..500 {
            let prio = ((i * 7 + 13) % 200) as u8 + 50;
            let rule = match i % 5 {
                0 => {
                    // UDP amplification: proto + src_port + src_ip
                    RuleSpec::compound(
                        vec![
                            Predicate::eq(FieldDim::Proto, 17),
                            Predicate::eq(FieldDim::L4Word0, 53 + (i % 100)),
                            Predicate::eq(FieldDim::SrcIp, make_ip(i)),
                        ],
                        RuleAction::RateLimit { pps: 1000 + i, name: None },
                    ).with_priority(prio)
                }
                1 => {
                    // TCP SYN flood: proto + tcp_flags + dst_port
                    RuleSpec::compound(
                        vec![
                            Predicate::eq(FieldDim::Proto, 6),
                            Predicate::eq(FieldDim::TcpFlags, 0x02),
                            Predicate::eq(FieldDim::L4Word1, 80 + (i % 50)),
                        ],
                        RuleAction::Drop,
                    ).with_priority(prio)
                }
                2 => {
                    // IP ban: src_ip + dst_port
                    RuleSpec::compound(
                        vec![
                            Predicate::eq(FieldDim::SrcIp, make_ip(i)),
                            Predicate::eq(FieldDim::L4Word1, 9999),
                        ],
                        RuleAction::Drop,
                    ).with_priority(prio)
                }
                3 => {
                    // Full fingerprint: proto + src_ip + ttl + df
                    RuleSpec::compound(
                        vec![
                            Predicate::eq(FieldDim::Proto, 17),
                            Predicate::eq(FieldDim::SrcIp, make_ip(i)),
                            Predicate::eq(FieldDim::Ttl, 255),
                            Predicate::eq(FieldDim::DfBit, 0),
                        ],
                        RuleAction::RateLimit { pps: 500 + i, name: None },
                    ).with_priority(prio)
                }
                _ => {
                    // Simple: just src_port
                    RuleSpec::rate_limit_field(FieldDim::L4Word0, 123 + (i % 200), 2000)
                        .with_priority(prio)
                }
            };
            rules.push(rule);
        }

        stress_compile("realistic_500", &rules);
    }

    // =========================================================================
    // eBPF Integration Stress Test
    // =========================================================================

    /// Integration test: loads eBPF program, compiles rules into real maps, flips blue/green.
    ///
    /// Prerequisites:
    ///   1. Build eBPF: cd filter-ebpf && cargo +nightly build --target bpfel-unknown-none -Z build-std=core
    ///   2. Create veth pair: sudo ip link add veth-test type veth peer name veth-test-peer
    ///   3. Bring up: sudo ip link set veth-test up && sudo ip link set veth-test-peer up
    ///   4. Run as root: sudo -E cargo test test_stress_ebpf_integration -- --ignored --nocapture
    #[test]
    #[ignore]
    fn test_stress_ebpf_integration() {
        use crate::VethFilter;
        use aya::programs::XdpFlags;

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let filter = VethFilter::with_flags("veth-test", XdpFlags::SKB_MODE)
                .expect("Failed to load VethFilter (are you root? is veth-test created?)");

            // === First flip: 100 rules ===
            let rules_100: Vec<RuleSpec> = (0..100).map(|i| {
                RuleSpec::compound(
                    vec![
                        Predicate::eq(FieldDim::SrcIp, make_ip(i)),
                        Predicate::eq(FieldDim::L4Word1, 10000 + i),
                    ],
                    RuleAction::RateLimit { pps: 1000, name: None },
                )
            }).collect();

            let nodes = filter.compile_and_flip_tree(&rules_100).await
                .expect("compile_and_flip failed for 100 rules");
            eprintln!("eBPF integration: 100 rules -> {} nodes", nodes);
            assert!(nodes > 0, "Expected nodes > 0 for 100 rules");

            // === Second flip: 1000 rules (blue/green round-trip) ===
            let rules_1k: Vec<RuleSpec> = (0..1_000).map(|i| {
                RuleSpec::compound(
                    vec![
                        Predicate::eq(FieldDim::SrcIp, make_ip(i)),
                        Predicate::eq(FieldDim::L4Word1, 10000 + (i % 55000)),
                    ],
                    RuleAction::RateLimit { pps: 1000, name: None },
                )
            }).collect();

            let nodes = filter.compile_and_flip_tree(&rules_1k).await
                .expect("compile_and_flip failed for 1000 rules (second flip)");
            eprintln!("eBPF integration: 1000 rules -> {} nodes (blue/green flip)", nodes);
            assert!(nodes > 0, "Expected nodes > 0 for 1000 rules");

            // === Third flip: back to smaller set (verifies second slot cleanup) ===
            let nodes = filter.compile_and_flip_tree(&rules_100).await
                .expect("compile_and_flip failed on third flip");
            eprintln!("eBPF integration: back to 100 rules -> {} nodes (third flip)", nodes);
            assert!(nodes > 0);

            // === Clear and verify ===
            filter.clear_tree().await.expect("clear_tree failed");
            eprintln!("eBPF integration: tree cleared successfully");

            eprintln!("eBPF integration stress test PASSED");
        });
    }
}
