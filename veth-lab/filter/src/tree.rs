//! Tree Rete Compiler - Compiles rule sets into an eBPF-friendly decision tree.
//!
//! The compiler builds a trie keyed by packet field values. Each node branches
//! on one dimension (proto, src_ip, dst_ip, etc.) and optionally carries an action.
//!
//! Key properties:
//! - **Correct by construction**: wildcard rules are replicated into specific
//!   subtrees so that a single-path walk always finds the highest-priority match.
//! - **Blue/green double buffering**: two tree slots share the same eBPF maps
//!   via node ID offset. Atomic root-pointer flip for zero-downtime updates.
//! - **Idempotent**: rule identity is based on canonical hash, not insertion order.

use std::collections::HashMap as StdHashMap;
use anyhow::{Context, Result};
use aya::maps::{Array, HashMap as AyaHashMap};
use aya::Ebpf;
use tracing::info;

use crate::{
    EdgeKey, FieldDim, RuleAction, RuleSpec, TokenBucket, TreeNode,
    ACT_DROP, ACT_PASS, ACT_RATE_LIMIT, DIM_LEAF, NUM_DIMENSIONS, TREE_SLOT_SIZE,
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
#[derive(Debug, Clone)]
struct ShadowNode {
    /// Which dimension this node branches on (index into DIM_ORDER)
    dim_index: usize,
    /// Optional action at this node (from the highest-priority terminating rule)
    action: Option<ShadowAction>,
    /// Specific-value children: field_value -> subtree
    children: StdHashMap<u32, ShadowNode>,
    /// Wildcard child: subtree for rules that don't constrain this dimension
    wildcard: Option<Box<ShadowNode>>,
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

/// Compiles a set of RuleSpecs into a shadow tree.
/// The algorithm guarantees that single-path walk finds the correct answer:
/// wildcard rules are replicated into all specific subtrees at each level.
fn compile_tree(rules: &[RuleSpec]) -> ShadowNode {
    compile_recursive(rules, 0)
}

fn compile_recursive(rules: &[RuleSpec], dim_idx: usize) -> ShadowNode {
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
            node.action = Some(ShadowAction {
                action: match best.action {
                    RuleAction::Pass => ACT_PASS,
                    RuleAction::Drop => ACT_DROP,
                    RuleAction::RateLimit => ACT_RATE_LIMIT,
                },
                priority: best.priority,
                rate_pps: best.rate_pps.unwrap_or(0),
                rule_id: best.canonical_hash(),
            });
        }
        return node;
    }

    let dim = DIM_ORDER[dim_idx];

    // Check if ANY rule constrains this dimension
    let any_constrains = rules.iter().any(|r| {
        r.constraints.iter().any(|(d, _)| *d == dim)
    });

    // If no rule constrains this dimension, skip it entirely
    if !any_constrains {
        return compile_recursive(rules, dim_idx + 1);
    }

    // Partition rules: specific (constrain this dim) vs wildcard (don't)
    let mut specific: StdHashMap<u32, Vec<&RuleSpec>> = StdHashMap::new();
    let mut wildcard: Vec<&RuleSpec> = Vec::new();

    for rule in rules {
        if let Some((_, value)) = rule.constraints.iter().find(|(d, _)| *d == dim) {
            specific.entry(*value).or_default().push(rule);
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
        .filter(|r| !r.constraints.iter().any(|(d, _)| remaining_dims.contains(d)))
        .collect();
    if let Some(best) = terminating.iter().max_by_key(|r| r.priority) {
        node.action = Some(ShadowAction {
            action: match best.action {
                RuleAction::Pass => ACT_PASS,
                RuleAction::Drop => ACT_DROP,
                RuleAction::RateLimit => ACT_RATE_LIMIT,
            },
            priority: best.priority,
            rate_pps: best.rate_pps.unwrap_or(0),
            rule_id: best.canonical_hash(),
        });
    }

    // Build specific children: each gets its own rules PLUS all wildcard rules
    // This is the key replication step that makes single-path walk correct.
    for (value, specific_rules) in &specific {
        let mut child_rules: Vec<&RuleSpec> = specific_rules.clone();
        child_rules.extend(wildcard.iter()); // <-- REPLICATION
        // Collect into owned Vec for recursive call
        let owned: Vec<RuleSpec> = child_rules.iter().map(|r| (*r).clone()).collect();
        node.children.insert(*value, compile_recursive(&owned, dim_idx + 1));
    }

    // Build wildcard child: only wildcard rules apply
    if !wildcard.is_empty() {
        let owned: Vec<RuleSpec> = wildcard.iter().map(|r| (*r).clone()).collect();
        node.wildcard = Some(Box::new(compile_recursive(&owned, dim_idx + 1)));
    }

    node
}

// =============================================================================
// Flatten shadow tree into eBPF map entries
// =============================================================================

/// Result of flattening: ready to write to eBPF maps.
pub struct FlatTree {
    pub nodes: Vec<(u32, TreeNode)>,       // (node_id, node)
    pub edges: Vec<(EdgeKey, u32)>,         // (edge_key, child_id)
    pub rate_buckets: Vec<(u32, TokenBucket)>, // (rule_id, bucket)
    pub root_id: u32,
}

/// Flatten a shadow tree into eBPF map entries, using node IDs starting at `base_id`.
fn flatten_tree(shadow: &ShadowNode, base_id: u32) -> FlatTree {
    let mut allocator = NodeAllocator::new(base_id);
    let mut flat = FlatTree {
        nodes: Vec::new(),
        edges: Vec::new(),
        rate_buckets: Vec::new(),
        root_id: 0,
    };

    flat.root_id = flatten_recursive(shadow, &mut allocator, &mut flat);
    flat
}

struct NodeAllocator {
    next_id: u32,
}

impl NodeAllocator {
    fn new(base: u32) -> Self {
        // Start at base+1 (0 is NULL sentinel, base might be 0 for slot 0)
        Self { next_id: if base == 0 { 1 } else { base } }
    }

    fn alloc(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

fn flatten_recursive(
    shadow: &ShadowNode,
    alloc: &mut NodeAllocator,
    flat: &mut FlatTree,
) -> u32 {
    let my_id = alloc.alloc();

    // Determine the eBPF dimension value
    let dimension = if shadow.children.is_empty() && shadow.wildcard.is_none() {
        DIM_LEAF
    } else if shadow.dim_index < NUM_DIMENSIONS {
        DIM_ORDER[shadow.dim_index] as u8
    } else {
        DIM_LEAF
    };

    // Flatten wildcard child first (so we have its node_id)
    let wildcard_child = if let Some(wc) = &shadow.wildcard {
        flatten_recursive(wc, alloc, flat)
    } else {
        0
    };

    // Flatten specific children and create edges
    for (&value, child) in &shadow.children {
        let child_id = flatten_recursive(child, alloc, flat);
        flat.edges.push((EdgeKey { parent: my_id, value }, child_id));
    }

    // Build the TreeNode
    let (has_action, action, priority, rate_pps, rule_id) = if let Some(a) = &shadow.action {
        // Track rate buckets
        if a.action == ACT_RATE_LIMIT && a.rate_pps > 0 {
            // Only add if not already present (multiple nodes can share a rule_id)
            if !flat.rate_buckets.iter().any(|(id, _)| *id == a.rule_id) {
                flat.rate_buckets.push((a.rule_id, TokenBucket {
                    rate_pps: a.rate_pps,
                    tokens: a.rate_pps,
                    last_update_ns: 0,
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
}

impl TreeManager {
    pub fn new() -> Self {
        Self { active_slot: 0 }
    }

    /// Which slot is currently active
    pub fn active_slot(&self) -> u32 {
        self.active_slot
    }

    /// The node ID base for the inactive (staging) slot
    fn staging_base(&self) -> u32 {
        if self.active_slot == 0 {
            TREE_SLOT_SIZE + 1 // Slot 1 starts at 250_001
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
        {
            let mut edges_map: AyaHashMap<_, EdgeKey, u32> = bpf
                .map_mut("TREE_EDGES").context("TREE_EDGES not found")?
                .try_into()?;
            for &(ref key, child_id) in &flat.edges {
                edges_map.insert(*key, child_id, 0)?;
            }
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
    use crate::{FieldDim, RuleAction, RuleSpec};

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
                vec![(FieldDim::Proto, 17), (FieldDim::L4Word0, 53)],
                RuleAction::Drop, None,
            ),
            RuleSpec::compound(
                vec![(FieldDim::Proto, 17), (FieldDim::L4Word0, 123)],
                RuleAction::Drop, None,
            ),
        ];
        let tree = compile_tree(&rules);
        let flat = flatten_tree(&tree, 1);

        // Should have edges for proto=17, src_port=53, src_port=123
        assert!(flat.edges.len() >= 2, "Expected >= 2 edges, got {}", flat.edges.len());
    }

    #[test]
    fn test_priority_replication() {
        // Rule A: proto=17 -> RATE_LIMIT (prio 5)
        // Rule B: proto=17, src_port=53 -> DROP (prio 10)
        // A packet matching proto=17, src_port=53 should get DROP (higher prio)
        // A packet matching proto=17, src_port=999 should get RATE_LIMIT
        let rules = vec![
            RuleSpec::rate_limit_field(FieldDim::Proto, 17, 1000).with_priority(5),
            RuleSpec::compound(
                vec![(FieldDim::Proto, 17), (FieldDim::L4Word0, 53)],
                RuleAction::Drop, None,
            ).with_priority(10),
        ];
        let tree = compile_tree(&rules);
        let flat = flatten_tree(&tree, 1);

        // The tree should have:
        // - Root branches on Proto
        // - proto=17 node branches on L4Word0
        // - src_port=53 -> DROP (prio 10)
        // - wildcard -> RATE_LIMIT (prio 5, replicated from Rule A)

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
            vec![(FieldDim::Proto, 17), (FieldDim::L4Word0, 53)],
            RuleAction::Drop, None,
        );
        let spec2 = RuleSpec::compound(
            // Same constraints in different order
            vec![(FieldDim::L4Word0, 53), (FieldDim::Proto, 17)],
            RuleAction::Drop, None,
        );
        assert_eq!(spec1.canonical_hash(), spec2.canonical_hash());
    }
}
