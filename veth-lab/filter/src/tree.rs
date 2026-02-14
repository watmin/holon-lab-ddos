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
    EdgeKey, FieldDim, FieldRef, Predicate, RuleSpec, TokenBucket, TreeNode,
    ACT_PASS, ACT_RATE_LIMIT, DIM_LEAF, NUM_DIMENSIONS, TREE_SLOT_SIZE,
    RANGE_OP_NONE,
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
pub(crate) struct ShadowNode {
    /// Which dimension this node branches on (index into DIM_ORDER)
    dim_index: usize,
    /// Optional action at this node (from the highest-priority terminating rule)
    action: Option<ShadowAction>,
    /// Specific-value children: field_value -> subtree (Rc for cheap sharing)
    children: StdHashMap<u32, Rc<ShadowNode>>,
    /// Wildcard child: subtree for rules that don't constrain this dimension
    wildcard: Option<Rc<ShadowNode>>,
    /// Range-guarded children: (range_op, threshold) -> subtree
    /// Rules with range predicates (>, <, >=, <=) on this dimension.
    /// The eBPF walker checks: if packet_value OP threshold, push range child.
    range_children: Vec<(RangeEdge, Rc<ShadowNode>)>,
}

/// A range edge descriptor for compile-time tree building.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RangeEdge {
    /// Range operator (RANGE_OP_GT, RANGE_OP_LT, RANGE_OP_GTE, RANGE_OP_LTE)
    op: u8,
    /// Threshold value for comparison
    value: u32,
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

/// Result of L4Byte resolution: maps (offset, length) -> CustomN dim
#[derive(Debug, Clone, Default)]
pub struct CustomDimMapping {
    /// Maps (offset, length) to custom dim index (0-6)
    pub entries: Vec<(u16, u8, FieldDim)>,
}

impl CustomDimMapping {
    /// Look up the custom dim for a given (offset, length) pair
    pub fn get(&self, offset: u16, length: u8) -> Option<FieldDim> {
        self.entries.iter()
            .find(|(o, l, _)| *o == offset && *l == length)
            .map(|(_, _, dim)| *dim)
    }

    /// Get the CustomDimEntry for a custom dim index
    pub fn config_entry(&self, index: usize) -> Option<crate::CustomDimEntry> {
        self.entries.iter()
            .find(|(_, _, dim)| dim.custom_index() == Some(index))
            .map(|(offset, length, _)| crate::CustomDimEntry {
                offset: *offset,
                length: *length,
                _pad: 0,
            })
    }

    /// Number of custom dims in use
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Compiles a set of RuleSpecs into a shadow DAG (no replication).
/// Wildcard rules live only in the wildcard_child branch.
/// The eBPF walker explores specific, range-guarded, and wildcard paths via DFS.
#[cfg(test)]
fn compile_tree(rules: &[RuleSpec]) -> Rc<ShadowNode> {
    let (tree, _, _, _) = compile_tree_full(rules);
    tree
}

/// Full compilation: returns the shadow tree, custom dim mapping, dimension order,
/// and rule manifest (post-compilation rule_id → action/label mapping).
/// Also populates byte_patterns on the returned PatternAlloc for pattern guard edges.
pub(crate) fn compile_tree_full(rules: &[RuleSpec]) -> (Rc<ShadowNode>, CustomDimMapping, Vec<FieldDim>, Vec<crate::RuleManifestEntry>) {
    // Expand In predicates into multiple Eq-based rules.
    // Range predicates are NOT expanded — they become range edges in the tree,
    // evaluated at runtime by the eBPF walker.
    let mut expanded = expand_in_predicates(rules);

    // Save pre-transformation labels (before resolve/allocate modify predicates)
    let pre_labels: Vec<String> = expanded.iter().map(|r| r.display_label()).collect();

    // Phase 2a: Resolve 1-4 byte L4Byte references to custom dimensions
    let mapping = resolve_l4byte_refs(&mut expanded);

    // Phase 2b: Convert remaining L4Byte predicates (5-64 bytes) to pattern guard predicates
    // This allocates BytePattern entries and converts L4Byte to guard edges on dim 0 (Proto).
    let pattern_alloc = allocate_patterns(&mut expanded);
    
    // Store patterns in thread-local for flatten to pick up
    PATTERN_ALLOC.with(|pa| {
        *pa.borrow_mut() = pattern_alloc;
    });

    // Build rule manifest: post-compilation rule_id paired with labels.
    // This is the authoritative mapping for TREE_COUNTERS observability.
    // Prefer the action's :name for the label (if set), otherwise fall back to
    // the rule-level display_label (which uses :label or constraint-based system label).
    let mut manifest_map: std::collections::HashMap<u32, crate::RuleManifestEntry> = std::collections::HashMap::new();
    for (spec, label) in expanded.iter().zip(pre_labels.iter()) {
        let rule_id = spec.bucket_key().unwrap_or_else(|| spec.canonical_hash());
        if let Some(action) = spec.actions.first() {
            let effective_label = if let Some((ns, name)) = action.name() {
                format!("[{} {}]", ns, name)
            } else {
                label.clone()
            };
            manifest_map.entry(rule_id).or_insert_with(|| crate::RuleManifestEntry {
                rule_id,
                action: action.clone(),
                label: effective_label,
            });
        }
    }
    let manifest: Vec<crate::RuleManifestEntry> = manifest_map.into_values().collect();

    // Build dimension order: static dims + active custom dims
    let mut dim_order: Vec<FieldDim> = DIM_ORDER.to_vec();
    for &(_, _, dim) in &mapping.entries {
        dim_order.push(dim);
    }

    let tree = compile_recursive_dynamic(&expanded, 0, &dim_order);
    (tree, mapping, dim_order, manifest)
}

/// Thread-local storage for pattern allocations (passed from compile to flatten)
use std::cell::RefCell;
thread_local! {
    static PATTERN_ALLOC: RefCell<Vec<crate::BytePattern>> = RefCell::new(Vec::new());
}

/// Choose a dimension for guard edge placement that doesn't conflict with
/// the rule's existing Eq/In constraints. Pattern guard byte-comparison is
/// dimension-agnostic, so any dimension works — we just need one whose
/// tree node the walker will visit.
fn pick_guard_dim(rule: &RuleSpec) -> FieldDim {
    let used_dims: Vec<FieldDim> = rule.constraints.iter()
        .filter_map(|p| match p {
            Predicate::Eq(FieldRef::Dim(d), _) | Predicate::In(FieldRef::Dim(d), _) => Some(*d),
            _ => None,
        })
        .collect();
    // Find the first static dimension not used by a specific (Eq/In) constraint
    for &dim in &DIM_ORDER {
        if !used_dims.contains(&dim) {
            return dim;
        }
    }
    // Fallback (shouldn't happen with 9 static dims)
    FieldDim::Proto
}

/// Allocate BytePattern entries for unresolved L4Byte predicates.
/// Converts `Eq/MaskEq(L4Byte{...}, ...)` and `RawByteMatch` to
/// `PatternGuard(dim, pattern_idx)`. The guard dimension is chosen to not
/// conflict with existing Eq/In constraints in the rule.
fn allocate_patterns(rules: &mut Vec<RuleSpec>) -> Vec<crate::BytePattern> {
    let mut patterns: Vec<crate::BytePattern> = Vec::new();
    
    for rule in rules.iter_mut() {
        // Pick a guard dimension for this rule (before modifying constraints)
        let guard_dim = pick_guard_dim(rule);
        
        let mut new_constraints = Vec::with_capacity(rule.constraints.len());
        for pred in &rule.constraints {
            let resolved = match pred {
                Predicate::Eq(FieldRef::L4Byte { offset, length }, value) => {
                    // Create a pattern for exact match — pre-shifted so
                    // match/mask_bytes[i] corresponds to pattern_data[i] directly.
                    let mut pat = crate::BytePattern::default();
                    pat.offset = *offset;
                    pat.length = *length;
                    let off = *offset as usize;
                    let len = *length as usize;
                    if len <= 4 && off + len <= crate::MAX_PATTERN_LEN {
                        let val_bytes = value.to_be_bytes();
                        let start = 4 - len;
                        for i in 0..len {
                            pat.match_bytes[off + i] = val_bytes[start + i];
                            pat.mask_bytes[off + i] = 0xFF;
                        }
                    }
                    let pattern_idx = patterns.len() as u32;
                    patterns.push(pat);
                    Predicate::PatternGuard(guard_dim, pattern_idx)
                }
                Predicate::MaskEq(FieldRef::L4Byte { offset, length }, _mask, _expected) => {
                    let off = *offset as usize;
                    let len = *length as usize;
                    let mut pat = crate::BytePattern::default();
                    pat.offset = *offset;
                    pat.length = *length;
                    
                    if len <= 4 && off + len <= crate::MAX_PATTERN_LEN {
                        let exp_bytes = _expected.to_be_bytes();
                        let mask_bytes_val = _mask.to_be_bytes();
                        let start = 4 - len;
                        for i in 0..len {
                            pat.match_bytes[off + i] = exp_bytes[start + i] & mask_bytes_val[start + i];
                            pat.mask_bytes[off + i] = mask_bytes_val[start + i];
                        }
                    }
                    
                    let pattern_idx = patterns.len() as u32;
                    patterns.push(pat);
                    Predicate::PatternGuard(guard_dim, pattern_idx)
                }
                Predicate::RawByteMatch(raw_pat) => {
                    // Pre-built BytePattern from sidecar parsing (>4 byte matches).
                    // Pre-shift bytes to position `offset` within the 64-byte arrays
                    // so match/mask_bytes[i] corresponds to pattern_data[i] directly.
                    let off = raw_pat.offset as usize;
                    let len = raw_pat.length as usize;
                    let mut shifted = crate::BytePattern::default();
                    shifted.offset = raw_pat.offset;
                    shifted.length = raw_pat.length;
                    for i in 0..len {
                        if off + i < crate::MAX_PATTERN_LEN {
                            shifted.match_bytes[off + i] = raw_pat.match_bytes[i];
                            shifted.mask_bytes[off + i] = raw_pat.mask_bytes[i];
                        }
                    }
                    let pattern_idx = patterns.len() as u32;
                    patterns.push(shifted);
                    Predicate::PatternGuard(guard_dim, pattern_idx)
                }
                other => other.clone(),
            };
            new_constraints.push(resolved);
        }
        rule.constraints = new_constraints;
    }
    
    if !patterns.is_empty() {
        info!("Allocated {} byte pattern(s) for pattern guard edges", patterns.len());
    }
    
    patterns
}

/// Scan all rules for L4Byte field refs, assign custom dim slots (for 1-4 byte),
/// and resolve them to Dim(CustomN) predicates. Long patterns (5-64 bytes) and
/// patterns that can't pack into custom dims are left as L4Byte refs for later
/// conversion to pattern guard edges.
///
/// For 1-4 byte exact matches (mask = all-FF), auto-promotes MaskEq to Eq
/// for specific-edge fan-out.
fn resolve_l4byte_refs(rules: &mut Vec<RuleSpec>) -> CustomDimMapping {
    use std::collections::BTreeSet;
    use std::collections::BTreeMap;
    
    // Pass 1: Collect unique (offset, length) combinations (order-independent)
    let mut seen: BTreeSet<(u16, u8)> = BTreeSet::new();
    for rule in rules.iter() {
        for pred in &rule.constraints {
            match pred.field_ref() {
                FieldRef::L4Byte { offset, length } if *length <= 4 => {
                    seen.insert((*offset, *length));
                }
                FieldRef::L4Byte { offset, length } if *length > 4 => {
                    info!("L4Byte offset={} length={} -> pattern guard (too long for custom dim)", offset, length);
                }
                _ => {}
            }
        }
    }
    
    // Pass 2: Assign custom dims in deterministic sorted order (by offset, then length)
    let mut unique_combos: BTreeMap<(u16, u8), FieldDim> = BTreeMap::new();
    let mut next_custom = 0usize;
    for key in &seen {
        if next_custom >= crate::NUM_CUSTOM_DIMS {
            tracing::warn!(
                "Too many unique L4Byte combos (>{}), ignoring offset={} length={}",
                crate::NUM_CUSTOM_DIMS, key.0, key.1
            );
            continue;
        }
        let dim = FieldDim::from_custom_index(next_custom).unwrap();
        unique_combos.insert(*key, dim);
        next_custom += 1;
    }
    
    // Build the mapping
    let mapping = CustomDimMapping {
        entries: unique_combos.iter()
            .map(|((offset, length), dim)| (*offset, *length, *dim))
            .collect(),
    };
    
    if !mapping.entries.is_empty() {
        info!("Custom dim mapping: {} entries", mapping.entries.len());
        for (offset, length, dim) in &mapping.entries {
            info!("  offset={}, length={} -> {:?}", offset, length, dim);
        }
    }
    
    // Resolve 1-4 byte L4Byte refs in rules to their assigned custom dims.
    // Leave 5+ byte L4Byte refs unresolved for pattern guard handling.
    for rule in rules.iter_mut() {
        let mut new_constraints = Vec::with_capacity(rule.constraints.len());
        for pred in &rule.constraints {
            let resolved = match pred {
                Predicate::Eq(FieldRef::L4Byte { offset, length }, value) if *length <= 4 => {
                    if let Some(dim) = unique_combos.get(&(*offset, *length)) {
                        Predicate::Eq(FieldRef::Dim(*dim), *value)
                    } else {
                        pred.clone()
                    }
                }
                Predicate::MaskEq(FieldRef::L4Byte { offset, length }, mask, expected) if *length <= 4 => {
                    if let Some(dim) = unique_combos.get(&(*offset, *length)) {
                        let all_ff = match length {
                            1 => *mask == 0xFF,
                            2 => *mask == 0xFFFF,
                            4 => *mask == 0xFFFFFFFF,
                            _ => false,
                        };
                        if all_ff {
                            Predicate::Eq(FieldRef::Dim(*dim), *expected)
                        } else {
                            Predicate::MaskEq(FieldRef::Dim(*dim), *mask, *expected)
                        }
                    } else {
                        pred.clone()
                    }
                }
                // 5-64 byte patterns: leave as L4Byte for pattern guard allocation
                other => other.clone(),
            };
            new_constraints.push(resolved);
        }
        rule.constraints = new_constraints;
    }
    
    mapping
}

/// compile_recursive with dynamic dimension order (supports custom dims)
fn compile_recursive_dynamic(rules: &[RuleSpec], dim_idx: usize, dim_order: &[FieldDim]) -> Rc<ShadowNode> {
    // Base case: no more dimensions to branch on
    if dim_idx >= dim_order.len() || rules.is_empty() {
        let mut node = ShadowNode {
            dim_index: dim_idx,
            action: None,
            children: StdHashMap::new(),
            wildcard: None,
            range_children: Vec::new(),
        };
        if let Some(best) = rules.iter().max_by_key(|r| r.priority) {
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

    let dim = dim_order[dim_idx];

    // Check if ANY rule constrains this dimension
    let any_constrains = rules.iter().any(|r| {
        r.constraints.iter().any(|p| p.constrains_dim(dim))
    });

    if !any_constrains {
        return compile_recursive_dynamic(rules, dim_idx + 1, dim_order);
    }

    // Three-way partition
    let mut specific: StdHashMap<u32, Vec<&RuleSpec>> = StdHashMap::new();
    let mut range_guarded: Vec<(RangeEdge, &RuleSpec)> = Vec::new();
    let mut wildcard: Vec<&RuleSpec> = Vec::new();

    for rule in rules {
        let eq_value = rule.constraints.iter()
            .find_map(|p| p.as_eq_dim().filter(|(d, _)| *d == dim).map(|(_, v)| v));
        if let Some(value) = eq_value {
            specific.entry(value).or_default().push(rule);
        } else if let Some((op, val)) = rule.constraints.iter()
            .find_map(|p| p.as_guard_on_dim(dim))
        {
            range_guarded.push((RangeEdge { op, value: val }, rule));
        } else {
            wildcard.push(rule);
        }
    }

    let mut node = ShadowNode {
        dim_index: dim_idx,
        action: None,
        children: StdHashMap::new(),
        wildcard: None,
        range_children: Vec::new(),
    };

    let remaining_dims: Vec<FieldDim> = dim_order[dim_idx..].to_vec();
    let terminating: Vec<&RuleSpec> = rules.iter()
        .filter(|r| !r.constraints.iter().any(|p| {
            p.field_dim().map_or(false, |d| remaining_dims.contains(&d))
        }))
        .collect();
    if let Some(best) = terminating.iter().max_by_key(|r| r.priority) {
        if let Some(first_action) = best.actions.first() {
            node.action = Some(ShadowAction {
                action: first_action.action_type(),
                priority: best.priority,
                rate_pps: first_action.rate_pps().unwrap_or(0),
                rule_id: best.bucket_key().unwrap_or_else(|| best.canonical_hash()),
            });
        }
    }

    for (value, specific_rules) in &specific {
        let owned: Vec<RuleSpec> = specific_rules.iter().map(|r| (*r).clone()).collect();
        node.children.insert(*value, compile_recursive_dynamic(&owned, dim_idx + 1, dim_order));
    }

    let mut range_groups: StdHashMap<RangeEdge, Vec<&RuleSpec>> = StdHashMap::new();
    for (edge, rule) in &range_guarded {
        range_groups.entry(edge.clone()).or_default().push(rule);
    }
    for (edge, range_rules) in &range_groups {
        let owned: Vec<RuleSpec> = range_rules.iter().map(|r| (*r).clone()).collect();
        let child = compile_recursive_dynamic(&owned, dim_idx + 1, dim_order);
        node.range_children.push((edge.clone(), child));
    }

    if !wildcard.is_empty() {
        let owned: Vec<RuleSpec> = wildcard.iter().map(|r| (*r).clone()).collect();
        node.wildcard = Some(compile_recursive_dynamic(&owned, dim_idx + 1, dim_order));
    }

    Rc::new(node)
}

/// Expand In predicates into multiple Eq-based rules.
/// (in proto 6 17) becomes two rules: one with (= proto 6), one with (= proto 17)
pub fn expand_in_predicates(rules: &[RuleSpec]) -> Vec<RuleSpec> {
    let mut expanded = Vec::new();
    
    for rule in rules {
        // Check if this rule has any In predicates
        let has_in = rule.constraints.iter().any(|p| matches!(p, Predicate::In(_, _)));
        
        if !has_in {
            // No In predicates - keep as-is
            expanded.push(rule.clone());
            continue;
        }
        
        // Expand: create one rule per combination of In values
        let mut current_rules = vec![rule.clone()];
        
        for (pred_idx, pred) in rule.constraints.iter().enumerate() {
            if let Predicate::In(field_ref, values) = pred {
                let mut new_rules = Vec::new();
                
                // For each existing rule, create N variants (one per value in the In set)
                for base_rule in &current_rules {
                    for val in values {
                        let mut new_rule = base_rule.clone();
                        // Replace the In predicate with an Eq predicate
                        new_rule.constraints[pred_idx] = Predicate::Eq(field_ref.clone(), *val);
                        new_rules.push(new_rule);
                    }
                }
                
                current_rules = new_rules;
            }
        }
        
        expanded.extend(current_rules);
    }
    
    expanded
}


// (compile_recursive removed — replaced by compile_recursive_dynamic)

// =============================================================================
// Flatten shadow DAG into eBPF map entries (with lazy replication)
// =============================================================================

/// Result of flattening: ready to write to eBPF maps.
pub struct FlatTree {
    pub nodes: Vec<(u32, TreeNode)>,       // (node_id, node)
    pub edges: Vec<(EdgeKey, u32)>,         // (edge_key, child_id)
    pub rate_buckets: Vec<(u32, TokenBucket)>, // (rule_id, bucket)
    pub byte_patterns: Vec<(u32, crate::BytePattern)>, // (pattern_idx, pattern)
    pub root_id: u32,
}

/// Flatten a shadow DAG directly into eBPF map entries with no replication.
/// The DAG is walked once, and each unique Rc node gets a unique flat ID.
/// Wildcard rules are NOT replicated into specific subtrees; the eBPF
/// walker's stack-based DFS explores both specific and wildcard paths.
#[cfg(test)]
fn flatten_tree(shadow: &Rc<ShadowNode>, base_id: u32) -> FlatTree {
    // Use the static DIM_ORDER for non-custom-dim trees (tests without custom dims)
    flatten_tree_with_dims(shadow, base_id, &DIM_ORDER)
}

fn flatten_tree_with_dims(shadow: &Rc<ShadowNode>, base_id: u32, dim_order: &[FieldDim]) -> FlatTree {
    let mut alloc = NodeAllocator::new(base_id);
    // Collect byte patterns from the thread-local pattern allocator
    let byte_patterns = PATTERN_ALLOC.with(|pa| {
        let patterns = pa.borrow();
        patterns.iter().enumerate()
            .map(|(i, p)| (i as u32, *p))
            .collect::<Vec<_>>()
    });

    let mut flat = FlatTree {
        nodes: Vec::new(),
        edges: Vec::new(),
        rate_buckets: Vec::new(),
        byte_patterns,
        root_id: 0,
    };
    let mut dedup: StdHashMap<usize, u32> = StdHashMap::new(); // Rc ptr -> flat node_id

    flat.root_id = flatten_recursive(shadow, &mut alloc, &mut flat, &mut dedup, dim_order);
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
    dim_order: &[FieldDim],
) -> u32 {
    let ptr = Rc::as_ptr(shadow) as usize;
    if let Some(&existing) = dedup.get(&ptr) {
        return existing;
    }

    let my_id = alloc.alloc();
    dedup.insert(ptr, my_id);

    // Flatten wildcard child
    let wildcard_child = if let Some(wc) = &shadow.wildcard {
        flatten_recursive(wc, alloc, flat, dedup, dim_order)
    } else {
        0
    };

    // Flatten specific children
    for (&value, child) in &shadow.children {
        let child_id = flatten_recursive(child, alloc, flat, dedup, dim_order);
        flat.edges.push((EdgeKey { parent: my_id, value }, child_id));
    }

    // Flatten range/guard children.
    // Each TreeNode has 2 guard edge slots. If >2 guards exist on a single
    // dimension, we chain overflow through intermediate nodes connected via
    // the wildcard pointer. The DFS walker naturally follows the chain.
    //
    // Example with 4 guards:
    //   MainNode: guards[0,1], wildcard → OverflowNode
    //   OverflowNode: guards[2,3], wildcard → original_wildcard
    //
    // The overflow nodes have the same dimension, no specific edges, no action.
    // The walker visits them via wildcard traversal and evaluates their guards.

    // First, flatten all guard edge children to get their node IDs
    let guard_children: Vec<(RangeEdge, u32)> = shadow.range_children.iter()
        .map(|(edge, child)| {
            let child_id = flatten_recursive(child, alloc, flat, dedup, dim_order);
            (edge.clone(), child_id)
        })
        .collect();

    let has_children = !shadow.children.is_empty()
        || shadow.wildcard.is_some()
        || !guard_children.is_empty();
    let dimension = if !has_children {
        DIM_LEAF
    } else if shadow.dim_index < dim_order.len() {
        dim_order[shadow.dim_index] as u8
    } else {
        DIM_LEAF
    };

    // Build overflow chain for guards beyond the first 2
    let effective_wildcard = if guard_children.len() <= 2 {
        wildcard_child
    } else {
        // Chain overflow nodes from tail to head.
        // Last overflow gets the original wildcard; each earlier one's
        // wildcard points to the next overflow in the chain.
        let overflow = &guard_children[2..];
        let mut chain_tail = wildcard_child; // original wildcard goes at the end

        // Process pairs from end to start so each node's wildcard → next node
        let chunks: Vec<&[(RangeEdge, u32)]> = overflow.chunks(2).collect();
        for chunk in chunks.iter().rev() {
            let overflow_id = alloc.alloc();
            let mut ov_count = 0u8;
            let mut ov_op_0 = RANGE_OP_NONE;
            let mut ov_op_1 = RANGE_OP_NONE;
            let mut ov_val_0 = 0u32;
            let mut ov_ch_0 = 0u32;
            let mut ov_val_1 = 0u32;
            let mut ov_ch_1 = 0u32;

            if let Some((edge, child_id)) = chunk.get(0) {
                ov_op_0 = edge.op;
                ov_val_0 = edge.value;
                ov_ch_0 = *child_id;
                ov_count += 1;
            }
            if let Some((edge, child_id)) = chunk.get(1) {
                ov_op_1 = edge.op;
                ov_val_1 = edge.value;
                ov_ch_1 = *child_id;
                ov_count += 1;
            }

            flat.nodes.push((overflow_id, TreeNode {
                dimension,
                has_action: 0,
                action: ACT_PASS,
                priority: 0,
                rate_pps: 0,
                wildcard_child: chain_tail,
                rule_id: 0,
                range_count: ov_count,
                range_op_0: ov_op_0,
                range_op_1: ov_op_1,
                _range_pad: 0,
                range_val_0: ov_val_0,
                range_child_0: ov_ch_0,
                range_val_1: ov_val_1,
                range_child_1: ov_ch_1,
            }));

            chain_tail = overflow_id;
        }

        chain_tail // main node's wildcard → head of overflow chain
    };

    // First 2 guards go directly on the main node
    let mut range_count = 0u8;
    let mut range_op_0 = RANGE_OP_NONE;
    let mut range_op_1 = RANGE_OP_NONE;
    let mut range_val_0 = 0u32;
    let mut range_child_0 = 0u32;
    let mut range_val_1 = 0u32;
    let mut range_child_1 = 0u32;

    if let Some((edge, child_id)) = guard_children.get(0) {
        range_op_0 = edge.op;
        range_val_0 = edge.value;
        range_child_0 = *child_id;
        range_count += 1;
    }
    if let Some((edge, child_id)) = guard_children.get(1) {
        range_op_1 = edge.op;
        range_val_1 = edge.value;
        range_child_1 = *child_id;
        range_count += 1;
    }

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
        wildcard_child: effective_wildcard,
        rule_id,
        range_count,
        range_op_0,
        range_op_1,
        _range_pad: 0,
        range_val_0,
        range_child_0,
        range_val_1,
        range_child_1,
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
    ) -> Result<(usize, Vec<crate::RuleManifestEntry>)> {
        let base = self.staging_base();

        // 1. Compile the tree (with L4Byte resolution)
        let (shadow, custom_dim_mapping, dim_order, manifest) = compile_tree_full(rules);

        // 2. Flatten into map entries (using full dim_order including custom dims)
        let flat = flatten_tree_with_dims(&shadow, base, &dim_order);
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
            return Ok((0, manifest));
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
        // Clear old buckets and write new ones
        {
            let mut rate_map: AyaHashMap<_, u32, TokenBucket> = bpf
                .map_mut("TREE_RATE_STATE").context("TREE_RATE_STATE not found")?
                .try_into()?;
            
            // Collect current bucket IDs from new rules
            let new_bucket_ids: std::collections::HashSet<u32> = 
                flat.rate_buckets.iter().map(|(id, _)| *id).collect();
            
            // Remove stale buckets (not in new rule set)
            let all_keys: Vec<u32> = rate_map.keys().filter_map(|k| k.ok()).collect();
            let mut removed_count = 0;
            for key in all_keys {
                if !new_bucket_ids.contains(&key) {
                    if rate_map.remove(&key).is_ok() {
                        removed_count += 1;
                    }
                }
            }
            if removed_count > 0 {
                info!("Cleaned up {} expired rate limiter bucket(s) from eBPF map", removed_count);
            }
            
            // Insert/update buckets (preserve tokens for buckets that still exist)
            for &(rule_id, ref bucket) in &flat.rate_buckets {
                // Only insert if not already present (preserves token state across flips)
                if rate_map.get(&rule_id, 0).is_err() {
                    rate_map.insert(rule_id, *bucket, 0)?;
                }
            }
        }

        // 6. Write CUSTOM_DIM_CONFIG for l4-match byte extraction
        {
            let mut dim_config: Array<_, u32> = bpf
                .map_mut("CUSTOM_DIM_CONFIG").context("CUSTOM_DIM_CONFIG not found")?
                .try_into()?;
            for i in 0..crate::NUM_CUSTOM_DIMS {
                let packed = if let Some(entry) = custom_dim_mapping.config_entry(i) {
                    (entry.offset as u32) | ((entry.length as u32) << 16)
                } else {
                    0u32  // inactive slot
                };
                dim_config.set(i as u32, packed, 0)?;
            }
            if custom_dim_mapping.len() > 0 {
                info!("CUSTOM_DIM_CONFIG: {} active slot(s)", custom_dim_mapping.len());
            }
        }

        // 7. Write BYTE_PATTERNS for pattern guard edges
        if !flat.byte_patterns.is_empty() {
            let mut pat_map: Array<_, crate::BytePattern> = bpf
                .map_mut("BYTE_PATTERNS").context("BYTE_PATTERNS not found")?
                .try_into()?;
            for &(idx, ref pattern) in &flat.byte_patterns {
                pat_map.set(idx, *pattern, 0)?;
            }
            info!("BYTE_PATTERNS: wrote {} pattern(s)", flat.byte_patterns.len());
        }

        // 8. ATOMIC FLIP: update TREE_ROOT to point to new tree's root
        {
            let mut root_map: Array<_, u32> = bpf
                .map_mut("TREE_ROOT").context("TREE_ROOT not found")?
                .try_into()?;
            root_map.set(0, flat.root_id, 0)?;
        }

        info!("Tree flip complete: root={} (slot {})", flat.root_id, 1 - self.active_slot);
        self.active_slot = 1 - self.active_slot;

        Ok((node_count, manifest))
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

    /// Simulate a byte pattern check for userspace tests.
    /// `pkt_bytes` is a flat byte array representing the "transport payload"
    /// (offset 0 = first byte of transport header).
    fn sim_check_pattern(flat: &FlatTree, pkt_bytes: &[u8], pattern_idx: u32) -> bool {
        if let Some((_, pat)) = flat.byte_patterns.iter().find(|(idx, _)| *idx == pattern_idx) {
            // Pre-shifted layout: match/mask_bytes[i] corresponds to pkt_bytes[i]
            // directly. Bytes outside the pattern range have mask=0 (always pass).
            for j in 0..crate::MAX_PATTERN_LEN {
                let byte = if j < pkt_bytes.len() { pkt_bytes[j] } else { 0 };
                if (byte & pat.mask_bytes[j]) != pat.match_bytes[j] {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }

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
                RuleAction::drop(),
            ),
            RuleSpec::compound(
                vec![Predicate::eq(FieldDim::Proto, 17), Predicate::eq(FieldDim::L4Word0, 123)],
                RuleAction::drop(),
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
                RuleAction::drop(),
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
        let has_drop = action_nodes.iter().any(|(_, n)| n.action == crate::ACT_DROP);
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
            RuleAction::drop(),
        );
        let spec2 = RuleSpec::compound(
            // Same constraints in different order
            vec![Predicate::eq(FieldDim::L4Word0, 53), Predicate::eq(FieldDim::Proto, 17)],
            RuleAction::drop(),
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
        let pkt_bytes: &[u8] = &[]; // No raw bytes for non-pattern tests
        simulate_walk_inner_with_bytes(flat, packet, pkt_bytes, trace)
    }

    fn simulate_walk_inner_with_bytes(
        flat: &FlatTree,
        packet: &[(FieldDim, u32)],
        pkt_bytes: &[u8],
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

        for level in 0..(crate::MAX_DIM as usize) {
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
                if node.dimension == DIM_LEAF || node.dimension >= crate::MAX_DIM {
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

                // Also push range-guarded children where the packet value satisfies the range
                if node.range_count > 0 && node.range_op_0 != 0 && node.range_child_0 != 0 {
                    let passes = match node.range_op_0 {
                        crate::RANGE_OP_GT  => fv > node.range_val_0,
                        crate::RANGE_OP_LT  => fv < node.range_val_0,
                        crate::RANGE_OP_GTE => fv >= node.range_val_0,
                        crate::RANGE_OP_LTE => fv <= node.range_val_0,
                        crate::RANGE_OP_MASK_EQ => {
                            let mask = node.range_val_0 >> 16;
                            let expected = node.range_val_0 & 0xFFFF;
                            (fv & mask) == expected
                        }
                        crate::RANGE_OP_PATTERN => sim_check_pattern(flat, pkt_bytes, node.range_val_0),
                        _ => false,
                    };
                    if passes {
                        next_cursors.push(node.range_child_0);
                    }
                }
                if node.range_count > 1 && node.range_op_1 != 0 && node.range_child_1 != 0 {
                    let passes = match node.range_op_1 {
                        crate::RANGE_OP_GT  => fv > node.range_val_1,
                        crate::RANGE_OP_LT  => fv < node.range_val_1,
                        crate::RANGE_OP_GTE => fv >= node.range_val_1,
                        crate::RANGE_OP_LTE => fv <= node.range_val_1,
                        crate::RANGE_OP_MASK_EQ => {
                            let mask = node.range_val_1 >> 16;
                            let expected = node.range_val_1 & 0xFFFF;
                            (fv & mask) == expected
                        }
                        crate::RANGE_OP_PATTERN => sim_check_pattern(flat, pkt_bytes, node.range_val_1),
                        _ => false,
                    };
                    if passes {
                        next_cursors.push(node.range_child_1);
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
        let pkt_bytes: &[u8] = &[];
        simulate_single_walk_inner_with_bytes(flat, packet, pkt_bytes, trace)
    }

    fn simulate_single_walk_inner_with_bytes(
        flat: &FlatTree,
        packet: &[(FieldDim, u32)],
        pkt_bytes: &[u8],
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
            if node.dimension == DIM_LEAF || node.dimension >= crate::MAX_DIM {
                if trace { eprintln!("  iter={}: nid={} LEAF", _iter, nid); }
                continue;
            }

            // Get packet field value for this dimension
            let fv = pkt.get(&node.dimension).copied().unwrap_or(0);

            // Push wildcard child FIRST (lowest priority in LIFO order)
            if node.wildcard_child != 0 && top < 16 {
                if trace {
                    eprintln!("  iter={}: nid={} dim={} PUSH wildcard_child={}", _iter, nid, node.dimension, node.wildcard_child);
                }
                stack[top] = node.wildcard_child;
                top += 1;
            }

            // Push range-guarded children (evaluated against packet value)
            if node.range_count > 1 && node.range_op_1 != 0 && node.range_child_1 != 0 {
                let passes = match node.range_op_1 {
                    crate::RANGE_OP_GT  => fv > node.range_val_1,
                    crate::RANGE_OP_LT  => fv < node.range_val_1,
                    crate::RANGE_OP_GTE => fv >= node.range_val_1,
                    crate::RANGE_OP_LTE => fv <= node.range_val_1,
                    crate::RANGE_OP_MASK_EQ => {
                        let mask = node.range_val_1 >> 16;
                        let expected = node.range_val_1 & 0xFFFF;
                        (fv & mask) == expected
                    }
                    crate::RANGE_OP_PATTERN => sim_check_pattern(flat, pkt_bytes, node.range_val_1),
                    _ => false,
                };
                if passes && top < 16 {
                    if trace {
                        eprintln!("  iter={}: nid={} dim={} val={} PUSH range_child_1={} (op={} thr={})",
                            _iter, nid, node.dimension, fv, node.range_child_1, node.range_op_1, node.range_val_1);
                    }
                    stack[top] = node.range_child_1;
                    top += 1;
                }
            }
            if node.range_count > 0 && node.range_op_0 != 0 && node.range_child_0 != 0 {
                let passes = match node.range_op_0 {
                    crate::RANGE_OP_GT  => fv > node.range_val_0,
                    crate::RANGE_OP_LT  => fv < node.range_val_0,
                    crate::RANGE_OP_GTE => fv >= node.range_val_0,
                    crate::RANGE_OP_LTE => fv <= node.range_val_0,
                    crate::RANGE_OP_MASK_EQ => {
                        let mask = node.range_val_0 >> 16;
                        let expected = node.range_val_0 & 0xFFFF;
                        (fv & mask) == expected
                    }
                    crate::RANGE_OP_PATTERN => sim_check_pattern(flat, pkt_bytes, node.range_val_0),
                    _ => false,
                };
                if passes && top < 16 {
                    if trace {
                        eprintln!("  iter={}: nid={} dim={} val={} PUSH range_child_0={} (op={} thr={})",
                            _iter, nid, node.dimension, fv, node.range_child_0, node.range_op_0, node.range_val_0);
                    }
                    stack[top] = node.range_child_0;
                    top += 1;
                }
            }

            // Push specific child (popped first due to LIFO — most discriminating)
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
                RuleAction::drop(),
            ).with_priority(10),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);

        // Single-cursor walk
        let (matched, action, prio, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::L4Word0, 53),
        ]);
        assert!(matched, "Should match");
        assert_eq!(action, crate::ACT_DROP);
        assert_eq!(prio, 10);

        // Multi-cursor walk (theoretical reference)
        let (matched, action, prio, _) = simulate_dual_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::L4Word0, 53),
        ]);
        assert!(matched, "Should match (multi-cursor)");
        assert_eq!(action, crate::ACT_DROP);
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
                RuleAction::drop(),
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
                RuleAction::drop(),
            ).with_priority(10),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);
        let (matched, action, prio, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::L4Word0, 53),
        ]);
        assert!(matched, "Should match");
        assert_eq!(action, crate::ACT_DROP, "Higher-prio specific should win");
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
                RuleAction::drop(),
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
                RuleAction::drop(),
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
                RuleAction::drop(),
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
        assert_eq!(a, crate::ACT_DROP, "Test 2: background drop");
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
                RuleAction::drop(),
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
                RuleAction::drop(),
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
                RuleAction::drop(),
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
        assert_eq!(a, crate::ACT_DROP, "Replicated wildcard (prio 150) should beat specific (prio 100)");
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
                    RuleAction::drop(),
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
                    Predicate::Eq(crate::FieldRef::Dim(dim), value) => {
                        pkt.get(dim).copied() == Some(*value)
                    }
                    Predicate::In(crate::FieldRef::Dim(dim), values) => {
                        pkt.get(dim).map_or(false, |v| values.contains(v))
                    }
                    Predicate::Gt(crate::FieldRef::Dim(dim), value) => {
                        pkt.get(dim).map_or(false, |v| v > value)
                    }
                    Predicate::Lt(crate::FieldRef::Dim(dim), value) => {
                        pkt.get(dim).map_or(false, |v| v < value)
                    }
                    Predicate::Gte(crate::FieldRef::Dim(dim), value) => {
                        pkt.get(dim).map_or(false, |v| v >= value)
                    }
                    Predicate::Lte(crate::FieldRef::Dim(dim), value) => {
                        pkt.get(dim).map_or(false, |v| v <= value)
                    }
                    Predicate::MaskEq(crate::FieldRef::Dim(dim), mask, expected) => {
                        pkt.get(dim).map_or(false, |v| (v & mask) == *expected)
                    }
                    _ => false,
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
            RuleAction::drop(), 
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
                                Predicate::In(crate::FieldRef::Dim(dim), vals) => pkt_map.get(dim).map_or(false, |v| vals.contains(v)),
                                Predicate::Gt(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).map_or(false, |v| v > val),
                                Predicate::Lt(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).map_or(false, |v| v < val),
                                Predicate::Gte(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).map_or(false, |v| v >= val),
                                Predicate::Lte(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).map_or(false, |v| v <= val),
                                Predicate::MaskEq(crate::FieldRef::Dim(dim), mask, expected) => pkt_map.get(dim).map_or(false, |v| (v & mask) == *expected),
                                _ => false,
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
                            Predicate::In(crate::FieldRef::Dim(dim), vals) => pkt_map.get(dim).map_or(false, |v| vals.contains(v)),
                            Predicate::Gt(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).map_or(false, |v| v > val),
                            Predicate::Lt(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).map_or(false, |v| v < val),
                            Predicate::Gte(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).map_or(false, |v| v >= val),
                            Predicate::Lte(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).map_or(false, |v| v <= val),
                            Predicate::MaskEq(crate::FieldRef::Dim(dim), mask, expected) => pkt_map.get(dim).map_or(false, |v| (v & mask) == *expected),
                                _ => false,
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
            RuleAction::drop(), 
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
                                Predicate::In(crate::FieldRef::Dim(dim), vals) => pkt_map.get(dim).map_or(false, |v| vals.contains(v)),
                                Predicate::Gt(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).map_or(false, |v| v > val),
                                Predicate::Lt(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).map_or(false, |v| v < val),
                                Predicate::Gte(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).map_or(false, |v| v >= val),
                                Predicate::Lte(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).map_or(false, |v| v <= val),
                                Predicate::MaskEq(crate::FieldRef::Dim(dim), mask, expected) => pkt_map.get(dim).map_or(false, |v| (v & mask) == *expected),
                                _ => false,
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
                            Predicate::In(crate::FieldRef::Dim(dim), vals) => pkt_map.get(dim).map_or(false, |v| vals.contains(v)),
                            Predicate::Gt(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).map_or(false, |v| v > val),
                            Predicate::Lt(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).map_or(false, |v| v < val),
                            Predicate::Gte(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).map_or(false, |v| v >= val),
                            Predicate::Lte(crate::FieldRef::Dim(dim), val) => pkt_map.get(dim).map_or(false, |v| v <= val),
                            Predicate::MaskEq(crate::FieldRef::Dim(dim), mask, expected) => pkt_map.get(dim).map_or(false, |v| (v & mask) == *expected),
                                _ => false,
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
                    RuleAction::drop(),
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
                RuleAction::drop(),
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
                        RuleAction::drop(),
                    ).with_priority(prio)
                }
                2 => {
                    // IP ban: src_ip + dst_port
                    RuleSpec::compound(
                        vec![
                            Predicate::eq(FieldDim::SrcIp, make_ip(i)),
                            Predicate::eq(FieldDim::L4Word1, 9999),
                        ],
                        RuleAction::drop(),
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
    // Range Predicate Tests
    // =========================================================================

    #[test]
    fn test_range_gt_basic() {
        // Rule: (> dst-port 1000) -> DROP, priority 100
        // Packet with dst-port=2000 should match
        // Packet with dst-port=500 should NOT match
        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::Gt(crate::FieldRef::Dim(FieldDim::L4Word1), 1000)],
                RuleAction::drop(),
            ).with_priority(100),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);

        // dst-port=2000 > 1000 → match
        let (matched, action, prio, _) = simulate_single_walk(&flat, &[
            (FieldDim::L4Word1, 2000),
        ]);
        assert!(matched, "dst-port 2000 > 1000 should match");
        assert_eq!(action, crate::ACT_DROP);
        assert_eq!(prio, 100);

        // dst-port=500, NOT > 1000 → no match
        let (matched, _, _, _) = simulate_single_walk(&flat, &[
            (FieldDim::L4Word1, 500),
        ]);
        assert!(!matched, "dst-port 500 should NOT match (> 1000)");

        // dst-port=1000, NOT > 1000 (strictly greater) → no match
        let (matched, _, _, _) = simulate_single_walk(&flat, &[
            (FieldDim::L4Word1, 1000),
        ]);
        assert!(!matched, "dst-port 1000 should NOT match (> 1000, strict)");

        // dst-port=1001, > 1000 → match
        let (matched, _, _, _) = simulate_single_walk(&flat, &[
            (FieldDim::L4Word1, 1001),
        ]);
        assert!(matched, "dst-port 1001 should match (> 1000)");
    }

    #[test]
    fn test_range_lt_basic() {
        // Rule: (< ttl 5) -> DROP
        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::Lt(crate::FieldRef::Dim(FieldDim::Ttl), 5)],
                RuleAction::drop(),
            ).with_priority(100),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);

        let (matched, _, _, _) = simulate_single_walk(&flat, &[(FieldDim::Ttl, 3)]);
        assert!(matched, "ttl 3 < 5 should match");

        let (matched, _, _, _) = simulate_single_walk(&flat, &[(FieldDim::Ttl, 5)]);
        assert!(!matched, "ttl 5 should NOT match (< 5, strict)");

        let (matched, _, _, _) = simulate_single_walk(&flat, &[(FieldDim::Ttl, 128)]);
        assert!(!matched, "ttl 128 should NOT match (< 5)");
    }

    #[test]
    fn test_range_gte_lte() {
        // Rule: (>= src-port 49152) -> COUNT
        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::Gte(crate::FieldRef::Dim(FieldDim::L4Word0), 49152)],
                RuleAction::Count { name: None },
            ).with_priority(50),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);

        let (matched, _, _, _) = simulate_single_walk(&flat, &[(FieldDim::L4Word0, 49152)]);
        assert!(matched, "src-port 49152 >= 49152 should match");

        let (matched, _, _, _) = simulate_single_walk(&flat, &[(FieldDim::L4Word0, 65535)]);
        assert!(matched, "src-port 65535 >= 49152 should match");

        let (matched, _, _, _) = simulate_single_walk(&flat, &[(FieldDim::L4Word0, 49151)]);
        assert!(!matched, "src-port 49151 should NOT match (>= 49152)");
    }

    #[test]
    fn test_range_with_eq_priority_competition() {
        // Rule A: (= proto 17) (> dst-port 1000) -> DROP, priority 100
        // Rule B: (= proto 17) -> PASS, priority 50 (wildcard on dst-port)
        // Packet proto=17, dst-port=2000: both match, A wins (higher prio)
        // Packet proto=17, dst-port=500: only B matches (range fails), B wins
        let rules = vec![
            RuleSpec::compound(
                vec![
                    Predicate::eq(FieldDim::Proto, 17),
                    Predicate::Gt(crate::FieldRef::Dim(FieldDim::L4Word1), 1000),
                ],
                RuleAction::drop(),
            ).with_priority(100),
            RuleSpec::compound(
                vec![Predicate::eq(FieldDim::Proto, 17)],
                RuleAction::Pass,
            ).with_priority(50),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);

        // dst-port=2000 > 1000 → both rules match, A wins (prio 100)
        let (matched, action, prio, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::L4Word1, 2000),
        ]);
        assert!(matched, "Should match (range passes)");
        assert_eq!(action, crate::ACT_DROP, "Range rule should win");
        assert_eq!(prio, 100);

        // dst-port=500 NOT > 1000 → only B matches (prio 50)
        let (matched, action, prio, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::L4Word1, 500),
        ]);
        assert!(matched, "Wildcard rule should still match");
        assert_eq!(action, ACT_PASS, "Wildcard rule should win when range fails");
        assert_eq!(prio, 50);
    }

    #[test]
    fn test_range_with_specific_and_wildcard() {
        // Rule A: (= proto 17) (= dst-port 8080) -> DROP, priority 200
        // Rule B: (= proto 17) (> dst-port 1000) -> RATE_LIMIT, priority 100
        // Rule C: (= proto 17) -> PASS, priority 50
        //
        // Packet proto=17, dst-port=8080: A wins (specific, highest prio)
        // Packet proto=17, dst-port=2000: B wins (range match, prio 100 > 50)
        // Packet proto=17, dst-port=500: C wins (only wildcard matches)
        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::eq(FieldDim::Proto, 17), Predicate::eq(FieldDim::L4Word1, 8080)],
                RuleAction::drop(),
            ).with_priority(200),
            RuleSpec::compound(
                vec![
                    Predicate::eq(FieldDim::Proto, 17),
                    Predicate::Gt(crate::FieldRef::Dim(FieldDim::L4Word1), 1000),
                ],
                RuleAction::RateLimit { pps: 5000, name: None },
            ).with_priority(100),
            RuleSpec::compound(
                vec![Predicate::eq(FieldDim::Proto, 17)],
                RuleAction::Pass,
            ).with_priority(50),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);

        // dst-port=8080: specific A wins
        let (matched, action, prio, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::L4Word1, 8080),
        ]);
        assert!(matched);
        assert_eq!(action, crate::ACT_DROP);
        assert_eq!(prio, 200);

        // dst-port=2000: range B wins
        let (matched, action, prio, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::L4Word1, 2000),
        ]);
        assert!(matched);
        assert_eq!(action, ACT_RATE_LIMIT);
        assert_eq!(prio, 100);

        // dst-port=500: wildcard C wins
        let (matched, action, prio, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17), (FieldDim::L4Word1, 500),
        ]);
        assert!(matched);
        assert_eq!(action, ACT_PASS);
        assert_eq!(prio, 50);
    }

    #[test]
    fn test_range_two_ranges_same_dim() {
        // Rule A: (> dst-port 1000) -> DROP, priority 100
        // Rule B: (< dst-port 100) -> RATE_LIMIT, priority 100
        // Packet dst-port=2000: only A matches
        // Packet dst-port=50: only B matches
        // Packet dst-port=500: neither range matches → no match
        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::Gt(crate::FieldRef::Dim(FieldDim::L4Word1), 1000)],
                RuleAction::drop(),
            ).with_priority(100),
            RuleSpec::compound(
                vec![Predicate::Lt(crate::FieldRef::Dim(FieldDim::L4Word1), 100)],
                RuleAction::RateLimit { pps: 5000, name: None },
            ).with_priority(100),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);

        let (matched, action, _, _) = simulate_single_walk(&flat, &[(FieldDim::L4Word1, 2000)]);
        assert!(matched, "dst-port 2000 should match (> 1000)");
        assert_eq!(action, crate::ACT_DROP);

        let (matched, action, _, _) = simulate_single_walk(&flat, &[(FieldDim::L4Word1, 50)]);
        assert!(matched, "dst-port 50 should match (< 100)");
        assert_eq!(action, ACT_RATE_LIMIT);

        let (matched, _, _, _) = simulate_single_walk(&flat, &[(FieldDim::L4Word1, 500)]);
        assert!(!matched, "dst-port 500 should NOT match (neither range)");
    }

    // =========================================================================
    // Mask Predicate Tests
    // =========================================================================

    #[test]
    fn test_mask_basic() {
        // Rule: (mask tcp-flags 0x02) -> DROP (SYN bit set)
        // Packet with tcp-flags=2 (SYN only): matches
        // Packet with tcp-flags=3 (SYN+FIN): matches
        // Packet with tcp-flags=1 (FIN only): does NOT match
        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::MaskEq(crate::FieldRef::Dim(FieldDim::TcpFlags), 0x02, 0x02)],
                RuleAction::drop(),
            ).with_priority(100),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);

        let (matched, action, _, _) = simulate_single_walk(&flat, &[(FieldDim::TcpFlags, 2)]);
        assert!(matched, "tcp-flags=2 (SYN only) should match");
        assert_eq!(action, crate::ACT_DROP);

        let (matched, action, _, _) = simulate_single_walk(&flat, &[(FieldDim::TcpFlags, 3)]);
        assert!(matched, "tcp-flags=3 (SYN+FIN) should match");
        assert_eq!(action, crate::ACT_DROP);

        let (matched, _, _, _) = simulate_single_walk(&flat, &[(FieldDim::TcpFlags, 1)]);
        assert!(!matched, "tcp-flags=1 (FIN only) should NOT match");
    }

    #[test]
    fn test_mask_with_eq() {
        // Rule: (= proto 6) (mask tcp-flags 0x02) -> DROP (TCP SYN packets)
        // Packet proto=6, flags=2: matches
        // Packet proto=6, flags=1: does NOT match (no SYN bit)
        // Packet proto=17, flags=2: does NOT match (wrong proto)
        let rules = vec![
            RuleSpec::compound(
                vec![
                    Predicate::Eq(crate::FieldRef::Dim(FieldDim::Proto), 6),
                    Predicate::MaskEq(crate::FieldRef::Dim(FieldDim::TcpFlags), 0x02, 0x02),
                ],
                RuleAction::drop(),
            ).with_priority(100),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);

        let (matched, action, _, _) = simulate_single_walk(&flat, &[(FieldDim::Proto, 6), (FieldDim::TcpFlags, 2)]);
        assert!(matched, "TCP with SYN should match");
        assert_eq!(action, crate::ACT_DROP);

        let (matched, _, _, _) = simulate_single_walk(&flat, &[(FieldDim::Proto, 6), (FieldDim::TcpFlags, 1)]);
        assert!(!matched, "TCP without SYN should NOT match");

        let (matched, _, _, _) = simulate_single_walk(&flat, &[(FieldDim::Proto, 17), (FieldDim::TcpFlags, 2)]);
        assert!(!matched, "UDP with flags=2 should NOT match");
    }

    #[test]
    fn test_mask_vs_wildcard_priority() {
        // Rule A: (mask tcp-flags 0x02) -> DROP, priority 100
        // Rule B: wildcard -> PASS, priority 50
        // Packet flags=2: A wins (higher priority)
        // Packet flags=1: B wins (only matches B)
        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::MaskEq(crate::FieldRef::Dim(FieldDim::TcpFlags), 0x02, 0x02)],
                RuleAction::drop(),
            ).with_priority(100),
            RuleSpec::compound(vec![], RuleAction::Pass).with_priority(50),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);

        let (matched, action, prio, _) = simulate_single_walk(&flat, &[(FieldDim::TcpFlags, 2)]);
        assert!(matched);
        assert_eq!(prio, 100, "Mask rule should win");
        assert_eq!(action, crate::ACT_DROP);

        let (matched, action, prio, _) = simulate_single_walk(&flat, &[(FieldDim::TcpFlags, 1)]);
        assert!(matched);
        assert_eq!(prio, 50, "Wildcard rule should win");
        assert_eq!(action, crate::ACT_PASS);
    }

    #[test]
    fn test_mask_two_masks_same_dim() {
        // Rule A: (mask tcp-flags 0x02) -> DROP, priority 100 (SYN bit)
        // Rule B: (mask tcp-flags 0x10) -> RATE_LIMIT, priority 100 (ACK bit)
        // Packet flags=0x02: only A matches
        // Packet flags=0x10: only B matches
        // Packet flags=0x12 (SYN+ACK): both match, but DFS order/priority tie breaks
        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::MaskEq(crate::FieldRef::Dim(FieldDim::TcpFlags), 0x02, 0x02)],
                RuleAction::drop(),
            ).with_priority(100),
            RuleSpec::compound(
                vec![Predicate::MaskEq(crate::FieldRef::Dim(FieldDim::TcpFlags), 0x10, 0x10)],
                RuleAction::RateLimit { pps: 5000, name: None },
            ).with_priority(100),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);

        let (matched, action, _, _) = simulate_single_walk(&flat, &[(FieldDim::TcpFlags, 0x02)]);
        assert!(matched, "flags=0x02 (SYN) should match rule A");
        assert_eq!(action, crate::ACT_DROP);

        let (matched, action, _, _) = simulate_single_walk(&flat, &[(FieldDim::TcpFlags, 0x10)]);
        assert!(matched, "flags=0x10 (ACK) should match rule B");
        assert_eq!(action, ACT_RATE_LIMIT);

        // When both match (SYN+ACK), priority ties, so DFS order determines outcome.
        // Both rules are at the same priority, so whichever is visited last wins.
        let (matched, _, prio, _) = simulate_single_walk(&flat, &[(FieldDim::TcpFlags, 0x12)]);
        assert!(matched, "flags=0x12 (SYN+ACK) should match at least one rule");
        assert_eq!(prio, 100);
    }

    #[test]
    fn test_guard_edge_overflow_4_masks() {
        // 4 mask predicates on tcp-flags, all under proto=6.
        // This produces 4 guard edges at the tcp-flags dimension — more than
        // the 2 per-node limit. The compiler must chain overflow nodes.
        //
        // Rule A: (= proto 6) (mask tcp-flags 0x02) -> DROP,       prio 200 (SYN)
        // Rule B: (= proto 6) (mask tcp-flags 0x10) -> RATE_LIMIT, prio 150 (ACK)
        // Rule C: (= proto 6) (mask tcp-flags 0x04) -> PASS,       prio 100 (RST)
        // Rule D: (= proto 6) (mask tcp-flags 0x01) -> DROP,       prio 50  (FIN)
        let rules = vec![
            RuleSpec::compound(
                vec![
                    Predicate::Eq(crate::FieldRef::Dim(FieldDim::Proto), 6),
                    Predicate::MaskEq(crate::FieldRef::Dim(FieldDim::TcpFlags), 0x02, 0x02),
                ],
                RuleAction::drop(),
            ).with_priority(200),
            RuleSpec::compound(
                vec![
                    Predicate::Eq(crate::FieldRef::Dim(FieldDim::Proto), 6),
                    Predicate::MaskEq(crate::FieldRef::Dim(FieldDim::TcpFlags), 0x10, 0x10),
                ],
                RuleAction::RateLimit { pps: 500, name: None },
            ).with_priority(150),
            RuleSpec::compound(
                vec![
                    Predicate::Eq(crate::FieldRef::Dim(FieldDim::Proto), 6),
                    Predicate::MaskEq(crate::FieldRef::Dim(FieldDim::TcpFlags), 0x04, 0x04),
                ],
                RuleAction::Pass,
            ).with_priority(100),
            RuleSpec::compound(
                vec![
                    Predicate::Eq(crate::FieldRef::Dim(FieldDim::Proto), 6),
                    Predicate::MaskEq(crate::FieldRef::Dim(FieldDim::TcpFlags), 0x01, 0x01),
                ],
                RuleAction::drop(),
            ).with_priority(50),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);

        // SYN only (0x02): matches rule A (prio 200, DROP)
        let (m, a, p, _) = simulate_single_walk(&flat, &[(FieldDim::Proto, 6), (FieldDim::TcpFlags, 0x02)]);
        assert!(m, "SYN should match");
        assert_eq!(p, 200);
        assert_eq!(a, crate::ACT_DROP);

        // ACK only (0x10): matches rule B (prio 150, RATE_LIMIT)
        let (m, a, p, _) = simulate_single_walk(&flat, &[(FieldDim::Proto, 6), (FieldDim::TcpFlags, 0x10)]);
        assert!(m, "ACK should match");
        assert_eq!(p, 150);
        assert_eq!(a, ACT_RATE_LIMIT);

        // RST only (0x04): matches rule C (prio 100, PASS)
        let (m, a, p, _) = simulate_single_walk(&flat, &[(FieldDim::Proto, 6), (FieldDim::TcpFlags, 0x04)]);
        assert!(m, "RST should match");
        assert_eq!(p, 100);
        assert_eq!(a, crate::ACT_PASS);

        // FIN only (0x01): matches rule D (prio 50, DROP)
        let (m, a, p, _) = simulate_single_walk(&flat, &[(FieldDim::Proto, 6), (FieldDim::TcpFlags, 0x01)]);
        assert!(m, "FIN should match");
        assert_eq!(p, 50);
        assert_eq!(a, crate::ACT_DROP);

        // SYN+ACK (0x12): matches A (200) and B (150). A wins.
        let (m, a, p, _) = simulate_single_walk(&flat, &[(FieldDim::Proto, 6), (FieldDim::TcpFlags, 0x12)]);
        assert!(m, "SYN+ACK should match");
        assert_eq!(p, 200, "SYN rule (prio 200) should beat ACK rule (prio 150)");
        assert_eq!(a, crate::ACT_DROP);

        // RST+FIN (0x05): matches C (100) and D (50). C wins.
        let (m, a, p, _) = simulate_single_walk(&flat, &[(FieldDim::Proto, 6), (FieldDim::TcpFlags, 0x05)]);
        assert!(m, "RST+FIN should match");
        assert_eq!(p, 100, "RST rule (prio 100) should beat FIN rule (prio 50)");
        assert_eq!(a, crate::ACT_PASS);

        // SYN+RST+FIN+ACK (0x17): all 4 match. A wins (highest prio 200).
        let (m, a, p, _) = simulate_single_walk(&flat, &[(FieldDim::Proto, 6), (FieldDim::TcpFlags, 0x17)]);
        assert!(m, "all flags should match something");
        assert_eq!(p, 200, "highest-priority rule should win");
        assert_eq!(a, crate::ACT_DROP);

        // No matching bits (0x08): no rule matches
        let (m, _, _, _) = simulate_single_walk(&flat, &[(FieldDim::Proto, 6), (FieldDim::TcpFlags, 0x08)]);
        assert!(!m, "no mask should match 0x08 (PSH only)");

        // Wrong proto: no match regardless of flags
        let (m, _, _, _) = simulate_single_walk(&flat, &[(FieldDim::Proto, 17), (FieldDim::TcpFlags, 0x02)]);
        assert!(!m, "UDP should not match any rule");
    }

    #[test]
    fn test_guard_edge_overflow_5_guards_mixed() {
        // 5 guard edges on the same dimension: 3 ranges + 2 masks.
        // Exercises the overflow chain with an odd number (5 = 2+2+1 → 2 overflow nodes).
        //
        // Rule A: (> dst-port 50000) -> DROP,       prio 200
        // Rule B: (< dst-port 100)   -> DROP,       prio 150
        // Rule C: (mask dst-port 0x8000) -> PASS,    prio 100  (high bit set = port >= 32768)
        // Rule D: (>= dst-port 1024)  -> RATE_LIMIT, prio 80
        // Rule E: (mask dst-port 0x0001) -> DROP,    prio 50   (odd port)
        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::Gt(crate::FieldRef::Dim(FieldDim::L4Word1), 50000)],
                RuleAction::drop(),
            ).with_priority(200),
            RuleSpec::compound(
                vec![Predicate::Lt(crate::FieldRef::Dim(FieldDim::L4Word1), 100)],
                RuleAction::drop(),
            ).with_priority(150),
            RuleSpec::compound(
                vec![Predicate::MaskEq(crate::FieldRef::Dim(FieldDim::L4Word1), 0x8000, 0x8000)],
                RuleAction::Pass,
            ).with_priority(100),
            RuleSpec::compound(
                vec![Predicate::Gte(crate::FieldRef::Dim(FieldDim::L4Word1), 1024)],
                RuleAction::RateLimit { pps: 1000, name: None },
            ).with_priority(80),
            RuleSpec::compound(
                vec![Predicate::MaskEq(crate::FieldRef::Dim(FieldDim::L4Word1), 0x0001, 0x0001)],
                RuleAction::drop(),
            ).with_priority(50),
        ];
        let flat = flatten_tree(&compile_tree(&rules), 1);

        // port 60000 (>50000, >=1024, bit 0x8000 set, even): A(200), C(100), D(80) match. A wins.
        let (m, a, p, _) = simulate_single_walk(&flat, &[(FieldDim::L4Word1, 60000)]);
        assert!(m);
        assert_eq!(p, 200);
        assert_eq!(a, crate::ACT_DROP);

        // port 50: (<100, odd): B(150), E(50) match (50 is even actually! 50=0x32)
        // Wait, 50 is even. So only B matches.
        let (m, a, p, _) = simulate_single_walk(&flat, &[(FieldDim::L4Word1, 50)]);
        assert!(m);
        assert_eq!(p, 150);
        assert_eq!(a, crate::ACT_DROP);

        // port 51: (<100, odd port): B(150), E(50) match. B wins.
        let (m, a, p, _) = simulate_single_walk(&flat, &[(FieldDim::L4Word1, 51)]);
        assert!(m);
        assert_eq!(p, 150);
        assert_eq!(a, crate::ACT_DROP);

        // port 33000: (>=1024, bit 0x8000 set, even): C(100), D(80) match. C wins.
        let (m, a, p, _) = simulate_single_walk(&flat, &[(FieldDim::L4Word1, 33000)]);
        assert!(m);
        assert_eq!(p, 100);
        assert_eq!(a, crate::ACT_PASS);

        // port 2000 (>=1024, no 0x8000, even): only D(80) matches.
        let (m, a, p, _) = simulate_single_walk(&flat, &[(FieldDim::L4Word1, 2000)]);
        assert!(m);
        assert_eq!(p, 80);
        assert_eq!(a, ACT_RATE_LIMIT);

        // port 2001 (>=1024, no 0x8000, odd): D(80), E(50) match. D wins.
        let (m, a, p, _) = simulate_single_walk(&flat, &[(FieldDim::L4Word1, 2001)]);
        assert!(m);
        assert_eq!(p, 80);
        assert_eq!(a, ACT_RATE_LIMIT);

        // port 500 (not >50000, not <100, not >=1024, no 0x8000, even): no match
        let (m, _, _, _) = simulate_single_walk(&flat, &[(FieldDim::L4Word1, 500)]);
        assert!(!m, "port 500 should not match any rule");

        // port 501 (same but odd): only E(50) matches.
        let (m, a, p, _) = simulate_single_walk(&flat, &[(FieldDim::L4Word1, 501)]);
        assert!(m);
        assert_eq!(p, 50);
        assert_eq!(a, crate::ACT_DROP);
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

            let (nodes, _manifest) = filter.compile_and_flip_tree(&rules_100).await
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

            let (nodes, _) = filter.compile_and_flip_tree(&rules_1k).await
                .expect("compile_and_flip failed for 1000 rules (second flip)");
            eprintln!("eBPF integration: 1000 rules -> {} nodes (blue/green flip)", nodes);
            assert!(nodes > 0, "Expected nodes > 0 for 1000 rules");

            // === Third flip: back to smaller set (verifies second slot cleanup) ===
            let (nodes, _) = filter.compile_and_flip_tree(&rules_100).await
                .expect("compile_and_flip failed on third flip");
            eprintln!("eBPF integration: back to 100 rules -> {} nodes (third flip)", nodes);
            assert!(nodes > 0);

            // === Clear and verify ===
            filter.clear_tree().await.expect("clear_tree failed");
            eprintln!("eBPF integration: tree cleared successfully");

            eprintln!("eBPF integration stress test PASSED");
        });
    }

    // =========================================================================
    // Phase 2a Tests: Short (1-4 byte) L4Byte fan-out via custom dimensions
    // =========================================================================

    #[test]
    fn test_l4byte_single_byte_fanout() {
        // Simulate a game protocol: 1-byte message type at transport offset 0.
        // 80 message types, each mapped to a different action.
        // The compiler should assign this to a single CustomN dimension,
        // enabling O(1) fan-out via specific edges.
        let mut rules = Vec::new();
        for msg_type in 0u32..80 {
            rules.push(RuleSpec::compound(
                vec![
                    Predicate::Eq(FieldRef::Dim(FieldDim::Proto), 6), // TCP
                    Predicate::Eq(FieldRef::L4Byte { offset: 0, length: 1 }, msg_type),
                ],
                RuleAction::drop(),
            ).with_priority(100));
        }

        let (shadow, mapping, dim_order, _) = compile_tree_full(&rules);
        let flat = flatten_tree_with_dims(&shadow, 1, &dim_order);

        // The mapping should have 1 custom dim for offset=0, len=1
        assert_eq!(mapping.len(), 1, "Should have exactly 1 custom dimension");

        // Dim order should have 9 static + 1 custom = 10
        assert_eq!(dim_order.len(), 10, "Dim order should have 10 entries");

        // Find which custom dim was assigned
        let custom_dim = mapping.entries[0].2;
        assert!(custom_dim.is_custom(), "Should be a custom dim");

        // Test: TCP packet with message type 42 should match
        let (matched, action, _, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 6),
            (custom_dim, 42),
        ]);
        assert!(matched, "Message type 42 should match");
        assert_eq!(action, crate::ACT_DROP);

        // Test: TCP packet with message type 79 should match
        let (matched, _, _, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 6),
            (custom_dim, 79),
        ]);
        assert!(matched, "Message type 79 should match");

        // Test: TCP packet with message type 80 should NOT match (out of range)
        let (matched, _, _, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 6),
            (custom_dim, 80),
        ]);
        assert!(!matched, "Message type 80 should NOT match");

        // Test: UDP packet with message type 42 should NOT match (wrong proto)
        let (matched, _, _, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17),
            (custom_dim, 42),
        ]);
        assert!(!matched, "UDP packet should NOT match");

        eprintln!("l4byte_single_byte_fanout: {} nodes, {} edges (80 msg types)",
            flat.nodes.len(), flat.edges.len());
    }

    #[test]
    fn test_l4byte_two_byte_fanout() {
        // 2-byte value at offset 4 (e.g., a game opcode)
        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::Eq(FieldRef::L4Byte { offset: 4, length: 2 }, 0x0100)],
                RuleAction::drop(),
            ).with_priority(100),
            RuleSpec::compound(
                vec![Predicate::Eq(FieldRef::L4Byte { offset: 4, length: 2 }, 0x0200)],
                RuleAction::Pass,
            ).with_priority(50),
        ];

        let (shadow, mapping, dim_order, _) = compile_tree_full(&rules);
        let flat = flatten_tree_with_dims(&shadow, 1, &dim_order);

        assert_eq!(mapping.len(), 1, "Should have 1 custom dim for offset=4, len=2");
        let custom_dim = mapping.entries[0].2;

        let (matched, action, _, _) = simulate_single_walk(&flat, &[(custom_dim, 0x0100)]);
        assert!(matched);
        assert_eq!(action, crate::ACT_DROP);

        let (matched, action, _, _) = simulate_single_walk(&flat, &[(custom_dim, 0x0200)]);
        assert!(matched);
        assert_eq!(action, crate::ACT_PASS);

        let (matched, _, _, _) = simulate_single_walk(&flat, &[(custom_dim, 0x0300)]);
        assert!(!matched, "Unmatched opcode should NOT match");
    }

    #[test]
    fn test_l4byte_four_byte_fanout() {
        // 4-byte value at offset 8 (e.g., a session ID prefix)
        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::Eq(FieldRef::L4Byte { offset: 8, length: 4 }, 0xDEADBEEF)],
                RuleAction::drop(),
            ).with_priority(100),
        ];

        let (shadow, mapping, dim_order, _) = compile_tree_full(&rules);
        let flat = flatten_tree_with_dims(&shadow, 1, &dim_order);

        assert_eq!(mapping.len(), 1);
        let custom_dim = mapping.entries[0].2;

        let (matched, _, _, _) = simulate_single_walk(&flat, &[(custom_dim, 0xDEADBEEF)]);
        assert!(matched, "0xDEADBEEF should match");

        let (matched, _, _, _) = simulate_single_walk(&flat, &[(custom_dim, 0xDEADBEE0)]);
        assert!(!matched, "0xDEADBEE0 should NOT match");
    }

    #[test]
    fn test_l4byte_masked_short_match() {
        // Masked 1-byte match: check only the upper 4 bits of a byte at offset 0
        // mask = 0xF0, match = 0x30 -> matches 0x30-0x3F
        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::MaskEq(FieldRef::L4Byte { offset: 0, length: 1 }, 0xF0, 0x30)],
                RuleAction::drop(),
            ).with_priority(100),
        ];

        let (shadow, mapping, dim_order, _) = compile_tree_full(&rules);
        let flat = flatten_tree_with_dims(&shadow, 1, &dim_order);

        // MaskEq on short L4Byte should still get a custom dim, but as a guard edge
        // (since the mask isn't full-width, it can't be a specific edge)
        assert!(mapping.len() <= 1, "Should use at most 1 custom dim");

        if mapping.len() == 1 {
            let custom_dim = mapping.entries[0].2;
            // Value 0x35 should match (0x35 & 0xF0 == 0x30)
            let (matched, _, _, _) = simulate_single_walk(&flat, &[(custom_dim, 0x35)]);
            assert!(matched, "0x35 should match (upper nibble = 0x3)");

            // Value 0x45 should NOT match (0x45 & 0xF0 == 0x40)
            let (matched, _, _, _) = simulate_single_walk(&flat, &[(custom_dim, 0x45)]);
            assert!(!matched, "0x45 should NOT match (upper nibble = 0x4)");
        }
    }

    #[test]
    fn test_l4byte_multiple_custom_dims() {
        // Use two different L4Byte locations (different offsets)
        // This should allocate two custom dimensions.
        let rules = vec![
            RuleSpec::compound(
                vec![
                    Predicate::Eq(FieldRef::L4Byte { offset: 0, length: 1 }, 0x01),
                    Predicate::Eq(FieldRef::L4Byte { offset: 2, length: 2 }, 0x1234),
                ],
                RuleAction::drop(),
            ).with_priority(100),
        ];

        let (shadow, mapping, dim_order, _) = compile_tree_full(&rules);
        let flat = flatten_tree_with_dims(&shadow, 1, &dim_order);

        assert_eq!(mapping.len(), 2, "Should have 2 custom dimensions");
        assert_eq!(dim_order.len(), 11, "Dim order: 9 static + 2 custom");

        let dim_a = mapping.entries[0].2; // offset=0,len=1
        let dim_b = mapping.entries[1].2; // offset=2,len=2

        let (matched, _, _, _) = simulate_single_walk(&flat, &[
            (dim_a, 0x01),
            (dim_b, 0x1234),
        ]);
        assert!(matched, "Both custom dims matched should hit");

        let (matched, _, _, _) = simulate_single_walk(&flat, &[
            (dim_a, 0x01),
            (dim_b, 0x5678),
        ]);
        assert!(!matched, "Second custom dim mismatch should NOT hit");
    }

    #[test]
    fn test_l4byte_mixed_with_existing_fields() {
        // Combine L4Byte with traditional fields (proto, src-port)
        let rules = vec![
            RuleSpec::compound(
                vec![
                    Predicate::Eq(FieldRef::Dim(FieldDim::Proto), 6),      // TCP
                    Predicate::Eq(FieldRef::Dim(FieldDim::L4Word1), 8080), // dst-port
                    Predicate::Eq(FieldRef::L4Byte { offset: 20, length: 1 }, 0x42), // payload byte
                ],
                RuleAction::drop(),
            ).with_priority(100),
        ];

        let (shadow, mapping, dim_order, _) = compile_tree_full(&rules);
        let flat = flatten_tree_with_dims(&shadow, 1, &dim_order);

        assert_eq!(mapping.len(), 1, "One custom dim for the payload byte");
        let custom_dim = mapping.entries[0].2;

        // Full match
        let (matched, _, _, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 6),
            (FieldDim::L4Word1, 8080),
            (custom_dim, 0x42),
        ]);
        assert!(matched, "Full match should hit");

        // Wrong proto
        let (matched, _, _, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 17),
            (FieldDim::L4Word1, 8080),
            (custom_dim, 0x42),
        ]);
        assert!(!matched, "Wrong proto should NOT match");

        // Wrong payload byte
        let (matched, _, _, _) = simulate_single_walk(&flat, &[
            (FieldDim::Proto, 6),
            (FieldDim::L4Word1, 8080),
            (custom_dim, 0x43),
        ]);
        assert!(!matched, "Wrong payload byte should NOT match");
    }

    // =========================================================================
    // Phase 2b Tests: Long pattern guard edges (5-64 byte patterns)
    // =========================================================================

    #[test]
    fn test_pattern_guard_8byte() {
        // 8-byte exact match at offset 0 via RawByteMatch
        let mut pat = crate::BytePattern::default();
        pat.offset = 0;
        pat.length = 8;
        pat.match_bytes[..8].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
        for i in 0..8 { pat.mask_bytes[i] = 0xFF; }

        let rules = vec![
            RuleSpec::compound(
                vec![
                    Predicate::Eq(FieldRef::Dim(FieldDim::Proto), 6),
                    Predicate::RawByteMatch(Box::new(pat)),
                ],
                RuleAction::drop(),
            ).with_priority(100),
        ];

        let (shadow, _, dim_order, _) = compile_tree_full(&rules);
        let flat = flatten_tree_with_dims(&shadow, 1, &dim_order);

        // The pattern should have been allocated
        assert_eq!(flat.byte_patterns.len(), 1, "Should have 1 byte pattern");

        // Matching packet bytes (transport payload starts at offset 0)
        let pkt_bytes = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let (matched, action, _, _) = simulate_walk_inner_with_bytes(
            &flat,
            &[(FieldDim::Proto, 6)],
            &pkt_bytes,
            false,
        );
        assert!(matched, "8-byte pattern should match");
        assert_eq!(action, crate::ACT_DROP);

        // Non-matching packet bytes (last byte differs)
        let pkt_bytes_bad = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0x00];
        let (matched, _, _, _) = simulate_walk_inner_with_bytes(
            &flat,
            &[(FieldDim::Proto, 6)],
            &pkt_bytes_bad,
            false,
        );
        assert!(!matched, "Mismatched 8-byte pattern should NOT match");

        // Wrong proto: guard is on Proto dim, so if proto doesn't match,
        // the specific edge for proto won't be taken (no cursor reaches the pattern node)
        let (matched, _, _, _) = simulate_walk_inner_with_bytes(
            &flat,
            &[(FieldDim::Proto, 17)],
            &pkt_bytes,
            false,
        );
        assert!(!matched, "Wrong proto should NOT match even with matching bytes");
    }

    #[test]
    fn test_pattern_guard_32byte_masked() {
        // 32-byte match with mask: only first 4 bytes must be exact, rest ignored
        let mut pat = crate::BytePattern::default();
        pat.offset = 10;
        pat.length = 32;
        // First 4 bytes: exact match
        pat.match_bytes[..4].copy_from_slice(&[0x47, 0x45, 0x54, 0x20]); // "GET "
        for i in 0..4 { pat.mask_bytes[i] = 0xFF; }
        // Remaining 28 bytes: mask = 0x00 (don't care)
        for i in 4..32 { pat.mask_bytes[i] = 0x00; pat.match_bytes[i] = 0x00; }

        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::RawByteMatch(Box::new(pat))],
                RuleAction::drop(),
            ).with_priority(100),
        ];

        let (shadow, _, dim_order, _) = compile_tree_full(&rules);
        let flat = flatten_tree_with_dims(&shadow, 1, &dim_order);
        assert_eq!(flat.byte_patterns.len(), 1);

        // Build a packet: some prefix bytes, then at offset 10: "GET " followed by random
        let mut pkt = vec![0u8; 50];
        pkt[10] = 0x47; pkt[11] = 0x45; pkt[12] = 0x54; pkt[13] = 0x20; // "GET "
        // Rest can be anything
        for i in 14..42 { pkt[i] = 0xAB; }

        let (matched, _, _, _) = simulate_walk_inner_with_bytes(&flat, &[], &pkt, false);
        assert!(matched, "GET prefix at offset 10 should match");

        // Wrong first byte
        pkt[10] = 0x48; // 'H' instead of 'G'
        let (matched, _, _, _) = simulate_walk_inner_with_bytes(&flat, &[], &pkt, false);
        assert!(!matched, "Wrong prefix should NOT match");
    }

    #[test]
    fn test_pattern_guard_64byte_exact() {
        // Maximum pattern length: 64-byte exact match
        let mut pat = crate::BytePattern::default();
        pat.offset = 0;
        pat.length = 64;
        for i in 0..64 {
            pat.match_bytes[i] = i as u8;
            pat.mask_bytes[i] = 0xFF;
        }

        let rules = vec![
            RuleSpec::compound(
                vec![Predicate::RawByteMatch(Box::new(pat))],
                RuleAction::drop(),
            ).with_priority(100),
        ];

        let (shadow, _, dim_order, _) = compile_tree_full(&rules);
        let flat = flatten_tree_with_dims(&shadow, 1, &dim_order);
        assert_eq!(flat.byte_patterns.len(), 1);

        // Matching: bytes 0-63 at offset 0
        let pkt: Vec<u8> = (0..64).collect();
        let (matched, _, _, _) = simulate_walk_inner_with_bytes(&flat, &[], &pkt, false);
        assert!(matched, "64-byte exact match should match");

        // Mismatched at byte 63
        let mut pkt_bad = pkt.clone();
        pkt_bad[63] = 0xFF;
        let (matched, _, _, _) = simulate_walk_inner_with_bytes(&flat, &[], &pkt_bad, false);
        assert!(!matched, "64-byte mismatch at last byte should NOT match");

        // Too short packet
        let pkt_short: Vec<u8> = (0..60).collect();
        let (matched, _, _, _) = simulate_walk_inner_with_bytes(&flat, &[], &pkt_short, false);
        assert!(!matched, "Packet too short for 64-byte pattern should NOT match");
    }

    #[test]
    fn test_pattern_guard_mixed_with_short_match() {
        // Rule 1: 1-byte fan-out at offset 0 (msg_type = 0x01) + 8-byte pattern at offset 4
        // Rule 2: Same msg_type, different 8-byte pattern -> different action
        let mut pat1 = crate::BytePattern::default();
        pat1.offset = 4;
        pat1.length = 8;
        pat1.match_bytes[..8].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        for i in 0..8 { pat1.mask_bytes[i] = 0xFF; }

        let mut pat2 = crate::BytePattern::default();
        pat2.offset = 4;
        pat2.length = 8;
        pat2.match_bytes[..8].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]);
        for i in 0..8 { pat2.mask_bytes[i] = 0xFF; }

        let rules = vec![
            RuleSpec::compound(
                vec![
                    Predicate::Eq(FieldRef::L4Byte { offset: 0, length: 1 }, 0x01),
                    Predicate::RawByteMatch(Box::new(pat1)),
                ],
                RuleAction::drop(),
            ).with_priority(100),
            RuleSpec::compound(
                vec![
                    Predicate::Eq(FieldRef::L4Byte { offset: 0, length: 1 }, 0x01),
                    Predicate::RawByteMatch(Box::new(pat2)),
                ],
                RuleAction::Pass,
            ).with_priority(50),
        ];

        let (shadow, mapping, dim_order, _) = compile_tree_full(&rules);
        let flat = flatten_tree_with_dims(&shadow, 1, &dim_order);

        assert_eq!(mapping.len(), 1, "1 custom dim for msg_type");
        assert_eq!(flat.byte_patterns.len(), 2, "2 byte patterns");

        let custom_dim = mapping.entries[0].2;

        // Packet: msg_type=0x01, then pat1 bytes at offset 4
        let mut pkt = vec![0u8; 20];
        pkt[4..12].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        let (matched, action, _, _) = simulate_walk_inner_with_bytes(
            &flat,
            &[(custom_dim, 0x01)],
            &pkt,
            false,
        );
        assert!(matched, "pat1 should match");
        assert_eq!(action, crate::ACT_DROP, "pat1 is higher priority -> DROP");

        // Packet: msg_type=0x01, then pat2 bytes at offset 4
        pkt[4..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]);
        let (matched, action, _, _) = simulate_walk_inner_with_bytes(
            &flat,
            &[(custom_dim, 0x01)],
            &pkt,
            false,
        );
        assert!(matched, "pat2 should match");
        assert_eq!(action, crate::ACT_PASS, "pat2 only match -> PASS");

        // Packet: msg_type=0x02 (no rule for this msg type)
        let (matched, _, _, _) = simulate_walk_inner_with_bytes(
            &flat,
            &[(custom_dim, 0x02)],
            &pkt,
            false,
        );
        assert!(!matched, "Wrong msg_type should NOT match");
    }

    #[test]
    fn test_multiple_pattern_guards() {
        // 3 rules, each with a different long pattern, testing independent matching
        let patterns: Vec<[u8; 8]> = vec![
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11],
            [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88],
        ];

        let mut rules = Vec::new();
        for (i, bytes) in patterns.iter().enumerate() {
            let mut pat = crate::BytePattern::default();
            pat.offset = 0;
            pat.length = 8;
            pat.match_bytes[..8].copy_from_slice(bytes);
            for j in 0..8 { pat.mask_bytes[j] = 0xFF; }

            rules.push(RuleSpec::compound(
                vec![Predicate::RawByteMatch(Box::new(pat))],
                RuleAction::drop(),
            ).with_priority((100 - i * 10) as u8));
        }

        let (shadow, _, dim_order, _) = compile_tree_full(&rules);
        let flat = flatten_tree_with_dims(&shadow, 1, &dim_order);
        assert_eq!(flat.byte_patterns.len(), 3, "Should have 3 byte patterns");

        // Test each pattern matches
        for (i, bytes) in patterns.iter().enumerate() {
            let (matched, _, _, _) = simulate_walk_inner_with_bytes(
                &flat, &[], bytes, false,
            );
            assert!(matched, "Pattern {} should match", i);
        }

        // Test non-matching
        let bad = [0x00u8; 8];
        let (matched, _, _, _) = simulate_walk_inner_with_bytes(&flat, &[], &bad, false);
        assert!(!matched, "Non-matching bytes should NOT match");
    }
}
