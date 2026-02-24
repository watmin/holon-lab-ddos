//! Rete-spirit rule tree compiler for HTTP dimensions.
//!
//! Direct port of veth-lab/filter/src/tree.rs logic into pure Rust —
//! no eBPF maps. The compiled tree lives in a Vec<TreeNode> behind an
//! ArcSwap instead of eBPF array maps.
//!
//! Key properties (same as veth-lab):
//! - Pure DAG: wildcard rules live only in wildcard_child links, no replication.
//! - Idempotent: rule identity is based on canonical constraint key.
//! - Blue/green via ArcSwap: sidecar writes new Arc, proxy reads load().
//! - DIM_ORDER controls traversal: primary discriminators first.

use std::collections::HashMap;
use std::rc::Rc;

use tracing::info;

use crate::types::{
    CompiledTree, DIM_ORDER, FieldDim, Predicate, RuleAction, RuleSpec, TreeNode,
};

// =============================================================================
// Shadow tree (in-memory compilation representation)
// =============================================================================

#[derive(Debug, Clone)]
struct ShadowNode {
    dim_index: usize,
    action: Option<(RuleAction, u32)>, // (action, rule_id)
    /// Specific-value children: field_value → subtree
    children: HashMap<u32, Rc<ShadowNode>>,
    /// Wildcard child (rules that don't constrain this dimension)
    wildcard: Option<Rc<ShadowNode>>,
}

impl ShadowNode {
    fn new(dim_index: usize) -> Self {
        ShadowNode {
            dim_index,
            action: None,
            children: HashMap::new(),
            wildcard: None,
        }
    }
}

// =============================================================================
// Compilation
// =============================================================================

/// Compile a set of RuleSpecs into a CompiledTree ready for ArcSwap deployment.
pub fn compile(rules: &[RuleSpec]) -> CompiledTree {
    if rules.is_empty() {
        return CompiledTree::empty();
    }

    let shadow = compile_recursive(rules, 0);
    let mut nodes: Vec<TreeNode> = Vec::new();
    let root = flatten(&shadow, &mut nodes);

    let rule_fingerprint = build_fingerprint(rules);

    info!(
        rules = rules.len(),
        nodes = nodes.len(),
        "rule tree compiled"
    );

    CompiledTree { nodes, root, rule_fingerprint }
}

/// Recursively build the shadow trie for rules starting at dim_index.
///
/// At each level:
/// 1. Partition rules into those that constrain this dim (specific) vs. those that don't (wildcard pass-through).
/// 2. Group specific rules by their exact value for this dim.
/// 3. Recurse into each specific group + the wildcard group.
fn compile_recursive(rules: &[RuleSpec], dim_idx: usize) -> Rc<ShadowNode> {
    let mut node = ShadowNode::new(dim_idx);

    // Terminal case: past all dimensions — assign the highest-priority rule's action
    if dim_idx >= DIM_ORDER.len() {
        if let Some(rule) = rules.iter().max_by_key(|r| r.priority) {
            let rule_id = rule_identity_hash(rule);
            node.action = Some((rule.action.clone(), rule_id));
        }
        return Rc::new(node);
    }

    let dim = DIM_ORDER[dim_idx];

    // Check if any active rule constrains this dimension with an Eq predicate
    let any_constrained = rules.iter().any(|r| rule_constrains_eq(r, dim));

    if !any_constrained {
        // No rule constrains this dim — skip it, recurse deeper
        let child = compile_recursive(rules, dim_idx + 1);
        node.wildcard = Some(child);
        return Rc::new(node);
    }

    // Partition: rules with an Eq constraint on this dim vs. those without
    let mut grouped: HashMap<u32, Vec<&RuleSpec>> = HashMap::new();
    let mut wildcard_rules: Vec<&RuleSpec> = Vec::new();

    for rule in rules {
        if let Some(val) = rule_eq_value(rule, dim) {
            grouped.entry(val).or_default().push(rule);
        } else {
            wildcard_rules.push(rule);
        }
    }

    // Build specific children
    for (val, val_rules) in grouped {
        // Each specific group gets the wildcard rules too (they still apply)
        let combined: Vec<RuleSpec> = val_rules.iter()
            .copied()
            .chain(wildcard_rules.iter().copied())
            .cloned()
            .collect();
        let child = compile_recursive(&combined, dim_idx + 1);
        node.children.insert(val, child);
    }

    // Build wildcard child (rules that don't constrain this dim apply to all values)
    if !wildcard_rules.is_empty() {
        let owned: Vec<RuleSpec> = wildcard_rules.iter().copied().cloned().collect();
        let child = compile_recursive(&owned, dim_idx + 1);
        node.wildcard = Some(child);
    }

    Rc::new(node)
}

fn rule_constrains_eq(rule: &RuleSpec, dim: FieldDim) -> bool {
    rule.constraints.iter().any(|p| matches!(p, Predicate::Eq(d, _) if *d == dim))
}

fn rule_eq_value(rule: &RuleSpec, dim: FieldDim) -> Option<u32> {
    rule.constraints.iter().find_map(|p| match p {
        Predicate::Eq(d, v) if *d == dim => Some(*v),
        _ => None,
    })
}

// =============================================================================
// Flatten shadow tree → Vec<TreeNode>
// =============================================================================

fn flatten(node: &Rc<ShadowNode>, nodes: &mut Vec<TreeNode>) -> usize {
    let idx = nodes.len();
    let dim_idx = node.dim_index.min(DIM_ORDER.len() - 1);
    nodes.push(TreeNode {
        dim: DIM_ORDER[dim_idx],
        children: HashMap::new(),
        wildcard: None,
        action: node.action.clone(),
    });

    // Recurse children — must push after reserving our slot
    for (&val, child) in &node.children {
        let child_idx = flatten(child, nodes);
        nodes[idx].children.insert(val, child_idx);
    }

    if let Some(ref wc) = node.wildcard {
        let wc_idx = flatten(wc, nodes);
        nodes[idx].wildcard = Some(wc_idx);
    }

    idx
}

// =============================================================================
// Rule fingerprint for change detection
// =============================================================================

fn build_fingerprint(rules: &[RuleSpec]) -> String {
    let mut keys: Vec<String> = rules.iter()
        .map(|r| r.identity_key())
        .collect();
    keys.sort();
    keys.join("|")
}

fn rule_identity_hash(rule: &RuleSpec) -> u32 {
    let key = rule.identity_key();
    let mut h: u32 = 0x811c9dc5;
    for b in key.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::types::{FieldDim, Predicate, RuleAction, RuleSpec};

    fn make_rule(dim: FieldDim, val: u32, action: RuleAction) -> RuleSpec {
        RuleSpec::new(vec![Predicate::eq(dim, val)], action)
    }

    #[test]
    fn empty_tree_passes() {
        let tree = compile(&[]);
        assert!(tree.nodes.len() == 1);
    }

    #[test]
    fn single_rule_matches() {
        use crate::types::{RequestSample, HttpVersion, TlsContext, now_us};
        use std::net::IpAddr;
        use std::sync::Arc;
        use holon::kernel::{Encoder, VectorManager};

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let ip_u32 = match ip {
            IpAddr::V4(v4) => u32::from_ne_bytes(v4.octets()),
            _ => 0,
        };

        let rules = vec![make_rule(FieldDim::SrcIp, ip_u32, RuleAction::block())];
        let tree = compile(&rules);

        let tls_ctx = Arc::new(TlsContext::default());
        let encoder = Encoder::new(VectorManager::new(4096));
        let tls_vec = encoder.encode_walkable(tls_ctx.as_ref());

        let req = RequestSample {
            method: "GET".into(),
            path: "/".into(),
            query: None,
            version: HttpVersion::Http11,
            headers: vec![],
            host: None,
            user_agent: None,
            content_type: None,
            content_length: None,
            cookies: vec![],
            body: None,
            body_len: 0,
            src_ip: ip,
            conn_id: 1,
            tls_ctx,
            tls_vec,
            timestamp_us: now_us(),
        };

        let action = tree.evaluate_req(&req);
        assert!(matches!(action, Some(RuleAction::Block { status: 403 })));
    }

    fn make_test_req(method: &str, path: &str, ip_str: &str) -> crate::types::RequestSample {
        use crate::types::{TlsContext, test_request_sample};
        use holon::kernel::{Encoder, VectorManager};
        let tls_ctx = Arc::new(TlsContext::default());
        let encoder = Encoder::new(VectorManager::new(4096));
        let tls_vec = encoder.encode_walkable(tls_ctx.as_ref());
        let ip: std::net::IpAddr = ip_str.parse().unwrap();
        test_request_sample(method, path, ip, vec![], tls_ctx, tls_vec)
    }

    fn ip_u32(s: &str) -> u32 {
        let ip: std::net::IpAddr = s.parse().unwrap();
        match ip {
            std::net::IpAddr::V4(v4) => u32::from_ne_bytes(v4.octets()),
            _ => 0,
        }
    }

    #[test]
    fn multiple_rules_different_dims() {
        let rules = vec![
            make_rule(FieldDim::SrcIp, ip_u32("10.0.0.1"), RuleAction::block()),
            make_rule(FieldDim::SrcIp, ip_u32("10.0.0.2"), RuleAction::CloseConnection),
        ];
        let tree = compile(&rules);

        let req1 = make_test_req("GET", "/", "10.0.0.1");
        let req2 = make_test_req("GET", "/", "10.0.0.2");
        let req3 = make_test_req("GET", "/", "10.0.0.3");

        assert!(matches!(tree.evaluate_req(&req1), Some(RuleAction::Block { status: 403 })));
        assert!(matches!(tree.evaluate_req(&req2), Some(RuleAction::CloseConnection)));
        assert!(tree.evaluate_req(&req3).is_none());
    }

    #[test]
    fn wildcard_rule_matches_all() {
        // A rule with no constraints matches everything via wildcard path
        let rule = RuleSpec::new(vec![], RuleAction::count("test"));
        let tree = compile(&[rule]);

        let req = make_test_req("GET", "/", "1.2.3.4");
        let action = tree.evaluate_req(&req);
        assert!(matches!(action, Some(RuleAction::Count { .. })));
    }

    #[test]
    fn specific_rule_takes_precedence_over_wildcard() {
        let ip = ip_u32("10.0.0.1");
        let block_rule = RuleSpec::new(
            vec![Predicate::eq(FieldDim::SrcIp, ip)],
            RuleAction::block(),
        );
        // default priority is 100 for both

        let mut pass_rule = RuleSpec::new(vec![], RuleAction::pass());
        pass_rule.priority = 50; // lower priority than the block rule

        let rules = vec![pass_rule, block_rule];
        let tree = compile(&rules);

        // 10.0.0.1 should match the specific (block) rule since it has higher priority
        let req_blocked = make_test_req("GET", "/", "10.0.0.1");
        let action = tree.evaluate_req(&req_blocked);
        assert!(matches!(action, Some(RuleAction::Block { .. })));

        // Other IPs should fall through to wildcard (pass)
        let req_other = make_test_req("GET", "/", "10.0.0.2");
        let action = tree.evaluate_req(&req_other);
        assert!(matches!(action, Some(RuleAction::Pass)));
    }

    #[test]
    fn multi_constraint_rule() {
        use crate::types::fnv1a_str;
        let ip = ip_u32("10.0.0.1");
        let method_hash = fnv1a_str("POST");
        let rule = RuleSpec::new(
            vec![
                Predicate::eq(FieldDim::SrcIp, ip),
                Predicate::eq(FieldDim::Method, method_hash),
            ],
            RuleAction::block(),
        );
        let tree = compile(&[rule]);

        // Both constraints match
        let req_match = make_test_req("POST", "/api", "10.0.0.1");
        assert!(matches!(tree.evaluate_req(&req_match), Some(RuleAction::Block { .. })));

        // IP matches but method doesn't
        let req_wrong_method = make_test_req("GET", "/api", "10.0.0.1");
        assert!(tree.evaluate_req(&req_wrong_method).is_none());

        // Method matches but IP doesn't
        let req_wrong_ip = make_test_req("POST", "/api", "10.0.0.2");
        assert!(tree.evaluate_req(&req_wrong_ip).is_none());
    }

    #[test]
    fn compile_idempotent() {
        let rules = vec![
            make_rule(FieldDim::SrcIp, ip_u32("10.0.0.1"), RuleAction::block()),
            make_rule(FieldDim::SrcIp, ip_u32("10.0.0.2"), RuleAction::CloseConnection),
        ];
        let tree1 = compile(&rules);
        let tree2 = compile(&rules);
        assert_eq!(tree1.rule_fingerprint, tree2.rule_fingerprint);
        assert_eq!(tree1.nodes.len(), tree2.nodes.len());
    }

    #[test]
    fn fingerprint_changes_with_rules() {
        let rules1 = vec![make_rule(FieldDim::SrcIp, 1, RuleAction::block())];
        let rules2 = vec![make_rule(FieldDim::SrcIp, 2, RuleAction::block())];
        let tree1 = compile(&rules1);
        let tree2 = compile(&rules2);
        assert_ne!(tree1.rule_fingerprint, tree2.rule_fingerprint);
    }
}
