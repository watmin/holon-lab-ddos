//! Expression-based rule tree compiler and evaluator.
//!
//! Parallel to tree.rs (FieldDim/Predicate) but works with the new
//! Dimension/Expr/Value types. Supports dynamic DIM_ORDER, MatchMode
//! (Exact vs Membership), and typed Value branching.

use std::collections::HashMap;
use std::rc::Rc;

use tracing::info;

use crate::expr::{Dimension, MatchMode, RuleExpr, Value};
use crate::types::{DagEdge, DagNode, RuleAction, RequestSample, Specificity, TlsSample};

// =============================================================================
// ExprTreeNode — a node in the compiled expression tree
// =============================================================================

#[derive(Debug, Clone)]
pub struct ExprTreeNode {
    pub dim: Dimension,
    pub mode: MatchMode,
    /// Exact-match children: canonical_key → child_index.
    pub children: HashMap<String, usize>,
    /// Wildcard child: rules that don't constrain this dimension.
    pub wildcard: Option<usize>,
    /// Leaf action if a rule terminates here.
    pub action: Option<(RuleAction, u32, Specificity)>,
}

// =============================================================================
// ExprCompiledTree — the compiled tree ready for evaluation
// =============================================================================

#[derive(Debug, Clone)]
pub struct ExprCompiledTree {
    pub nodes: Vec<ExprTreeNode>,
    pub root: usize,
    pub dim_order: Vec<Dimension>,
    pub rule_fingerprint: String,
    pub rule_labels: HashMap<u32, (String, String)>,
}

impl ExprCompiledTree {
    pub fn empty() -> Self {
        Self {
            nodes: vec![ExprTreeNode {
                dim: Dimension::method(),
                mode: MatchMode::Exact,
                children: HashMap::new(),
                wildcard: None,
                action: None,
            }],
            root: 0,
            dim_order: vec![],
            rule_fingerprint: String::new(),
            rule_labels: HashMap::new(),
        }
    }

    pub fn to_dag_nodes(&self) -> Vec<DagNode> {
        self.nodes.iter().enumerate().map(|(i, node)| {
            let mut edges: Vec<DagEdge> = node.children.iter()
                .map(|(val, &target)| DagEdge { target, label: val.clone() })
                .collect();
            edges.sort_by(|a, b| a.label.cmp(&b.label));

            let child_ids: Vec<usize> = edges.iter().map(|e| e.target).collect();
            let mut all_children = child_ids;
            if let Some(wc) = node.wildcard {
                all_children.push(wc);
            }

            let action = node.action.as_ref().map(|(act, _, _)| act.to_sexpr());

            let dim_label = if node.action.is_some() && all_children.is_empty() {
                "terminal".to_string()
            } else {
                node.dim.to_sexpr()
            };

            DagNode {
                id: i,
                dim: dim_label,
                children: all_children,
                edges,
                wildcard: node.wildcard,
                action,
            }
        }).collect()
    }

    pub fn evaluate_req(&self, req: &RequestSample) -> Option<(&RuleAction, u32)> {
        self.dfs_req(req, self.root).map(|(a, id, _)| (a, id))
    }

    pub fn evaluate_tls(&self, sample: &TlsSample) -> Option<(&RuleAction, u32)> {
        self.dfs_tls(sample, self.root).map(|(a, id, _)| (a, id))
    }

    fn dfs_req<'a>(
        &'a self,
        req: &RequestSample,
        node_idx: usize,
    ) -> Option<(&'a RuleAction, u32, Specificity)> {
        let node = self.nodes.get(node_idx)?;
        let extracted = node.dim.extract_from_request(req);

        let specific = match node.mode {
            MatchMode::Exact => {
                let key = extracted.canonical_key();
                node.children.get(&key)
                    .and_then(|&child| self.dfs_req(req, child))
            }
            MatchMode::Membership => {
                self.membership_search_req(req, node, &extracted)
            }
        };

        let wildcard = node.wildcard
            .and_then(|child| self.dfs_req(req, child));

        let best_child = pick_best(specific, wildcard);
        let this_node = node.action.as_ref().map(|(a, id, s)| (a, *id, *s));
        pick_best(best_child, this_node)
    }

    fn dfs_tls<'a>(
        &'a self,
        sample: &TlsSample,
        node_idx: usize,
    ) -> Option<(&'a RuleAction, u32, Specificity)> {
        let node = self.nodes.get(node_idx)?;
        let extracted = node.dim.extract_from_tls(sample);

        let specific = match node.mode {
            MatchMode::Exact => {
                let key = extracted.canonical_key();
                node.children.get(&key)
                    .and_then(|&child| self.dfs_tls(sample, child))
            }
            MatchMode::Membership => {
                self.membership_search_tls(sample, node, &extracted)
            }
        };

        let wildcard = node.wildcard
            .and_then(|child| self.dfs_tls(sample, child));

        let best_child = pick_best(specific, wildcard);
        let this_node = node.action.as_ref().map(|(a, id, s)| (a, *id, *s));
        pick_best(best_child, this_node)
    }

    /// For Membership mode: the extracted value is a collection (List/Set).
    /// Check each element against children keys.
    fn membership_search_req<'a>(
        &'a self,
        req: &RequestSample,
        node: &ExprTreeNode,
        extracted: &Value,
    ) -> Option<(&'a RuleAction, u32, Specificity)> {
        let mut best: Option<(&RuleAction, u32, Specificity)> = None;
        match extracted {
            Value::List(items) => {
                for item in items {
                    let key = item.canonical_key();
                    if let Some(&child) = node.children.get(&key) {
                        best = pick_best(best, self.dfs_req(req, child));
                    }
                }
            }
            Value::Set(items) => {
                for item in items {
                    if let Some(&child) = node.children.get(item) {
                        best = pick_best(best, self.dfs_req(req, child));
                    }
                }
            }
            _ => {}
        }
        best
    }

    fn membership_search_tls<'a>(
        &'a self,
        sample: &TlsSample,
        node: &ExprTreeNode,
        extracted: &Value,
    ) -> Option<(&'a RuleAction, u32, Specificity)> {
        let mut best: Option<(&RuleAction, u32, Specificity)> = None;
        match extracted {
            Value::List(items) => {
                for item in items {
                    let key = item.canonical_key();
                    if let Some(&child) = node.children.get(&key) {
                        best = pick_best(best, self.dfs_tls(sample, child));
                    }
                }
            }
            Value::Set(items) => {
                for item in items {
                    if let Some(&child) = node.children.get(item) {
                        best = pick_best(best, self.dfs_tls(sample, child));
                    }
                }
            }
            _ => {}
        }
        best
    }
}

fn pick_best<'a>(
    a: Option<(&'a RuleAction, u32, Specificity)>,
    b: Option<(&'a RuleAction, u32, Specificity)>,
) -> Option<(&'a RuleAction, u32, Specificity)> {
    match (a, b) {
        (Some(av), Some(bv)) => {
            if bv.2 > av.2 { Some(bv) } else { Some(av) }
        }
        (Some(v), None) | (None, Some(v)) => Some(v),
        (None, None) => None,
    }
}

// =============================================================================
// Dynamic DIM_ORDER computation
// =============================================================================

/// Compute an ordered list of dimensions from the active rules.
/// Dimensions are ordered by discrimination power (how many distinct values
/// they partition rules into) descending, with layer rank as tiebreaker
/// (TLS before HTTP).
fn compute_dim_order(rules: &[RuleExpr]) -> Vec<Dimension> {
    let mut dim_count: HashMap<Dimension, usize> = HashMap::new();
    for rule in rules {
        for expr in &rule.constraints {
            if expr.is_tier1() {
                *dim_count.entry(expr.dim.clone()).or_insert(0) += 1;
            }
        }
    }

    let mut dims: Vec<(Dimension, usize)> = dim_count.into_iter().collect();

    dims.sort_by(|(dim_a, count_a), (dim_b, count_b)| {
        count_b.cmp(count_a)
            .then_with(|| dim_a.layer_rank().cmp(&dim_b.layer_rank()))
    });

    dims.into_iter().map(|(dim, _)| dim).collect()
}

// =============================================================================
// Shadow tree (compilation intermediate)
// =============================================================================

#[derive(Debug, Clone)]
struct ShadowNode {
    dim_index: usize,
    mode: MatchMode,
    action: Option<(RuleAction, u32, Specificity)>,
    children: HashMap<String, Rc<ShadowNode>>,
    wildcard: Option<Rc<ShadowNode>>,
}

impl ShadowNode {
    fn new(dim_index: usize, mode: MatchMode) -> Self {
        Self {
            dim_index,
            mode,
            action: None,
            children: HashMap::new(),
            wildcard: None,
        }
    }
}

// =============================================================================
// Compilation
// =============================================================================

pub fn compile_expr(rules: &[RuleExpr]) -> ExprCompiledTree {
    if rules.is_empty() {
        return ExprCompiledTree::empty();
    }

    let dim_order = compute_dim_order(rules);

    let refs: Vec<&RuleExpr> = rules.iter().collect();
    let shadow = compile_recursive(&refs, 0, &dim_order);
    let mut nodes: Vec<ExprTreeNode> = Vec::new();
    let root = flatten(&shadow, &mut nodes, &dim_order);

    let rule_fingerprint = build_fingerprint(rules);

    info!(
        rules = rules.len(),
        nodes = nodes.len(),
        dims = dim_order.len(),
        "expr tree compiled"
    );

    let mut rule_labels = HashMap::new();
    for rule in rules {
        let rid = rule_identity_hash(rule);
        rule_labels.entry(rid).or_insert_with(|| {
            (rule.constraints_sexpr(), rule.action.to_sexpr())
        });
    }

    ExprCompiledTree {
        nodes,
        root,
        dim_order,
        rule_fingerprint,
        rule_labels,
    }
}

fn compile_recursive<'a>(
    rules: &[&'a RuleExpr],
    dim_idx: usize,
    dim_order: &[Dimension],
) -> Rc<ShadowNode> {
    if dim_idx >= dim_order.len() {
        let mut node = ShadowNode::new(dim_idx, MatchMode::Exact);
        if let Some(rule) = rules.iter().max_by_key(|r| r.priority) {
            let rule_id = rule_identity_hash(rule);
            let score = specificity_score(rule);
            node.action = Some((rule.action.clone(), rule_id, score));
        }
        return Rc::new(node);
    }

    let dim = &dim_order[dim_idx];

    let mode = rules.iter()
        .flat_map(|r| r.constraints.iter())
        .find(|e| &e.dim == dim && e.is_tier1())
        .map(|e| e.match_mode())
        .unwrap_or(MatchMode::Exact);

    let any_constrained = rules.iter().any(|r| rule_constrains(r, dim));

    if !any_constrained {
        let mut node = ShadowNode::new(dim_idx, mode);
        let child = compile_recursive(rules, dim_idx + 1, dim_order);
        node.wildcard = Some(child);
        return Rc::new(node);
    }

    let mut node = ShadowNode::new(dim_idx, mode);

    let mut grouped: HashMap<String, Vec<&'a RuleExpr>> = HashMap::new();
    let mut wildcard_rules: Vec<&'a RuleExpr> = Vec::new();

    for rule in rules {
        match rule_constraint_key_cow(rule, dim) {
            Some(std::borrow::Cow::Borrowed(s)) => {
                // Zero-copy path for Value::Str — reuse the rule's own string
                if let Some(group) = grouped.get_mut(s) {
                    group.push(rule);
                } else {
                    grouped.insert(s.to_string(), vec![rule]);
                }
            }
            Some(std::borrow::Cow::Owned(s)) => {
                grouped.entry(s).or_default().push(rule);
            }
            None => {
                wildcard_rules.push(rule);
            }
        }
    }

    for (val, val_rules) in grouped {
        let child = compile_recursive(&val_rules, dim_idx + 1, dim_order);
        node.children.insert(val, child);
    }

    if !wildcard_rules.is_empty() {
        let child = compile_recursive(&wildcard_rules, dim_idx + 1, dim_order);
        node.wildcard = Some(child);
    }

    Rc::new(node)
}

fn rule_constrains(rule: &RuleExpr, dim: &Dimension) -> bool {
    rule.constraints.iter().any(|e| &e.dim == dim && e.is_tier1())
}

fn rule_constraint_key_cow<'a>(rule: &'a RuleExpr, dim: &Dimension) -> Option<std::borrow::Cow<'a, str>> {
    rule.constraints.iter().find_map(|e| {
        if &e.dim == dim && e.is_tier1() {
            Some(e.value.canonical_key_cow())
        } else {
            None
        }
    })
}

// =============================================================================
// Flatten shadow tree → Vec<ExprTreeNode>
// =============================================================================

fn flatten(
    node: &Rc<ShadowNode>,
    nodes: &mut Vec<ExprTreeNode>,
    dim_order: &[Dimension],
) -> usize {
    let idx = nodes.len();
    let dim_idx = node.dim_index.min(dim_order.len().saturating_sub(1));
    let dim = if dim_order.is_empty() {
        Dimension::method()
    } else {
        dim_order[dim_idx].clone()
    };

    nodes.push(ExprTreeNode {
        dim,
        mode: node.mode,
        children: HashMap::new(),
        wildcard: None,
        action: node.action.clone(),
    });

    for (val, child) in &node.children {
        let child_idx = flatten(child, nodes, dim_order);
        nodes[idx].children.insert(val.clone(), child_idx);
    }

    if let Some(ref wc) = node.wildcard {
        let wc_idx = flatten(wc, nodes, dim_order);
        nodes[idx].wildcard = Some(wc_idx);
    }

    idx
}

// =============================================================================
// Helpers
// =============================================================================

fn build_fingerprint(rules: &[RuleExpr]) -> String {
    let mut hashes: Vec<u32> = rules.iter()
        .map(|r| rule_identity_hash(r))
        .collect();
    hashes.sort();
    let mut combined: u64 = 0xcbf29ce484222325;
    for h in hashes {
        combined ^= h as u64;
        combined = combined.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", combined)
}

fn specificity_score(rule: &RuleExpr) -> Specificity {
    let (has_tls, has_http) = rule.layer_count();
    Specificity {
        layers: has_tls as u8 + has_http as u8,
        has_http: has_http as u8,
        constraints: rule.constraints.len() as u8,
    }
}

fn rule_identity_hash(rule: &RuleExpr) -> u32 {
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
    use crate::expr::{Dimension, Expr, SimpleDim, Value};
    use crate::types::{RuleAction, TlsContext};
    use holon::kernel::{Encoder, VectorManager};
    use std::sync::Arc;

    fn make_encoder() -> Encoder {
        Encoder::new(VectorManager::new(4096))
    }

    fn make_req(method: &str, path: &str, ip: &str) -> RequestSample {
        let tls_ctx = Arc::new(TlsContext::default());
        let enc = make_encoder();
        let tls_vec = enc.encode_walkable(tls_ctx.as_ref());
        let ip: std::net::IpAddr = ip.parse().unwrap();
        crate::types::test_request_sample(method, path, ip, vec![], tls_ctx, tls_vec)
    }

    fn make_req_with_headers(
        method: &str,
        path: &str,
        ip: &str,
        headers: Vec<(&str, &str)>,
    ) -> RequestSample {
        let tls_ctx = Arc::new(TlsContext::default());
        let enc = make_encoder();
        let tls_vec = enc.encode_walkable(tls_ctx.as_ref());
        let ip: std::net::IpAddr = ip.parse().unwrap();
        let hdrs: Vec<(String, String)> = headers.into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        crate::types::test_request_sample(method, path, ip, hdrs, tls_ctx, tls_vec)
    }

    fn make_tls_sample(ciphers: Vec<u16>) -> TlsSample {
        let mut tls = TlsContext::default();
        tls.cipher_suites = ciphers;
        TlsSample {
            conn_id: 1,
            src_ip: "10.0.0.1".parse().unwrap(),
            tls_ctx: Arc::new(tls),
            tls_vec: make_encoder().encode_walkable(&TlsContext::default()),
            timestamp_us: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Basic compilation and evaluation
    // -----------------------------------------------------------------------

    #[test]
    fn empty_tree_passes() {
        let tree = compile_expr(&[]);
        assert!(tree.nodes.len() == 1);
    }

    #[test]
    fn single_eq_method_rule() {
        let rules = vec![RuleExpr::new(
            vec![Expr::eq(Dimension::method(), Value::str("POST"))],
            RuleAction::block(),
        )];
        let tree = compile_expr(&rules);
        let req_match = make_req("POST", "/", "10.0.0.1");
        let req_miss = make_req("GET", "/", "10.0.0.1");
        assert!(matches!(tree.evaluate_req(&req_match), Some((RuleAction::Block { .. }, _))));
        assert!(tree.evaluate_req(&req_miss).is_none());
    }

    #[test]
    fn multi_constraint_rule() {
        let rules = vec![RuleExpr::new(
            vec![
                Expr::eq(Dimension::method(), Value::str("POST")),
                Expr::eq(Dimension::src_ip(), Value::str("10.0.0.1")),
            ],
            RuleAction::block(),
        )];
        let tree = compile_expr(&rules);

        assert!(matches!(
            tree.evaluate_req(&make_req("POST", "/", "10.0.0.1")),
            Some((RuleAction::Block { .. }, _))
        ));
        assert!(tree.evaluate_req(&make_req("GET", "/", "10.0.0.1")).is_none());
        assert!(tree.evaluate_req(&make_req("POST", "/", "10.0.0.2")).is_none());
    }

    #[test]
    fn wildcard_rule_matches_all() {
        let rules = vec![RuleExpr::new(vec![], RuleAction::count())];
        let tree = compile_expr(&rules);
        let req = make_req("GET", "/", "1.2.3.4");
        assert!(matches!(tree.evaluate_req(&req), Some((RuleAction::Count { .. }, _))));
    }

    #[test]
    fn specific_beats_wildcard() {
        let block = RuleExpr::new(
            vec![Expr::eq(Dimension::method(), Value::str("POST"))],
            RuleAction::block(),
        );
        let mut pass = RuleExpr::new(vec![], RuleAction::pass());
        pass.priority = 50;

        let tree = compile_expr(&[pass, block]);

        assert!(matches!(
            tree.evaluate_req(&make_req("POST", "/", "1.2.3.4")),
            Some((RuleAction::Block { .. }, _))
        ));
        assert!(matches!(
            tree.evaluate_req(&make_req("GET", "/", "1.2.3.4")),
            Some((RuleAction::Pass { name: None }, _))
        ));
    }

    #[test]
    fn multiple_values_same_dim() {
        let rules = vec![
            RuleExpr::new(
                vec![Expr::eq(Dimension::method(), Value::str("POST"))],
                RuleAction::block(),
            ),
            RuleExpr::new(
                vec![Expr::eq(Dimension::method(), Value::str("DELETE"))],
                RuleAction::CloseConnection { name: None },
            ),
        ];
        let tree = compile_expr(&rules);

        assert!(matches!(
            tree.evaluate_req(&make_req("POST", "/", "1.2.3.4")),
            Some((RuleAction::Block { .. }, _))
        ));
        assert!(matches!(
            tree.evaluate_req(&make_req("DELETE", "/", "1.2.3.4")),
            Some((RuleAction::CloseConnection { name: None }, _))
        ));
        assert!(tree.evaluate_req(&make_req("GET", "/", "1.2.3.4")).is_none());
    }

    // -----------------------------------------------------------------------
    // Composed dimensions in tree
    // -----------------------------------------------------------------------

    #[test]
    fn header_first_in_tree() {
        let rules = vec![RuleExpr::new(
            vec![Expr::eq(Dimension::header_first("host"), Value::str("example.com"))],
            RuleAction::block(),
        )];
        let tree = compile_expr(&rules);

        let req_match = make_req_with_headers("GET", "/", "10.0.0.1", vec![("host", "example.com")]);
        let req_miss = make_req_with_headers("GET", "/", "10.0.0.1", vec![("host", "other.com")]);

        assert!(matches!(tree.evaluate_req(&req_match), Some((RuleAction::Block { .. }, _))));
        assert!(tree.evaluate_req(&req_miss).is_none());
    }

    #[test]
    fn mixed_simple_and_composed_dims() {
        let rules = vec![RuleExpr::new(
            vec![
                Expr::eq(Dimension::method(), Value::str("POST")),
                Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
            ],
            RuleAction::RateLimit { rps: 100, name: None },
        )];
        let tree = compile_expr(&rules);

        let req_match = make_req_with_headers(
            "POST", "/api", "10.0.0.1",
            vec![("content-type", "application/json")],
        );
        let req_wrong_method = make_req_with_headers(
            "GET", "/api", "10.0.0.1",
            vec![("content-type", "application/json")],
        );
        let req_wrong_ct = make_req_with_headers(
            "POST", "/api", "10.0.0.1",
            vec![("content-type", "text/plain")],
        );

        assert!(matches!(tree.evaluate_req(&req_match), Some((RuleAction::RateLimit { rps: 100, name: None }, _))));
        assert!(tree.evaluate_req(&req_wrong_method).is_none());
        assert!(tree.evaluate_req(&req_wrong_ct).is_none());
    }

    // -----------------------------------------------------------------------
    // Membership mode (exists operator)
    // -----------------------------------------------------------------------

    #[test]
    fn exists_in_list_via_membership() {
        let rules = vec![RuleExpr::new(
            vec![Expr::exists(
                Dimension::Simple(SimpleDim::PathParts),
                Value::str("admin"),
            )],
            RuleAction::block(),
        )];
        let tree = compile_expr(&rules);

        let req_match = make_req("GET", "/api/admin/users", "10.0.0.1");
        let req_miss = make_req("GET", "/api/public/docs", "10.0.0.1");

        assert!(matches!(tree.evaluate_req(&req_match), Some((RuleAction::Block { .. }, _))));
        assert!(tree.evaluate_req(&req_miss).is_none());
    }

    #[test]
    fn exists_combined_with_eq() {
        let rules = vec![RuleExpr::new(
            vec![
                Expr::eq(Dimension::method(), Value::str("POST")),
                Expr::exists(
                    Dimension::Simple(SimpleDim::PathParts),
                    Value::str("admin"),
                ),
            ],
            RuleAction::block(),
        )];
        let tree = compile_expr(&rules);

        assert!(matches!(
            tree.evaluate_req(&make_req("POST", "/api/admin/users", "10.0.0.1")),
            Some((RuleAction::Block { .. }, _))
        ));
        assert!(tree.evaluate_req(&make_req("GET", "/api/admin/users", "10.0.0.1")).is_none());
        assert!(tree.evaluate_req(&make_req("POST", "/api/public/docs", "10.0.0.1")).is_none());
    }

    // -----------------------------------------------------------------------
    // TLS evaluation
    // -----------------------------------------------------------------------

    #[test]
    fn tls_cipher_set_equality() {
        let expected_set = Value::set_from_strs(vec!["0x1301", "0x1302"]);
        let rules = vec![RuleExpr::new(
            vec![Expr::eq(Dimension::Simple(SimpleDim::TlsCiphers), expected_set)],
            RuleAction::CloseConnection { name: None },
        )];
        let tree = compile_expr(&rules);

        let sample_match = make_tls_sample(vec![0x1301, 0x1302]);
        let sample_miss = make_tls_sample(vec![0x1301, 0x1303]);

        assert!(matches!(tree.evaluate_tls(&sample_match), Some((RuleAction::CloseConnection { name: None }, _))));
        assert!(tree.evaluate_tls(&sample_miss).is_none());
    }

    #[test]
    fn tls_exists_in_cipher_set() {
        let rules = vec![RuleExpr::new(
            vec![Expr::exists(
                Dimension::Simple(SimpleDim::TlsCiphers),
                Value::str("0x1301"),
            )],
            RuleAction::CloseConnection { name: None },
        )];
        let tree = compile_expr(&rules);

        let sample_match = make_tls_sample(vec![0x1301, 0xc02b]);
        let sample_miss = make_tls_sample(vec![0xc02b, 0xc02c]);

        assert!(matches!(tree.evaluate_tls(&sample_match), Some((RuleAction::CloseConnection { name: None }, _))));
        assert!(tree.evaluate_tls(&sample_miss).is_none());
    }

    // -----------------------------------------------------------------------
    // Dynamic DIM_ORDER
    // -----------------------------------------------------------------------

    #[test]
    fn dim_order_reflects_active_rules() {
        let rules = vec![
            RuleExpr::new(
                vec![Expr::eq(Dimension::method(), Value::str("POST"))],
                RuleAction::block(),
            ),
            RuleExpr::new(
                vec![Expr::eq(Dimension::method(), Value::str("DELETE"))],
                RuleAction::block(),
            ),
            RuleExpr::new(
                vec![Expr::eq(Dimension::header_first("host"), Value::str("example.com"))],
                RuleAction::block(),
            ),
        ];

        let order = compute_dim_order(&rules);

        // method has 2 distinct values, host has 1 → method first
        assert_eq!(order[0], Dimension::method());
        assert_eq!(order[1], Dimension::header_first("host"));
    }

    #[test]
    fn dim_order_empty_for_no_rules() {
        assert!(compute_dim_order(&[]).is_empty());
    }

    // -----------------------------------------------------------------------
    // Specificity / best-match
    // -----------------------------------------------------------------------

    #[test]
    fn more_specific_wins() {
        let narrow = RuleExpr::new(
            vec![
                Expr::eq(Dimension::method(), Value::str("POST")),
                Expr::eq(Dimension::header_first("host"), Value::str("example.com")),
            ],
            RuleAction::block(),
        );
        let broad = RuleExpr::new(
            vec![Expr::eq(Dimension::method(), Value::str("POST"))],
            RuleAction::RateLimit { rps: 100, name: None },
        );

        let tree = compile_expr(&[narrow, broad]);

        let req = make_req_with_headers("POST", "/", "10.0.0.1", vec![("host", "example.com")]);
        let result = tree.evaluate_req(&req);
        assert!(matches!(result, Some((RuleAction::Block { .. }, _))));
    }

    // -----------------------------------------------------------------------
    // Fingerprinting / idempotency
    // -----------------------------------------------------------------------

    #[test]
    fn compile_idempotent() {
        let rules = vec![
            RuleExpr::new(
                vec![Expr::eq(Dimension::method(), Value::str("POST"))],
                RuleAction::block(),
            ),
            RuleExpr::new(
                vec![Expr::eq(Dimension::method(), Value::str("DELETE"))],
                RuleAction::CloseConnection { name: None },
            ),
        ];
        let t1 = compile_expr(&rules);
        let t2 = compile_expr(&rules);
        assert_eq!(t1.rule_fingerprint, t2.rule_fingerprint);
        assert_eq!(t1.nodes.len(), t2.nodes.len());
    }

    #[test]
    fn fingerprint_changes_with_rules() {
        let r1 = vec![RuleExpr::new(
            vec![Expr::eq(Dimension::method(), Value::str("POST"))],
            RuleAction::block(),
        )];
        let r2 = vec![RuleExpr::new(
            vec![Expr::eq(Dimension::method(), Value::str("GET"))],
            RuleAction::block(),
        )];
        assert_ne!(compile_expr(&r1).rule_fingerprint, compile_expr(&r2).rule_fingerprint);
    }

    // =====================================================================
    // Integration: realistic attack scenarios
    // =====================================================================

    fn make_attack_tls() -> TlsContext {
        TlsContext {
            record_version: 0x0301,
            handshake_version: 0x0303,
            session_id_len: 32,
            cipher_suites: vec![0x00ff, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9],
            compression_methods: vec![0x00],
            extensions: vec![
                (0x0000, vec![]), (0x0005, vec![]), (0x000a, vec![]),
                (0x000b, vec![]), (0x000d, vec![]), (0x0017, vec![]),
                (0x0023, vec![]), (0x002b, vec![]), (0x002d, vec![]),
                (0x0033, vec![]),
            ],
            supported_groups: vec![0x0017, 0x0018, 0x001d],
            ec_point_formats: vec![0x00],
            sig_algs: vec![0x0403, 0x0804],
            alpn: vec!["h2".into(), "http/1.1".into()],
            sni: Some("target.example.com".into()),
            session_ticket: false,
            psk_modes: vec![0x01],
            key_share_groups: vec![0x001d],
            supported_versions: vec![0x0304, 0x0303],
            compress_certificate: vec![],
        }
    }

    fn make_legit_tls() -> TlsContext {
        TlsContext {
            record_version: 0x0301,
            handshake_version: 0x0303,
            session_id_len: 32,
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
            compression_methods: vec![0x00],
            extensions: vec![
                (0x0000, vec![]), (0x000a, vec![]), (0x000b, vec![]),
                (0x000d, vec![]), (0x0017, vec![]), (0x002b, vec![]),
                (0x0033, vec![]),
            ],
            supported_groups: vec![0x001d, 0x0017],
            ec_point_formats: vec![0x00],
            sig_algs: vec![0x0403, 0x0804, 0x0401],
            alpn: vec!["h2".into(), "http/1.1".into()],
            sni: Some("target.example.com".into()),
            session_ticket: false,
            psk_modes: vec![0x01],
            key_share_groups: vec![0x001d],
            supported_versions: vec![0x0304, 0x0303],
            compress_certificate: vec![],
        }
    }

    fn make_full_req(
        method: &str, path: &str, ip: &str,
        headers: Vec<(&str, &str)>,
        tls: TlsContext,
    ) -> RequestSample {
        let tls_ctx = Arc::new(tls);
        let enc = make_encoder();
        let tls_vec = enc.encode_walkable(tls_ctx.as_ref());
        let ip: std::net::IpAddr = ip.parse().unwrap();
        let hdrs: Vec<(String, String)> = headers.into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        crate::types::test_request_sample(method, path, ip, hdrs, tls_ctx, tls_vec)
    }

    fn attack_ext_set() -> Value {
        Value::set_from_strs(vec![
            "0x0000", "0x0005", "0x000a", "0x000b", "0x000d",
            "0x0017", "0x0023", "0x002b", "0x002d", "0x0033",
        ])
    }

    fn attack_cipher_set() -> Value {
        Value::set_from_strs(vec![
            "0x00ff", "0x1301", "0x1302", "0x1303", "0xc02b",
            "0xc02c", "0xc02f", "0xc030", "0xcca8", "0xcca9",
        ])
    }

    fn attack_group_set() -> Value {
        Value::set_from_strs(vec!["0x0017", "0x0018", "0x001d"])
    }

    /// Scenario from a real attack run: 6 rules spanning TLS-only,
    /// TLS+HTTP mixed, and HTTP-only. Validates that the tree correctly
    /// routes requests to the most specific matching rule.
    #[test]
    fn integration_realistic_attack_rules() {
        // Rule 1: TLS ext-set + path + content-type (TLS+HTTP, 3 constraints)
        let r1 = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::path(), Value::str("/api/v1/auth/login")),
            Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
        ], RuleAction::RateLimit { rps: 83, name: None });

        // Rule 2: TLS ext-set + method + content-type (TLS+HTTP, 3 constraints)
        let r2 = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::method(), Value::str("POST")),
            Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
        ], RuleAction::RateLimit { rps: 83, name: None });

        // Rule 3: TLS ext-set + path + user-agent (TLS+HTTP, 3 constraints)
        let r3 = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::path(), Value::str("/api/v1/auth/login")),
            Expr::eq(Dimension::header_first("user-agent"), Value::str("python-requests/2.31.0")),
        ], RuleAction::RateLimit { rps: 83, name: None });

        // Rule 4: TLS ext-set + user-agent + content-type (TLS+HTTP, 3 constraints)
        let r4 = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::header_first("user-agent"), Value::str("python-requests/2.31.0")),
            Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
        ], RuleAction::RateLimit { rps: 83, name: None });

        // Rule 5: TLS-only (cipher + ext + group sets, 3 constraints)
        let r5 = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsCiphers), attack_cipher_set()),
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::Simple(SimpleDim::TlsGroups), attack_group_set()),
        ], RuleAction::RateLimit { rps: 83, name: None });

        // Rule 6: HTTP-only (path only, 1 constraint)
        let r6 = RuleExpr::new(vec![
            Expr::eq(Dimension::path(), Value::str("/api/search")),
        ], RuleAction::RateLimit { rps: 83, name: None });

        let tree = compile_expr(&[r1, r2, r3, r4, r5, r6]);

        // --- Attacker request: POST /api/v1/auth/login with python UA and attack TLS ---
        // Matches r1 (ext+path+ct), r2 (ext+method+ct), r3 (ext+path+ua),
        //         r4 (ext+ua+ct), r5 (TLS-only). Most specific wins.
        let attacker_login = make_full_req(
            "POST", "/api/v1/auth/login", "10.0.0.1",
            vec![
                ("host", "target.example.com"),
                ("user-agent", "python-requests/2.31.0"),
                ("content-type", "application/json"),
            ],
            make_attack_tls(),
        );
        let result = tree.evaluate_req(&attacker_login);
        assert!(result.is_some(), "attacker login should match a rule");
        let (action, _rid) = result.unwrap();
        assert!(matches!(action, RuleAction::RateLimit { rps: 83, .. }));

        // --- Attacker request: GET /api/search with attack TLS ---
        // Matches r5 (TLS-only) and r6 (path-only).
        // r5 has more constraints so higher specificity.
        let attacker_search = make_full_req(
            "GET", "/api/search", "10.0.0.2",
            vec![
                ("host", "target.example.com"),
                ("user-agent", "python-requests/2.31.0"),
            ],
            make_attack_tls(),
        );
        let result = tree.evaluate_req(&attacker_search);
        assert!(result.is_some(), "attacker search should match a rule");

        // --- Legitimate user: GET /api/search with different TLS ---
        // Only matches r6 (path-only). Different TLS fingerprint so
        // r5 doesn't apply.
        let legit_search = make_full_req(
            "GET", "/api/search", "192.168.1.10",
            vec![
                ("host", "target.example.com"),
                ("user-agent", "Mozilla/5.0"),
            ],
            make_legit_tls(),
        );
        let result = tree.evaluate_req(&legit_search);
        assert!(result.is_some(), "legit search hits path-only rule");
        let (action, _) = result.unwrap();
        assert!(matches!(action, RuleAction::RateLimit { rps: 83, .. }));

        // --- Legitimate user: GET /dashboard with different TLS ---
        // Matches nothing. Different TLS, different path, different UA.
        let legit_dashboard = make_full_req(
            "GET", "/dashboard", "192.168.1.10",
            vec![
                ("host", "target.example.com"),
                ("user-agent", "Mozilla/5.0"),
            ],
            make_legit_tls(),
        );
        assert!(tree.evaluate_req(&legit_dashboard).is_none(),
                "legit dashboard request should not match any rule");
    }

    /// Mixed TLS+HTTP rules should beat TLS-only rules of equal constraint
    /// count because of the `has_http` tiebreaker in Specificity.
    #[test]
    fn integration_tls_http_beats_tls_only_at_equal_constraints() {
        let tls_only = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsCiphers), attack_cipher_set()),
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
        ], RuleAction::RateLimit { rps: 50, name: None });

        let tls_http = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::header_first("user-agent"), Value::str("Scrapy/2.11.0")),
        ], RuleAction::RateLimit { rps: 99, name: None });

        let tree = compile_expr(&[tls_only, tls_http]);

        // Request matches both (same ext-set, same cipher-set, scrapy UA)
        let req = make_full_req(
            "GET", "/", "10.0.0.1",
            vec![("user-agent", "Scrapy/2.11.0")],
            make_attack_tls(),
        );

        let (action, _) = tree.evaluate_req(&req).expect("should match");
        // tls_http wins: same constraint count (2), but has_http=1 > has_http=0
        assert!(matches!(action, RuleAction::RateLimit { rps: 99, .. }),
                "TLS+HTTP should beat TLS-only at equal constraint count");
    }

    /// More constraints always wins regardless of layer composition.
    #[test]
    fn integration_more_constraints_wins() {
        let broad = RuleExpr::new(vec![
            Expr::eq(Dimension::method(), Value::str("POST")),
        ], RuleAction::RateLimit { rps: 200, name: None });

        let narrow = RuleExpr::new(vec![
            Expr::eq(Dimension::method(), Value::str("POST")),
            Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
            Expr::eq(Dimension::path(), Value::str("/api/v1/auth/login")),
        ], RuleAction::RateLimit { rps: 50, name: None });

        let tree = compile_expr(&[broad, narrow]);

        let req_narrow = make_full_req(
            "POST", "/api/v1/auth/login", "10.0.0.1",
            vec![("content-type", "application/json")],
            make_legit_tls(),
        );
        let (action, _) = tree.evaluate_req(&req_narrow).expect("should match");
        assert!(matches!(action, RuleAction::RateLimit { rps: 50, .. }),
                "3-constraint rule should beat 1-constraint");

        // Same method, different path — only the broad rule matches
        let req_broad = make_full_req(
            "POST", "/other", "10.0.0.1",
            vec![("content-type", "text/plain")],
            make_legit_tls(),
        );
        let (action, _) = tree.evaluate_req(&req_broad).expect("should match");
        assert!(matches!(action, RuleAction::RateLimit { rps: 200, .. }),
                "only broad rule matches this request");
    }

    /// TLS-level evaluation (no HTTP data yet) correctly matches TLS rules
    /// and ignores HTTP-dependent rules.
    #[test]
    fn integration_tls_only_evaluation() {
        let tls_rule = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsCiphers), attack_cipher_set()),
            Expr::eq(Dimension::Simple(SimpleDim::TlsGroups), attack_group_set()),
        ], RuleAction::CloseConnection { name: None });

        let http_rule = RuleExpr::new(vec![
            Expr::eq(Dimension::method(), Value::str("POST")),
        ], RuleAction::block());

        let tree = compile_expr(&[tls_rule, http_rule]);

        let attack_sample = TlsSample {
            conn_id: 1,
            src_ip: "10.0.0.1".parse().unwrap(),
            tls_ctx: Arc::new(make_attack_tls()),
            tls_vec: make_encoder().encode_walkable(&TlsContext::default()),
            timestamp_us: 0,
        };

        let (action, _) = tree.evaluate_tls(&attack_sample).expect("should match TLS rule");
        assert!(matches!(action, RuleAction::CloseConnection { .. }));

        let legit_sample = TlsSample {
            conn_id: 2,
            src_ip: "192.168.1.10".parse().unwrap(),
            tls_ctx: Arc::new(make_legit_tls()),
            tls_vec: make_encoder().encode_walkable(&TlsContext::default()),
            timestamp_us: 0,
        };
        assert!(tree.evaluate_tls(&legit_sample).is_none(),
                "legit TLS should not match");
    }

    /// Verify tree node count is reasonable — pure DAG, no explosion.
    #[test]
    fn integration_no_node_explosion() {
        let rules: Vec<RuleExpr> = vec![
            RuleExpr::new(vec![
                Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
                Expr::eq(Dimension::path(), Value::str("/api/v1/auth/login")),
                Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
            ], RuleAction::RateLimit { rps: 83, name: None }),
            RuleExpr::new(vec![
                Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
                Expr::eq(Dimension::method(), Value::str("POST")),
                Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
            ], RuleAction::RateLimit { rps: 83, name: None }),
            RuleExpr::new(vec![
                Expr::eq(Dimension::Simple(SimpleDim::TlsCiphers), attack_cipher_set()),
                Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
                Expr::eq(Dimension::Simple(SimpleDim::TlsGroups), attack_group_set()),
            ], RuleAction::RateLimit { rps: 83, name: None }),
            RuleExpr::new(vec![
                Expr::eq(Dimension::path(), Value::str("/api/search")),
            ], RuleAction::RateLimit { rps: 83, name: None }),
        ];

        let tree = compile_expr(&rules);

        // Pure DAG: 4 rules should NOT explode into 100+ nodes
        assert!(tree.nodes.len() <= 30,
                "expected <= 30 nodes for 4 rules, got {} (explosion?)", tree.nodes.len());
        assert!(tree.nodes.len() >= 4,
                "expected at least 4 nodes, got {}", tree.nodes.len());
    }

    /// End-to-end: detection bridge produces RuleExpr, tree compiles and
    /// evaluates correctly.
    #[test]
    fn integration_detection_bridge_roundtrip() {
        use crate::expr::{Dimension, Expr, SimpleDim, Value};

        // Simulate what the detection bridge produces
        let rule = RuleExpr::new(vec![
            Expr::eq(
                Dimension::Simple(SimpleDim::TlsExtTypes),
                Value::set_from_strs(vec!["0x0000", "0x000a", "0x000d"]),
            ),
            Expr::eq(Dimension::header_first("user-agent"), Value::str("python-requests/2.31.0")),
            Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
        ], RuleAction::RateLimit { rps: 82, name: None });

        let tree = compile_expr(&[rule]);

        // Build a matching request
        let mut tls = make_legit_tls();
        tls.extensions = vec![(0x0000, vec![]), (0x000a, vec![]), (0x000d, vec![])];
        let req = make_full_req(
            "POST", "/api/login", "10.0.0.1",
            vec![
                ("user-agent", "python-requests/2.31.0"),
                ("content-type", "application/json"),
            ],
            tls,
        );

        let (action, _) = tree.evaluate_req(&req).expect("bridge rule should match");
        assert!(matches!(action, RuleAction::RateLimit { rps: 82, .. }));

        // Mismatch on user-agent
        let req_miss = make_full_req(
            "POST", "/api/login", "10.0.0.1",
            vec![
                ("user-agent", "Mozilla/5.0"),
                ("content-type", "application/json"),
            ],
            make_legit_tls(),
        );
        assert!(tree.evaluate_req(&req_miss).is_none());
    }

    // =====================================================================
    // Specificity gauntlet: rule expressions → tree → evaluation
    // =====================================================================
    //
    // Each test constructs RuleExpr values, compiles them into a tree, and
    // asserts that the *correct* rule wins when multiple rules match the
    // same request.  Actions carry distinct rps values so we can tell
    // exactly which rule was chosen.

    /// layers=2 (TLS+HTTP) beats layers=1 (TLS-only) even with fewer constraints.
    #[test]
    fn specificity_cross_layer_beats_single_layer() {
        let tls_only_3 = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsCiphers), attack_cipher_set()),
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::Simple(SimpleDim::TlsGroups), attack_group_set()),
        ], RuleAction::RateLimit { rps: 10, name: None });

        let tls_http_2 = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::method(), Value::str("POST")),
        ], RuleAction::RateLimit { rps: 99, name: None });

        let tree = compile_expr(&[tls_only_3, tls_http_2]);

        let req = make_full_req(
            "POST", "/", "10.0.0.1", vec![], make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&req).expect("should match");
        assert!(
            matches!(action, RuleAction::RateLimit { rps: 99, .. }),
            "cross-layer (layers=2) should beat single-layer (layers=1) \
             even though TLS-only has 3 constraints vs 2"
        );
    }

    /// Same layer count, same has_http — more constraints wins.
    #[test]
    fn specificity_more_constraints_wins_within_same_layers() {
        let narrow = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::method(), Value::str("POST")),
            Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
        ], RuleAction::RateLimit { rps: 30, name: None });

        let broad = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::method(), Value::str("POST")),
        ], RuleAction::RateLimit { rps: 20, name: None });

        let tree = compile_expr(&[narrow, broad]);

        let req = make_full_req(
            "POST", "/", "10.0.0.1",
            vec![("content-type", "application/json")],
            make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&req).expect("should match");
        assert!(
            matches!(action, RuleAction::RateLimit { rps: 30, .. }),
            "3-constraint rule beats 2-constraint rule at same layer composition"
        );
    }

    /// has_http=1 beats has_http=0 when layers and constraint count are equal.
    /// This was a hard-won tiebreaker: TLS ext + user-agent should beat
    /// TLS cipher + TLS ext.
    #[test]
    fn specificity_has_http_tiebreaker() {
        let tls_pair = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsCiphers), attack_cipher_set()),
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
        ], RuleAction::RateLimit { rps: 50, name: None });

        let tls_http_pair = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::header_first("user-agent"), Value::str("Scrapy/2.11.0")),
        ], RuleAction::RateLimit { rps: 77, name: None });

        let tree = compile_expr(&[tls_pair, tls_http_pair]);

        let req = make_full_req(
            "GET", "/", "10.0.0.1",
            vec![("user-agent", "Scrapy/2.11.0")],
            make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&req).expect("should match");
        assert!(
            matches!(action, RuleAction::RateLimit { rps: 77, .. }),
            "TLS+HTTP beats TLS-only at equal constraint count (has_http tiebreaker)"
        );
    }

    /// Full ranking ladder: 4 rules with distinct specificity scores all
    /// match the same request. Only the most specific should win.
    ///
    /// Ranking (high to low):
    ///   1. layers=2, has_http=1, constraints=4  → rps=1
    ///   2. layers=2, has_http=1, constraints=2  → rps=2
    ///   3. layers=1, has_http=1, constraints=3  → rps=3
    ///   4. layers=1, has_http=0, constraints=3  → rps=4
    #[test]
    fn specificity_full_ranking_ladder() {
        let rank1 = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::method(), Value::str("POST")),
            Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
            Expr::eq(Dimension::path(), Value::str("/api/v1/auth/login")),
        ], RuleAction::RateLimit { rps: 1, name: None });

        let rank2 = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::method(), Value::str("POST")),
        ], RuleAction::RateLimit { rps: 2, name: None });

        let rank3 = RuleExpr::new(vec![
            Expr::eq(Dimension::method(), Value::str("POST")),
            Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
            Expr::eq(Dimension::path(), Value::str("/api/v1/auth/login")),
        ], RuleAction::RateLimit { rps: 3, name: None });

        let rank4 = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsCiphers), attack_cipher_set()),
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::Simple(SimpleDim::TlsGroups), attack_group_set()),
        ], RuleAction::RateLimit { rps: 4, name: None });

        let tree = compile_expr(&[rank4, rank2, rank3, rank1]);

        let req = make_full_req(
            "POST", "/api/v1/auth/login", "10.0.0.1",
            vec![("content-type", "application/json")],
            make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&req).expect("should match");
        assert!(
            matches!(action, RuleAction::RateLimit { rps: 1, .. }),
            "rank-1 rule (layers=2, http=1, constraints=4) should win the ladder"
        );
    }

    /// When the most specific rule doesn't match, the next-best should win.
    #[test]
    fn specificity_fallback_to_next_best() {
        let narrow = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::method(), Value::str("POST")),
            Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
            Expr::eq(Dimension::path(), Value::str("/api/v1/auth/login")),
        ], RuleAction::RateLimit { rps: 1, name: None });

        let broad = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::method(), Value::str("POST")),
        ], RuleAction::RateLimit { rps: 2, name: None });

        let tree = compile_expr(&[narrow, broad]);

        // Wrong path — narrow rule can't match, broad rule should win
        let req = make_full_req(
            "POST", "/other/path", "10.0.0.1",
            vec![("content-type", "application/json")],
            make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&req).expect("broad should match");
        assert!(
            matches!(action, RuleAction::RateLimit { rps: 2, .. }),
            "broad rule catches what narrow misses"
        );
    }

    /// Rules with different actions but overlapping TLS fingerprints:
    /// the one with HTTP constraints wins over the TLS-only rule.
    #[test]
    fn specificity_block_vs_ratelimit_tls_overlap() {
        let tls_close = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsCiphers), attack_cipher_set()),
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
        ], RuleAction::CloseConnection { name: None });

        let tls_http_block = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::method(), Value::str("POST")),
            Expr::eq(Dimension::header_first("user-agent"), Value::str("python-requests/2.31.0")),
        ], RuleAction::block());

        let tree = compile_expr(&[tls_close, tls_http_block]);

        // Attacker request matching both
        let req = make_full_req(
            "POST", "/", "10.0.0.1",
            vec![("user-agent", "python-requests/2.31.0")],
            make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&req).expect("should match");
        assert!(
            matches!(action, RuleAction::Block { .. }),
            "TLS+HTTP block (layers=2) should beat TLS-only close (layers=1)"
        );

        // Same TLS but different UA — TLS-only rule should win
        let req_diff_ua = make_full_req(
            "POST", "/", "10.0.0.1",
            vec![("user-agent", "Mozilla/5.0")],
            make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&req_diff_ua).expect("TLS rule should match");
        assert!(
            matches!(action, RuleAction::CloseConnection { .. }),
            "only TLS rule matches when HTTP constraints fail"
        );
    }

    /// HTTP-only rules compete purely on constraint count.
    #[test]
    fn specificity_http_only_constraint_count() {
        let one = RuleExpr::new(vec![
            Expr::eq(Dimension::method(), Value::str("POST")),
        ], RuleAction::RateLimit { rps: 200, name: None });

        let two = RuleExpr::new(vec![
            Expr::eq(Dimension::method(), Value::str("POST")),
            Expr::eq(Dimension::path(), Value::str("/api")),
        ], RuleAction::RateLimit { rps: 100, name: None });

        let three = RuleExpr::new(vec![
            Expr::eq(Dimension::method(), Value::str("POST")),
            Expr::eq(Dimension::path(), Value::str("/api")),
            Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
        ], RuleAction::RateLimit { rps: 50, name: None });

        let tree = compile_expr(&[one, two, three]);

        // Matches all three → 3-constraint wins
        let req = make_full_req(
            "POST", "/api", "10.0.0.1",
            vec![("content-type", "application/json")],
            make_legit_tls(),
        );
        let (action, _) = tree.evaluate_req(&req).expect("should match");
        assert!(matches!(action, RuleAction::RateLimit { rps: 50, .. }));

        // Wrong content-type → 2-constraint wins
        let req2 = make_full_req(
            "POST", "/api", "10.0.0.1",
            vec![("content-type", "text/plain")],
            make_legit_tls(),
        );
        let (action, _) = tree.evaluate_req(&req2).expect("should match");
        assert!(matches!(action, RuleAction::RateLimit { rps: 100, .. }));

        // Wrong path → only 1-constraint matches
        let req3 = make_full_req(
            "POST", "/other", "10.0.0.1",
            vec![("content-type", "application/json")],
            make_legit_tls(),
        );
        let (action, _) = tree.evaluate_req(&req3).expect("should match");
        assert!(matches!(action, RuleAction::RateLimit { rps: 200, .. }));
    }

    /// Composed dimensions (header first, path parts) participate in
    /// specificity correctly — they're HTTP-layer.
    #[test]
    fn specificity_composed_dimensions_layer_attribution() {
        let tls_3 = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsCiphers), attack_cipher_set()),
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::Simple(SimpleDim::TlsGroups), attack_group_set()),
        ], RuleAction::RateLimit { rps: 10, name: None });

        // 2 constraints but layers=2 because header_first is HTTP
        let composed_2 = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::header_first("host"), Value::str("target.example.com")),
        ], RuleAction::RateLimit { rps: 55, name: None });

        let tree = compile_expr(&[tls_3, composed_2]);

        let req = make_full_req(
            "GET", "/", "10.0.0.1",
            vec![("host", "target.example.com")],
            make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&req).expect("should match");
        assert!(
            matches!(action, RuleAction::RateLimit { rps: 55, .. }),
            "layers=2 (composed HTTP dim) beats layers=1 (TLS-only 3 constraints)"
        );
    }

    /// Membership (exists) constraints count the same as exact (eq)
    /// constraints for specificity.
    #[test]
    fn specificity_exists_counts_as_constraint() {
        let exists_rule = RuleExpr::new(vec![
            Expr::eq(Dimension::method(), Value::str("GET")),
            Expr::exists(
                Dimension::Simple(SimpleDim::PathParts),
                Value::str("admin"),
            ),
        ], RuleAction::block());

        let method_only = RuleExpr::new(vec![
            Expr::eq(Dimension::method(), Value::str("GET")),
        ], RuleAction::RateLimit { rps: 100, name: None });

        let tree = compile_expr(&[exists_rule, method_only]);

        let req = make_full_req(
            "GET", "/api/admin/panel", "10.0.0.1",
            vec![], make_legit_tls(),
        );
        let (action, _) = tree.evaluate_req(&req).expect("should match");
        assert!(
            matches!(action, RuleAction::Block { .. }),
            "2-constraint (eq+exists) beats 1-constraint (eq only)"
        );
    }

    /// EDN rendering of rules is stable and correct — proves the
    /// expressions we built actually render to what the dashboard shows.
    #[test]
    fn specificity_winner_edn_roundtrip() {
        let winner = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::path(), Value::str("/api/v1/auth/login")),
            Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
        ], RuleAction::RateLimit { rps: 83, name: None });

        let edn = winner.to_edn();
        assert!(edn.contains("tls-ext-types"), "EDN should mention tls-ext-types");
        assert!(edn.contains("rate-limit 83"), "EDN should mention rate-limit");
        assert!(edn.contains("/api/v1/auth/login"), "EDN should mention path");

        let pretty = winner.to_edn_pretty();
        assert!(pretty.contains("\n"), "pretty EDN should be multi-line");
        assert!(pretty.contains("(= (first (header \"content-type\")) \"application/json\")"),
                "composed dimension should render as nested s-expr");
    }

    /// Verifies that a request falling through all specific branches to
    /// a wildcard rule still gets the wildcard action.
    #[test]
    fn specificity_wildcard_is_least_specific() {
        let specific = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::method(), Value::str("POST")),
            Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
        ], RuleAction::RateLimit { rps: 10, name: None });

        let wildcard = RuleExpr::new(vec![
            Expr::eq(Dimension::method(), Value::str("POST")),
        ], RuleAction::RateLimit { rps: 200, name: None });

        let tree = compile_expr(&[specific, wildcard]);

        // Matches both — specific wins (layers=2 > layers=1)
        let req_both = make_full_req(
            "POST", "/", "10.0.0.1",
            vec![("content-type", "application/json")],
            make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&req_both).expect("should match");
        assert!(matches!(action, RuleAction::RateLimit { rps: 10, .. }),
                "specific rule wins when both match");

        // Different TLS — only wildcard matches
        let req_wild = make_full_req(
            "POST", "/", "10.0.0.1",
            vec![("content-type", "text/plain")],
            make_legit_tls(),
        );
        let (action, _) = tree.evaluate_req(&req_wild).expect("wildcard should match");
        assert!(matches!(action, RuleAction::RateLimit { rps: 200, .. }),
                "wildcard catches requests the specific rule misses");
    }

    /// All 4 rules from a real attack run inserted at once. Verify that
    /// the same request matches different rules depending on which
    /// dimensions are present, and the winner is always correct.
    #[test]
    fn specificity_attack_replay_four_rules() {
        let ext_path_ct = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::path(), Value::str("/api/v1/auth/login")),
            Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
        ], RuleAction::RateLimit { rps: 11, name: None });

        let ext_method_ct = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::method(), Value::str("POST")),
            Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
        ], RuleAction::RateLimit { rps: 22, name: None });

        let ext_path_ua = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::path(), Value::str("/api/v1/auth/login")),
            Expr::eq(Dimension::header_first("user-agent"), Value::str("python-requests/2.31.0")),
        ], RuleAction::RateLimit { rps: 33, name: None });

        let ext_ua_ct = RuleExpr::new(vec![
            Expr::eq(Dimension::Simple(SimpleDim::TlsExtTypes), attack_ext_set()),
            Expr::eq(Dimension::header_first("user-agent"), Value::str("python-requests/2.31.0")),
            Expr::eq(Dimension::header_first("content-type"), Value::str("application/json")),
        ], RuleAction::RateLimit { rps: 44, name: None });

        let tree = compile_expr(&[ext_path_ct, ext_method_ct, ext_path_ua, ext_ua_ct]);

        // POST /api/v1/auth/login, python UA, json CT, attack TLS
        // Matches ALL FOUR. All have layers=2, has_http=1, constraints=3.
        // Equal specificity — stable pick (first inserted or specific-branch
        // preference). The important thing is SOME valid rule wins.
        let req_all = make_full_req(
            "POST", "/api/v1/auth/login", "10.0.0.1",
            vec![
                ("user-agent", "python-requests/2.31.0"),
                ("content-type", "application/json"),
            ],
            make_attack_tls(),
        );
        let result = tree.evaluate_req(&req_all);
        assert!(result.is_some(), "at least one rule must match");

        // GET /api/v1/auth/login, python UA, no CT, attack TLS
        // Only ext_path_ua matches (method is GET, no CT)
        let req_get_ua = make_full_req(
            "GET", "/api/v1/auth/login", "10.0.0.1",
            vec![("user-agent", "python-requests/2.31.0")],
            make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&req_get_ua).expect("ext_path_ua should match");
        assert!(matches!(action, RuleAction::RateLimit { rps: 33, .. }));

        // POST /other, python UA, json CT, attack TLS
        // Only ext_method_ct and ext_ua_ct match (wrong path).
        // Both are layers=2, has_http=1, constraints=3. Stable pick.
        let req_other_path = make_full_req(
            "POST", "/other", "10.0.0.1",
            vec![
                ("user-agent", "python-requests/2.31.0"),
                ("content-type", "application/json"),
            ],
            make_attack_tls(),
        );
        let result = tree.evaluate_req(&req_other_path);
        assert!(result.is_some(), "at least ext_method_ct or ext_ua_ct should match");

        // Legit TLS, POST /api/v1/auth/login, json CT
        // No rules match (all require attack TLS ext set)
        let req_legit = make_full_req(
            "POST", "/api/v1/auth/login", "10.0.0.1",
            vec![("content-type", "application/json")],
            make_legit_tls(),
        );
        assert!(tree.evaluate_req(&req_legit).is_none(),
                "legit TLS should not match any attack-fingerprint rule");
    }

    /// EDN identity key is order-independent: same constraints in
    /// different order produce the same identity key.
    #[test]
    fn rule_expr_identity_key_order_independence() {
        let r1 = RuleExpr::new(vec![
            Expr::eq(Dimension::method(), Value::str("POST")),
            Expr::eq(Dimension::path(), Value::str("/api")),
            Expr::eq(Dimension::header_first("host"), Value::str("example.com")),
        ], RuleAction::RateLimit { rps: 50, name: None });

        let r2 = RuleExpr::new(vec![
            Expr::eq(Dimension::header_first("host"), Value::str("example.com")),
            Expr::eq(Dimension::method(), Value::str("POST")),
            Expr::eq(Dimension::path(), Value::str("/api")),
        ], RuleAction::RateLimit { rps: 50, name: None });

        assert_eq!(r1.identity_key(), r2.identity_key(),
                   "same constraints in different order must produce same identity");

        let t1 = compile_expr(&[r1]);
        let t2 = compile_expr(&[r2]);
        assert_eq!(t1.rule_fingerprint, t2.rule_fingerprint,
                   "tree fingerprints must be identical for order-equivalent rules");
    }

    // =====================================================================
    // End-to-end: EDN string → parse → compile → evaluate
    // =====================================================================
    //
    // These tests start from literal EDN rule strings (the wire format),
    // parse them into RuleExpr values, compile a tree, and evaluate
    // against realistic stub requests. This is the full pipeline that
    // proves the language actually works for enforcement.

    fn parse_rules(edns: &[&str]) -> Vec<RuleExpr> {
        edns.iter()
            .map(|s| crate::expr::parse_edn(s).unwrap_or_else(|e| panic!("parse failed: {}\ninput: {}", e, s)))
            .collect()
    }

    /// Six rules from a real attack run, expressed as EDN strings.
    /// Parse, compile, and evaluate against attacker and legit requests.
    #[test]
    fn edn_to_enforcement_realistic_attack() {
        let rules = parse_rules(&[
            // Rule 1: TLS ext + path + content-type
            r#"{:constraints [(= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"}) (= path "/api/v1/auth/login") (= (first (header "content-type")) "application/json")] :actions [(rate-limit 83)]}"#,
            // Rule 2: TLS ext + method + content-type
            r#"{:constraints [(= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"}) (= method "POST") (= (first (header "content-type")) "application/json")] :actions [(rate-limit 83)]}"#,
            // Rule 3: TLS ext + path + user-agent
            r#"{:constraints [(= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"}) (= path "/api/v1/auth/login") (= (first (header "user-agent")) "python-requests/2.31.0")] :actions [(rate-limit 83)]}"#,
            // Rule 4: TLS ext + user-agent + content-type
            r#"{:constraints [(= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"}) (= (first (header "user-agent")) "python-requests/2.31.0") (= (first (header "content-type")) "application/json")] :actions [(rate-limit 83)]}"#,
            // Rule 5: TLS-only (cipher + ext + group sets)
            r#"{:constraints [(= tls-ciphers #{"0x00ff" "0x1301" "0x1302" "0x1303" "0xc02b" "0xc02c" "0xc02f" "0xc030" "0xcca8" "0xcca9"}) (= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"}) (= tls-groups #{"0x0017" "0x0018" "0x001d"})] :actions [(rate-limit 83)]}"#,
            // Rule 6: HTTP-only (path)
            r#"{:constraints [(= path "/api/search")] :actions [(rate-limit 83)]}"#,
        ]);

        let tree = compile_expr(&rules);

        // Attacker: POST /api/v1/auth/login, python UA, json CT, attack TLS
        let attacker = make_full_req(
            "POST", "/api/v1/auth/login", "10.0.0.1",
            vec![
                ("host", "target.example.com"),
                ("user-agent", "python-requests/2.31.0"),
                ("content-type", "application/json"),
            ],
            make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&attacker).expect("attacker should match");
        assert!(matches!(action, RuleAction::RateLimit { rps: 83, .. }));

        // Legit user: GET /dashboard, normal TLS
        let legit = make_full_req(
            "GET", "/dashboard", "192.168.1.10",
            vec![("host", "target.example.com"), ("user-agent", "Mozilla/5.0")],
            make_legit_tls(),
        );
        assert!(tree.evaluate_req(&legit).is_none(), "legit dashboard request should match nothing");

        // Legit user on /api/search: only rule 6 (HTTP-only) matches
        let legit_search = make_full_req(
            "GET", "/api/search", "192.168.1.10",
            vec![("host", "target.example.com"), ("user-agent", "Mozilla/5.0")],
            make_legit_tls(),
        );
        let result = tree.evaluate_req(&legit_search);
        assert!(result.is_some(), "legit search should hit path-only rule");
    }

    /// Specificity from EDN: cross-layer beats single-layer.
    /// TLS+HTTP rule (2 constraints) should beat TLS-only rule (3 constraints).
    #[test]
    fn edn_specificity_cross_layer_wins() {
        let rules = parse_rules(&[
            // TLS-only: 3 constraints, layers=1
            r#"{:constraints [(= tls-ciphers #{"0x00ff" "0x1301" "0x1302" "0x1303" "0xc02b" "0xc02c" "0xc02f" "0xc030" "0xcca8" "0xcca9"}) (= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"}) (= tls-groups #{"0x0017" "0x0018" "0x001d"})] :actions [(rate-limit 10)]}"#,
            // TLS+HTTP: 2 constraints, layers=2
            r#"{:constraints [(= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"}) (= method "POST")] :actions [(rate-limit 99)]}"#,
        ]);

        let tree = compile_expr(&rules);

        let req = make_full_req(
            "POST", "/", "10.0.0.1", vec![], make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&req).expect("should match");
        assert!(
            matches!(action, RuleAction::RateLimit { rps: 99, .. }),
            "cross-layer (layers=2, rps=99) should beat single-layer (layers=1, rps=10)"
        );
    }

    /// Specificity from EDN: has_http tiebreaker.
    /// At equal constraint count and equal layer count, has_http=1 wins.
    #[test]
    fn edn_specificity_has_http_tiebreaker() {
        let rules = parse_rules(&[
            // TLS-only: 2 constraints, layers=1, has_http=0
            r#"{:constraints [(= tls-ciphers #{"0x00ff" "0x1301" "0x1302" "0x1303" "0xc02b" "0xc02c" "0xc02f" "0xc030" "0xcca8" "0xcca9"}) (= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"})] :actions [(rate-limit 50)]}"#,
            // TLS+HTTP: 2 constraints, layers=2, has_http=1
            r#"{:constraints [(= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"}) (= (first (header "user-agent")) "Scrapy/2.11.0")] :actions [(rate-limit 77)]}"#,
        ]);

        let tree = compile_expr(&rules);

        let req = make_full_req(
            "GET", "/", "10.0.0.1",
            vec![("user-agent", "Scrapy/2.11.0")],
            make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&req).expect("should match");
        assert!(
            matches!(action, RuleAction::RateLimit { rps: 77, .. }),
            "TLS+HTTP (rps=77) should beat TLS-only (rps=50) via has_http tiebreaker"
        );
    }

    /// Full ranking ladder from EDN: 4 tiers of specificity, all matching
    /// the same request. Only the top-ranked rule should fire.
    #[test]
    fn edn_specificity_full_ladder() {
        let rules = parse_rules(&[
            // Rank 4: TLS-only, 3 constraints (layers=1, has_http=0, constraints=3)
            r#"{:constraints [(= tls-ciphers #{"0x00ff" "0x1301" "0x1302" "0x1303" "0xc02b" "0xc02c" "0xc02f" "0xc030" "0xcca8" "0xcca9"}) (= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"}) (= tls-groups #{"0x0017" "0x0018" "0x001d"})] :actions [(rate-limit 4)]}"#,
            // Rank 3: HTTP-only, 3 constraints (layers=1, has_http=1, constraints=3)
            r#"{:constraints [(= method "POST") (= (first (header "content-type")) "application/json") (= path "/api/v1/auth/login")] :actions [(rate-limit 3)]}"#,
            // Rank 2: TLS+HTTP, 2 constraints (layers=2, has_http=1, constraints=2)
            r#"{:constraints [(= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"}) (= method "POST")] :actions [(rate-limit 2)]}"#,
            // Rank 1: TLS+HTTP, 4 constraints (layers=2, has_http=1, constraints=4)
            r#"{:constraints [(= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"}) (= method "POST") (= (first (header "content-type")) "application/json") (= path "/api/v1/auth/login")] :actions [(rate-limit 1)]}"#,
        ]);

        let tree = compile_expr(&rules);

        let req = make_full_req(
            "POST", "/api/v1/auth/login", "10.0.0.1",
            vec![("content-type", "application/json")],
            make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&req).expect("should match");
        assert!(
            matches!(action, RuleAction::RateLimit { rps: 1, .. }),
            "rank-1 (layers=2, has_http=1, constraints=4) should win the full ladder"
        );
    }

    /// Fallback: when the most specific rule doesn't match, the next
    /// best one from the same EDN batch should take over.
    #[test]
    fn edn_specificity_fallback() {
        let rules = parse_rules(&[
            // Narrow: TLS+HTTP, 4 constraints
            r#"{:constraints [(= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"}) (= method "POST") (= (first (header "content-type")) "application/json") (= path "/api/v1/auth/login")] :actions [(rate-limit 1)]}"#,
            // Broad: TLS+HTTP, 2 constraints
            r#"{:constraints [(= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"}) (= method "POST")] :actions [(rate-limit 2)]}"#,
        ]);

        let tree = compile_expr(&rules);

        // Wrong path — narrow rule can't match
        let req = make_full_req(
            "POST", "/other", "10.0.0.1",
            vec![("content-type", "application/json")],
            make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&req).expect("broad should still match");
        assert!(
            matches!(action, RuleAction::RateLimit { rps: 2, .. }),
            "broad rule (rps=2) should catch what narrow misses"
        );
    }

    /// Actions diverge: CloseConnection vs Block. The more specific
    /// TLS+HTTP block wins; when HTTP fails, TLS-only close catches.
    #[test]
    fn edn_different_actions_overlap() {
        let rules = parse_rules(&[
            // TLS-only close
            r#"{:constraints [(= tls-ciphers #{"0x00ff" "0x1301" "0x1302" "0x1303" "0xc02b" "0xc02c" "0xc02f" "0xc030" "0xcca8" "0xcca9"}) (= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"})] :actions [(close-connection)]}"#,
            // TLS+HTTP block
            r#"{:constraints [(= tls-ext-types #{"0x0000" "0x0005" "0x000a" "0x000b" "0x000d" "0x0017" "0x0023" "0x002b" "0x002d" "0x0033"}) (= method "POST") (= (first (header "user-agent")) "python-requests/2.31.0")] :actions [(block 403)]}"#,
        ]);

        let tree = compile_expr(&rules);

        // Attacker with matching UA — block wins (layers=2 > layers=1)
        let req_block = make_full_req(
            "POST", "/", "10.0.0.1",
            vec![("user-agent", "python-requests/2.31.0")],
            make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&req_block).expect("should match");
        assert!(matches!(action, RuleAction::Block { .. }),
                "TLS+HTTP block should win over TLS-only close");

        // Different UA — only TLS close matches
        let req_close = make_full_req(
            "POST", "/", "10.0.0.1",
            vec![("user-agent", "Mozilla/5.0")],
            make_attack_tls(),
        );
        let (action, _) = tree.evaluate_req(&req_close).expect("TLS rule should match");
        assert!(matches!(action, RuleAction::CloseConnection { .. }),
                "TLS-only close is the only rule left");
    }

    /// HTTP-only rules from EDN: progressive constraint narrowing.
    #[test]
    fn edn_http_only_progressive() {
        let rules = parse_rules(&[
            r#"{:constraints [(= method "POST")] :actions [(rate-limit 200)]}"#,
            r#"{:constraints [(= method "POST") (= path "/api")] :actions [(rate-limit 100)]}"#,
            r#"{:constraints [(= method "POST") (= path "/api") (= (first (header "content-type")) "application/json")] :actions [(rate-limit 50)]}"#,
        ]);

        let tree = compile_expr(&rules);

        // All 3 match → most specific wins
        let req_all = make_full_req(
            "POST", "/api", "10.0.0.1",
            vec![("content-type", "application/json")],
            make_legit_tls(),
        );
        let (action, _) = tree.evaluate_req(&req_all).expect("should match");
        assert!(matches!(action, RuleAction::RateLimit { rps: 50, .. }));

        // Wrong CT → 2-constraint wins
        let req_two = make_full_req(
            "POST", "/api", "10.0.0.1",
            vec![("content-type", "text/plain")],
            make_legit_tls(),
        );
        let (action, _) = tree.evaluate_req(&req_two).expect("should match");
        assert!(matches!(action, RuleAction::RateLimit { rps: 100, .. }));

        // Wrong path → 1-constraint wins
        let req_one = make_full_req(
            "POST", "/other", "10.0.0.1",
            vec![("content-type", "application/json")],
            make_legit_tls(),
        );
        let (action, _) = tree.evaluate_req(&req_one).expect("should match");
        assert!(matches!(action, RuleAction::RateLimit { rps: 200, .. }));

        // GET → nothing matches
        assert!(tree.evaluate_req(&make_full_req(
            "GET", "/api", "10.0.0.1",
            vec![("content-type", "application/json")],
            make_legit_tls(),
        )).is_none());
    }

    /// Membership (exists) operator in EDN, combined with specificity.
    #[test]
    fn edn_exists_with_specificity() {
        let rules = parse_rules(&[
            // Broad: method only
            r#"{:constraints [(= method "GET")] :actions [(rate-limit 200)]}"#,
            // Narrow: method + exists in path-parts
            r#"{:constraints [(= method "GET") (exists path-parts "admin")] :actions [(block 403)]}"#,
        ]);

        let tree = compile_expr(&rules);

        // /api/admin/panel — both match, narrow wins
        let req_admin = make_full_req(
            "GET", "/api/admin/panel", "10.0.0.1",
            vec![], make_legit_tls(),
        );
        let (action, _) = tree.evaluate_req(&req_admin).expect("should match");
        assert!(matches!(action, RuleAction::Block { .. }));

        // /api/public — only broad matches
        let req_pub = make_full_req(
            "GET", "/api/public", "10.0.0.1",
            vec![], make_legit_tls(),
        );
        let (action, _) = tree.evaluate_req(&req_pub).expect("should match");
        assert!(matches!(action, RuleAction::RateLimit { rps: 200, .. }));
    }

    /// Parse EDN → compile → evaluate at TLS layer (no HTTP data yet).
    #[test]
    fn edn_tls_layer_evaluation() {
        let rules = parse_rules(&[
            r#"{:constraints [(= tls-ciphers #{"0x00ff" "0x1301" "0x1302" "0x1303" "0xc02b" "0xc02c" "0xc02f" "0xc030" "0xcca8" "0xcca9"}) (= tls-groups #{"0x0017" "0x0018" "0x001d"})] :actions [(close-connection)]}"#,
            r#"{:constraints [(= method "POST")] :actions [(block 403)]}"#,
        ]);

        let tree = compile_expr(&rules);

        let attack_sample = TlsSample {
            conn_id: 1,
            src_ip: "10.0.0.1".parse().unwrap(),
            tls_ctx: Arc::new(make_attack_tls()),
            tls_vec: make_encoder().encode_walkable(&TlsContext::default()),
            timestamp_us: 0,
        };
        let (action, _) = tree.evaluate_tls(&attack_sample).expect("TLS rule should match");
        assert!(matches!(action, RuleAction::CloseConnection { .. }));

        let legit_sample = TlsSample {
            conn_id: 2,
            src_ip: "192.168.1.10".parse().unwrap(),
            tls_ctx: Arc::new(make_legit_tls()),
            tls_vec: make_encoder().encode_walkable(&TlsContext::default()),
            timestamp_us: 0,
        };
        assert!(tree.evaluate_tls(&legit_sample).is_none());
    }

    // =====================================================================
    // Stress tests: prove evaluation is O(depth), not O(rules)
    // Run: cargo test -p http-proxy stress_ -- --ignored --nocapture
    // =====================================================================

    fn idx_to_ip(i: usize) -> String {
        format!("10.{}.{}.{}", (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF)
    }

    /// Simple xorshift PRNG — deterministic, no deps.
    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    #[test]
    #[ignore]
    fn stress_randomized_lookups_1m() {
        use std::time::Instant;

        let n: usize = 1_000_000;
        let methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];

        eprintln!("\n=== Building 1M rules (src-ip + method, unique rps per rule) ===");

        let rules: Vec<RuleExpr> = (0..n).map(|i| {
            let ip = idx_to_ip(i);
            let method = methods[i % methods.len()];
            RuleExpr::new(
                vec![
                    Expr::eq(Dimension::src_ip(), Value::str(&ip)),
                    Expr::eq(Dimension::method(), Value::str(method)),
                ],
                RuleAction::RateLimit { rps: (i % 9999 + 1) as u32, name: None },
            )
        }).collect();

        let t0 = Instant::now();
        let tree = compile_expr(&rules);
        let compile_ms = t0.elapsed().as_millis();
        eprintln!("compile: {}ms, nodes: {}, dims: {}",
                  compile_ms, tree.nodes.len(), tree.dim_order.len());

        // -- Phase 1: correctness sweep -- verify 1000 random rules return correct rps
        eprintln!("\n--- Phase 1: correctness (1000 random spot checks) ---");
        let mut rng = 0xDEAD_BEEF_CAFE_u64;
        let mut correct = 0usize;
        for _ in 0..1000 {
            let i = (xorshift(&mut rng) as usize) % n;
            let ip = idx_to_ip(i);
            let method = methods[i % methods.len()];
            let expected_rps = (i % 9999 + 1) as u32;
            let req = make_req(method, "/anything", &ip);
            match tree.evaluate_req(&req) {
                Some((RuleAction::RateLimit { rps, .. }, _)) => {
                    assert_eq!(*rps, expected_rps,
                        "rule {} (ip={}, method={}) expected rps={}, got rps={}",
                        i, ip, method, expected_rps, rps);
                    correct += 1;
                }
                other => panic!("rule {} should match RateLimit, got {:?}", i, other),
            }
        }
        eprintln!("  {}/1000 correct", correct);

        // -- Phase 2: random-access latency (cold cache paths) --
        eprintln!("\n--- Phase 2: random-access evaluation (5000 unique requests) ---");
        let eval_count = 5000;
        let mut hit_times: Vec<u128> = Vec::with_capacity(eval_count);
        let mut miss_times: Vec<u128> = Vec::with_capacity(eval_count);
        rng = 0xCAFE_BABE_1234_u64;

        // Pre-build all requests to exclude construction cost from timing
        let hit_reqs: Vec<RequestSample> = (0..eval_count).map(|_| {
            let i = (xorshift(&mut rng) as usize) % n;
            let ip = idx_to_ip(i);
            let method = methods[i % methods.len()];
            make_req(method, "/anything", &ip)
        }).collect();

        let miss_reqs: Vec<RequestSample> = (0..eval_count).map(|j| {
            let ip = format!("192.168.{}.{}", (j >> 8) & 0xFF, j & 0xFF);
            make_req("GET", "/miss", &ip)
        }).collect();

        for req in &hit_reqs {
            let t = Instant::now();
            let result = tree.evaluate_req(req);
            hit_times.push(t.elapsed().as_nanos());
            assert!(result.is_some(), "pre-verified hit request must match");
        }

        for req in &miss_reqs {
            let t = Instant::now();
            let result = tree.evaluate_req(req);
            miss_times.push(t.elapsed().as_nanos());
            assert!(result.is_none(), "miss request must not match");
        }

        hit_times.sort();
        miss_times.sort();

        let hit_p50 = hit_times[eval_count / 2];
        let hit_p99 = hit_times[eval_count * 99 / 100];
        let hit_max = hit_times[eval_count - 1];
        let miss_p50 = miss_times[eval_count / 2];
        let miss_p99 = miss_times[eval_count * 99 / 100];
        let miss_max = miss_times[eval_count - 1];

        eprintln!("  HIT  p50={}ns  p99={}ns  max={}ns", hit_p50, hit_p99, hit_max);
        eprintln!("  MISS p50={}ns  p99={}ns  max={}ns", miss_p50, miss_p99, miss_max);

        // -- Phase 3: scaling comparison (same random workload at different rule counts) --
        eprintln!("\n--- Phase 3: scaling ladder (random access, no cache warming) ---");
        let scales: &[usize] = &[10, 100, 1_000, 10_000, 100_000, 1_000_000];
        eprintln!("{:>10} {:>10} {:>12} {:>10} {:>10} {:>10}",
                  "rules", "nodes", "compile_ms", "p50_ns", "p99_ns", "max_ns");
        eprintln!("{}", "-".repeat(68));

        let mut p50_by_scale: Vec<(usize, u128)> = Vec::new();

        for &s in scales {
            let sub_rules: Vec<RuleExpr> = (0..s).map(|i| {
                let ip = idx_to_ip(i);
                let method = methods[i % methods.len()];
                RuleExpr::new(
                    vec![
                        Expr::eq(Dimension::src_ip(), Value::str(&ip)),
                        Expr::eq(Dimension::method(), Value::str(method)),
                    ],
                    RuleAction::RateLimit { rps: (i % 9999 + 1) as u32, name: None },
                )
            }).collect();

            let tc = Instant::now();
            let sub_tree = compile_expr(&sub_rules);
            let cms = tc.elapsed().as_millis();

            // Random-access eval — each request hits a different rule
            rng = 0xAAAA_BBBB_CCCC_u64;
            let probes = 2000;
            let probe_reqs: Vec<RequestSample> = (0..probes).map(|_| {
                let i = (xorshift(&mut rng) as usize) % s;
                let ip = idx_to_ip(i);
                let method = methods[i % methods.len()];
                make_req(method, "/probe", &ip)
            }).collect();

            let mut times: Vec<u128> = Vec::with_capacity(probes);
            for req in &probe_reqs {
                let t = Instant::now();
                let _ = sub_tree.evaluate_req(req);
                times.push(t.elapsed().as_nanos());
            }
            times.sort();

            let p50 = times[probes / 2];
            let p99 = times[probes * 99 / 100];
            let max = times[probes - 1];
            eprintln!("{:>10} {:>10} {:>12} {:>10} {:>10} {:>10}",
                      s, sub_tree.nodes.len(), cms, p50, p99, max);
            p50_by_scale.push((s, p50));
        }

        let (_, t_10) = p50_by_scale[0];
        let (_, t_1m) = p50_by_scale[p50_by_scale.len() - 1];
        let ratio = t_1m as f64 / t_10.max(1) as f64;
        eprintln!("\np50 ratio (1M/10): {:.1}x", ratio);

        // If linear: 1M/10 = 100,000x. We allow 20x for HashMap overhead at scale.
        assert!(ratio < 20.0,
            "p50 at 1M ({} ns) vs 10 ({} ns) = {:.1}x — should be <20x for O(depth)",
            t_1m, t_10, ratio);
    }

    #[test]
    #[ignore]
    fn stress_multi_dim_random_access() {
        use std::time::Instant;

        let n: usize = 100_000;
        let methods = ["GET", "POST", "PUT", "DELETE", "PATCH"];
        let prefixes = ["/api/v1", "/api/v2", "/api/v3", "/admin", "/health",
                        "/auth", "/users", "/products", "/orders", "/search"];

        eprintln!("\n=== 100K rules (3 dimensions: src-ip + method + path-prefix) ===");

        let rules: Vec<RuleExpr> = (0..n).map(|i| {
            let ip = idx_to_ip(i);
            let method = methods[i % methods.len()];
            let prefix = prefixes[i % prefixes.len()];
            RuleExpr::new(
                vec![
                    Expr::eq(Dimension::src_ip(), Value::str(&ip)),
                    Expr::eq(Dimension::method(), Value::str(method)),
                    Expr::prefix(Dimension::path(), prefix),
                ],
                RuleAction::RateLimit { rps: (i % 500 + 10) as u32, name: None },
            )
        }).collect();

        let t0 = Instant::now();
        let tree = compile_expr(&rules);
        let compile_ms = t0.elapsed().as_millis();
        eprintln!("compile: {}ms, nodes: {}, dims: {}", compile_ms, tree.nodes.len(), tree.dim_order.len());

        // Correctness: verify 500 random hits
        let mut rng = 0x1234_5678_ABCD_u64;
        for _ in 0..500 {
            let i = (xorshift(&mut rng) as usize) % n;
            let ip = idx_to_ip(i);
            let method = methods[i % methods.len()];
            let prefix = prefixes[i % prefixes.len()];
            let expected_rps = (i % 500 + 10) as u32;
            let req = make_req(method, &format!("{}/deep/path", prefix), &ip);
            match tree.evaluate_req(&req) {
                Some((RuleAction::RateLimit { rps, .. }, _)) => {
                    assert_eq!(*rps, expected_rps, "rule {} wrong rps", i);
                }
                other => panic!("rule {} should match, got {:?}", i, other),
            }
        }
        eprintln!("correctness: 500/500 spot checks passed");

        // Random-access latency: 3000 unique requests hitting different tree paths
        rng = 0xFEED_FACE_DEAD_u64;
        let probes = 3000;
        let reqs: Vec<RequestSample> = (0..probes).map(|_| {
            let i = (xorshift(&mut rng) as usize) % n;
            let ip = idx_to_ip(i);
            let method = methods[i % methods.len()];
            let prefix = prefixes[i % prefixes.len()];
            make_req(method, &format!("{}/page", prefix), &ip)
        }).collect();

        let mut times: Vec<u128> = Vec::with_capacity(probes);
        for req in &reqs {
            let t = Instant::now();
            let _ = tree.evaluate_req(req);
            times.push(t.elapsed().as_nanos());
        }
        times.sort();

        let p50 = times[probes / 2];
        let p99 = times[probes * 99 / 100];
        let max = times[probes - 1];
        let avg: u128 = times.iter().sum::<u128>() / probes as u128;
        eprintln!("\nrandom-access eval (100K rules, 3 dims, {} probes):", probes);
        eprintln!("  avg={}ns  p50={}ns  p99={}ns  max={}ns", avg, p50, p99, max);

        // Throughput estimate
        let throughput = 1_000_000_000u128 / avg.max(1);
        eprintln!("  est. throughput: {} evals/sec per core", throughput);
    }

    /// Roundtrip: EDN → parse → to_edn → parse again. Both parses
    /// produce identical trees with identical fingerprints.
    #[test]
    fn edn_roundtrip_tree_fingerprint_stable() {
        let edns = &[
            r#"{:constraints [(= tls-ext-types #{"0x0000" "0x000a" "0x000d"}) (= method "POST") (= (first (header "content-type")) "application/json")] :actions [(rate-limit 83)]}"#,
            r#"{:constraints [(= path "/api/search")] :actions [(rate-limit 83)]}"#,
        ];

        let rules1 = parse_rules(edns);
        let tree1 = compile_expr(&rules1);

        // Re-emit and re-parse
        let re_edns: Vec<String> = rules1.iter().map(|r| r.to_edn()).collect();
        let re_strs: Vec<&str> = re_edns.iter().map(|s| s.as_str()).collect();
        let rules2 = parse_rules(&re_strs);
        let tree2 = compile_expr(&rules2);

        assert_eq!(tree1.rule_fingerprint, tree2.rule_fingerprint,
                   "roundtripped tree must have identical fingerprint");
        assert_eq!(tree1.nodes.len(), tree2.nodes.len());
    }
}
