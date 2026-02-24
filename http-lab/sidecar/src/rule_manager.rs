//! Rule lifecycle management: upsert, expire, redundancy check, tree recompile.
//!
//! Adapted from veth-lab/sidecar/src/rule_manager.rs.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use tracing::info;

use http_proxy::types::{CompiledTree, RuleSpec};
use http_proxy::tree::compile;

/// An active rule with expiry tracking.
pub struct ActiveRule {
    pub last_seen: Instant,
    pub spec: RuleSpec,
    pub preloaded: bool,
}

/// Central rule manager — upsert, expire, compile, ArcSwap write.
pub struct RuleManager {
    rules: HashMap<String, ActiveRule>,
    /// Time-to-live for auto-generated rules.
    ttl: Duration,
}

impl RuleManager {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            rules: HashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Upsert rules into the active set. Returns keys of newly added rules.
    pub fn upsert(&mut self, specs: &[RuleSpec]) -> Vec<String> {
        let mut newly_added = Vec::new();
        for spec in specs {
            let key = spec.identity_key();
            if let Some(existing) = self.rules.get_mut(&key) {
                existing.last_seen = Instant::now();
            } else {
                let action_str = spec.action.describe();
                info!("Rule added [{}]: {}", action_str, spec.display_label());
                self.rules.insert(key.clone(), ActiveRule {
                    last_seen: Instant::now(),
                    spec: spec.clone(),
                    preloaded: false,
                });
                newly_added.push(key);
            }
        }
        newly_added
    }

    /// Remove rules that haven't been seen within TTL.
    pub fn expire(&mut self) -> usize {
        let ttl = self.ttl;
        let before = self.rules.len();
        self.rules.retain(|_, r| r.preloaded || r.last_seen.elapsed() < ttl);
        let removed = before - self.rules.len();
        if removed > 0 {
            info!("Expired {} rules ({} remaining)", removed, self.rules.len());
        }
        removed
    }

    /// Check if a candidate rule is redundant given existing rules.
    pub fn is_redundant(&self, candidate: &RuleSpec) -> Option<&'static str> {
        if candidate.constraints.is_empty() { return Some("empty"); }
        let candidate_action = std::mem::discriminant(&candidate.action);

        for active in self.rules.values() {
            let existing = &active.spec;
            if existing.constraints.is_empty() { continue; }
            if std::mem::discriminant(&existing.action) != candidate_action { continue; }

            let existing_subset = existing.constraints.iter()
                .all(|ec| candidate.constraints.contains(ec));
            let candidate_subset = candidate.constraints.iter()
                .all(|cc| existing.constraints.contains(cc));

            if existing_subset && candidate.constraints.len() > existing.constraints.len() {
                return Some("subsumed");
            }
            if candidate_subset && candidate.constraints.len() < existing.constraints.len() {
                return Some("over-broad");
            }
        }
        None
    }

    /// Compile the current rule set and write to the shared ArcSwap.
    pub fn recompile_and_deploy(&self, tree: &ArcSwap<CompiledTree>) {
        let specs: Vec<RuleSpec> = self.rules.values().map(|r| r.spec.clone()).collect();
        let compiled = compile(&specs);
        info!(
            rules = specs.len(),
            nodes = compiled.nodes.len(),
            "deploying new rule tree"
        );
        tree.store(Arc::new(compiled));
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn all_specs(&self) -> Vec<RuleSpec> {
        self.rules.values().map(|r| r.spec.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_proxy::types::{FieldDim, Predicate, RuleAction};

    fn make_rule(dim: FieldDim, val: u32, action: RuleAction) -> RuleSpec {
        RuleSpec::new(vec![Predicate::eq(dim, val)], action)
    }

    #[test]
    fn upsert_adds_new_rules() {
        let mut mgr = RuleManager::new(300);
        let rule = make_rule(FieldDim::SrcIp, 1, RuleAction::block());
        let added = mgr.upsert(&[rule]);
        assert_eq!(added.len(), 1);
        assert_eq!(mgr.rule_count(), 1);
    }

    #[test]
    fn upsert_deduplicates() {
        let mut mgr = RuleManager::new(300);
        let rule = make_rule(FieldDim::SrcIp, 1, RuleAction::block());
        let added1 = mgr.upsert(&[rule.clone()]);
        let added2 = mgr.upsert(&[rule]);
        assert_eq!(added1.len(), 1);
        assert_eq!(added2.len(), 0); // same rule, not newly added
        assert_eq!(mgr.rule_count(), 1);
    }

    #[test]
    fn expire_removes_old_rules() {
        let mut mgr = RuleManager::new(0); // TTL = 0 seconds
        let rule = make_rule(FieldDim::SrcIp, 1, RuleAction::block());
        mgr.upsert(&[rule]);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let removed = mgr.expire();
        assert_eq!(removed, 1);
        assert_eq!(mgr.rule_count(), 0);
    }

    #[test]
    fn expire_preserves_preloaded() {
        let mut mgr = RuleManager::new(0);
        let rule = make_rule(FieldDim::SrcIp, 1, RuleAction::block());
        mgr.upsert(&[rule]);
        // Manually mark as preloaded
        for active in mgr.rules.values_mut() {
            active.preloaded = true;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
        let removed = mgr.expire();
        assert_eq!(removed, 0);
        assert_eq!(mgr.rule_count(), 1);
    }

    #[test]
    fn is_redundant_detects_subsumed() {
        let mut mgr = RuleManager::new(300);
        let broad = make_rule(FieldDim::SrcIp, 1, RuleAction::block());
        mgr.upsert(&[broad]);

        // A more specific rule (IP + Method) is subsumed by the existing IP-only rule
        let specific = RuleSpec::new(
            vec![
                Predicate::eq(FieldDim::SrcIp, 1),
                Predicate::eq(FieldDim::Method, 42),
            ],
            RuleAction::block(),
        );
        assert_eq!(mgr.is_redundant(&specific), Some("subsumed"));
    }

    #[test]
    fn is_redundant_allows_unrelated() {
        let mut mgr = RuleManager::new(300);
        let rule1 = make_rule(FieldDim::SrcIp, 1, RuleAction::block());
        mgr.upsert(&[rule1]);

        let rule2 = make_rule(FieldDim::SrcIp, 2, RuleAction::block());
        assert!(mgr.is_redundant(&rule2).is_none());
    }

    #[test]
    fn is_redundant_rejects_empty() {
        let mgr = RuleManager::new(300);
        let empty = RuleSpec::new(vec![], RuleAction::block());
        assert_eq!(mgr.is_redundant(&empty), Some("empty"));
    }

    #[test]
    fn recompile_and_deploy_updates_tree() {
        let mgr_rules = vec![
            make_rule(FieldDim::SrcIp, 1, RuleAction::block()),
            make_rule(FieldDim::SrcIp, 2, RuleAction::CloseConnection),
        ];
        let mut mgr = RuleManager::new(300);
        mgr.upsert(&mgr_rules);

        let tree = ArcSwap::new(Arc::new(CompiledTree::empty()));
        mgr.recompile_and_deploy(&tree);

        let loaded = tree.load();
        assert!(loaded.nodes.len() > 1);
    }
}
