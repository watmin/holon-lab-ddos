use std::collections::HashMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use tokio::sync::RwLock;
use tracing::info;
use veth_filter::{FieldDim, RuleAction, RuleSpec, VethFilter};

use crate::detection::rule_identity_key;
use crate::metrics_server;

/// A rule currently active in the decision tree.
pub(crate) struct ActiveRule {
    pub(crate) last_seen: Instant,
    pub(crate) spec: RuleSpec,
    /// Pre-loaded rules never expire
    pub(crate) preloaded: bool,
}

/// Validate byte match policy: every l4-match rule MUST have a destination address
/// constraint (tenant scoping), and no scope may exceed the configured density limit.
pub(crate) fn validate_byte_match_density(rules: &[RuleSpec], max_per_scope: usize) -> Result<()> {
    use veth_filter::{FieldRef, Predicate};

    let mut scope_counts: HashMap<String, usize> = HashMap::new();
    let mut total_byte_matches = 0usize;
    let mut unscoped_rules: Vec<String> = Vec::new();

    for rule in rules {
        let byte_match_count = rule.constraints.iter().filter(|p| {
            matches!(p.field_ref(), FieldRef::L4Byte { .. })
        }).count();

        if byte_match_count == 0 {
            continue;
        }

        total_byte_matches += byte_match_count;

        let scope = rule.constraints.iter().find_map(|p| {
            match p {
                Predicate::Eq(FieldRef::Dim(FieldDim::DstIp), val) => {
                    Some(format!("{}.{}.{}.{}",
                        (val >> 24) & 0xFF, (val >> 16) & 0xFF,
                        (val >> 8) & 0xFF, val & 0xFF))
                }
                _ => None,
            }
        });

        match scope {
            Some(addr) => {
                *scope_counts.entry(addr).or_insert(0) += byte_match_count;
            }
            None => {
                unscoped_rules.push(rule.display_label());
            }
        }
    }

    if !unscoped_rules.is_empty() {
        let examples: Vec<&str> = unscoped_rules.iter().take(3).map(|s| s.as_str()).collect();
        anyhow::bail!(
            "{} byte match rule(s) missing required (= dst-addr ...) constraint. \
             Every l4-match rule must be scoped to a destination address for tenant isolation.\n  \
             Examples: {}",
            unscoped_rules.len(),
            examples.join("\n  ")
        );
    }

    if total_byte_matches > 0 {
        let num_scopes = scope_counts.len();
        let max_scope = scope_counts.iter().max_by_key(|(_, v)| *v);
        info!("Byte match density: {} total across {} scopes (limit: {}/scope)",
              total_byte_matches, num_scopes, max_per_scope);

        for (scope, count) in &scope_counts {
            if *count > max_per_scope {
                anyhow::bail!(
                    "Scope '{}' has {} byte match rules, exceeding limit of {}. \
                     Split into separate scopes or increase --max-byte-matches-per-scope.",
                    scope, count, max_per_scope
                );
            }
        }

        if let Some((scope, count)) = max_scope {
            info!("  Densest scope: {} ({} byte matches)", scope, count);
        }
    }

    Ok(())
}

/// Check if a candidate rule is redundant given the current active rules.
///
/// Returns Some(reason) if the candidate should be suppressed:
///   - "subsumed": an existing rule's constraints are a subset of the candidate's
///   - "over-broad": the candidate's constraints are a strict subset of an existing rule's
pub(crate) fn rule_is_redundant(candidate: &RuleSpec, existing_rules: &HashMap<String, ActiveRule>) -> Option<&'static str> {
    if candidate.constraints.is_empty() {
        return Some("empty");
    }
    let candidate_action_type = candidate.actions.first().map(|a| std::mem::discriminant(a));

    for (_, active) in existing_rules.iter() {
        let existing = &active.spec;
        if existing.constraints.is_empty() { continue; }

        let existing_action_type = existing.actions.first().map(|a| std::mem::discriminant(a));
        if candidate_action_type != existing_action_type { continue; }

        let existing_subset_of_candidate = existing.constraints.iter()
            .all(|ec| candidate.constraints.contains(ec));
        let candidate_subset_of_existing = candidate.constraints.iter()
            .all(|cc| existing.constraints.contains(cc));

        if existing_subset_of_candidate && candidate.constraints.len() > existing.constraints.len() {
            return Some("subsumed");
        }
        if candidate_subset_of_existing && candidate.constraints.len() < existing.constraints.len() {
            return Some("over-broad");
        }
    }
    None
}

pub(crate) fn attach_manifest_labels_to_dag(
    dag_nodes: &mut [metrics_server::DagNode],
    manifest: &[veth_filter::RuleManifestEntry],
) {
    let manifest_by_rule_id: HashMap<u32, veth_filter::RuleManifestEntry> = manifest
        .iter()
        .cloned()
        .map(|entry| (entry.rule_id, entry))
        .collect();

    for node in dag_nodes.iter_mut() {
        if let Some(rule_id) = node.action_rule_id {
            if let Some(entry) = manifest_by_rule_id.get(&rule_id) {
                node.label = Some(entry.label.clone());
                node.rule_constraints = Some(entry.constraints.clone());
                node.rule_expression = Some(entry.expression.clone());
            }
        }
    }
}

/// Upsert rules into the active rule set.
///
/// For each spec: if the rule already exists, refreshes its timestamp and updates the spec
/// if changed; otherwise inserts a new rule. Returns the rule_keys of newly-added rules.
pub(crate) async fn upsert_rules(
    specs: &[RuleSpec],
    rules: &mut HashMap<String, ActiveRule>,
    bucket_key_to_spec: &RwLock<HashMap<u32, RuleSpec>>,
    tree_dirty: &std::sync::atomic::AtomicBool,
    metrics_state: &Option<metrics_server::MetricsState>,
    log_prefix: &str,
) -> Vec<String> {
    let mut newly_added = Vec::new();

    for spec in specs {
        let rule_key = rule_identity_key(spec);

        if let Some(existing) = rules.get_mut(&rule_key) {
            let spec_changed = existing.spec.to_edn() != spec.to_edn();
            existing.last_seen = Instant::now();
            if spec_changed {
                existing.spec = spec.clone();
                if let Some(bk) = spec.bucket_key() {
                    let mut bmap = bucket_key_to_spec.write().await;
                    bmap.insert(bk, spec.clone());
                }
                tree_dirty.store(true, std::sync::atomic::Ordering::SeqCst);
            }

            if let Some(ref state) = metrics_state {
                state.broadcast(metrics_server::MetricsEvent::RuleEvent {
                    ts: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
                    action: "refreshed".to_string(),
                    key: rule_key.clone(),
                    spec_summary: spec.to_edn(),
                    is_preloaded: false,
                    ttl_secs: 300,
                });
            }
        } else {
            let action_str = match &spec.actions[0] {
                RuleAction::Drop { .. } => "DROP",
                RuleAction::RateLimit { .. } => "RATE-LIMIT",
                RuleAction::Pass { .. } => "PASS",
                RuleAction::Count { .. } => "COUNT",
            };
            info!("    {} [{}]: {}", log_prefix, action_str, spec.describe());

            rules.insert(rule_key.clone(), ActiveRule {
                last_seen: Instant::now(),
                spec: spec.clone(),
                preloaded: false,
            });

            if let Some(ref state) = metrics_state {
                state.broadcast(metrics_server::MetricsEvent::RuleEvent {
                    ts: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
                    action: "added".to_string(),
                    key: rule_key.clone(),
                    spec_summary: spec.to_edn(),
                    is_preloaded: false,
                    ttl_secs: 300,
                });
            }

            if let Some(bk) = spec.bucket_key() {
                let mut bmap = bucket_key_to_spec.write().await;
                bmap.entry(bk).or_insert_with(|| spec.clone());
            }

            tree_dirty.store(true, std::sync::atomic::Ordering::SeqCst);
            newly_added.push(rule_key);
        }
    }

    newly_added
}

/// Recompile the decision tree and broadcast the updated DAG snapshot.
pub(crate) async fn recompile_tree_and_broadcast(
    filter: &VethFilter,
    rules: &HashMap<String, ActiveRule>,
    tree_counter_labels: &RwLock<HashMap<u32, (String, String)>>,
    tree_dirty: &std::sync::atomic::AtomicBool,
    metrics_state: &Option<metrics_server::MetricsState>,
    log_context: &str,
) -> Result<()> {
    let all_specs: Vec<RuleSpec> = rules.values()
        .map(|r| r.spec.clone())
        .collect();

    let (nodes, manifest, retired) = filter.compile_and_flip_tree(&all_specs).await?;
    info!("    Tree recompiled ({}): {} rules -> {} nodes", log_context, all_specs.len(), nodes);

    if let Some(ref state) = metrics_state {
        state.accumulate_retired_counts(&retired).await;
    }

    let mut tcl = tree_counter_labels.write().await;
    tcl.clear();
    for entry in &manifest {
        tcl.insert(entry.rule_id, (entry.action_kind().to_string(), entry.label.clone()));
    }
    drop(tcl);
    tree_dirty.store(false, std::sync::atomic::Ordering::SeqCst);

    if let Some(ref state) = metrics_state {
        let mut dag_nodes = filter.serialize_dag().await;
        attach_manifest_labels_to_dag(&mut dag_nodes, &manifest);
        state.broadcast(metrics_server::MetricsEvent::DagSnapshot {
            ts: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64(),
            node_count: dag_nodes.len(),
            rule_count: all_specs.len(),
            nodes: dag_nodes,
        });
    }

    Ok(())
}
