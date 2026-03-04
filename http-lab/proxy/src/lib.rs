//! HTTP WAF Proxy — library interface.
//!
//! Exports all shared types, the TLS parser, the rule tree compiler, the
//! request enforcer, and the HTTP server. The sidecar crate depends on this
//! library for types and the tree compiler. The runner crate provides the
//! main() entry point and links both proxy and sidecar.

pub mod denial_token;
pub mod enforcer;
pub mod expr;
pub mod expr_tree;
pub mod http;
pub mod manifold;
pub mod tls;
pub mod tls_names;
pub mod tree;
pub mod types;

pub use types::*;

/// Number of independent vector stripes for FQDN leaf-hashed encoding.
/// Each leaf binding's full dotted path is hashed to pick one of N stripes.
pub const N_STRIPES: usize = 32;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub static ENFORCED_PASS: AtomicU64 = AtomicU64::new(0);
pub static ENFORCED_BLOCKS: AtomicU64 = AtomicU64::new(0);
pub static ENFORCED_RATE_LIMITS: AtomicU64 = AtomicU64::new(0);
pub static ENFORCED_CLOSE_CONN: AtomicU64 = AtomicU64::new(0);

pub static MANIFOLD_ALLOW: AtomicU64 = AtomicU64::new(0);
pub static MANIFOLD_WARMUP: AtomicU64 = AtomicU64::new(0);
pub static MANIFOLD_RATE_LIMIT: AtomicU64 = AtomicU64::new(0);
pub static MANIFOLD_DENY: AtomicU64 = AtomicU64::new(0);

static RULE_COUNTERS: Mutex<Option<HashMap<u32, u64>>> = Mutex::new(None);

/// Increment the hit counter for a matched rule.
pub fn increment_rule_counter(rule_id: u32) {
    let mut guard = RULE_COUNTERS.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    *map.entry(rule_id).or_insert(0) += 1;
}

/// Snapshot of per-rule hit counters.
pub fn rule_counter_snapshot() -> HashMap<u32, u64> {
    RULE_COUNTERS.lock().unwrap().clone().unwrap_or_default()
}

/// Snapshot of enforcement counters.
pub fn enforcement_counts() -> (u64, u64, u64, u64) {
    (
        ENFORCED_PASS.load(Ordering::Relaxed),
        ENFORCED_BLOCKS.load(Ordering::Relaxed),
        ENFORCED_RATE_LIMITS.load(Ordering::Relaxed),
        ENFORCED_CLOSE_CONN.load(Ordering::Relaxed),
    )
}

/// Snapshot of manifold enforcement counters.
pub fn manifold_counts() -> (u64, u64, u64, u64) {
    (
        MANIFOLD_ALLOW.load(Ordering::Relaxed),
        MANIFOLD_WARMUP.load(Ordering::Relaxed),
        MANIFOLD_RATE_LIMIT.load(Ordering::Relaxed),
        MANIFOLD_DENY.load(Ordering::Relaxed),
    )
}
