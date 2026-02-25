//! HTTP WAF Proxy — library interface.
//!
//! Exports all shared types, the TLS parser, the rule tree compiler, the
//! request enforcer, and the HTTP server. The sidecar crate depends on this
//! library for types and the tree compiler. The runner crate provides the
//! main() entry point and links both proxy and sidecar.

pub mod enforcer;
pub mod http;
pub mod tls;
pub mod tls_names;
pub mod tree;
pub mod types;

pub use types::*;

use std::sync::atomic::{AtomicU64, Ordering};

pub static ENFORCED_PASS: AtomicU64 = AtomicU64::new(0);
pub static ENFORCED_BLOCKS: AtomicU64 = AtomicU64::new(0);
pub static ENFORCED_RATE_LIMITS: AtomicU64 = AtomicU64::new(0);
pub static ENFORCED_CLOSE_CONN: AtomicU64 = AtomicU64::new(0);

/// Snapshot of enforcement counters.
pub fn enforcement_counts() -> (u64, u64, u64, u64) {
    (
        ENFORCED_PASS.load(Ordering::Relaxed),
        ENFORCED_BLOCKS.load(Ordering::Relaxed),
        ENFORCED_RATE_LIMITS.load(Ordering::Relaxed),
        ENFORCED_CLOSE_CONN.load(Ordering::Relaxed),
    )
}
