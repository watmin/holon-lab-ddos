//! HTTP WAF Proxy — library interface.
//!
//! Exports all shared types, the TLS parser, the rule tree compiler, the
//! request enforcer, and the HTTP server. The sidecar crate depends on this
//! library for types and the tree compiler. The runner crate provides the
//! main() entry point and links both proxy and sidecar.

pub mod enforcer;
pub mod http;
pub mod tls;
pub mod tree;
pub mod types;

pub use types::*;
