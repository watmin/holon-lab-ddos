//! Synchronous rule enforcer.
//!
//! Called on every request in the hot path. Loads the current CompiledTree
//! from the ArcSwap (wait-free) and evaluates rules against the request.
//! Returns a Verdict that the http handler acts on immediately.

use crate::types::{CompiledTree, RequestSample, RuleAction, TlsSample};

/// What the enforcer decided to do with a request.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Forward the request to the upstream backend.
    Pass,
    /// Block with the given HTTP status code.
    Block(u16),
    /// Rate limit — respond with 429.
    RateLimit(u32),
    /// Close the TCP connection entirely.
    CloseConnection,
    /// Count only — do not block, but record the match.
    Count,
}

/// Evaluate a RequestSample against the compiled tree.
/// Called synchronously on every request (ArcSwap load is wait-free).
pub fn evaluate(req: &RequestSample, tree: &CompiledTree) -> Verdict {
    match tree.evaluate_req(req) {
        None => Verdict::Pass,
        Some(action) => action_to_verdict(action),
    }
}

/// Evaluate a TlsSample against the compiled tree.
/// Called once per connection at TLS accept time.
pub fn evaluate_tls(sample: &TlsSample, tree: &CompiledTree) -> Verdict {
    match tree.evaluate_tls(sample) {
        None => Verdict::Pass,
        Some(action) => action_to_verdict(action),
    }
}

fn action_to_verdict(action: &RuleAction) -> Verdict {
    match action {
        RuleAction::Block { status } => Verdict::Block(*status),
        RuleAction::RateLimit { rps } => Verdict::RateLimit(*rps),
        RuleAction::CloseConnection => Verdict::CloseConnection,
        RuleAction::Count { .. } => Verdict::Count,
        RuleAction::Pass => Verdict::Pass,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::compile;
    use crate::types::*;
    use std::sync::Arc;
    use holon::kernel::{Encoder, VectorManager};

    fn make_req(ip_str: &str) -> RequestSample {
        let tls_ctx = Arc::new(TlsContext::default());
        let enc = Encoder::new(VectorManager::new(4096));
        let tls_vec = enc.encode_walkable(tls_ctx.as_ref());
        test_request_sample("GET", "/", ip_str.parse().unwrap(), vec![], tls_ctx, tls_vec)
    }

    fn ip_u32(s: &str) -> u32 {
        let ip: std::net::IpAddr = s.parse().unwrap();
        match ip {
            std::net::IpAddr::V4(v4) => u32::from_ne_bytes(v4.octets()),
            _ => 0,
        }
    }

    #[test]
    fn evaluate_empty_tree_is_pass() {
        let tree = CompiledTree::empty();
        let req = make_req("1.2.3.4");
        assert!(matches!(evaluate(&req, &tree), Verdict::Pass));
    }

    #[test]
    fn evaluate_block_verdict() {
        let rules = vec![RuleSpec::new(
            vec![Predicate::eq(FieldDim::SrcIp, ip_u32("10.0.0.1"))],
            RuleAction::Block { status: 403 },
        )];
        let tree = compile(&rules);
        let req = make_req("10.0.0.1");
        assert!(matches!(evaluate(&req, &tree), Verdict::Block(403)));
    }

    #[test]
    fn evaluate_rate_limit_verdict() {
        let rules = vec![RuleSpec::new(
            vec![Predicate::eq(FieldDim::SrcIp, ip_u32("10.0.0.1"))],
            RuleAction::RateLimit { rps: 100 },
        )];
        let tree = compile(&rules);
        let req = make_req("10.0.0.1");
        assert!(matches!(evaluate(&req, &tree), Verdict::RateLimit(100)));
    }

    #[test]
    fn evaluate_close_connection_verdict() {
        let rules = vec![RuleSpec::new(
            vec![Predicate::eq(FieldDim::SrcIp, ip_u32("10.0.0.1"))],
            RuleAction::CloseConnection,
        )];
        let tree = compile(&rules);
        let req = make_req("10.0.0.1");
        assert!(matches!(evaluate(&req, &tree), Verdict::CloseConnection));
    }

    #[test]
    fn evaluate_count_verdict() {
        let rules = vec![RuleSpec::new(
            vec![Predicate::eq(FieldDim::SrcIp, ip_u32("10.0.0.1"))],
            RuleAction::count("test-counter"),
        )];
        let tree = compile(&rules);
        let req = make_req("10.0.0.1");
        assert!(matches!(evaluate(&req, &tree), Verdict::Count));
    }

    #[test]
    fn evaluate_pass_verdict() {
        let rules = vec![RuleSpec::new(
            vec![Predicate::eq(FieldDim::SrcIp, ip_u32("10.0.0.1"))],
            RuleAction::Pass,
        )];
        let tree = compile(&rules);
        let req = make_req("10.0.0.1");
        assert!(matches!(evaluate(&req, &tree), Verdict::Pass));
    }

    #[test]
    fn evaluate_non_matching_is_pass() {
        let rules = vec![RuleSpec::new(
            vec![Predicate::eq(FieldDim::SrcIp, ip_u32("10.0.0.1"))],
            RuleAction::block(),
        )];
        let tree = compile(&rules);
        let req = make_req("10.0.0.2");
        assert!(matches!(evaluate(&req, &tree), Verdict::Pass));
    }

    #[test]
    fn evaluate_tls_with_empty_tree() {
        let tree = CompiledTree::empty();
        let tls_ctx = Arc::new(TlsContext::default());
        let enc = Encoder::new(VectorManager::new(4096));
        let tls_vec = enc.encode_walkable(tls_ctx.as_ref());
        let sample = TlsSample {
            conn_id: 1,
            src_ip: "1.2.3.4".parse().unwrap(),
            tls_ctx,
            tls_vec,
            timestamp_us: now_us(),
        };
        assert!(matches!(evaluate_tls(&sample, &tree), Verdict::Pass));
    }
}
