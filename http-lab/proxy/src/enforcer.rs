//! Synchronous rule enforcer.
//!
//! Called on every request in the hot path. Loads the current CompiledTree
//! from the ArcSwap (wait-free) and evaluates rules against the request.
//! Returns a Verdict that the http handler acts on immediately.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

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

// =============================================================================
// Per-IP token bucket rate limiter
// =============================================================================

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

/// Concurrent per-source-IP token bucket.
///
/// Each IP gets its own bucket that refills at `rps` tokens/sec (capacity
/// also capped at `rps`). `allow()` is called in the hot path; the Mutex
/// hold time is pure arithmetic — no I/O, no allocations on the fast path.
pub struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if the request is allowed through, `false` if it
    /// should be 429'd. Consumes one token from the bucket for `ip`.
    pub fn allow(&self, ip: IpAddr, rps: u32) -> bool {
        let now = Instant::now();
        let rate = rps as f64;
        let mut map = self.buckets.lock().unwrap();
        let bucket = map.entry(ip).or_insert_with(|| TokenBucket {
            tokens: rate,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(rate);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Evaluate a RequestSample against the compiled tree.
/// Called synchronously on every request (ArcSwap load is wait-free).
/// Returns (verdict, optional rule_id) for per-rule counter tracking.
pub fn evaluate(req: &RequestSample, tree: &CompiledTree) -> (Verdict, Option<u32>) {
    match tree.evaluate_req(req) {
        None => (Verdict::Pass, None),
        Some((action, rule_id)) => (action_to_verdict(action), Some(rule_id)),
    }
}

/// Evaluate a TlsSample against the compiled tree.
/// Called once per connection at TLS accept time.
pub fn evaluate_tls(sample: &TlsSample, tree: &CompiledTree) -> (Verdict, Option<u32>) {
    match tree.evaluate_tls(sample) {
        None => (Verdict::Pass, None),
        Some((action, rule_id)) => (action_to_verdict(action), Some(rule_id)),
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

    #[test]
    fn evaluate_empty_tree_is_pass() {
        let tree = CompiledTree::empty();
        let req = make_req("1.2.3.4");
        assert!(matches!(evaluate(&req, &tree), (Verdict::Pass, None)));
    }

    #[test]
    fn evaluate_block_verdict() {
        let rules = vec![RuleSpec::new(
            vec![Predicate::eq(FieldDim::SrcIp, "10.0.0.1")],
            RuleAction::Block { status: 403 },
        )];
        let tree = compile(&rules);
        let req = make_req("10.0.0.1");
        let (v, rid) = evaluate(&req, &tree);
        assert!(matches!(v, Verdict::Block(403)));
        assert!(rid.is_some());
    }

    #[test]
    fn evaluate_rate_limit_verdict() {
        let rules = vec![RuleSpec::new(
            vec![Predicate::eq(FieldDim::SrcIp, "10.0.0.1")],
            RuleAction::RateLimit { rps: 100 },
        )];
        let tree = compile(&rules);
        let req = make_req("10.0.0.1");
        let (v, rid) = evaluate(&req, &tree);
        assert!(matches!(v, Verdict::RateLimit(100)));
        assert!(rid.is_some());
    }

    #[test]
    fn evaluate_close_connection_verdict() {
        let rules = vec![RuleSpec::new(
            vec![Predicate::eq(FieldDim::SrcIp, "10.0.0.1")],
            RuleAction::CloseConnection,
        )];
        let tree = compile(&rules);
        let req = make_req("10.0.0.1");
        let (v, rid) = evaluate(&req, &tree);
        assert!(matches!(v, Verdict::CloseConnection));
        assert!(rid.is_some());
    }

    #[test]
    fn evaluate_count_verdict() {
        let rules = vec![RuleSpec::new(
            vec![Predicate::eq(FieldDim::SrcIp, "10.0.0.1")],
            RuleAction::count("test-counter"),
        )];
        let tree = compile(&rules);
        let req = make_req("10.0.0.1");
        let (v, rid) = evaluate(&req, &tree);
        assert!(matches!(v, Verdict::Count));
        assert!(rid.is_some());
    }

    #[test]
    fn evaluate_pass_verdict() {
        let rules = vec![RuleSpec::new(
            vec![Predicate::eq(FieldDim::SrcIp, "10.0.0.1")],
            RuleAction::Pass,
        )];
        let tree = compile(&rules);
        let req = make_req("10.0.0.1");
        let (v, rid) = evaluate(&req, &tree);
        assert!(matches!(v, Verdict::Pass));
        assert!(rid.is_some());
    }

    #[test]
    fn evaluate_non_matching_is_pass() {
        let rules = vec![RuleSpec::new(
            vec![Predicate::eq(FieldDim::SrcIp, "10.0.0.1")],
            RuleAction::block(),
        )];
        let tree = compile(&rules);
        let req = make_req("10.0.0.2");
        assert!(matches!(evaluate(&req, &tree), (Verdict::Pass, None)));
    }

    #[test]
    fn rate_limiter_allows_within_budget() {
        let rl = RateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // Bucket starts full at rps tokens — first rps calls should pass
        for _ in 0..100 {
            assert!(rl.allow(ip, 100));
        }
        // Next call exhausts the bucket
        assert!(!rl.allow(ip, 100));
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let rl = RateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // Drain the bucket
        for _ in 0..10 {
            rl.allow(ip, 10);
        }
        assert!(!rl.allow(ip, 10));
        // After sleeping, bucket should have refilled
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(rl.allow(ip, 10));
    }

    #[test]
    fn rate_limiter_isolates_ips() {
        let rl = RateLimiter::new();
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();
        // Drain ip_a
        for _ in 0..5 {
            rl.allow(ip_a, 5);
        }
        assert!(!rl.allow(ip_a, 5));
        // ip_b should be unaffected
        assert!(rl.allow(ip_b, 5));
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
        assert!(matches!(evaluate_tls(&sample, &tree), (Verdict::Pass, None)));
    }
}
