//! Performance benchmarks for the expression tree compiler and evaluator.
//!
//! Run with: cargo bench -p http-proxy --bench tree_perf
//! Or:       cargo test  -p http-proxy --bench tree_perf (same thing)
//!
//! NOT included in `cargo test` — these are on-demand benchmarks that compile
//! and evaluate 100K–1M rules, which takes minutes in debug mode.

use std::time::Instant;
use std::sync::Arc;
use http_proxy::expr::{Dimension, SimpleDim, Expr, Value, RuleExpr};
use http_proxy::expr_tree::compile_expr;
use http_proxy::types::{RuleAction, TlsContext, RequestSample, HttpVersion};
use holon::kernel::{Encoder, VectorManager};

fn idx_to_ip(i: usize) -> String {
    format!("10.{}.{}.{}", (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF)
}

fn make_req(method: &str, path: &str, ip: &str, ua: Option<&str>, ct: Option<&str>, sni: Option<&str>) -> RequestSample {
    let mut tls = TlsContext::default();
    if let Some(s) = sni {
        tls.sni = Some(s.to_string());
    }
    let tls_ctx = Arc::new(tls);
    let enc = Encoder::new(VectorManager::new(4096));
    let tls_vec = enc.encode_walkable(tls_ctx.as_ref());
    let mut headers: Vec<(String, String)> = vec![];
    if let Some(s) = sni {
        headers.push(("Host".to_string(), s.to_string()));
    }
    if let Some(u) = ua {
        headers.push(("User-Agent".to_string(), u.to_string()));
    }
    if let Some(c) = ct {
        headers.push(("Content-Type".to_string(), c.to_string()));
    }
    RequestSample {
        method: method.to_string(),
        path: path.to_string(),
        query: None,
        version: HttpVersion::Http11,
        headers,
        host: sni.map(|s| s.to_string()),
        user_agent: ua.map(|s| s.to_string()),
        content_type: ct.map(|s| s.to_string()),
        content_length: None,
        cookies: vec![],
        body: None,
        src_ip: ip.parse().unwrap(),
        conn_id: 0,
        tls_ctx,
        tls_vec,
        timestamp_us: 0,
    }
}

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

const METHODS: [&str; 5] = ["GET", "POST", "PUT", "DELETE", "PATCH"];
const PREFIXES: [&str; 10] = ["/api/v1", "/api/v2", "/api/v3", "/admin", "/health",
                               "/auth", "/users", "/products", "/orders", "/search"];
const USER_AGENTS: [&str; 6] = ["Mozilla/5.0", "curl/8.4.0", "python-requests/2.31.0",
                                  "Scrapy/2.11.0", "Go-http-client/2.0", "PostmanRuntime/7.36"];
const CONTENT_TYPES: [&str; 4] = ["application/json", "text/html", "text/xml", "multipart/form-data"];
const HOSTS: [&str; 5] = ["api.example.com", "app.example.com", "cdn.example.com",
                           "admin.example.com", "auth.example.com"];

fn make_rule(i: usize, complexity: usize) -> RuleExpr {
    let mut constraints = Vec::with_capacity(complexity);
    let ip = idx_to_ip(i);

    if complexity >= 1 {
        constraints.push(Expr::eq(Dimension::src_ip(), Value::str(&ip)));
    }
    if complexity >= 2 {
        constraints.push(Expr::eq(Dimension::method(), Value::str(METHODS[i % METHODS.len()])));
    }
    if complexity >= 3 {
        constraints.push(Expr::prefix(Dimension::path(), PREFIXES[i % PREFIXES.len()]));
    }
    if complexity >= 4 {
        constraints.push(Expr::eq(
            Dimension::header_first("user-agent"),
            Value::str(USER_AGENTS[i % USER_AGENTS.len()]),
        ));
    }
    if complexity >= 5 {
        constraints.push(Expr::eq(
            Dimension::header_first("content-type"),
            Value::str(CONTENT_TYPES[i % CONTENT_TYPES.len()]),
        ));
    }
    if complexity >= 6 {
        constraints.push(Expr::eq(
            Dimension::Simple(SimpleDim::Sni),
            Value::str(HOSTS[i % HOSTS.len()]),
        ));
    }

    RuleExpr::new(
        constraints,
        RuleAction::RateLimit { rps: (i % 9999 + 1) as u32, name: None },
    )
}

fn make_matching_req(i: usize, complexity: usize) -> RequestSample {
    let ip = idx_to_ip(i);
    let method = METHODS[i % METHODS.len()];
    let path = if complexity >= 3 {
        format!("{}/deep/page", PREFIXES[i % PREFIXES.len()])
    } else {
        "/anything".to_string()
    };
    let ua = if complexity >= 4 { Some(USER_AGENTS[i % USER_AGENTS.len()]) } else { None };
    let ct = if complexity >= 5 { Some(CONTENT_TYPES[i % CONTENT_TYPES.len()]) } else { None };
    let host = if complexity >= 6 { Some(HOSTS[i % HOSTS.len()]) } else { None };
    make_req(method, &path, &ip, ua, ct, host)
}

fn percentile(sorted: &[u128], pct: f64) -> u128 {
    let idx = ((sorted.len() as f64) * pct / 100.0) as usize;
    sorted[idx.min(sorted.len() - 1)]
}

// ─── Benchmark: Fixed Scale, Varying Complexity ─────────────────────────────

fn complexity_sweep() {
    let scale = 100_000_usize;
    let probe_count = 2000_usize;
    let complexities: &[usize] = &[1, 2, 3, 4, 5, 6];

    eprintln!("\n=== {} rules, varying constraint complexity ===", scale);
    eprintln!("{:>6} {:>8} {:>10} {:>8} {:>10} {:>10} {:>10} {:>10} {:>10}",
              "dims", "layers", "compile", "nodes", "hit_p50", "hit_p99", "miss_p50", "correct", "evals/s");
    eprintln!("{}", "─".repeat(100));

    for &c in complexities {
        let rules: Vec<RuleExpr> = (0..scale).map(|i| make_rule(i, c)).collect();

        let t0 = Instant::now();
        let tree = compile_expr(&rules);
        let compile_ms = t0.elapsed().as_millis();

        let layers_desc = if c >= 6 { "TLS+HTTP" } else if c >= 1 { "HTTP" } else { "none" };

        let mut rng = 0xDEAD_BEEF_u64;
        let hit_reqs: Vec<(RequestSample, u32)> = (0..probe_count).map(|_| {
            let i = (xorshift(&mut rng) as usize) % scale;
            let expected_rps = (i % 9999 + 1) as u32;
            (make_matching_req(i, c), expected_rps)
        }).collect();

        let miss_req = make_req("OPTIONS", "/nonexistent", "192.168.255.255", None, None, None);

        let mut correct = 0usize;
        let mut hit_times: Vec<u128> = Vec::with_capacity(probe_count);
        for (req, expected) in &hit_reqs {
            let t = Instant::now();
            let result = tree.evaluate_req(req);
            hit_times.push(t.elapsed().as_nanos());
            if let Some((RuleAction::RateLimit { rps, .. }, _)) = result {
                if *rps == *expected { correct += 1; }
            }
        }
        hit_times.sort();

        let mut miss_times: Vec<u128> = Vec::with_capacity(probe_count);
        for _ in 0..probe_count {
            let t = Instant::now();
            let _ = tree.evaluate_req(&miss_req);
            miss_times.push(t.elapsed().as_nanos());
        }
        miss_times.sort();

        let hit_p50 = percentile(&hit_times, 50.0);
        let hit_p99 = percentile(&hit_times, 99.0);
        let miss_p50 = percentile(&miss_times, 50.0);
        let throughput = 1_000_000_000u128 / hit_p50.max(1);

        eprintln!("{:>6} {:>8} {:>8}ms {:>8} {:>8}ns {:>8}ns {:>8}ns {:>6}/{} {:>8}",
                  c, layers_desc, compile_ms, tree.nodes.len(),
                  hit_p50, hit_p99, miss_p50,
                  correct, probe_count, throughput);
    }
}

// ─── Benchmark: Fixed Complexity, Varying Scale ─────────────────────────────

fn scale_sweep() {
    let scales: &[usize] = &[100, 1_000, 10_000, 100_000, 500_000, 1_000_000];
    let probe_count = 2000_usize;

    for &complexity in &[2_usize, 4, 6] {
        let label = match complexity {
            2 => "2-dim (ip+method)",
            4 => "4-dim (ip+method+path+ua)",
            6 => "6-dim (ip+method+path+ua+ct+sni)",
            _ => "?",
        };
        eprintln!("\n=== Scale sweep: {} ===", label);
        eprintln!("{:>10} {:>10} {:>10} {:>10} {:>10} {:>10} {:>10}",
                  "rules", "compile", "nodes", "hit_p50", "hit_p99", "miss_p50", "correct");
        eprintln!("{}", "─".repeat(84));

        for &n in scales {
            let rules: Vec<RuleExpr> = (0..n).map(|i| make_rule(i, complexity)).collect();

            let t0 = Instant::now();
            let tree = compile_expr(&rules);
            let compile_ms = t0.elapsed().as_millis();

            let mut rng = 0xCAFE_BABE_u64;
            let hit_reqs: Vec<(RequestSample, u32)> = (0..probe_count).map(|_| {
                let i = (xorshift(&mut rng) as usize) % n;
                let expected_rps = (i % 9999 + 1) as u32;
                (make_matching_req(i, complexity), expected_rps)
            }).collect();

            let miss_req = make_req("OPTIONS", "/nope", "192.168.255.255", None, None, None);

            let mut correct = 0_usize;
            let mut hit_times: Vec<u128> = Vec::with_capacity(probe_count);
            for (req, expected) in &hit_reqs {
                let t = Instant::now();
                let result = tree.evaluate_req(req);
                hit_times.push(t.elapsed().as_nanos());
                if let Some((RuleAction::RateLimit { rps, .. }, _)) = result {
                    if *rps == *expected { correct += 1; }
                }
            }
            hit_times.sort();

            let mut miss_times: Vec<u128> = Vec::with_capacity(probe_count);
            for _ in 0..probe_count {
                let t = Instant::now();
                let _ = tree.evaluate_req(&miss_req);
                miss_times.push(t.elapsed().as_nanos());
            }
            miss_times.sort();

            let hp50 = percentile(&hit_times, 50.0);
            let hp99 = percentile(&hit_times, 99.0);
            let mp50 = percentile(&miss_times, 50.0);

            eprintln!("{:>10} {:>8}ms {:>10} {:>8}ns {:>8}ns {:>8}ns {:>6}/{}",
                      n, compile_ms, tree.nodes.len(), hp50, hp99, mp50, correct, probe_count);
        }
    }
}

// ─── Benchmark: Mixed-Complexity Workload ───────────────────────────────────

fn mixed_complexity() {
    let total = 100_000_usize;
    let probes_per_tier = 2000_usize;

    let mix: &[(usize, f64)] = &[(1, 0.10), (2, 0.25), (3, 0.30), (4, 0.20), (5, 0.10), (6, 0.05)];

    eprintln!("\n=== Mixed-complexity: {}K rules, realistic distribution ===", total / 1000);
    eprintln!("  distribution: {}", mix.iter()
        .map(|(c, p)| format!("{}-dim={:.0}%", c, p * 100.0))
        .collect::<Vec<_>>().join(", "));

    struct Tier { complexity: usize, start: usize, count: usize }
    let mut tiers: Vec<Tier> = Vec::new();
    let mut rules = Vec::with_capacity(total);
    let mut idx = 0_usize;
    for &(complexity, fraction) in mix {
        let count = (total as f64 * fraction) as usize;
        let start = idx;
        for _ in 0..count {
            rules.push(make_rule(idx, complexity));
            idx += 1;
        }
        tiers.push(Tier { complexity, start, count });
    }

    eprintln!("  actual rules: {}", rules.len());

    let t0 = Instant::now();
    let tree = compile_expr(&rules);
    let compile_ms = t0.elapsed().as_millis();
    eprintln!("  compile: {}ms, nodes: {}", compile_ms, tree.nodes.len());

    eprintln!("\n{:>10} {:>8} {:>10} {:>10} {:>10} {:>10}",
              "target", "rules", "hit_p50", "hit_p99", "miss_p50", "correct");
    eprintln!("{}", "─".repeat(70));

    let miss_req = make_req("OPTIONS", "/miss", "192.168.255.255", None, None, None);

    for tier in &tiers {
        let mut rng = (0xBEEF_0000_u64) | (tier.complexity as u64);
        let mut hit_times = Vec::with_capacity(probes_per_tier);
        let mut correct = 0_usize;

        for _ in 0..probes_per_tier {
            let i = tier.start + ((xorshift(&mut rng) as usize) % tier.count);
            let expected_rps = (i % 9999 + 1) as u32;
            let req = make_matching_req(i, tier.complexity);
            let t = Instant::now();
            let result = tree.evaluate_req(&req);
            hit_times.push(t.elapsed().as_nanos());
            if let Some((RuleAction::RateLimit { rps, .. }, _)) = result {
                if *rps == expected_rps { correct += 1; }
            }
        }
        hit_times.sort();

        let mut miss_times = Vec::with_capacity(500);
        for _ in 0..500 {
            let t = Instant::now();
            let _ = tree.evaluate_req(&miss_req);
            miss_times.push(t.elapsed().as_nanos());
        }
        miss_times.sort();

        eprintln!("{:>6}-dim {:>8} {:>8}ns {:>8}ns {:>8}ns {:>6}/{}",
                  tier.complexity, tier.count,
                  percentile(&hit_times, 50.0),
                  percentile(&hit_times, 99.0),
                  percentile(&miss_times, 50.0),
                  correct, probes_per_tier);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let bench = args.get(1).map(|s| s.as_str()).unwrap_or("all");

    match bench {
        "complexity" => complexity_sweep(),
        "scale"      => scale_sweep(),
        "mixed"      => mixed_complexity(),
        "all" | _    => {
            complexity_sweep();
            scale_sweep();
            mixed_complexity();
        }
    }
}
