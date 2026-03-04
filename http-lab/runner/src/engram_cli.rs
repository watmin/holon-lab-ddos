//! Engram CLI — export, import, and list engram libraries for CI/CD promotion.
//!
//! Usage:
//!   holon-engram list   --path engrams/http.req
//!   holon-engram export --path engrams/http.req --output exported.json
//!   holon-engram import --path engrams/http.req --input promoted.json

use std::process;

use clap::{Parser, Subcommand};
use holon::memory::EngramLibrary;
use http_proxy::denial_token::{self, DenialKey};

#[derive(Parser)]
#[command(name = "holon-engram", about = "Engram library management for CI/CD promotion")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List engrams in a library file: names, observation counts, eigenvalue summary.
    List {
        /// Path to the engram library JSON file.
        #[arg(long)]
        path: String,
    },
    /// Export an engram library to a portable JSON file.
    Export {
        /// Path to the source engram library JSON file.
        #[arg(long)]
        path: String,
        /// Output file path (defaults to stdout if not specified).
        #[arg(long)]
        output: Option<String>,
    },
    /// Import (merge) engrams from a JSON file into an existing library.
    Import {
        /// Path to the target engram library JSON file.
        #[arg(long)]
        path: String,
        /// Input file to import from.
        #[arg(long)]
        input: String,
        /// Overwrite existing engrams with the same name.
        #[arg(long, default_value_t = false)]
        overwrite: bool,
    },
    /// Unseal a denial context token to see why a request was denied.
    Unseal {
        /// The base64 token from the X-Denial-Context header.
        token: String,
        /// Path to the denial key file (hex-encoded, 32 bytes).
        #[arg(long, default_value = "http-lab/engrams/nikto/denial.key")]
        key: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::List { path } => cmd_list(&path),
        Commands::Export { path, output } => cmd_export(&path, output.as_deref()),
        Commands::Import { path, input, overwrite } => cmd_import(&path, &input, overwrite),
        Commands::Unseal { token, key } => cmd_unseal(&token, &key),
    }
}

fn cmd_list(path: &str) {
    let mut lib = match EngramLibrary::load(path) {
        Ok(lib) => lib,
        Err(e) => {
            eprintln!("error: cannot load '{}': {}", path, e);
            process::exit(1);
        }
    };

    if lib.is_empty() {
        println!("(empty library)");
        return;
    }

    println!("{:<40} {:>8} {:>12}  eigenvalues (top 5)", "NAME", "N", "THRESHOLD");
    println!("{}", "-".repeat(90));

    let names: Vec<String> = lib.names().into_iter().map(|s| s.to_string()).collect();
    for name in &names {
        if let Some(engram) = lib.get_mut(name) {
            let n = engram.n();
            let sub = engram.subspace();
            let threshold = sub.threshold();
            let eigs = sub.eigenvalues();
            let top_eigs: Vec<String> = eigs.iter()
                .take(5)
                .map(|e| format!("{:.2}", e))
                .collect();
            println!(
                "{:<40} {:>8} {:>12.4}  [{}]",
                name, n, threshold, top_eigs.join(", ")
            );
        }
    }

    println!("\n{} engrams, dim={}", lib.len(), lib.dim());
}

fn cmd_export(path: &str, output: Option<&str>) {
    let lib = match EngramLibrary::load(path) {
        Ok(lib) => lib,
        Err(e) => {
            eprintln!("error: cannot load '{}': {}", path, e);
            process::exit(1);
        }
    };

    let json = match serde_json::to_string_pretty(&lib) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("error: serialize failed: {}", e);
            process::exit(1);
        }
    };

    match output {
        Some(out_path) => {
            if let Err(e) = std::fs::write(out_path, &json) {
                eprintln!("error: cannot write '{}': {}", out_path, e);
                process::exit(1);
            }
            eprintln!("exported {} engrams to '{}'", lib.len(), out_path);
        }
        None => {
            println!("{}", json);
        }
    }
}

fn cmd_import(path: &str, input: &str, overwrite: bool) {
    let source = match EngramLibrary::load(input) {
        Ok(lib) => lib,
        Err(e) => {
            eprintln!("error: cannot load source '{}': {}", input, e);
            process::exit(1);
        }
    };

    let mut target = match EngramLibrary::load(path) {
        Ok(lib) => lib,
        Err(_) => {
            eprintln!("target '{}' not found, creating new library (dim={})", path, source.dim());
            EngramLibrary::new(source.dim())
        }
    };

    let source_names: Vec<String> = source.names().into_iter().map(|s| s.to_string()).collect();
    let mut imported = 0usize;
    let mut skipped = 0usize;

    for name in &source_names {
        if target.contains(name) && !overwrite {
            eprintln!("  skip: '{}' (already exists, use --overwrite)", name);
            skipped += 1;
            continue;
        }
        if target.contains(name) {
            target.remove(name);
        }
        if let Some(engram) = source.get(name) {
            target.add_from_engram(name, engram);
            imported += 1;
        }
    }

    if let Err(e) = target.save(path) {
        eprintln!("error: cannot save '{}': {}", path, e);
        process::exit(1);
    }

    eprintln!("imported {} engrams, skipped {} → '{}' (total: {})",
             imported, skipped, path, target.len());
}

fn cmd_unseal(token: &str, key_path: &str) {
    let hex = match std::fs::read_to_string(key_path) {
        Ok(h) => h.trim().to_string(),
        Err(e) => {
            eprintln!("error: cannot read key '{}': {}", key_path, e);
            eprintln!("hint: the proxy saves the key to <engram-path>/denial.key on first run");
            process::exit(1);
        }
    };

    let mut bytes = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate().take(32) {
        bytes[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or("00"), 16).unwrap_or(0);
    }
    let key = DenialKey::from_bytes(bytes);

    match denial_token::unseal(token, &key) {
        Ok(ctx) => {
            println!("Denial Context (unsealed):");
            println!();
            println!("  verdict:         {}", ctx.verdict);
            println!("  residual:        {:.4}  (threshold: {:.4}, deny: {:.4})",
                     ctx.residual, ctx.threshold, ctx.deny_threshold);
            println!("  deviation:       {:.1}x above normal",
                     ctx.residual / ctx.threshold);
            println!();
            println!("  request:");
            println!("    {} {} {}", ctx.method, ctx.path,
                     ctx.query.as_deref().map(|q| format!("?{}", q)).unwrap_or_default());
            println!("    src:        {}", ctx.src_ip);
            println!("    user-agent: {}", ctx.user_agent.as_deref().unwrap_or("(none)"));
            println!("    headers:    [{}]", ctx.header_names.join(", "));
            if !ctx.cookie_keys.is_empty() {
                println!("    cookies:    [{}]", ctx.cookie_keys.join(", "));
            } else {
                println!("    cookies:    (none)");
            }
            println!();
            if !ctx.top_fields.is_empty() {
                let top_level: Vec<_> = ctx.top_fields.iter()
                    .filter(|f| !f.field.contains('.'))
                    .collect();
                let nested: Vec<_> = ctx.top_fields.iter()
                    .filter(|f| f.field.contains('.'))
                    .collect();

                if !top_level.is_empty() {
                    println!("  anomalous dimensions:");
                    let max_w = top_level.iter().map(|f| f.field.len()).max().unwrap_or(12);
                    for f in &top_level {
                        println!("    {:<w$} {:.2}", f.field, f.score, w = max_w);
                    }
                }
                if !nested.is_empty() {
                    println!();
                    println!("  standout sub-fields:");
                    let max_w = nested.iter().map(|f| f.field.len()).max().unwrap_or(20);
                    for f in &nested {
                        let depth = f.field.matches('.').count();
                        let indent = "  ".repeat(depth);
                        println!("    {}{:<w$} {:.2}", indent, f.field, f.score,
                                 w = max_w.saturating_sub(indent.len()));
                    }
                }
            }
            println!();
            let ts_secs = ctx.timestamp_us / 1_000_000;
            let ts_us = ctx.timestamp_us % 1_000_000;
            println!("  timestamp:       {}.{:06} ({} us)", ts_secs, ts_us, ctx.timestamp_us);
        }
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    }
}
