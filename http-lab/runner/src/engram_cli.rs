//! Engram CLI — export, import, and list engram libraries for CI/CD promotion.
//!
//! Usage:
//!   holon-engram list   --path engrams/http.req
//!   holon-engram export --path engrams/http.req --output exported.json
//!   holon-engram import --path engrams/http.req --input promoted.json

use std::process;

use clap::{Parser, Subcommand};
use holon::memory::EngramLibrary;

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
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::List { path } => cmd_list(&path),
        Commands::Export { path, output } => cmd_export(&path, output.as_deref()),
        Commands::Import { path, input, overwrite } => cmd_import(&path, &input, overwrite),
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
