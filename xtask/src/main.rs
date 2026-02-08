//! Build helper for eBPF programs

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::process::Command;

#[derive(Parser)]
enum Cli {
    /// Build the eBPF programs
    BuildEbpf {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Build everything (eBPF + userspace)
    Build {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Run the control plane
    Run {
        /// Interface to attach to
        #[arg(short, long, default_value = "eno1")]
        interface: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::BuildEbpf { release } => build_ebpf(release),
        Cli::Build { release } => {
            build_ebpf(release)?;
            build_userspace(release)
        }
        Cli::Run { interface } => run(&interface),
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    println!("Building eBPF programs...");

    let mut args = vec![
        "+nightly",
        "build",
        "-p",
        "xdp-filter-ebpf",
        "--target",
        "bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ];

    if release {
        args.push("--release");
    }

    let status = Command::new("cargo")
        .args(&args)
        .env("CARGO_CFG_BPF_TARGET_ARCH", std::env::consts::ARCH)
        .status()
        .context("Failed to run cargo")?;

    if !status.success() {
        bail!("eBPF build failed");
    }

    println!("eBPF build complete");
    Ok(())
}

fn build_userspace(release: bool) -> Result<()> {
    println!("Building userspace programs...");

    let mut args = vec!["build"];
    if release {
        args.push("--release");
    }

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .context("Failed to run cargo")?;

    if !status.success() {
        bail!("Userspace build failed");
    }

    println!("Userspace build complete");
    Ok(())
}

fn run(interface: &str) -> Result<()> {
    println!("Running control plane on interface {}...", interface);

    let status = Command::new("sudo")
        .args([
            "./target/release/ddos-lab",
            "--interface",
            interface,
        ])
        .status()
        .context("Failed to run control plane")?;

    if !status.success() {
        bail!("Control plane exited with error");
    }

    Ok(())
}
