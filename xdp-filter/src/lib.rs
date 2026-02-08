//! XDP Filter - Userspace loader and management
//! 
//! Loads the xdp-filter eBPF program and provides an API for:
//! - Reading statistics from eBPF maps
//! - Configuring filter mode (detect vs enforce)
//! - Per-IP packet counts
//!
//! NOTE: XDP filter is currently disabled until eBPF toolchain issues are resolved.
//! The generator works standalone using raw sockets.

use anyhow::{Result, bail};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Filter operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterMode {
    /// Log attacks but don't drop packets
    Detect = 0,
    /// Actively drop attack packets
    Enforce = 1,
}

/// Statistics from the XDP filter
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FilterStats {
    pub total_packets: u64,
    pub passed_packets: u64,
    pub dropped_packets: u64,
    pub detected_attacks: u64,
}

/// XDP Filter manager (stub - XDP not yet implemented)
pub struct XdpFilter {
    interface: String,
    mode: Arc<RwLock<FilterMode>>,
    // Will hold eBPF handle once toolchain is fixed
}

impl XdpFilter {
    /// Load and attach the XDP filter to an interface
    /// Currently returns an error - XDP support pending toolchain fix
    pub fn new(interface: &str) -> Result<Self> {
        // TODO: Load actual eBPF program once toolchain issues are resolved
        // For now, return a stub that tracks mode but doesn't filter
        bail!(
            "XDP filter not yet available - eBPF toolchain compatibility issue. \
             Use --no-filter to run generator-only mode."
        );
        
        // When eBPF works, this will load the program:
        // let data = include_bytes_aligned!("../../target/bpfel-unknown-none/release/xdp-filter");
        // let mut bpf = Ebpf::load(data)?;
        // ...
    }

    /// Create a stub filter for testing (no actual XDP)
    pub fn stub(interface: &str) -> Self {
        info!("Creating stub XDP filter for {} (no actual filtering)", interface);
        Self {
            interface: interface.to_string(),
            mode: Arc::new(RwLock::new(FilterMode::Detect)),
        }
    }

    /// Get current statistics (stub returns zeros)
    pub async fn stats(&self) -> Result<FilterStats> {
        Ok(FilterStats::default())
    }

    /// Set the filter mode
    pub async fn set_mode(&self, mode: FilterMode) -> Result<()> {
        *self.mode.write().await = mode;
        info!("Filter mode set to {:?} (stub - no actual filtering)", mode);
        Ok(())
    }

    /// Get top source IPs by packet count (stub returns empty)
    pub async fn top_ips(&self, _limit: usize) -> Result<Vec<(std::net::Ipv4Addr, u64)>> {
        Ok(vec![])
    }

    /// Get the interface name
    pub fn interface(&self) -> &str {
        &self.interface
    }
}

impl Drop for XdpFilter {
    fn drop(&mut self) {
        info!("Dropping XDP filter stub for {}", self.interface);
    }
}
