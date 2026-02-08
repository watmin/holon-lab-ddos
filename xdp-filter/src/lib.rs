//! XDP Filter - Userspace loader and management
//! 
//! Loads the xdp-filter eBPF program and provides an API for:
//! - Reading statistics from eBPF maps
//! - Configuring filter mode (detect vs enforce)
//! - Per-IP packet counts

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{HashMap, PerCpuArray, PerCpuValues},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Filter operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterMode {
    /// Log attacks but don't drop packets
    Detect = 0,
    /// Actively drop attack packets
    Enforce = 1,
}

/// Statistics from the XDP filter
#[derive(Debug, Clone, Default)]
pub struct FilterStats {
    pub total_packets: u64,
    pub passed_packets: u64,
    pub dropped_packets: u64,
    pub detected_attacks: u64,
}

/// XDP Filter manager
pub struct XdpFilter {
    bpf: Arc<RwLock<Ebpf>>,
    interface: String,
}

impl XdpFilter {
    /// Load and attach the XDP filter to an interface
    pub fn new(interface: &str) -> Result<Self> {
        // Load the eBPF bytecode
        #[cfg(debug_assertions)]
        let data = include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/xdp-filter"
        );
        #[cfg(not(debug_assertions))]
        let data = include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/xdp-filter"
        );

        let mut bpf = Ebpf::load(data).context("Failed to load eBPF program")?;

        // Attach to interface
        let program: &mut Xdp = bpf
            .program_mut("xdp_filter")
            .context("Failed to find xdp_filter program")?
            .try_into()?;
        
        program.load().context("Failed to load XDP program")?;
        
        // Use SKB mode for compatibility (works with macvlan, veth, etc.)
        program
            .attach(interface, XdpFlags::SKB_MODE)
            .context(format!("Failed to attach to {}", interface))?;

        info!("XDP filter attached to {}", interface);

        Ok(Self {
            bpf: Arc::new(RwLock::new(bpf)),
            interface: interface.to_string(),
        })
    }

    /// Get current statistics
    pub async fn stats(&self) -> Result<FilterStats> {
        let bpf = self.bpf.read().await;
        
        let stats: PerCpuArray<_, u64> = bpf
            .map("STATS")
            .context("STATS map not found")?
            .try_into()?;

        let mut result = FilterStats::default();

        // Sum across all CPUs
        if let Ok(values) = stats.get(&0, 0) {
            result.total_packets = values.iter().sum();
        }
        if let Ok(values) = stats.get(&1, 0) {
            result.passed_packets = values.iter().sum();
        }
        if let Ok(values) = stats.get(&2, 0) {
            result.dropped_packets = values.iter().sum();
        }
        if let Ok(values) = stats.get(&3, 0) {
            result.detected_attacks = values.iter().sum();
        }

        Ok(result)
    }

    /// Set the filter mode
    pub async fn set_mode(&self, mode: FilterMode) -> Result<()> {
        let mut bpf = self.bpf.write().await;
        
        let mut config: PerCpuArray<_, u32> = bpf
            .map_mut("CONFIG")
            .context("CONFIG map not found")?
            .try_into()?;

        let num_cpus = aya::util::nr_cpus()?;
        let values = PerCpuValues::try_from(vec![mode as u32; num_cpus])?;
        config.set(0, values, 0)?;

        info!("Filter mode set to {:?}", mode);
        Ok(())
    }

    /// Get top source IPs by packet count
    pub async fn top_ips(&self, limit: usize) -> Result<Vec<(std::net::Ipv4Addr, u64)>> {
        let bpf = self.bpf.read().await;
        
        let ip_counts: HashMap<_, u32, u64> = bpf
            .map("IP_COUNTS")
            .context("IP_COUNTS map not found")?
            .try_into()?;

        let mut entries: Vec<_> = ip_counts
            .iter()
            .filter_map(|r| r.ok())
            .map(|(ip, count)| {
                let addr = std::net::Ipv4Addr::from(u32::from_be(ip));
                (addr, count)
            })
            .collect();

        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(limit);

        Ok(entries)
    }

    /// Get the interface name
    pub fn interface(&self) -> &str {
        &self.interface
    }
}

impl Drop for XdpFilter {
    fn drop(&mut self) {
        info!("Detaching XDP filter from {}", self.interface);
        // aya automatically detaches on drop
    }
}
