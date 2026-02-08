//! XDP Filter - Userspace loader and management
//!
//! Loads the xdp-filter eBPF program and provides an API for:
//! - Attaching XDP program to an interface
//! - Reading statistics from eBPF maps
//! - Configuring filter mode (detect vs enforce)
//! - Per-IP packet counts
//! - Packet sampling via perf buffer

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{HashMap, PerCpuArray, PerCpuValues, AsyncPerfEventArray},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};

/// Filter operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    pub sampled_packets: u64,
}

/// Maximum bytes captured per packet (must match eBPF SAMPLE_SIZE)
pub const SAMPLE_SIZE: usize = 256;

/// Packet sample from eBPF (must match xdp-filter-ebpf PacketSample)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PacketSample {
    /// Actual packet length (may be larger than captured)
    pub pkt_len: u32,
    /// How many bytes we actually captured
    pub cap_len: u32,
    /// Is this an attack packet?
    pub is_attack: u32,
    /// Padding
    pub _pad: u32,
    /// First SAMPLE_SIZE bytes of the packet
    pub data: [u8; SAMPLE_SIZE],
}

/// XDP Filter manager
pub struct XdpFilter {
    #[allow(dead_code)]
    bpf: Arc<RwLock<Ebpf>>,
    interface: String,
    mode: Arc<RwLock<FilterMode>>,
}

impl XdpFilter {
    /// Load and attach the XDP filter to an interface
    pub fn new(interface: &str) -> Result<Self> {
        info!("Loading XDP filter for interface {}", interface);

        // Load the eBPF program (compiled from xdp-filter-ebpf)
        // The bytes are included at compile time
        #[cfg(debug_assertions)]
        let data = include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/xdp-filter"
        );
        #[cfg(not(debug_assertions))]
        let data = include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/xdp-filter"
        );

        let mut bpf = Ebpf::load(data).context("Failed to load eBPF program")?;
        
        // Initialize aya-log for eBPF logging (optional, ignore errors)
        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            debug!("eBPF logger not available: {}", e);
        }

        // Get the XDP program
        let program: &mut Xdp = bpf
            .program_mut("xdp_filter")
            .context("XDP program 'xdp_filter' not found")?
            .try_into()
            .context("Program is not XDP")?;

        // Load the program into the kernel
        program.load().context("Failed to load XDP program")?;
        info!("XDP program loaded");

        // Try to attach with native driver mode first, fall back to SKB mode
        let attach_result = program.attach(interface, XdpFlags::DRV_MODE);
        if let Err(e) = attach_result {
            warn!("Native XDP mode not supported ({}), trying SKB mode", e);
            program
                .attach(interface, XdpFlags::SKB_MODE)
                .context("Failed to attach XDP program in SKB mode")?;
            info!("XDP program attached to {} in SKB mode", interface);
        } else {
            info!("XDP program attached to {} in native driver mode", interface);
        }

        Ok(Self {
            bpf: Arc::new(RwLock::new(bpf)),
            interface: interface.to_string(),
            mode: Arc::new(RwLock::new(FilterMode::Detect)),
        })
    }

    /// Create a stub filter for testing (no actual XDP)
    /// This is used when --no-filter is specified
    pub fn stub(interface: &str) -> Result<Self> {
        info!("Creating stub XDP filter for {} (no actual filtering)", interface);
        
        // Create a minimal eBPF context that doesn't attach anything
        // This is a workaround - in production you'd want a proper stub
        Err(anyhow::anyhow!("Stub mode - use new() to load real XDP filter"))
    }

    /// Get current statistics from eBPF maps
    pub async fn stats(&self) -> Result<FilterStats> {
        let bpf = self.bpf.read().await;
        
        let stats: PerCpuArray<_, u64> = bpf
            .map("STATS")
            .context("STATS map not found")?
            .try_into()
            .context("Wrong map type for STATS")?;

        // Read per-CPU values and sum them
        let total = stats.get(&0, 0).map(|v| sum_percpu(&v)).unwrap_or(0);
        let passed = stats.get(&1, 0).map(|v| sum_percpu(&v)).unwrap_or(0);
        let dropped = stats.get(&2, 0).map(|v| sum_percpu(&v)).unwrap_or(0);
        let detected = stats.get(&3, 0).map(|v| sum_percpu(&v)).unwrap_or(0);
        let sampled = stats.get(&4, 0).map(|v| sum_percpu(&v)).unwrap_or(0);

        Ok(FilterStats {
            total_packets: total,
            passed_packets: passed,
            dropped_packets: dropped,
            detected_attacks: detected,
            sampled_packets: sampled,
        })
    }

    /// Set the sample rate (1 = every packet, 100 = 1 in 100, 0 = disabled)
    pub async fn set_sample_rate(&self, rate: u32) -> Result<()> {
        let mut bpf = self.bpf.write().await;
        
        let mut config: PerCpuArray<_, u32> = bpf
            .map_mut("CONFIG")
            .context("CONFIG map not found")?
            .try_into()
            .context("Wrong map type for CONFIG")?;

        let num_cpus = aya::util::nr_cpus()
            .map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))?;
        let values = PerCpuValues::try_from(vec![rate; num_cpus])
            .context("Failed to create per-CPU values")?;
        
        config.set(1, values, 0).context("Failed to set sample rate")?;
        
        info!("Sample rate set to {} (1 in {} packets)", rate, if rate > 0 { rate } else { 0 });
        Ok(())
    }

    /// Take ownership of the SAMPLES perf array for reading packets
    /// This consumes the map from the BPF object - call only once
    pub async fn take_samples_perf_array(&self) -> Result<AsyncPerfEventArray<aya::maps::MapData>> {
        let mut bpf = self.bpf.write().await;
        
        let perf_array = bpf
            .take_map("SAMPLES")
            .context("SAMPLES map not found")?;
        
        AsyncPerfEventArray::try_from(perf_array)
            .context("Failed to create AsyncPerfEventArray from SAMPLES")
    }

    /// Set the filter mode (detect vs enforce)
    pub async fn set_mode(&self, mode: FilterMode) -> Result<()> {
        let mut bpf = self.bpf.write().await;
        
        let mut config: PerCpuArray<_, u32> = bpf
            .map_mut("CONFIG")
            .context("CONFIG map not found")?
            .try_into()
            .context("Wrong map type for CONFIG")?;

        // Set mode on all CPUs
        let num_cpus = aya::util::nr_cpus()
            .map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))?;
        let values = PerCpuValues::try_from(vec![mode as u32; num_cpus])
            .context("Failed to create per-CPU values")?;
        
        config.set(0, values, 0).context("Failed to set CONFIG")?;
        
        *self.mode.write().await = mode;
        info!("Filter mode set to {:?}", mode);
        Ok(())
    }

    /// Get top source IPs by packet count
    pub async fn top_ips(&self, limit: usize) -> Result<Vec<(Ipv4Addr, u64)>> {
        let bpf = self.bpf.read().await;
        
        let ip_counts: HashMap<_, u32, u64> = bpf
            .map("IP_COUNTS")
            .context("IP_COUNTS map not found")?
            .try_into()
            .context("Wrong map type for IP_COUNTS")?;

        let mut counts: Vec<(Ipv4Addr, u64)> = ip_counts
            .iter()
            .filter_map(|result| {
                result.ok().map(|(ip_host_order, count)| {
                    // IP is already in host byte order from eBPF, convert to Ipv4Addr
                    let ip = Ipv4Addr::from(ip_host_order.to_be_bytes());
                    (ip, count)
                })
            })
            .collect();

        // Sort by count descending
        counts.sort_by(|a, b| b.1.cmp(&a.1));
        counts.truncate(limit);

        Ok(counts)
    }

    /// Get the interface name
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Get current mode
    pub async fn get_mode(&self) -> FilterMode {
        *self.mode.read().await
    }
}

/// Sum per-CPU values
fn sum_percpu(values: &PerCpuValues<u64>) -> u64 {
    values.iter().sum()
}

impl Drop for XdpFilter {
    fn drop(&mut self) {
        info!("Detaching XDP filter from {}", self.interface);
        // XDP program is automatically detached when Ebpf is dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_mode() {
        assert_eq!(FilterMode::Detect as u32, 0);
        assert_eq!(FilterMode::Enforce as u32, 1);
    }
}
