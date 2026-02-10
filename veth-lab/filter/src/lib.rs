//! Veth Filter - Userspace loader and rule management
//!
//! Loads the XDP filter and provides an API for:
//! - Managing drop/rate-limit rules
//! - Reading statistics
//! - Receiving packet samples via ring buffer

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{HashMap, MapData, PerCpuArray, PerCpuValues, AsyncPerfEventArray},
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// =============================================================================
// Types matching eBPF program
// =============================================================================

/// Rule type discriminator
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum RuleType {
    SrcIp = 0,
    DstIp = 1,
    SrcPort = 2,
    DstPort = 3,
    Protocol = 4,
}

/// Rule action
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum RuleAction {
    Pass = 0,
    Drop = 1,
    RateLimit = 2,
}

/// Rule key (must match eBPF struct layout)
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuleKey {
    pub rule_type: u8,
    pub _pad: [u8; 3],
    pub value: u32,
}

// Implement Pod for aya map compatibility
unsafe impl aya::Pod for RuleKey {}

/// Rule value (must match eBPF struct layout)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RuleValue {
    pub action: u8,
    pub _pad: [u8; 3],
    pub rate_pps: u32,
    pub match_count: u64,
}

unsafe impl aya::Pod for RuleValue {}

/// Packet sample from perf buffer (must match eBPF struct)
pub const SAMPLE_DATA_SIZE: usize = 128;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketSample {
    pub pkt_len: u32,
    pub cap_len: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub matched_rule: u8,
    pub action_taken: u8,
    pub _pad: u8,
    pub data: [u8; SAMPLE_DATA_SIZE],
}

unsafe impl aya::Pod for PacketSample {}

impl PacketSample {
    /// Get source IP as Ipv4Addr
    /// Note: IP is stored in network byte order from packet
    pub fn src_ip_addr(&self) -> Ipv4Addr {
        // IP in packet is big-endian, raw u32 read gives us the bytes we need
        Ipv4Addr::from(self.src_ip.to_ne_bytes())
    }

    /// Get destination IP as Ipv4Addr
    pub fn dst_ip_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.dst_ip.to_ne_bytes())
    }

    /// Get protocol name
    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            _ => "OTHER",
        }
    }
}

/// Statistics from XDP filter
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FilterStats {
    pub total_packets: u64,
    pub passed_packets: u64,
    pub dropped_packets: u64,
    pub sampled_packets: u64,
}

/// High-level rule for API
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Rule {
    pub rule_type: RuleType,
    pub value: String,  // IP address or port number as string
    pub action: RuleAction,
    pub rate_pps: Option<u32>,  // For rate limiting
}

impl Rule {
    /// Create a drop rule for a source IP
    pub fn drop_src_ip(ip: Ipv4Addr) -> Self {
        Self {
            rule_type: RuleType::SrcIp,
            value: ip.to_string(),
            action: RuleAction::Drop,
            rate_pps: None,
        }
    }

    /// Create a drop rule for a destination port
    pub fn drop_dst_port(port: u16) -> Self {
        Self {
            rule_type: RuleType::DstPort,
            value: port.to_string(),
            action: RuleAction::Drop,
            rate_pps: None,
        }
    }

    /// Create a drop rule for a source port
    pub fn drop_src_port(port: u16) -> Self {
        Self {
            rule_type: RuleType::SrcPort,
            value: port.to_string(),
            action: RuleAction::Drop,
            rate_pps: None,
        }
    }

    /// Convert to BPF map key
    pub fn to_key(&self) -> Result<RuleKey> {
        let value = match self.rule_type {
            RuleType::SrcIp | RuleType::DstIp => {
                let ip: Ipv4Addr = self.value.parse()
                    .context("Invalid IP address")?;
                // Match the raw u32 that eBPF reads from packet (native byte order interpretation)
                u32::from_ne_bytes(ip.octets())
            }
            RuleType::SrcPort | RuleType::DstPort => {
                let port: u16 = self.value.parse()
                    .context("Invalid port number")?;
                port as u32
            }
            RuleType::Protocol => {
                let proto: u8 = self.value.parse()
                    .context("Invalid protocol number")?;
                proto as u32
            }
        };

        Ok(RuleKey {
            rule_type: self.rule_type as u8,
            _pad: [0; 3],
            value,
        })
    }

    /// Convert to BPF map value
    pub fn to_value(&self) -> RuleValue {
        RuleValue {
            action: self.action as u8,
            _pad: [0; 3],
            rate_pps: self.rate_pps.unwrap_or(0),
            match_count: 0,
        }
    }
}

// =============================================================================
// VethFilter - Main API
// =============================================================================

/// XDP Filter manager
pub struct VethFilter {
    bpf: Arc<RwLock<Ebpf>>,
    interface: String,
}

impl VethFilter {
    /// Load and attach the XDP filter to an interface
    pub fn new(interface: &str) -> Result<Self> {
        Self::with_flags(interface, XdpFlags::default())
    }

    /// Load with specific XDP flags (DRV_MODE, SKB_MODE, etc.)
    pub fn with_flags(interface: &str, flags: XdpFlags) -> Result<Self> {
        info!("Loading veth-filter XDP program for {}", interface);

        // Load the eBPF program
        // Note: eBPF is built separately in filter-ebpf with standalone workspace
        // Path is relative to this source file (src/lib.rs)
        #[cfg(debug_assertions)]
        let data = include_bytes_aligned!(
            "../../filter-ebpf/target/bpfel-unknown-none/debug/veth-filter"
        );
        #[cfg(not(debug_assertions))]
        let data = include_bytes_aligned!(
            "../../filter-ebpf/target/bpfel-unknown-none/release/veth-filter"
        );

        let mut bpf = Ebpf::load(data).context("Failed to load eBPF program")?;

        // Initialize logging (optional)
        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            debug!("eBPF logger not available: {}", e);
        }

        // Get and load the XDP program
        let program: &mut Xdp = bpf
            .program_mut("veth_filter")
            .context("XDP program 'veth_filter' not found")?
            .try_into()
            .context("Program is not XDP")?;

        program.load().context("Failed to load XDP program")?;
        info!("XDP program loaded");

        // Try to attach with requested flags, fall back to SKB mode
        let attach_result = program.attach(interface, flags);
        match attach_result {
            Ok(_) => {
                let mode = if flags.contains(XdpFlags::DRV_MODE) {
                    "native driver"
                } else if flags.contains(XdpFlags::SKB_MODE) {
                    "SKB"
                } else {
                    "default"
                };
                info!("XDP program attached to {} in {} mode", interface, mode);
            }
            Err(e) if !flags.contains(XdpFlags::SKB_MODE) => {
                warn!("Requested XDP mode failed ({}), trying SKB mode", e);
                program
                    .attach(interface, XdpFlags::SKB_MODE)
                    .context("Failed to attach XDP program in SKB mode")?;
                info!("XDP program attached to {} in SKB mode", interface);
            }
            Err(e) => {
                return Err(e).context("Failed to attach XDP program");
            }
        }

        Ok(Self {
            bpf: Arc::new(RwLock::new(bpf)),
            interface: interface.to_string(),
        })
    }

    /// Get the interface name
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Get current statistics
    pub async fn stats(&self) -> Result<FilterStats> {
        let bpf = self.bpf.read().await;

        let stats: PerCpuArray<_, u64> = bpf
            .map("STATS")
            .context("STATS map not found")?
            .try_into()
            .context("Wrong map type for STATS")?;

        let total = stats.get(&0, 0).map(|v| sum_percpu(&v)).unwrap_or(0);
        let passed = stats.get(&1, 0).map(|v| sum_percpu(&v)).unwrap_or(0);
        let dropped = stats.get(&2, 0).map(|v| sum_percpu(&v)).unwrap_or(0);
        let sampled = stats.get(&3, 0).map(|v| sum_percpu(&v)).unwrap_or(0);

        Ok(FilterStats {
            total_packets: total,
            passed_packets: passed,
            dropped_packets: dropped,
            sampled_packets: sampled,
        })
    }

    /// Set sample rate (1 = every packet, N = 1 in N, 0 = disabled)
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

        config.set(0, values, 0).context("Failed to set sample rate")?;
        info!("Sample rate set to {}", rate);
        Ok(())
    }

    /// Set enforce mode (true = drop matching packets, false = detect only)
    pub async fn set_enforce_mode(&self, enforce: bool) -> Result<()> {
        let mut bpf = self.bpf.write().await;

        let mut config: PerCpuArray<_, u32> = bpf
            .map_mut("CONFIG")
            .context("CONFIG map not found")?
            .try_into()
            .context("Wrong map type for CONFIG")?;

        let num_cpus = aya::util::nr_cpus()
            .map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))?;
        let values = PerCpuValues::try_from(vec![if enforce { 1u32 } else { 0u32 }; num_cpus])
            .context("Failed to create per-CPU values")?;

        config.set(1, values, 0).context("Failed to set enforce mode")?;
        info!("Enforce mode set to {}", enforce);
        Ok(())
    }

    /// Add a rule to the filter
    pub async fn add_rule(&self, rule: &Rule) -> Result<()> {
        let key = rule.to_key()?;
        let value = rule.to_value();

        let mut bpf = self.bpf.write().await;
        let mut rules: HashMap<_, RuleKey, RuleValue> = bpf
            .map_mut("RULES")
            .context("RULES map not found")?
            .try_into()
            .context("Wrong map type for RULES")?;

        rules.insert(key, value, 0).context("Failed to insert rule")?;
        info!("Added rule: {:?} -> {:?}", rule.rule_type, rule.action);
        Ok(())
    }

    /// Remove a rule from the filter
    pub async fn remove_rule(&self, rule: &Rule) -> Result<()> {
        let key = rule.to_key()?;

        let mut bpf = self.bpf.write().await;
        let mut rules: HashMap<_, RuleKey, RuleValue> = bpf
            .map_mut("RULES")
            .context("RULES map not found")?
            .try_into()
            .context("Wrong map type for RULES")?;

        rules.remove(&key).context("Failed to remove rule")?;
        info!("Removed rule: {:?}", rule.rule_type);
        Ok(())
    }

    /// List all current rules with their match counts
    pub async fn list_rules(&self) -> Result<Vec<(Rule, u64)>> {
        let bpf = self.bpf.read().await;
        let rules: HashMap<_, RuleKey, RuleValue> = bpf
            .map("RULES")
            .context("RULES map not found")?
            .try_into()
            .context("Wrong map type for RULES")?;

        let mut result = Vec::new();
        for item in rules.iter() {
            if let Ok((key, value)) = item {
                let rule_type = match key.rule_type {
                    0 => RuleType::SrcIp,
                    1 => RuleType::DstIp,
                    2 => RuleType::SrcPort,
                    3 => RuleType::DstPort,
                    4 => RuleType::Protocol,
                    _ => continue,
                };

                let value_str = match rule_type {
                    RuleType::SrcIp | RuleType::DstIp => {
                        Ipv4Addr::from(key.value.to_be_bytes()).to_string()
                    }
                    RuleType::SrcPort | RuleType::DstPort => {
                        (key.value as u16).to_string()
                    }
                    RuleType::Protocol => {
                        (key.value as u8).to_string()
                    }
                };

                let action = match value.action {
                    0 => RuleAction::Pass,
                    1 => RuleAction::Drop,
                    2 => RuleAction::RateLimit,
                    _ => continue,
                };

                let rule = Rule {
                    rule_type,
                    value: value_str,
                    action,
                    rate_pps: if value.rate_pps > 0 { Some(value.rate_pps) } else { None },
                };

                result.push((rule, value.match_count));
            }
        }

        Ok(result)
    }

    /// Clear all rules
    pub async fn clear_rules(&self) -> Result<()> {
        let rules = self.list_rules().await?;
        for (rule, _) in rules {
            self.remove_rule(&rule).await?;
        }
        info!("All rules cleared");
        Ok(())
    }

    /// Take ownership of the perf array for sample reading
    /// Call this once and use the returned AsyncPerfEventArray for polling samples
    pub async fn take_perf_array(&self) -> Result<AsyncPerfEventArray<MapData>> {
        let mut bpf = self.bpf.write().await;
        
        let samples = bpf
            .take_map("SAMPLES")
            .context("SAMPLES map not found")?;
        
        AsyncPerfEventArray::try_from(samples)
            .context("Failed to create AsyncPerfEventArray from SAMPLES")
    }

    /// Get a reference to the underlying BPF object for advanced use
    pub fn bpf(&self) -> Arc<RwLock<Ebpf>> {
        self.bpf.clone()
    }
}

impl Drop for VethFilter {
    fn drop(&mut self) {
        info!("Detaching XDP filter from {}", self.interface);
    }
}

/// Sum per-CPU values
fn sum_percpu(values: &PerCpuValues<u64>) -> u64 {
    values.iter().sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_key_conversion() {
        let rule = Rule::drop_src_ip(Ipv4Addr::new(10, 0, 0, 1));
        let key = rule.to_key().unwrap();
        
        assert_eq!(key.rule_type, RuleType::SrcIp as u8);
        // 10.0.0.1 in network order
        assert_eq!(key.value, u32::from_be_bytes([10, 0, 0, 1]));
    }

    #[test]
    fn test_port_rule() {
        let rule = Rule::drop_dst_port(53);
        let key = rule.to_key().unwrap();
        
        assert_eq!(key.rule_type, RuleType::DstPort as u8);
        assert_eq!(key.value, 53);
    }
}
