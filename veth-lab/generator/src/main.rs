//! Veth Lab Traffic Generator
//!
//! Generates test traffic for XDP filter development.
//! Runs inside the veth-lab-gen namespace.
//!
//! Usage:
//!   sudo ip netns exec veth-lab-gen ./target/release/veth-generator
//!
//! Supports:
//! - Normal traffic patterns (baseline)
//! - Attack bursts (high rate from specific sources)
//! - Mixed traffic for detection testing

use anyhow::Result;
use clap::{Parser, ValueEnum};
use rand::{Rng, SeedableRng};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(name = "veth-generator")]
#[command(about = "Generate test traffic for XDP filter")]
struct Args {
    /// Interface to send on (inside namespace)
    #[arg(short, long, default_value = "veth-gen")]
    interface: String,

    /// Target IP address
    #[arg(short, long, default_value = "10.100.0.2")]
    target: String,

    /// Traffic pattern to generate
    #[arg(short, long, default_value = "mixed")]
    pattern: TrafficPattern,

    /// Packets per second (0 = max speed)
    #[arg(short = 'r', long, default_value = "1000")]
    pps: u32,

    /// Duration in seconds (0 = run forever)
    #[arg(short, long, default_value = "30")]
    duration: u64,

    /// Source IP for attack traffic (spoofed)
    #[arg(long, default_value = "10.0.0.100")]
    attack_src: String,

    /// Destination port for normal traffic
    #[arg(long, default_value = "8888")]
    normal_port: u16,

    /// Destination port for attack traffic  
    #[arg(long, default_value = "9999")]
    attack_port: u16,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TrafficPattern {
    /// Normal traffic only (varied sources, normal ports)
    Normal,
    /// Attack traffic only (single source, attack port)
    Attack,
    /// Mixed: normal baseline with periodic attack bursts
    Mixed,
    /// Ramp: gradually increase attack ratio
    Ramp,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();
    
    info!("Veth Lab Traffic Generator");
    info!("  Interface: {}", args.interface);
    info!("  Target: {}", args.target);
    info!("  Pattern: {:?}", args.pattern);
    info!("  PPS: {}", if args.pps == 0 { "max".to_string() } else { args.pps.to_string() });
    info!("  Duration: {}s", if args.duration == 0 { "infinite".to_string() } else { args.duration.to_string() });
    
    let target_ip: Ipv4Addr = args.target.parse()?;
    let attack_src: Ipv4Addr = args.attack_src.parse()?;

    // Stats
    let running = Arc::new(AtomicBool::new(true));
    let packets_sent = Arc::new(AtomicU64::new(0));
    let bytes_sent = Arc::new(AtomicU64::new(0));

    // Handle Ctrl+C
    let running_clone = running.clone();
    ctrlc_handler(running_clone);

    // Create socket
    let socket = create_packet_socket(&args.interface)?;

    // Get MACs
    let src_mac = get_interface_mac(&args.interface)?;
    let dst_mac = get_interface_mac("veth-gen")?;  // Same interface, we're on the gen side

    info!("Socket ready, starting traffic generation...");
    info!("");

    // Traffic generation loop
    let start = Instant::now();
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut last_report = Instant::now();
    let mut last_count = 0u64;
    
    // For mixed pattern: track phases
    let phase_duration = Duration::from_secs(5);
    let mut phase_start = Instant::now();
    let mut in_attack_phase = false;

    while running.load(Ordering::Relaxed) {
        // Check duration
        if args.duration > 0 && start.elapsed().as_secs() >= args.duration {
            info!("Duration reached, stopping");
            break;
        }

        // Determine if this packet is attack or normal based on pattern
        let is_attack = match args.pattern {
            TrafficPattern::Normal => false,
            TrafficPattern::Attack => true,
            TrafficPattern::Mixed => {
                // 5 seconds normal, 5 seconds attack
                if phase_start.elapsed() >= phase_duration {
                    in_attack_phase = !in_attack_phase;
                    phase_start = Instant::now();
                    if in_attack_phase {
                        info!(">>> Attack phase started");
                    } else {
                        info!("<<< Normal phase started");
                    }
                }
                in_attack_phase
            }
            TrafficPattern::Ramp => {
                // Gradually increase attack ratio: 0% -> 100% over duration
                let progress = if args.duration > 0 {
                    start.elapsed().as_secs_f64() / args.duration as f64
                } else {
                    (start.elapsed().as_secs() % 60) as f64 / 60.0
                };
                rng.gen::<f64>() < progress
            }
        };

        // Generate packet
        let (src_ip, dst_port) = if is_attack {
            (attack_src, args.attack_port)
        } else {
            // Normal traffic: random source in 192.168.x.x range
            let src = Ipv4Addr::new(192, 168, rng.gen_range(1..255), rng.gen_range(1..255));
            (src, args.normal_port)
        };

        let src_port: u16 = rng.gen_range(10000..60000);
        
        // Build and send UDP packet
        let packet = craft_udp_packet(
            &src_mac,
            &dst_mac,
            src_ip,
            target_ip,
            src_port,
            dst_port,
            b"VETH-LAB-TEST",
        );

        match send_packet(socket, &packet) {
            Ok(n) => {
                packets_sent.fetch_add(1, Ordering::Relaxed);
                bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) => {
                if running.load(Ordering::Relaxed) {
                    tracing::warn!("Send error: {}", e);
                }
            }
        }

        // Rate limiting
        if args.pps > 0 {
            let target_interval = Duration::from_nanos(1_000_000_000 / args.pps as u64);
            // Simple busy-wait for accurate timing at high PPS
            // In production, we'd batch packets
            std::thread::sleep(target_interval.saturating_sub(Duration::from_micros(50)));
        }

        // Periodic stats report
        if last_report.elapsed() >= Duration::from_secs(2) {
            let current = packets_sent.load(Ordering::Relaxed);
            let pps = (current - last_count) / 2;
            let total_bytes = bytes_sent.load(Ordering::Relaxed);
            
            info!(
                "Stats: {} packets sent ({} pps), {:.2} KB",
                current,
                pps,
                total_bytes as f64 / 1024.0
            );
            
            last_count = current;
            last_report = Instant::now();
        }
    }

    // Final stats
    let total = packets_sent.load(Ordering::Relaxed);
    let total_bytes = bytes_sent.load(Ordering::Relaxed);
    let elapsed = start.elapsed().as_secs_f64();
    
    info!("");
    info!("=== Final Stats ===");
    info!("  Total packets: {}", total);
    info!("  Total bytes: {:.2} KB", total_bytes as f64 / 1024.0);
    info!("  Duration: {:.2}s", elapsed);
    info!("  Average PPS: {:.0}", total as f64 / elapsed);

    // Close socket
    unsafe { libc::close(socket); }

    Ok(())
}

fn ctrlc_handler(running: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let mut signals = signal_hook::iterator::Signals::new(&[signal_hook::consts::SIGINT])
            .expect("Failed to register signal handler");
        for _ in signals.forever() {
            info!("\nReceived Ctrl+C, stopping...");
            running.store(false, Ordering::Relaxed);
            break;
        }
    });
}

fn create_packet_socket(interface: &str) -> Result<i32> {
    // Create AF_PACKET socket
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_ALL as u16).to_be() as i32,
        )
    };
    
    if fd < 0 {
        return Err(anyhow::anyhow!(
            "Failed to create packet socket: {}. Need CAP_NET_RAW",
            std::io::Error::last_os_error()
        ));
    }

    // Get interface index
    let ifindex = get_ifindex(interface)?;

    // Bind to interface
    let sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
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
        return Err(anyhow::anyhow!(
            "Failed to bind to {}: {}",
            interface,
            std::io::Error::last_os_error()
        ));
    }

    Ok(fd)
}

fn get_ifindex(name: &str) -> Result<i32> {
    let name_cstr = std::ffi::CString::new(name)?;
    let idx = unsafe { libc::if_nametoindex(name_cstr.as_ptr()) };
    if idx == 0 {
        return Err(anyhow::anyhow!("Interface {} not found", name));
    }
    Ok(idx as i32)
}

fn get_interface_mac(name: &str) -> Result<[u8; 6]> {
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

fn craft_udp_packet(
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let ip_len = 20 + udp_len;
    let total_len = 14 + ip_len;
    
    let mut packet = vec![0u8; total_len];
    
    // Ethernet header (14 bytes)
    packet[0..6].copy_from_slice(dst_mac);
    packet[6..12].copy_from_slice(src_mac);
    packet[12..14].copy_from_slice(&(0x0800u16).to_be_bytes());  // IPv4
    
    // IP header (20 bytes)
    let ip_offset = 14;
    packet[ip_offset] = 0x45;  // Version + IHL
    packet[ip_offset + 1] = 0x00;  // DSCP + ECN
    packet[ip_offset + 2..ip_offset + 4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    packet[ip_offset + 4..ip_offset + 6].copy_from_slice(&rand::random::<u16>().to_be_bytes());  // ID
    packet[ip_offset + 6] = 0x40;  // Flags: DF
    packet[ip_offset + 7] = 0x00;  // Fragment offset
    packet[ip_offset + 8] = 64;  // TTL
    packet[ip_offset + 9] = 17;  // Protocol: UDP
    // Checksum at 10-11
    packet[ip_offset + 12..ip_offset + 16].copy_from_slice(&src_ip.octets());
    packet[ip_offset + 16..ip_offset + 20].copy_from_slice(&dst_ip.octets());
    
    // IP checksum
    let ip_csum = checksum(&packet[ip_offset..ip_offset + 20]);
    packet[ip_offset + 10..ip_offset + 12].copy_from_slice(&ip_csum.to_be_bytes());
    
    // UDP header (8 bytes)
    let udp_offset = 34;
    packet[udp_offset..udp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[udp_offset + 4..udp_offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // UDP checksum at 6-7 (optional for IPv4, leave as 0)
    
    // Payload
    packet[udp_offset + 8..].copy_from_slice(payload);
    
    packet
}

fn send_packet(fd: i32, packet: &[u8]) -> Result<usize> {
    let ret = unsafe {
        libc::send(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
        )
    };
    
    if ret < 0 {
        Err(anyhow::anyhow!("send failed: {}", std::io::Error::last_os_error()))
    } else {
        Ok(ret as usize)
    }
}

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
