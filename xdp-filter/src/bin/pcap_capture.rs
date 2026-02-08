//! Packet capture binary - samples packets from XDP filter and writes to pcap
//!
//! Usage: pcap_capture <interface> <output.pcap> [sample_rate]
//!
//! Example: pcap_capture eth1 attack.pcap 1   # Sample every packet
//!          pcap_capture eth1 attack.pcap 100 # Sample 1 in 100 packets

use anyhow::{Context, Result};
use aya::util::online_cpus;
use bytes::BytesMut;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{info, error};
use tracing_subscriber::EnvFilter;
use xdp_filter::{FilterMode, PacketSample, XdpFilter, SAMPLE_SIZE};

/// Pcap global header (24 bytes)
#[repr(C, packed)]
struct PcapGlobalHeader {
    magic_number: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    network: u32,
}

/// Pcap packet header (16 bytes)
#[repr(C, packed)]
struct PcapPacketHeader {
    ts_sec: u32,
    ts_usec: u32,
    incl_len: u32,
    orig_len: u32,
}

impl PcapGlobalHeader {
    fn new() -> Self {
        Self {
            magic_number: 0xa1b2c3d4, // Standard pcap magic
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: SAMPLE_SIZE as u32,
            network: 1, // LINKTYPE_ETHERNET
        }
    }

    fn to_bytes(&self) -> [u8; 24] {
        unsafe { std::mem::transmute_copy(self) }
    }
}

impl PcapPacketHeader {
    fn new(incl_len: u32, orig_len: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            ts_sec: now.as_secs() as u32,
            ts_usec: now.subsec_micros(),
            incl_len,
            orig_len,
        }
    }

    fn to_bytes(&self) -> [u8; 16] {
        unsafe { std::mem::transmute_copy(self) }
    }
}

/// Captured packet with sampled data
struct CapturedPacket {
    /// Original packet length
    orig_len: u32,
    /// Captured length
    cap_len: u32,
    /// Is this an attack packet?
    is_attack: bool,
    /// Captured packet data (up to SAMPLE_SIZE bytes)
    data: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <interface> <output.pcap> [sample_rate]", args[0]);
        eprintln!("  interface: Network interface to capture from (e.g., eth1)");
        eprintln!("  output.pcap: Output pcap file path");
        eprintln!("  sample_rate: 1 = every packet, 100 = 1/100 (default: 1)");
        std::process::exit(1);
    }

    let interface = &args[1];
    let pcap_path = &args[2];
    let sample_rate: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1);

    info!("=== XDP Packet Capture ===");
    info!("Interface: {}", interface);
    info!("Output: {}", pcap_path);
    info!("Sample rate: 1 in {} packets", sample_rate);
    info!("Capture size: {} bytes per packet", SAMPLE_SIZE);

    // Load and attach XDP filter
    let filter = XdpFilter::new(interface)?;
    
    // Set to detect mode (pass all packets, but sample them)
    filter.set_mode(FilterMode::Detect).await?;
    
    // Enable sampling
    filter.set_sample_rate(sample_rate).await?;

    // Take ownership of the perf array
    let mut perf_array = filter.take_samples_perf_array().await?;

    // Create channel for packets from all CPUs
    let (tx, mut rx) = mpsc::channel::<CapturedPacket>(10000);

    // Stats counters
    let packets_captured = Arc::new(AtomicU64::new(0));
    let attack_packets = Arc::new(AtomicU64::new(0));
    let bytes_captured = Arc::new(AtomicU64::new(0));

    // Spawn a task for each online CPU to read from perf buffer
    let cpus = online_cpus().map_err(|(msg, e)| anyhow::anyhow!("{}: {}", msg, e))?;
    info!("Starting capture on {} CPUs", cpus.len());

    // Size of PacketSample struct
    let sample_struct_size = std::mem::size_of::<PacketSample>();
    info!("PacketSample struct size: {} bytes", sample_struct_size);

    for cpu_id in cpus {
        let mut buf = perf_array
            .open(cpu_id, None)
            .context(format!("Failed to open perf buffer for CPU {}", cpu_id))?;

        let tx = tx.clone();

        tokio::spawn(async move {
            let mut buffers = (0..16)
                .map(|_| BytesMut::with_capacity(4096))
                .collect::<Vec<_>>();

            loop {
                // Wait for events
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        error!("Error reading perf events on CPU {}: {}", cpu_id, e);
                        continue;
                    }
                };

                for i in 0..events.read {
                    let event_buf = &buffers[i];
                    
                    // The buffer should contain a PacketSample struct
                    let expected_size = std::mem::size_of::<PacketSample>();
                    if event_buf.len() < expected_size {
                        error!("Short buffer: {} < {}", event_buf.len(), expected_size);
                        continue;
                    }

                    // Read the PacketSample struct
                    let sample = unsafe {
                        std::ptr::read_unaligned(event_buf.as_ptr() as *const PacketSample)
                    };

                    // Extract the captured packet data
                    let cap_len = sample.cap_len as usize;
                    let packet_data = sample.data[..cap_len.min(SAMPLE_SIZE)].to_vec();

                    if tx
                        .send(CapturedPacket {
                            orig_len: sample.pkt_len,
                            cap_len: sample.cap_len,
                            is_attack: sample.is_attack != 0,
                            data: packet_data,
                        })
                        .await
                        .is_err()
                    {
                        // Receiver dropped, exit
                        return;
                    }
                }
            }
        });
    }

    // Drop the original sender so the channel closes when all CPU tasks finish
    drop(tx);

    // Create pcap file
    let pcap_path = Path::new(pcap_path);
    let mut pcap_file = File::create(pcap_path).context("Failed to create pcap file")?;
    
    // Write pcap global header
    let global_header = PcapGlobalHeader::new();
    pcap_file.write_all(&global_header.to_bytes())?;
    pcap_file.flush()?;
    
    info!("Pcap file created: {}", pcap_path.display());
    info!("Capturing packets... Press Ctrl+C to stop");

    let packets_captured_clone = packets_captured.clone();
    let attack_packets_clone = attack_packets.clone();
    let bytes_captured_clone = bytes_captured.clone();

    // Spawn stats printer
    let stats_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            let total = packets_captured_clone.load(Ordering::Relaxed);
            let attacks = attack_packets_clone.load(Ordering::Relaxed);
            let bytes = bytes_captured_clone.load(Ordering::Relaxed);
            info!(
                "Captured: {} packets ({} attack) | {} bytes",
                total, attacks, bytes
            );
        }
    });

    // Handle Ctrl+C
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    // Receive and write packets
    loop {
        tokio::select! {
            Some(pkt) = rx.recv() => {
                // Write pcap packet header (captured len, original len)
                let pkt_header = PcapPacketHeader::new(pkt.cap_len, pkt.orig_len);
                pcap_file.write_all(&pkt_header.to_bytes())?;
                
                // Write packet data
                pcap_file.write_all(&pkt.data)?;
                
                // Update stats
                packets_captured.fetch_add(1, Ordering::Relaxed);
                bytes_captured.fetch_add(pkt.data.len() as u64, Ordering::Relaxed);
                if pkt.is_attack {
                    attack_packets.fetch_add(1, Ordering::Relaxed);
                }
            }
            _ = &mut shutdown => {
                info!("\nShutting down...");
                break;
            }
        }
    }

    stats_handle.abort();
    pcap_file.flush()?;

    let total = packets_captured.load(Ordering::Relaxed);
    let attacks = attack_packets.load(Ordering::Relaxed);
    let bytes = bytes_captured.load(Ordering::Relaxed);

    info!("=== Capture Complete ===");
    info!("Total packets: {}", total);
    info!("Attack packets: {}", attacks);
    info!("Total bytes: {}", bytes);
    info!("Output file: {}", pcap_path.display());
    info!("Open with: wireshark {} or tcpdump -r {}", pcap_path.display(), pcap_path.display());

    Ok(())
}
