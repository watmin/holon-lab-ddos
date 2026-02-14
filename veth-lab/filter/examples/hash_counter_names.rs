use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn main() {
    let counters = vec![
        ("monitor", "udp-total"),
        ("monitor", "dns-queries"),
        ("monitor", "ntp-packets"),
        ("monitor", "port-9999"),
    ];
    
    println!("Expected counter hashes:\n");
    for (ns, name) in counters {
        let mut hasher = DefaultHasher::new();
        ns.hash(&mut hasher);
        name.hash(&mut hasher);
        let hash = hasher.finish() as u32;
        let hash_nonzero = if hash == 0 { 1 } else { hash };
        println!("  [\"{}\" \"{}\"]: 0x{:08x} ({})", ns, name, hash_nonzero, hash_nonzero);
    }
    
    println!("\nFound in eBPF map:");
    println!("  0xb65c0e6a (3,060,899,434)");
}
