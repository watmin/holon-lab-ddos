#!/usr/bin/env python3
"""Decode TREE_COUNTERS map and show which counters fired."""

import subprocess
import struct
import sys

# Our count actions from rules-feature-test.edn
EXPECTED_COUNTERS = {
    "monitor:udp-total": ["monitor", "udp-total"],
    "monitor:dns-queries": ["monitor", "dns-queries"],
    "monitor:ntp-packets": ["monitor", "ntp-packets"],
    "monitor:port-9999": ["monitor", "port-9999"],
}

def hash_name(namespace, name):
    """Compute the bucket key hash (same as Rust DefaultHasher)."""
    # This is a simplification - we'll just show the raw keys
    # and let the user correlate them
    import hashlib
    # Python's hash is different from Rust's DefaultHasher
    # So we'll just show what we find
    pass

def decode_counters():
    """Dump and decode TREE_COUNTERS map."""
    try:
        result = subprocess.run(
            ["sudo", "bpftool", "map", "dump", "name", "TREE_COUNTERS"],
            capture_output=True,
            text=True,
            check=True
        )
        
        lines = result.stdout.strip().split('\n')
        counters = []
        
        for line in lines:
            if line.startswith("key:"):
                # Parse key and value from bpftool output
                # Format: "key: XX XX XX XX  value: YY YY YY YY YY YY YY YY"
                parts = line.split("value:")
                if len(parts) == 2:
                    key_hex = parts[0].replace("key:", "").strip().split()
                    val_hex = parts[1].strip().split()
                    
                    # Convert hex bytes to integers (little-endian)
                    key_bytes = bytes([int(b, 16) for b in key_hex])
                    val_bytes = bytes([int(b, 16) for b in val_hex])
                    
                    key = struct.unpack('<I', key_bytes)[0]
                    value = struct.unpack('<Q', val_bytes)[0]
                    
                    counters.append((key, value))
        
        return counters
        
    except subprocess.CalledProcessError as e:
        print(f"Error running bpftool: {e}")
        return []
    except Exception as e:
        print(f"Error decoding counters: {e}")
        return []

def main():
    print("=== TREE_COUNTERS Dump ===\n")
    
    counters = decode_counters()
    
    if not counters:
        print("No counters found or error reading map")
        return 1
    
    print(f"Found {len(counters)} counter entries:\n")
    
    for key, value in sorted(counters, key=lambda x: x[1], reverse=True):
        print(f"  Key: 0x{key:08x} ({key:10d}) → Count: {value:,} packets")
    
    print(f"\n=== Expected Counters ===\n")
    for name, (ns, n) in EXPECTED_COUNTERS.items():
        print(f"  {name:25s} → [{ns:10s}, {n:15s}]")
    
    print(f"\n=== Analysis ===\n")
    print(f"Expected: {len(EXPECTED_COUNTERS)} counters")
    print(f"Found:    {len(counters)} counters")
    
    if len(counters) == len(EXPECTED_COUNTERS):
        print("\n✅ Counter count matches!")
    elif len(counters) < len(EXPECTED_COUNTERS):
        print(f"\n⚠️  Missing {len(EXPECTED_COUNTERS) - len(counters)} counters")
        print("    This means some count rules didn't match any traffic")
    else:
        print(f"\n⚠️  Extra {len(counters) - len(EXPECTED_COUNTERS)} counters")
        print("    This could be from Holon-generated rules")
    
    print("\n=== Traffic Pattern Analysis ===\n")
    total_packets = sum(v for _, v in counters)
    print(f"Total counted packets: {total_packets:,}")
    
    for key, value in sorted(counters, key=lambda x: x[1], reverse=True):
        pct = (value / total_packets) * 100 if total_packets > 0 else 0
        print(f"  Key 0x{key:08x}: {value:10,} packets ({pct:5.1f}%)")
    
    print("\n=== To identify which counter is which ===")
    print("Look at the packet counts and correlate with traffic:")
    print("  - Highest count likely = 'udp-total' (matches ALL UDP)")
    print("  - Next highest = 'port-9999' (if attack traffic went there)")
    print("  - Lower/zero counts = dns-queries, ntp-packets (if no traffic to those ports)")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
