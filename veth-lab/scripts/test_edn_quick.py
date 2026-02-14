#!/usr/bin/env python3
"""Quick EDN parser test - validates EDN syntax without running full sidecar."""

import sys
import subprocess

def test_parse_edn(edn_file, count=10):
    """Test parsing EDN rules by feeding to Rust parser."""
    
    # Create a minimal Rust test program
    rust_test = '''
use std::io::{self, BufRead};
use edn_rs::Edn;

fn main() {
    let stdin = io::stdin();
    let mut line_num = 0;
    let mut success = 0;
    let mut failed = 0;
    
    for line in stdin.lock().lines() {
        line_num += 1;
        let line = line.unwrap();
        let line = line.trim();
        
        // Skip empty lines and comments
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        
        // Try to parse as EDN
        match line.parse::<Edn>() {
            Ok(edn) => {
                println!("✓ Line {}: OK", line_num);
                success += 1;
            }
            Err(e) => {
                println!("✗ Line {}: FAILED - {:?}", line_num, e);
                println!("  {}", line);
                failed += 1;
            }
        }
        
        if line_num >= %COUNT% {
            break;
        }
    }
    
    println!("");
    println!("Summary: {} OK, {} FAILED", success, failed);
    if failed > 0 {
        std::process::exit(1);
    }
}
'''.replace('%COUNT%', str(count))
    
    # Write temp Rust file
    with open('/tmp/test_edn_parse.rs', 'w') as f:
        f.write(rust_test)
    
    # Compile it
    print(f"Compiling EDN parser test...")
    result = subprocess.run(
        ['rustc', '/tmp/test_edn_parse.rs', '-o', '/tmp/test_edn_parse', 
         '--edition', '2021', '--extern', 'edn_rs'],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        print("Compilation failed:")
        print(result.stderr)
        return False
    
    # Run it
    print(f"\nTesting first {count} lines of {edn_file}...\n")
    with open(edn_file) as f:
        result = subprocess.run(
            ['/tmp/test_edn_parse'],
            stdin=f,
            capture_output=True, text=True
        )
    
    print(result.stdout)
    if result.stderr:
        print("Stderr:", result.stderr)
    
    return result.returncode == 0

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: test_edn_quick.py <edn-file> [count]")
        sys.exit(1)
    
    edn_file = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    
    success = test_parse_edn(edn_file, count)
    sys.exit(0 if success else 1)
