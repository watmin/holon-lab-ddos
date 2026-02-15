# Build Instructions for veth-lab

## TL;DR - The Right Way to Build

```bash
cd /home/watmin/work/holon/holon-lab-ddos
./veth-lab/scripts/build.sh
```

This is the **CORRECT** way to build everything. Use this script!

## What the Build Script Does

The `veth-lab/scripts/build.sh` script:

1. **Builds the eBPF program** (`filter-ebpf`)
   - Uses Rust nightly toolchain
   - Targets `bpfel-unknown-none` (eBPF architecture)
   - Requires `bpf-linker` (install: `cargo install bpf-linker`)
   - Output: `veth-lab/filter-ebpf/target/bpfel-unknown-none/release/veth-filter`

2. **Builds userspace components** (release mode)
   - `veth-filter` - XDP loader and rule manager
   - `veth-generator` - Traffic generator
   - `veth-sidecar` - Holon detection sidecar with metrics dashboard
   - Output: `target/release/{veth-loader,veth-generator,veth-sidecar}`

## Why NOT Just `cargo build --release`?

Running `cargo build --release` from the root **will skip the eBPF program** because it uses a different target architecture and build process.

You **MUST** use the build script to get both:
- eBPF kernel component
- Userspace binaries

## After Building

The script will show you the binary locations:

```
Binaries:
  target/release/veth-loader     - XDP loader and rule manager
  target/release/veth-generator  - Traffic generator
  target/release/veth-sidecar    - Holon detection sidecar

eBPF:
  veth-lab/filter-ebpf/target/bpfel-unknown-none/release/veth-filter
```

## Quick Check: Is My Binary Up-to-Date?

```bash
# Check binary timestamp
ls -lh target/release/veth-sidecar

# Check if metrics dashboard code is in the binary
strings target/release/veth-sidecar | grep "METRICS DASHBOARD"
```

If you don't see "METRICS DASHBOARD" in the strings output, rebuild!

## Development Workflow

When making changes to the sidecar:

1. Edit code in `veth-lab/sidecar/src/`
2. Run `./veth-lab/scripts/build.sh`
3. Stop the old sidecar process
4. Run the new binary: `sudo ./target/release/veth-sidecar ...`

## Common Mistakes

❌ **DON'T**: `cd holon-lab-ddos && cargo build --release`
   - Skips eBPF build

❌ **DON'T**: `cd veth-lab/sidecar && cargo build --release`
   - Wrong working directory
   - Won't find workspace dependencies

✅ **DO**: `cd holon-lab-ddos && ./veth-lab/scripts/build.sh`
   - Correct!

## Build Time

Expected build times on first build:
- eBPF program: ~30 seconds
- Userspace components: ~2-3 minutes (incremental builds much faster)

## Dependencies

Required tools (one-time setup):

1. **Rust nightly toolchain**:
   ```bash
   rustup toolchain install nightly
   ```

2. **bpf-linker** (eBPF linker tool):
   ```bash
   cargo install bpf-linker
   ```
   This takes ~30 seconds to build and install.

The build script will check for `bpf-linker` and fail with a clear error if missing.

## First Time Setup

If you get the error:
```
[ERROR] bpf-linker not found. Install with: cargo install bpf-linker
```

Just run the install command once:
```bash
cargo install bpf-linker
```

Then re-run the build script.
