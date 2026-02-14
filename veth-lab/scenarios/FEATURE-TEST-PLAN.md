# Feature Test Success Criteria

## Test Setup
```bash
# Terminal 1: Start sidecar with feature test rules
sudo ./target/release/veth-sidecar \
  --interface veth-filter \
  --enforce \
  --rate-limit \
  --rules-file veth-lab/scenarios/rules-feature-test.edn \
  --warmup-windows 15 \
  --warmup-packets 1500 \
  --sample-rate 100 \
  --min-packets 30 \
  --log-dir logs

# Terminal 2: Generate traffic (create scenario file - see below)
sudo ip netns exec veth-lab-gen ./target/release/veth-generator \
  --interface veth-gen \
  --scenario-file veth-lab/scenarios/feature-test-traffic.json \
  --log-dir logs
```

## Success Criteria

### 1. Rule Loading ✅
**Expected:**
- Parse 19 rules successfully from EDN
- Compile to tree with rate buckets
- Log shows: "Parsed 19 rules from ... in Xµs"
- Log shows: "Tree compiled: N nodes, M edges, **6 rate buckets**"

**Key metric:** `6 rate buckets` (not 11)
- 3 named buckets: `["attack", "dns-amp"]`, `["attack", "ntp-amp"]`, `["attack", "flood-9999"]`
- 3 unnamed buckets (per-rule)

### 2. Count Actions (Non-Terminating) ✅
**Expected behavior:**
- Count actions increment counters WITHOUT dropping packets
- Multiple count rules can match same packet
- Count + terminating action can both match

**Test:**
1. Send UDP traffic that matches count rules
2. Verify counters increment (eBPF map `TREE_COUNTERS`)
3. Verify traffic is NOT blocked by count actions
4. If count rule + rate-limit rule both match, BOTH should fire

**Observation:**
- Check eBPF map: `sudo bpftool map dump name TREE_COUNTERS`
- Should see 4 counter entries with non-zero counts

### 3. Named Rate Limiter Buckets (Shared) ✅
**Expected behavior:**
- Multiple rules with same `[namespace, name]` share ONE bucket
- Token depletion affects ALL rules with that name

**Test - DNS amplification:**
1. Send DNS traffic from `10.0.0.100` (matches rule 1)
2. Send DNS traffic from `10.0.0.101` (matches rule 2)
3. Send DNS traffic from `10.0.0.102` (matches rule 3)

**Expected:**
- All 3 rules share `["attack", "dns-amp"]` bucket (1000 pps limit)
- Combined traffic from all 3 sources is capped at 1000 pps total
- If source 100 exhausts tokens, sources 101 and 102 are also limited

**How to verify:**
- Generate >1000 pps from source 100 alone → should get rate-limited
- Then add 500 pps from source 101 → source 100 should see MORE drops (shared bucket)
- Check XDP stats: `dropped rate:N` should increase

### 4. Unnamed Rate Limiters (Per-Rule) ✅
**Expected behavior:**
- Rules without `:name` get independent buckets
- Each rule's limit is independent

**Test:**
1. Send UDP from `10.0.0.120` (per-rule limiter, 100 pps)
2. Send UDP from `10.0.0.121` (different per-rule limiter, 100 pps)

**Expected:**
- Each can send up to 100 pps independently
- Exhausting 120's limit does NOT affect 121's limit

### 5. Priority and Non-Terminating Interaction ✅
**Expected behavior:**
- Count actions (priority 50-100) don't prevent higher-priority terminating actions
- Packet can match count rule AND terminating rule

**Test - Port 9999 traffic:**
1. Send UDP to port 9999 from `10.0.0.200`

**Expected matches (in order):**
1. Count rule (priority 100): `["monitor", "port-9999"]` → counter++, continue
2. Rate-limit rule (priority 250): `["attack", "flood-9999"]` → rate-limit if needed

**Verification:**
- Counter for `port-9999` should increment
- High-volume traffic should ALSO get rate-limited
- Both actions fire for same packet

## Log Patterns to Look For

### Success Indicators:
```
✅ "Parsed 19 rules from ... in Xµs"
✅ "Tree compiled: X nodes, Y edges, 6 rate buckets"
✅ No "WARN: Named bucket X has conflicting PPS" (all consistent)
✅ XDP stats show "dropped rate:N" increasing under load
✅ Holon detection still works (drift, concentration metrics)
```

### Failure Indicators:
```
❌ "Tree compiled: X nodes, Y edges, 11 rate buckets" (named buckets not sharing)
❌ Parse errors on EDN rules
❌ Count actions blocking traffic (should be non-terminating)
❌ Named buckets not actually sharing (independent limits)
```

## Traffic Scenario

The `feature-test-traffic.json` scenario uses standard traffic types:
- `normal`: Baseline UDP traffic (random ports, TTL=64, DF=1)
- `attack`: UDP amplification pattern (port 9999, TTL=255, DF=0, src=10.0.0.100)
- `syn_flood`: TCP SYN flood (flags=2, window=65535, TTL=128)

**Note:** Generator doesn't allow custom source IPs, so we can't target specific rules perfectly. However:
1. **Count actions** will trigger on ALL UDP traffic (proto 17 matches)
2. **Named buckets** will trigger if attack traffic happens to use matching ports
3. The key test is: **"6 rate buckets"** in the log (proves sharing works)

To fully test specific IPs, you'd need to manually craft packets or extend the generator.

## Quantitative Success Metrics

| Metric | Expected Value | How to Check |
|--------|---------------|--------------|
| Rules parsed | 19 | Log: "Parsed 19 rules" |
| Rate buckets | 6 | Log: "6 rate buckets" |
| Count counters | 4 | `bpftool map dump name TREE_COUNTERS` |
| Named buckets | 3 | Code analysis / log inspection |
| Unnamed buckets | 3 | Code analysis / log inspection |
| All tests pass | Yes | `cargo test` output |

## Current Status

- ✅ Rules generated: `scenarios/rules-feature-test.edn`
- ⏳ Traffic scenario: Need to create `feature-test-traffic.json`
- ⏳ Live test: Pending execution
