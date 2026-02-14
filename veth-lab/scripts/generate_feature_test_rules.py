#!/usr/bin/env python3
"""Generate test rules for named buckets and count actions."""

def edn_rule(constraints, actions, priority=None, comment=None):
    """Format a single EDN rule."""
    c_strs = []
    for field, value in constraints:
        if field in ["src-addr", "dst-addr"]:
            c_strs.append(f'(= {field} "{value}")')
        else:
            c_strs.append(f'(= {field} {value})')
    constraints_edn = f'[{" ".join(c_strs)}]'
    
    a_strs = []
    for action in actions:
        a_type = action["type"]
        if a_type == "pass":
            a_strs.append("(pass)")
        elif a_type == "drop":
            a_strs.append("(drop)")
        elif a_type == "rate-limit":
            pps = action["pps"]
            name = action.get("name")
            if name:
                ns, n = name
                a_strs.append(f'(rate-limit {pps} :name ["{ns}", "{n}"])')
            else:
                a_strs.append(f'(rate-limit {pps})')
        elif a_type == "count":
            name = action.get("name")
            if name:
                ns, n = name
                a_strs.append(f'(count :name ["{ns}", "{n}"])')
            else:
                a_strs.append("(count)")
    actions_edn = f'[{" ".join(a_strs)}]'
    
    parts = [f'{{:constraints {constraints_edn} :actions {actions_edn}']
    if priority and priority != 100:
        parts.append(f' :priority {priority}')
    if comment:
        escaped = comment.replace('"', '\\"')[:256]
        parts.append(f' :comment "{escaped}"')
    parts.append('}')
    return ''.join(parts)

rules = []

print("Generating test rules for named buckets and count actions...\n")

# ===================================================================
# Count Actions (Non-Terminating) - Monitor all UDP traffic
# ===================================================================
print("1. Count actions (non-terminating):")
rules.append(edn_rule(
    [("proto", 17)],
    [{"type": "count", "name": ("monitor", "udp-total")}],
    priority=50,
    comment="Count all UDP packets (non-terminating)"
))
print("   - Count all UDP packets")

# Count DNS queries specifically
rules.append(edn_rule(
    [("proto", 17), ("dst-port", 53)],
    [{"type": "count", "name": ("monitor", "dns-queries")}],
    priority=60,
    comment="Count DNS queries (non-terminating)"
))
print("   - Count DNS queries")

# Count NTP packets
rules.append(edn_rule(
    [("proto", 17), ("dst-port", 123)],
    [{"type": "count", "name": ("monitor", "ntp-packets")}],
    priority=60,
    comment="Count NTP packets (non-terminating)"
))
print("   - Count NTP packets")

# ===================================================================
# Named Rate Limiter Buckets - Shared across attack patterns
# ===================================================================
print("\n2. Named rate limiter buckets (shared):")

# DNS amplification from multiple sources sharing "dns-amp" bucket
dns_sources = ["10.0.0.100", "10.0.0.101", "10.0.0.102"]
for ip in dns_sources:
    rules.append(edn_rule(
        [("proto", 17), ("dst-port", 53), ("src-addr", ip)],
        [{"type": "rate-limit", "pps": 1000, "name": ("attack", "dns-amp")}],
        priority=200,
        comment=f"DNS amp from {ip} - shared bucket"
    ))
print(f"   - {len(dns_sources)} DNS amp rules sharing [\"attack\", \"dns-amp\"] bucket")

# NTP amplification from multiple sources sharing "ntp-amp" bucket
ntp_sources = ["10.0.0.110", "10.0.0.111"]
for ip in ntp_sources:
    rules.append(edn_rule(
        [("proto", 17), ("dst-port", 123), ("src-addr", ip)],
        [{"type": "rate-limit", "pps": 500, "name": ("attack", "ntp-amp")}],
        priority=200,
        comment=f"NTP amp from {ip} - shared bucket"
    ))
print(f"   - {len(ntp_sources)} NTP amp rules sharing [\"attack\", \"ntp-amp\"] bucket")

# ===================================================================
# Unnamed Rate Limiters - Per-rule buckets
# ===================================================================
print("\n3. Unnamed rate limiters (per-rule buckets):")
for i in range(3):
    ip = f"10.0.0.{120 + i}"
    rules.append(edn_rule(
        [("proto", 17), ("src-addr", ip)],
        [{"type": "rate-limit", "pps": 100}],
        priority=150,
        comment=f"Per-rule limiter for {ip}"
    ))
print(f"   - 3 per-rule rate limiters")

# ===================================================================
# Combination: Count + Rate Limit
# ===================================================================
print("\n4. Combined rules (count + later rule rate-limits):")

# Count all traffic to port 9999
rules.append(edn_rule(
    [("proto", 17), ("dst-port", 9999)],
    [{"type": "count", "name": ("monitor", "port-9999")}],
    priority=100,
    comment="Count traffic to 9999 (non-terminating)"
))
print("   - Count all UDP to port 9999")

# Rate-limit high-volume sources to port 9999
for i in range(2):
    ip = f"10.0.0.{200 + i}"
    rules.append(edn_rule(
        [("proto", 17), ("dst-port", 9999), ("src-addr", ip)],
        [{"type": "rate-limit", "pps": 50, "name": ("attack", "flood-9999")}],
        priority=250,
        comment=f"Rate-limit {ip} to port 9999 - shared bucket"
    ))
print(f"   - Rate-limit 2 sources to port 9999 (sharing bucket)")

# ===================================================================
# Background traffic - passes through
# ===================================================================
print("\n5. Background TCP traffic (passes):")
for i in range(5):
    ip = f"10.0.0.{220 + i}"
    rules.append(edn_rule(
        [("proto", 6), ("src-addr", ip)],
        [{"type": "pass"}],
        priority=50
    ))
print(f"   - 5 TCP pass rules")

# Write to file
output_file = "scenarios/rules-feature-test.edn"
with open(output_file, "w") as f:
    for rule in rules:
        f.write(rule + "\n")

print(f"\n✅ Generated {len(rules)} rules to {output_file}")
print("\nExpected behavior:")
print("  - Count actions increment but don't block traffic")
print("  - Named buckets share rate limit across multiple rules")
print("  - Unnamed buckets are per-rule")
print("  - Traffic can trigger both count AND rate-limit actions")

print("\nExpected bucket count:")
dns_buckets = 1  # attack:dns-amp
ntp_buckets = 1  # attack:ntp-amp
flood_buckets = 1  # attack:flood-9999
unnamed_buckets = 3  # 3 per-rule limiters
total_buckets = dns_buckets + ntp_buckets + flood_buckets + unnamed_buckets
print(f"  - Rate limiter buckets: {total_buckets}")
print(f"    * Named: {dns_buckets + ntp_buckets + flood_buckets}")
print(f"    * Unnamed: {unnamed_buckets}")

count_counters = 4  # udp-total, dns-queries, ntp-packets, port-9999
print(f"  - Count counters: {count_counters}")
