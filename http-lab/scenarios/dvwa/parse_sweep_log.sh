#!/usr/bin/env bash
# Parse a proxy log from a threshold sweep run and output a summary line
# plus temporal false-positive analysis.
#
# Usage:
#   parse_sweep_log.sh <proxy_log> <strategy_name>          # summary line only
#   parse_sweep_log.sh <proxy_log> <strategy_name> --detail  # + temporal breakdown

set -euo pipefail

LOG="$1"
STRATEGY="${2:-unknown}"
DETAIL="${3:-}"

if [[ ! -f "$LOG" ]]; then
    printf "%-14s %11s %10s %8s %10s %10s %8s %8s\n" \
        "$STRATEGY" "NO_LOG" "-" "-" "-" "-" "-" "-"
    exit 0
fi

STRIPPED=$(sed 's/\x1b\[[0-9;]*m//g' "$LOG")

DENY_BROWSER=$(echo "$STRIPPED" | grep -cE '═ DENY ═.*label=browser-agent' || true)
DENY_UNKNOWN=$(echo "$STRIPPED" | grep -cE '═ DENY ═.*label=unknown' || true)

# --- Temporal FP analysis ---
# Extract epoch seconds for proxy start, all browser denies, first/last attack deny
extract_epoch() {
    local ts="$1"
    date -d "$ts" +%s 2>/dev/null || echo "0"
}

PROXY_START_TS=$(echo "$STRIPPED" | head -1 | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' || true)
PROXY_START_EPOCH=$(extract_epoch "${PROXY_START_TS:-2000-01-01T00:00:00}")

# Browser deny timestamps: line before each browser DENY has the timestamp
BROWSER_DENY_EPOCHS=()
while IFS= read -r ts; do
    [[ -z "$ts" ]] && continue
    ep=$(extract_epoch "$ts")
    BROWSER_DENY_EPOCHS+=("$ep")
done < <(echo "$STRIPPED" | grep -B1 '═ DENY ═.*label=browser-agent' | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' || true)

# First and last attack deny timestamps
FIRST_ATTACK_TS=$(echo "$STRIPPED" | grep -B1 '═ DENY ═.*label=unknown' | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' | head -1 || true)
LAST_ATTACK_TS=$(echo "$STRIPPED" | grep -B1 '═ DENY ═.*label=unknown' | grep -oP '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}' | tail -1 || true)
FIRST_ATTACK_EPOCH=$(extract_epoch "${FIRST_ATTACK_TS:-2099-01-01T00:00:00}")
LAST_ATTACK_EPOCH=$(extract_epoch "${LAST_ATTACK_TS:-2000-01-01T00:00:00}")

# Categorize browser FPs: early (before attacks), during (attacks running), late (after attacks)
FP_EARLY=0
FP_DURING=0
FP_LATE=0
LAST_FP_OFFSET="-"
for ep in "${BROWSER_DENY_EPOCHS[@]}"; do
    offset=$((ep - PROXY_START_EPOCH))
    LAST_FP_OFFSET="${offset}s"
    if [[ "$ep" -lt "$FIRST_ATTACK_EPOCH" ]]; then
        FP_EARLY=$((FP_EARLY + 1))
    elif [[ "$ep" -gt "$LAST_ATTACK_EPOCH" ]]; then
        FP_LATE=$((FP_LATE + 1))
    else
        FP_DURING=$((FP_DURING + 1))
    fi
done

# Browser action count for FP rate
TOTAL_BROWSER=0
AGENT_LOG_DIR="$(dirname "$0")/agent_logs"
if [[ -d "$AGENT_LOG_DIR" ]]; then
    for logf in "$AGENT_LOG_DIR"/agent_*.log; do
        [[ -f "$logf" ]] || continue
        actions=$(grep -c '^\[agent\] #' "$logf" 2>/dev/null || true)
        TOTAL_BROWSER=$((TOTAL_BROWSER + ${actions:-0}))
    done
fi

if [[ "$TOTAL_BROWSER" -gt 0 ]]; then
    FP_RATE=$(awk "BEGIN {printf \"%.1f%%\", 100.0 * ${DENY_BROWSER:-0} / $TOTAL_BROWSER}")
else
    FP_RATE="-"
fi

SCORE_THR=$(echo "$STRIPPED" | grep -oP 'score_threshold=\K[0-9.]+' | tail -1 || true)
DENY_THR=$(echo "$STRIPPED" | grep -oP 'deny_threshold=\K[0-9.]+' | tail -1 || true)
if [[ -z "$DENY_THR" ]]; then
    DENY_THR=$(echo "$STRIPPED" | grep 'MANIFOLD.*Initial' | grep -oP 'deny_threshold=\K[0-9.]+' || true)
fi

ADAPTIVE_TOTAL=$(echo "$STRIPPED" | grep 'adaptive_learns' | tail -1 | grep -oP 'adaptive_learns=\K\d+' || true)

# FP timing label: best = "early-only" or "none", worst = "late"
if [[ "${DENY_BROWSER:-0}" -eq 0 ]]; then
    FP_WHEN="none"
elif [[ "$FP_LATE" -gt 0 ]]; then
    FP_WHEN="LATE($FP_LATE)"
elif [[ "$FP_DURING" -gt 0 && "$FP_EARLY" -gt 0 ]]; then
    FP_WHEN="early+mid"
elif [[ "$FP_DURING" -gt 0 ]]; then
    FP_WHEN="mid($FP_DURING)"
else
    FP_WHEN="early-only"
fi

printf "%-14s %11s %10s %8s %10s %10s %8s %12s\n" \
    "$STRATEGY" \
    "${DENY_UNKNOWN:-0}" \
    "${DENY_BROWSER:-0}" \
    "$FP_RATE" \
    "${SCORE_THR:-?}" \
    "${DENY_THR:-?}" \
    "${ADAPTIVE_TOTAL:-0}" \
    "$FP_WHEN"

# --- Detailed temporal breakdown ---
if [[ "$DETAIL" == "--detail" ]]; then
    echo ""
    echo "  [$STRATEGY] Temporal FP breakdown:"
    echo "    early (pre-attack):  $FP_EARLY"
    echo "    during (attacks):    $FP_DURING"
    echo "    late (post-attack):  $FP_LATE"
    echo "    last FP at:          $LAST_FP_OFFSET from proxy start"
    echo ""
    echo "  Attack window: ${FIRST_ATTACK_TS:-?} → ${LAST_ATTACK_TS:-?}"
    echo "  Proxy start:   ${PROXY_START_TS:-?}"
    echo ""

    if [[ ${#BROWSER_DENY_EPOCHS[@]} -gt 0 ]]; then
        echo "  All browser FP offsets from proxy start:"
        for ep in "${BROWSER_DENY_EPOCHS[@]}"; do
            offset=$((ep - PROXY_START_EPOCH))
            echo "    +${offset}s"
        done
        echo ""
    fi
fi
