#!/usr/bin/env bash
# Threshold strategy sweep — runs the multi-attack scenario with each
# deny_threshold strategy and collects results for comparison.
#
# Tests strategies that survived simulation-based elimination (from 21 candidates).
# See NEXT-INVESTIGATIONS.md Section 6 for elimination rationale.
#
# Usage:
#   ./run-threshold-sweep.sh                                    # 4 strategies, 1 round
#   ./run-threshold-sweep.sh --rounds 5                         # 4 strategies, 5 rounds
#   ./run-threshold-sweep.sh --rounds 7 geometric log_mean      # 2 strategies, 7 rounds
#   ./run-threshold-sweep.sh --skip-build --rounds 5            # skip cargo build
#
# Prerequisites: same as run-multi-attack.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
LOGS_DIR="$LAB_DIR/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SWEEP_DIR="$LOGS_DIR/sweep_${TIMESTAMP}"
SUMMARY_FILE="$SWEEP_DIR/summary.txt"

STRATEGIES=()
SKIP_BUILD=false
ROUNDS=1

for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
        --rounds) ;; # handled below
        geometric|log_mean|heronian|arithmetic|mean_3std) STRATEGIES+=("$arg") ;;
        [0-9]*) ;; # handled below
    esac
done

# Parse --rounds N
ARGS=("$@")
for ((i=0; i<${#ARGS[@]}; i++)); do
    if [[ "${ARGS[i]}" == "--rounds" && $((i+1)) -lt ${#ARGS[@]} ]]; then
        ROUNDS="${ARGS[$((i+1))]}"
    fi
done

if [[ ${#STRATEGIES[@]} -eq 0 ]]; then
    STRATEGIES=(geometric log_mean heronian arithmetic)
fi

TOTAL_STRATS=${#STRATEGIES[@]}
TOTAL_RUNS=$((TOTAL_STRATS * ROUNDS))

mkdir -p "$SWEEP_DIR"

echo "============================================================"
echo " Threshold Strategy Sweep"
echo " Strategies: ${STRATEGIES[*]}"
echo " Rounds:     $ROUNDS ($TOTAL_RUNS total runs)"
echo " Results:    $SWEEP_DIR"
echo " Started:    $(date)"
echo "============================================================"
echo ""

# Build once before the loop
if [[ "$SKIP_BUILD" == "false" ]]; then
    echo "==> Building proxy + sidecar..."
    cd "$LAB_DIR" && bash scripts/build.sh
    echo ""
fi

RUN_NUM=0

for ((round=1; round<=ROUNDS; round++)); do
    for strategy in "${STRATEGIES[@]}"; do
        RUN_NUM=$((RUN_NUM + 1))
        RUN_LABEL="${strategy}_r${round}"
        echo "============================================================"
        echo " [$RUN_NUM/$TOTAL_RUNS] Round $round: $strategy"
        echo "============================================================"
        echo ""

        # Clear persisted engrams so each run starts from fresh warmup
        ENGRAMS_DIR="$LAB_DIR/engrams"
        rm -f "$ENGRAMS_DIR"/multi-attack/*.striped.json 2>/dev/null || true
        rm -f "$ENGRAMS_DIR"/multi-attack/baseline.* 2>/dev/null || true

        export DENY_STRATEGY="$strategy"
        export WARMUP_SAMPLES=100
        export WARMUP_DURATION=60
        export NIKTO_MAXTIME=60
        export NUCLEI_MAXTIME=90

        RUN_START=$SECONDS

        # Run the multi-attack scenario
        cd "$SCRIPT_DIR"
        bash ./run-multi-attack.sh --skip-build 2>&1 | tee "$SWEEP_DIR/run_${RUN_LABEL}.txt" || true

        RUN_ELAPSED=$((SECONDS - RUN_START))

        # Find the proxy log from this run (most recent)
        PROXY_LOG=$(ls -t "$LOGS_DIR"/multi_proxy_*.log 2>/dev/null | head -1)
        if [[ -n "$PROXY_LOG" ]]; then
            cp "$PROXY_LOG" "$SWEEP_DIR/proxy_${RUN_LABEL}.log"

            bash "$SCRIPT_DIR/parse_sweep_log.sh" "$SWEEP_DIR/proxy_${RUN_LABEL}.log" "$RUN_LABEL" >> "$SUMMARY_FILE"
            bash "$SCRIPT_DIR/parse_sweep_log.sh" "$SWEEP_DIR/proxy_${RUN_LABEL}.log" "$RUN_LABEL" --detail >> "$SWEEP_DIR/detail_${RUN_LABEL}.txt"
        else
            echo "$RUN_LABEL  NO_LOG  -  -  -  -  -  -  -" >> "$SUMMARY_FILE"
        fi

        echo ""
        echo "  $RUN_LABEL completed in ${RUN_ELAPSED}s"
        echo ""
    done
done

echo ""
echo "============================================================"
echo " Sweep Complete — All Rounds"
echo "============================================================"
echo ""
printf "%-18s %11s %10s %8s %10s %10s %8s %12s %10s %10s\n" \
    "STRATEGY" "ATTACK_DENY" "BROWSER_FP" "FP_RATE" "SCORE_THR" "DENY_THR" "ADAPTIVE" "FP_WHEN" "DG_BROWSER" "DG_ATTACK"
printf "%-18s %11s %10s %8s %10s %10s %8s %12s %10s %10s\n" \
    "----------------" "-----------" "----------" "--------" "----------" "----------" "--------" "------------" "----------" "----------"
cat "$SUMMARY_FILE"

# --- Aggregate stats per strategy ---
echo ""
echo "============================================================"
echo " Aggregate (mean across $ROUNDS rounds)"
echo "============================================================"
echo ""
printf "%-14s %11s %10s %8s %10s %10s %8s %6s %10s %10s\n" \
    "STRATEGY" "ATTACK_DENY" "BROWSER_FP" "FP_RATE" "SCORE_THR" "DENY_THR" "ADAPTIVE" "LATE" "DG_BROWSER" "DG_ATTACK"
printf "%-14s %11s %10s %8s %10s %10s %8s %6s %10s %10s\n" \
    "-----------" "-----------" "----------" "--------" "----------" "----------" "--------" "------" "----------" "----------"

for strategy in "${STRATEGIES[@]}"; do
    # Collect per-round values from the detail files
    ATK_VALS=()
    FP_VALS=()
    LATE_VALS=()
    ADAPTIVE_VALS=()
    SCORE_VALS=()
    DENY_VALS=()
    DG_B_VALS=()
    DG_A_VALS=()

    for ((r=1; r<=ROUNDS; r++)); do
        detail_file="$SWEEP_DIR/detail_${strategy}_r${r}.txt"
        [[ -f "$detail_file" ]] || continue

        # Re-parse from proxy log for numeric extraction
        proxy_log="$SWEEP_DIR/proxy_${strategy}_r${r}.log"
        [[ -f "$proxy_log" ]] || continue

        stripped=$(sed 's/\x1b\[[0-9;]*m//g' "$proxy_log")
        atk=$(echo "$stripped" | grep -cE '═ DENY ═.*label=unknown' || true)
        fps=$(echo "$stripped" | grep -cE '═ DENY ═.*label=browser-agent' || true)
        dg_b=$(echo "$stripped" | grep -cE '═ DOWNGRADE ═.*label=browser-agent' || true)
        dg_a=$(echo "$stripped" | grep -cE '═ DOWNGRADE ═.*label=unknown' || true)
        late=$(grep 'late (post-attack)' "$detail_file" | grep -oP '\d+' || echo "0")
        adaptive=$(echo "$stripped" | grep 'adaptive_learns' | tail -1 | grep -oP 'adaptive_learns=\K\d+' || echo "0")
        score_t=$(echo "$stripped" | grep -oP 'score_threshold=\K[0-9.]+' | tail -1 || echo "0")
        deny_t=$(echo "$stripped" | grep -oP 'deny_threshold=\K[0-9.]+' | tail -1 || echo "0")

        ATK_VALS+=("${atk:-0}")
        FP_VALS+=("${fps:-0}")
        LATE_VALS+=("${late:-0}")
        ADAPTIVE_VALS+=("${adaptive:-0}")
        SCORE_VALS+=("${score_t:-0}")
        DENY_VALS+=("${deny_t:-0}")
        DG_B_VALS+=("${dg_b:-0}")
        DG_A_VALS+=("${dg_a:-0}")
    done

    N=${#ATK_VALS[@]}
    if [[ "$N" -eq 0 ]]; then
        printf "%-14s %11s %10s %8s %10s %10s %8s %6s %10s %10s\n" "$strategy" "-" "-" "-" "-" "-" "-" "-" "-" "-"
        continue
    fi

    # Compute means with awk
    avg_atk=$(printf '%s\n' "${ATK_VALS[@]}" | awk '{s+=$1} END {printf "%.0f", s/NR}')
    avg_fp=$(printf '%s\n' "${FP_VALS[@]}" | awk '{s+=$1} END {printf "%.1f", s/NR}')
    avg_late=$(printf '%s\n' "${LATE_VALS[@]}" | awk '{s+=$1} END {printf "%.1f", s/NR}')
    avg_adaptive=$(printf '%s\n' "${ADAPTIVE_VALS[@]}" | awk '{s+=$1} END {printf "%.0f", s/NR}')
    avg_score=$(printf '%s\n' "${SCORE_VALS[@]}" | awk '{s+=$1} END {printf "%.2f", s/NR}')
    avg_deny=$(printf '%s\n' "${DENY_VALS[@]}" | awk '{s+=$1} END {printf "%.2f", s/NR}')
    avg_dg_b=$(printf '%s\n' "${DG_B_VALS[@]}" | awk '{s+=$1} END {printf "%.1f", s/NR}')
    avg_dg_a=$(printf '%s\n' "${DG_A_VALS[@]}" | awk '{s+=$1} END {printf "%.1f", s/NR}')

    # FP rate from averages
    total_browser=0
    AGENT_LOG_DIR="$SCRIPT_DIR/agent_logs"
    if [[ -d "$AGENT_LOG_DIR" ]]; then
        for logf in "$AGENT_LOG_DIR"/agent_*.log; do
            [[ -f "$logf" ]] || continue
            actions=$(grep -c '^\[agent\] #' "$logf" 2>/dev/null || true)
            total_browser=$((total_browser + ${actions:-0}))
        done
    fi
    if [[ "$total_browser" -gt 0 ]]; then
        avg_fpr=$(awk "BEGIN {printf \"%.1f%%\", 100.0 * $avg_fp / $total_browser}")
    else
        avg_fpr="-"
    fi

    printf "%-14s %11s %10s %8s %10s %10s %8s %6s %10s %10s\n" \
        "$strategy" "$avg_atk" "$avg_fp" "$avg_fpr" "$avg_score" "$avg_deny" "$avg_adaptive" "$avg_late" "$avg_dg_b" "$avg_dg_a"
done

echo ""
echo "Temporal detail per run:"
for f in "$SWEEP_DIR"/detail_*.txt; do
    [[ -f "$f" ]] && cat "$f"
done

echo ""
echo "Full results: $SWEEP_DIR/"
echo "Proxy logs:   $SWEEP_DIR/proxy_*.log"
echo ""
