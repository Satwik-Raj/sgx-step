#!/usr/bin/env bash
# =============================================================================
# run_bunnyhop_attack.sh
#
# Orchestrates the BunnyHop / SGX-Step attack experiment and automatically
# generates result visualisations after each run and across all runs.
#
# Usage
# -----
#   ./run_bunnyhop_attack.sh [OPTIONS]
#
# Options
#   -n NUM_RUNS      Number of attack repetitions          (default: 10)
#   -k NUM_KEYS      Number of random keys per run         (default: 25)
#   -t TIMER_INT     APIC timer interval for SGX-Step      (default: 19)
#   -o OUTPUT_DIR    Root output directory                  (default: ./results)
#   -d               Demo mode: skip the actual attack, use synthetic data
#   -h               Show this help and exit
#
# Produced artefacts (inside OUTPUT_DIR)
# ---------------------------------------
#   logs/run_NNN.log           Raw attack output per run
#   logs/ground_truth_NNN.txt  Ground-truth wNAF digit sequence per run
#   logs/accuracy_all_runs.csv Per-run accuracy summary
#   plots/bit_error_runNNN.png Bit-Error Position Plot per run
#   plots/bit_error_positions.png  Plot for the final run (symlink/copy)
#   plots/accuracy_distribution.png Accuracy Distribution across runs/models
# =============================================================================

set -euo pipefail

# ── defaults ──────────────────────────────────────────────────────────────────
NUM_RUNS=10
NUM_KEYS=25
TIMER_INT=19
OUTPUT_DIR="./results"
DEMO_MODE=false

# ── colour codes ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log()  { echo -e "${CYAN}[$(date '+%H:%M:%S')]${RESET} $*"; }
ok()   { echo -e "${GREEN}[✓]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
die()  { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

# ── usage ─────────────────────────────────────────────────────────────────────
usage() {
    sed -n '/^# Usage/,/^# =/p' "$0" | grep '^#' | sed 's/^# \?//'
    exit 0
}

# ── argument parsing ──────────────────────────────────────────────────────────
while getopts "n:k:t:o:dh" opt; do
    case "$opt" in
        n) NUM_RUNS="$OPTARG"   ;;
        k) NUM_KEYS="$OPTARG"   ;;
        t) TIMER_INT="$OPTARG"  ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        d) DEMO_MODE=true       ;;
        h) usage                ;;
        *) die "Unknown option -$OPTARG. Run with -h for help." ;;
    esac
done

# ── paths ─────────────────────────────────────────────────────────────────────
LOG_DIR="${OUTPUT_DIR}/logs"
PLOT_DIR="${OUTPUT_DIR}/plots"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLOT_SCRIPT="${SCRIPT_DIR}/plot_bunnyhop_results.py"
ACCURACY_CSV="${LOG_DIR}/accuracy_all_runs.csv"

# ── SGX-Step / BunnyHop binary paths (adjust to your build) ──────────────────
BUNNYHOP_BIN="${SCRIPT_DIR}/bunnyhop/bunnyhop"          # BunnyHop PoC binary
SGX_STEP_BENCH="${SCRIPT_DIR}/app/bench/bench"           # SGX-Step bench binary

# =============================================================================
# 0. Pre-flight checks
# =============================================================================
preflight() {
    log "Running pre-flight checks …"

    if ! command -v python3 &>/dev/null; then
        die "python3 not found. Please install Python 3.8+."
    fi

    # check required Python packages
    python3 - <<'PYCHECK'
import sys
missing = []
for pkg in ("numpy", "matplotlib"):
    try:
        __import__(pkg)
    except ImportError:
        missing.append(pkg)
if missing:
    print(f"Missing Python packages: {' '.join(missing)}", file=sys.stderr)
    sys.exit(1)
PYCHECK

    if [[ ! -f "$PLOT_SCRIPT" ]]; then
        die "Plotting script not found: ${PLOT_SCRIPT}"
    fi

    if [[ "$DEMO_MODE" == false ]]; then
        if [[ ! -x "$BUNNYHOP_BIN" ]] && [[ ! -x "$SGX_STEP_BENCH" ]]; then
            warn "Attack binary not found at expected path."
            warn "  BUNNYHOP_BIN = ${BUNNYHOP_BIN}"
            warn "  Falling back to DEMO_MODE."
            DEMO_MODE=true
        fi

        # check SGX driver
        if [[ "$DEMO_MODE" == false ]] && [[ ! -c "/dev/sgx-step" ]]; then
            warn "/dev/sgx-step not loaded. Falling back to DEMO_MODE."
            DEMO_MODE=true
        fi
    fi

    mkdir -p "${LOG_DIR}" "${PLOT_DIR}"
    ok "Pre-flight passed. Output root: ${OUTPUT_DIR}"
}

# =============================================================================
# 1. Single attack run
# =============================================================================
run_attack() {
    local run_id="$1"   # zero-padded, e.g. "001"
    local log_file="${LOG_DIR}/run_${run_id}.log"
    local gt_file="${LOG_DIR}/ground_truth_${run_id}.txt"

    log "Run ${run_id}/${NUM_RUNS} — launching attack …"

    if [[ "$DEMO_MODE" == true ]]; then
        # ── generate synthetic log ──────────────────────────────────────────
        python3 - "${log_file}" "${gt_file}" <<'PYSIM'
import sys, json, random, math
random.seed(int(sys.argv[1].split("run_")[-1].split(".")[0]) + 7)
log_path, gt_path = sys.argv[1], sys.argv[2]
N = 128
gt = [1 if random.random() < 0.22 else 0 for _ in range(N)]
observed = [g if random.random() > 0.02 else 1 - g for g in gt]
records = [{"digit_idx": i, "observed": observed[i], "ground_truth": gt[i]}
           for i in range(N)]
with open(log_path, "w") as f:
    json.dump(records, f)
with open(gt_path, "w") as f:
    f.write("\n".join(str(g) for g in gt))
PYSIM

    else
        # ── real BunnyHop attack ────────────────────────────────────────────
        # BunnyHop outputs one line per wNAF digit observation:
        #   DIGIT_IDX=<n>  OBSERVED=<0|1>  GROUND_TRUTH=<0|1>
        # Adjust the invocation to match your build's CLI.
        taskset -c 1 "${BUNNYHOP_BIN}" \
            --num-keys "${NUM_KEYS}" \
            --timer-interval "${TIMER_INT}" \
            --sgx-step \
            --output-format log \
            > "${log_file}" 2>&1 || {
                warn "Attack binary exited with error on run ${run_id}. See ${log_file}."
                return 1
            }

        # Extract ground truth from the log (last column) into a separate file
        grep -oP 'GROUND_TRUTH=\K[01]' "${log_file}" > "${gt_file}" || true
    fi

    ok "Run ${run_id} complete → ${log_file}"
}

# =============================================================================
# 2. Per-run plot
# =============================================================================
plot_run() {
    local run_id="$1"
    local log_file="${LOG_DIR}/run_${run_id}.log"
    local out_file="${PLOT_DIR}/bit_error_run${run_id}.png"

    log "Generating Bit-Error Position Plot for run ${run_id} …"
    python3 "${PLOT_SCRIPT}" \
        --attack-log "${log_file}" \
        --output-dir "${PLOT_DIR}" \
        --run-label "Run ${run_id} of ${NUM_RUNS}"

    # rename the generic output to the per-run name
    [[ -f "${PLOT_DIR}/bit_error_positions.png" ]] && \
        mv "${PLOT_DIR}/bit_error_positions.png" "${out_file}"

    ok "Bit-Error Position Plot → ${out_file}"
}

# =============================================================================
# 3. Compute per-run accuracy and append to CSV
# =============================================================================
record_accuracy() {
    local run_id="$1"
    local log_file="${LOG_DIR}/run_${run_id}.log"

    # python one-liner: parse log, compute accuracy, print CSV row
    python3 - "${log_file}" "${run_id}" >> "${ACCURACY_CSV}" <<'PYACC'
import sys, json
log_path, run_id = sys.argv[1], sys.argv[2]
raw = open(log_path).read().strip()
if raw.startswith("["):
    records = json.loads(raw)
    n = len(records)
    correct = sum(1 for r in records if r["observed"] == r["ground_truth"])
else:
    import re
    pattern = re.compile(r"DIGIT_IDX\s*=\s*\d+\s+OBSERVED\s*=\s*([01])\s+GROUND_TRUTH\s*=\s*([01])", re.I)
    pairs = pattern.findall(raw)
    n = len(pairs)
    correct = sum(1 for o, g in pairs if o == g)
acc = 100.0 * correct / n if n else 0.0
print(f"Run {run_id},BunnyHop-Reload,{acc:.4f}")
PYACC
}

# =============================================================================
# 4. Final aggregate plots
# =============================================================================
plot_aggregate() {
    log "Generating Accuracy Distribution Bar Chart across all runs …"

    # build a full accuracy dataset:
    # - per-run accuracy from CSV (runs as "models")
    # - paper-reported per-CPU-model accuracy (static, always included)

    python3 - "${ACCURACY_CSV}" "${PLOT_DIR}" <<'PYAGG'
import sys, csv, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

csv_path, plot_dir = sys.argv[1], sys.argv[2]

# ── per-run data from CSV ──
per_run = {}
with open(csv_path) as f:
    reader = csv.reader(f)
    next(reader)  # skip header
    for row in reader:
        if len(row) >= 3:
            per_run[row[0].strip()] = float(row[2].strip())

# ── paper-reported per-CPU-model data ──
paper_reload = {
    "i7-6700":   100.00,
    "i5-8265U":   99.92,
    "i7-9750H":   99.98,
    "i7-10710U":  99.94,
}
paper_probe = {
    "i7-6700":   99.13,
    "i5-8265U":  93.25,
    "i7-9750H":  87.13,
    "i7-10710U": 91.88,
}

acc_data = {
    "BunnyHop-Reload (KASLR, paper)": paper_reload,
    "BunnyHop-Probe (RSA, paper)":    paper_probe,
    "BunnyHop-Reload (this run)":     per_run,
}

# ── call the plotting function directly ──
import importlib.util, types
spec = importlib.util.spec_from_file_location(
    "plot_bunnyhop",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "plot_bunnyhop_results.py")
)
mod = importlib.util.load_from_spec(spec) if hasattr(importlib.util, "load_from_spec") else None
if mod is None:
    spec.loader.exec_module(types.ModuleType("plot_bunnyhop"))
    import importlib
    mod = importlib.import_module("plot_bunnyhop_results")

mod.plot_accuracy_distribution(
    acc_data,
    os.path.join(plot_dir, "accuracy_distribution.png"),
)
PYAGG

    ok "Accuracy Distribution Bar Chart → ${PLOT_DIR}/accuracy_distribution.png"
}

# =============================================================================
# Main
# =============================================================================
main() {
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  BunnyHop Attack Runner + Visualisation Pipeline          ${RESET}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
    echo -e "  Runs       : ${NUM_RUNS}"
    echo -e "  Keys/run   : ${NUM_KEYS}"
    echo -e "  Timer int  : ${TIMER_INT}"
    echo -e "  Output     : ${OUTPUT_DIR}"
    echo -e "  Demo mode  : ${DEMO_MODE}"
    echo ""

    preflight

    # Initialise accuracy CSV with header
    echo "run,attack,accuracy" > "${ACCURACY_CSV}"

    # ── main loop ──────────────────────────────────────────────────────────
    for i in $(seq 1 "${NUM_RUNS}"); do
        run_id=$(printf "%03d" "${i}")

        run_attack  "${run_id}" || { warn "Skipping plots for failed run ${run_id}."; continue; }
        plot_run    "${run_id}"
        record_accuracy "${run_id}"

        echo ""
    done

    # ── aggregate ─────────────────────────────────────────────────────────
    plot_aggregate

    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
    ok "All done."
    echo -e "  Logs  : ${LOG_DIR}"
    echo -e "  Plots : ${PLOT_DIR}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
    echo ""
}

main "$@"

