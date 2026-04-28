#!/usr/bin/env python3
"""
BunnyHop Attack Result Visualization
=====================================
Generates:
  1. Bit-Error Position Plot  — shows which bit/digit positions in the
     recovered wNAF key sequence were misclassified (missed zero/non-zero).
  2. Accuracy Distribution Bar Chart — per-CPU-model accuracy for
     BunnyHop-Reload (KASLR) and BunnyHop-Probe attacks.

Usage
-----
  # With real attack logs:
  python3 plot_bunnyhop_results.py \
      --attack-log attack_output.log \
      --ground-truth ground_truth.txt \
      --output-dir ./plots

  # With no logs (uses synthetic data from paper's reported numbers):
  python3 plot_bunnyhop_results.py --demo --output-dir ./plots
"""

import argparse
import os
import sys
import re
import json
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec

# ---------------------------------------------------------------------------
# Colour palette — consistent across both plots
# ---------------------------------------------------------------------------
COLOUR_HIT    = "#2ecc71"   # correct classification
COLOUR_ERR    = "#e74c3c"   # bit error
COLOUR_RELOAD = "#3498db"   # BunnyHop-Reload (KASLR)
COLOUR_PROBE  = "#9b59b6"   # BunnyHop-Probe  (RSA)
COLOUR_EVICT  = "#e67e22"   # BunnyHop-Evict  (AES, optional)

# ---------------------------------------------------------------------------
# ── SECTION 1: log parsers ──────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def parse_attack_log(log_path: str) -> dict:
    """
    Parse a BunnyHop / SGX-Step attack log.

    Expected log format (one line per observation):
        DIGIT_IDX=<int>  OBSERVED=<0|1>  GROUND_TRUTH=<0|1>

    OR a JSON array of objects with the same keys (lowercase).

    Returns
    -------
    dict with keys:
        'digit_indices'   : list[int]
        'observed'        : list[int]   (0 = non-zero digit absent, 1 = present)
        'ground_truth'    : list[int]
    """
    if not os.path.isfile(log_path):
        raise FileNotFoundError(f"Log file not found: {log_path}")

    raw = open(log_path).read().strip()

    # ── try JSON format first ──
    if raw.startswith("["):
        records = json.loads(raw)
        indices = [r["digit_idx"]    for r in records]
        observed= [r["observed"]     for r in records]
        gt      = [r["ground_truth"] for r in records]
        return dict(digit_indices=indices, observed=observed, ground_truth=gt)

    # ── fall back to key=value line format ──
    indices, observed, gt = [], [], []
    pattern = re.compile(
        r"DIGIT_IDX\s*=\s*(\d+)\s+OBSERVED\s*=\s*([01])\s+GROUND_TRUTH\s*=\s*([01])",
        re.IGNORECASE,
    )
    for line in raw.splitlines():
        m = pattern.search(line)
        if m:
            indices.append(int(m.group(1)))
            observed.append(int(m.group(2)))
            gt.append(int(m.group(3)))

    if not indices:
        raise ValueError(
            "Could not parse any observations from log.\n"
            "Expected lines like:  DIGIT_IDX=42  OBSERVED=1  GROUND_TRUTH=0"
        )
    return dict(digit_indices=indices, observed=observed, ground_truth=gt)


def parse_accuracy_csv(csv_path: str) -> dict:
    """
    Parse a CSV of per-model accuracy results.

    Expected header:  model,attack,accuracy
    Example row:      i7-6700,BunnyHop-Reload,100.00

    Returns a dict:  { attack_type -> { model -> accuracy_pct } }
    """
    import csv
    results: dict = {}
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            attack  = row["attack"].strip()
            model   = row["model"].strip()
            acc     = float(row["accuracy"])
            results.setdefault(attack, {})[model] = acc
    return results


# ---------------------------------------------------------------------------
# ── SECTION 2: synthetic / demo data (paper's exact numbers) ────────────────
# ---------------------------------------------------------------------------

def demo_bit_error_data(n_digits: int = 120, seed: int = 42) -> dict:
    """
    Simulate a single wNAF key-recovery run at ~98 % accuracy
    (as reported in Section 5 of the BunnyHop paper).

    Roughly 20 % of digits are non-zero in wNAF with w=4.
    """
    rng = np.random.default_rng(seed)
    gt  = (rng.random(n_digits) < 0.22).astype(int)   # ~22 % non-zero digits

    # 98 % accuracy → flip ~2 % of predictions
    observed = gt.copy()
    error_mask = rng.random(n_digits) < 0.02
    observed[error_mask] ^= 1

    return dict(
        digit_indices=list(range(n_digits)),
        observed=observed.tolist(),
        ground_truth=gt.tolist(),
    )


def demo_accuracy_data() -> dict:
    """
    Paper-reported accuracy numbers (Tables 3 & 4).
    """
    return {
        "BunnyHop-Reload (KASLR)": {
            "i7-6700":   100.00,
            "i5-8265U":   99.92,
            "i7-9750H":   99.98,
            "i7-10710U":  99.94,
        },
        "BunnyHop-Probe (RSA)": {
            "i7-6700":   99.13,
            "i5-8265U":  93.25,
            "i7-9750H":  87.13,
            "i7-10710U": 91.88,
        },
    }


# ---------------------------------------------------------------------------
# ── SECTION 3: Plot 1 — Bit-Error Position Plot ─────────────────────────────
# ---------------------------------------------------------------------------

def plot_bit_error_positions(data: dict, out_path: str, run_label: str = "Run 1") -> None:
    """
    Horizontal raster plot of wNAF digit positions.

    Each digit position is a thin vertical bar:
      • Green  → correct classification (hit)
      • Red    → misclassification     (error)

    A secondary row shows the ground-truth non-zero positions so the
    reader can see whether errors cluster around non-zero digits.
    """
    indices  = np.array(data["digit_indices"])
    observed = np.array(data["observed"])
    gt       = np.array(data["ground_truth"])

    correct = (observed == gt)
    errors  = ~correct

    n        = len(indices)
    n_errors = errors.sum()
    accuracy = 100.0 * correct.sum() / n

    fig, axes = plt.subplots(
        nrows=3, ncols=1, figsize=(14, 5),
        gridspec_kw={"height_ratios": [1.6, 0.6, 0.6]},
        facecolor="#0f1117",
    )
    fig.subplots_adjust(hspace=0.08, left=0.10, right=0.97, top=0.88, bottom=0.12)

    # ── top panel: per-position classification ──
    ax = axes[0]
    ax.set_facecolor("#0f1117")
    for spine in ax.spines.values():
        spine.set_visible(False)

    bar_width = max(0.8, 200 / n)

    ax.bar(
        indices[correct], 1, width=bar_width,
        color=COLOUR_HIT, linewidth=0, label="Correct", zorder=2,
    )
    ax.bar(
        indices[errors], 1, width=bar_width,
        color=COLOUR_ERR, linewidth=0, label="Error", zorder=3,
    )

    ax.set_xlim(-1, n + 1)
    ax.set_ylim(0, 1.3)
    ax.set_yticks([])
    ax.set_xticks([])
    ax.set_ylabel("Classification", color="white", fontsize=9, labelpad=4)

    hit_patch = mpatches.Patch(color=COLOUR_HIT, label=f"Correct ({correct.sum()})")
    err_patch = mpatches.Patch(color=COLOUR_ERR, label=f"Error   ({n_errors})")
    ax.legend(
        handles=[hit_patch, err_patch],
        loc="upper right", framealpha=0.15,
        labelcolor="white", fontsize=8,
    )

    title = (
        f"Bit-Error Position Plot — BunnyHop wNAF Digit Recovery  |  "
        f"{run_label}  |  n={n}  |  Accuracy: {accuracy:.2f} %  |  Errors: {n_errors}"
    )
    ax.set_title(title, color="white", fontsize=10, pad=6)

    # ── middle panel: ground-truth non-zero positions ──
    ax2 = axes[1]
    ax2.set_facecolor("#0f1117")
    for spine in ax2.spines.values():
        spine.set_visible(False)
    nz_positions = indices[gt == 1]
    ax2.bar(nz_positions, 1, width=bar_width, color="#f39c12", linewidth=0, zorder=2)
    ax2.set_xlim(-1, n + 1)
    ax2.set_ylim(0, 1.3)
    ax2.set_yticks([])
    ax2.set_xticks([])
    ax2.set_ylabel("Non-zero\ndigit (GT)", color="white", fontsize=8, labelpad=4)

    # ── bottom panel: error indicator ──
    ax3 = axes[2]
    ax3.set_facecolor("#0f1117")
    for spine in ax3.spines.values():
        spine.set_visible(False)
    ax3.bar(
        indices[errors], 1, width=bar_width,
        color=COLOUR_ERR, linewidth=0, zorder=3,
    )
    ax3.set_xlim(-1, n + 1)
    ax3.set_ylim(0, 1.3)
    ax3.set_yticks([])
    ax3.set_ylabel("Error\npositions", color="white", fontsize=8, labelpad=4)
    ax3.set_xlabel("wNAF Digit Index (0 = MSB)", color="white", fontsize=9)

    # shared x-tick labels on bottom panel
    tick_step = max(1, n // 20)
    ticks = list(range(0, n, tick_step)) + [n - 1]
    ax3.set_xticks(ticks)
    ax3.set_xticklabels([str(t) for t in ticks], color="white", fontsize=7)

    # apply white tick params to all axes
    for a in axes:
        a.tick_params(colors="white")

    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  [✓] Bit-Error Position Plot  →  {out_path}")


# ---------------------------------------------------------------------------
# ── SECTION 4: Plot 2 — Accuracy Distribution Bar Chart ─────────────────────
# ---------------------------------------------------------------------------

def plot_accuracy_distribution(acc_data: dict, out_path: str) -> None:
    """
    Grouped bar chart of per-CPU-model accuracy for each attack variant.

    acc_data: { attack_name -> { model -> accuracy_pct } }
    """
    attack_names = list(acc_data.keys())
    all_models   = sorted({m for v in acc_data.values() for m in v})
    n_attacks    = len(attack_names)
    n_models     = len(all_models)

    attack_colours = [COLOUR_RELOAD, COLOUR_PROBE, COLOUR_EVICT]
    model_index    = {m: i for i, m in enumerate(all_models)}

    fig, ax = plt.subplots(figsize=(11, 5.5), facecolor="#0f1117")
    ax.set_facecolor("#181c27")
    for spine in ax.spines.values():
        spine.set_edgecolor("#3d4460")

    group_width  = 0.72
    bar_width    = group_width / n_attacks
    x_positions  = np.arange(n_models)

    for a_idx, (attack, model_acc) in enumerate(acc_data.items()):
        colour  = attack_colours[a_idx % len(attack_colours)]
        offsets = (a_idx - (n_attacks - 1) / 2) * bar_width

        xs  = []
        ys  = []
        for model in all_models:
            acc = model_acc.get(model, None)
            if acc is not None:
                xs.append(model_index[model] + offsets)
                ys.append(acc)

        bars = ax.bar(
            xs, ys,
            width=bar_width * 0.88,
            color=colour,
            alpha=0.88,
            label=attack,
            zorder=3,
            linewidth=0,
        )

        # value labels on top of each bar
        for bar, y in zip(bars, ys):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                y + 0.08,
                f"{y:.2f}%",
                ha="center", va="bottom",
                color="white", fontsize=7.5, fontweight="bold",
            )

    # reference line at 100 %
    ax.axhline(100, color="#ffffff33", linewidth=0.8, linestyle="--", zorder=1)

    # ── formatting ──
    ax.set_ylim(82, 102.5)
    ax.set_xticks(x_positions)
    ax.set_xticklabels(all_models, color="white", fontsize=9.5)
    ax.tick_params(axis="y", colors="white", labelsize=8)
    ax.set_xlabel("CPU Model", color="white", fontsize=10, labelpad=8)
    ax.set_ylabel("Accuracy (%)", color="white", fontsize=10, labelpad=8)
    ax.set_title(
        "BunnyHop Attack Accuracy Distribution by CPU Model",
        color="white", fontsize=12, pad=12, fontweight="bold",
    )

    ax.yaxis.grid(True, color="#3d4460", linewidth=0.5, linestyle="--", zorder=0)
    ax.set_axisbelow(True)

    legend = ax.legend(
        framealpha=0.2, labelcolor="white",
        fontsize=9, loc="lower right",
    )
    legend.get_frame().set_edgecolor("#3d4460")

    plt.tight_layout(pad=1.2)
    plt.savefig(out_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  [✓] Accuracy Distribution Chart  →  {out_path}")


# ---------------------------------------------------------------------------
# ── SECTION 5: multi-run aggregation (called from bash loop) ────────────────
# ---------------------------------------------------------------------------

def aggregate_runs(log_paths: list, out_dir: str) -> None:
    """
    Plot the Bit-Error Position Plot for each run AND a summary accuracy
    bar chart across runs (per-run accuracy).
    """
    per_run_acc = []
    for i, lp in enumerate(log_paths, start=1):
        try:
            data = parse_attack_log(lp)
        except Exception as e:
            print(f"  [!] Skipping {lp}: {e}", file=sys.stderr)
            continue

        plot_path = os.path.join(out_dir, f"bit_error_run{i:03d}.png")
        plot_bit_error_positions(data, plot_path, run_label=f"Run {i}")

        n       = len(data["digit_indices"])
        correct = sum(o == g for o, g in zip(data["observed"], data["ground_truth"]))
        acc     = 100.0 * correct / n if n else 0.0
        per_run_acc.append((f"Run {i}", acc))

    if per_run_acc:
        # Build a small accuracy dataset for the bar chart
        acc_data = {"BunnyHop-Reload (per run)": {label: acc for label, acc in per_run_acc}}
        plot_accuracy_distribution(
            acc_data,
            os.path.join(out_dir, "accuracy_distribution_runs.png"),
        )


# ---------------------------------------------------------------------------
# ── SECTION 6: CLI entry point ───────────────────────────────────────────────
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--demo", action="store_true",
                   help="Use synthetic data from the paper (no log needed)")
    p.add_argument("--attack-log", metavar="PATH",
                   help="Path to a single attack output log")
    p.add_argument("--ground-truth", metavar="PATH",
                   help="Path to ground-truth key file (one bit/digit per line)")
    p.add_argument("--accuracy-csv", metavar="PATH",
                   help="CSV of per-model accuracy results (model,attack,accuracy)")
    p.add_argument("--log-dir", metavar="DIR",
                   help="Directory containing multiple run logs (run_*.log)")
    p.add_argument("--output-dir", metavar="DIR", default="./plots",
                   help="Where to write PNG files (default: ./plots)")
    p.add_argument("--run-label", default="Attack run",
                   help="Label for the Bit-Error Position Plot title")
    return p


def main() -> None:
    args = build_parser().parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    if args.demo:
        print("[*] Demo mode — using synthetic data (paper's reported numbers)")
        bit_data = demo_bit_error_data(n_digits=128)
        acc_data = demo_accuracy_data()

        plot_bit_error_positions(
            bit_data,
            os.path.join(args.output_dir, "bit_error_positions.png"),
            run_label="Demo run (synthetic, ~98 % accuracy)",
        )
        plot_accuracy_distribution(
            acc_data,
            os.path.join(args.output_dir, "accuracy_distribution.png"),
        )
        return

    # ── multi-run directory ──
    if args.log_dir:
        import glob
        logs = sorted(glob.glob(os.path.join(args.log_dir, "run_*.log")))
        if not logs:
            print(f"[!] No run_*.log files found in {args.log_dir}", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Aggregating {len(logs)} run logs from {args.log_dir}")
        aggregate_runs(logs, args.output_dir)
        return

    # ── single run ──
    if args.attack_log:
        data = parse_attack_log(args.attack_log)

        # optionally load separate ground-truth file
        if args.ground_truth:
            gt_lines = open(args.ground_truth).read().strip().splitlines()
            data["ground_truth"] = [int(x.strip()) for x in gt_lines]

        plot_bit_error_positions(
            data,
            os.path.join(args.output_dir, "bit_error_positions.png"),
            run_label=args.run_label,
        )

    if args.accuracy_csv:
        acc_data = parse_accuracy_csv(args.accuracy_csv)
        plot_accuracy_distribution(
            acc_data,
            os.path.join(args.output_dir, "accuracy_distribution.png"),
        )

    if not args.attack_log and not args.accuracy_csv:
        print("[!] No input specified. Use --demo or provide --attack-log / --accuracy-csv.",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

