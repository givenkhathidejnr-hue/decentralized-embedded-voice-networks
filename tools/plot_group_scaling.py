#!/usr/bin/env python3
"""
Figure for the group steady-state campaign (docs/DRAFT_RQ2_GROUP_EVALUATION.md
Table 5.13): sender stage cost, delivery quality and loss/deadline-miss
against audience size N=1-3, mirroring tools/visualize.py's established
panel style (markers, grid, log y where magnitudes span orders of
magnitude) but reading group_scaling.csv's own schema directly rather than
forcing it through visualize.py's receivers-keyed loader, which expects
parse_telemetry.py's unicast column names.

    python3 tools/plot_group_scaling.py results_group_scaling_full/group_scaling.csv \
        --out results_group_scaling_full/group_scaling.png

Sustained (300 s) rows are excluded from the plotted means/error bars --
they are a lifecycle-stability check (Sec 4.3.1), not additional samples of
the same steady-state quantity the repeated 30 s trials measure, and mixing
the two would understate the within-condition spread.
"""

from __future__ import annotations

import argparse
import csv
import os

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def _f(row: dict, key: str) -> float | None:
    v = row.get(key, "")
    if v in ("", None):
        return None
    try:
        return float(v)
    except ValueError:
        return None


def load(path: str) -> list[dict]:
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def by_n_role(rows: list[dict], role: str, exclude_sustained: bool = True) -> dict[int, list[dict]]:
    out: dict[int, list[dict]] = {}
    for r in rows:
        if r.get("role") != role:
            continue
        if exclude_sustained and r.get("rep") == "sustained":
            continue
        try:
            n = int(r["n"])
        except (KeyError, ValueError):
            continue
        out.setdefault(n, []).append(r)
    return out


def mean_sd(groups: dict[int, list[dict]], key: str) -> tuple[list[int], list[float], list[float]]:
    ns, means, sds = [], [], []
    for n in sorted(groups):
        vals = [_f(r, key) for r in groups[n]]
        vals = [v for v in vals if v is not None]
        if not vals:
            continue
        ns.append(n)
        means.append(float(np.mean(vals)))
        sds.append(float(np.std(vals)))
    return ns, means, sds


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv_path")
    ap.add_argument("--out", default=None, help="output PNG path (default: alongside the CSV)")
    ap.add_argument("--dpi", type=int, default=150)
    args = ap.parse_args()

    rows = load(args.csv_path)
    coord = by_n_role(rows, "coordinator")
    member = by_n_role(rows, "member")

    fig, axes = plt.subplots(1, 3, figsize=(16, 4.5))

    # --- Panel A: sender stage cost (coordinator), log y -------------------
    ax = axes[0]
    for key, label, marker in (("encode_us_mean", "encode", "o"),
                               ("protect_us_mean", "protect", "^"),
                               ("send_us_mean", "broadcast send", "s")):
        ns, means, sds = mean_sd(coord, key)
        if not ns:
            continue
        ax.errorbar(ns, means, yerr=sds, marker=marker, capsize=3, label=label)
    ax.set_yscale("log")
    ax.set_xlabel("audience size N")
    ax.set_ylabel("us per frame (log scale)")
    ax.set_title("Sender stage cost vs audience size (group, 40 ms)")
    ax.set_xticks([1, 2, 3])
    ax.grid(alpha=0.3, which="both")
    ax.legend(fontsize=8)

    # --- Panel B: delivery quality (member), OWD + jitter -------------------
    ax = axes[1]
    for key, label, marker in (("owd_mean_ms", "one-way delay", "o"),
                               ("rfc3550_jitter_ms", "RFC3550 jitter", "^")):
        ns, means, sds = mean_sd(member, key)
        if not ns:
            continue
        ax.errorbar(ns, means, yerr=sds, marker=marker, capsize=3, label=label)
    ax.axhline(150.0, color="red", ls=":", lw=1, label="150 ms OWD budget")
    ax.set_xlabel("audience size N")
    ax.set_ylabel("ms")
    ax.set_title("Delivered quality vs audience size (group, 40 ms)")
    ax.set_xticks([1, 2, 3])
    ax.set_xlim(0.7, 3.3)
    ax.grid(alpha=0.3)
    ax.legend(fontsize=8)
    # OWD/jitter are ~2.4 ms and ~0.3-0.5 ms respectively -- orders below the
    # 150 ms budget line. Annotate the actual values since the budget line
    # otherwise dominates the visible scale and flattens the real data.
    ns, means, sds = mean_sd(member, "owd_mean_ms")
    for n, m in zip(ns, means):
        ax.annotate(f"{m:.2f}", (n, m), textcoords="offset points",
                   xytext=(0, 6), ha="center", fontsize=7)

    # --- Panel C: loss and deadline miss ------------------------------------
    ax = axes[2]
    ns, means, sds = mean_sd(member, "loss_pct")
    if ns:
        ax.errorbar(ns, means, yerr=sds, marker="o", capsize=3, label="loss (member)")
    ns2, means2, _ = mean_sd(coord, "deadline_miss_pct")
    if ns2:
        ax.plot(ns2, means2, marker="s", ls="--", label="deadline miss (sender)")
    ax.axhline(1.0, color="red", ls=":", lw=1, label="1 % loss target")
    ax.set_xlabel("audience size N")
    ax.set_ylabel("%")
    ax.set_title("Loss and deadline-miss vs audience size (group, 40 ms)")
    ax.set_xticks([1, 2, 3])
    ax.set_xlim(0.7, 3.3)
    ax.set_ylim(-0.1, max(1.3, (max(means) if ns else 0) + 0.3))
    ax.grid(alpha=0.3)
    ax.legend(fontsize=8)

    fig.suptitle("Group steady-state campaign: N=1-3, 10 reps x 30 s per point "
                "(results_group_scaling_full/, firmware generation F6)",
                fontsize=9, y=1.02)
    fig.tight_layout()

    out = args.out or os.path.join(os.path.dirname(args.csv_path) or ".", "group_scaling.png")
    fig.savefig(out, dpi=args.dpi, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
