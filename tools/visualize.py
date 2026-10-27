#!/usr/bin/env python3
"""
Turn parsed telemetry into the plots and tables the write-up needs.

Takes one or more result directories produced by parse_telemetry.py (each with
per-label *_tx.csv, *_rx.csv, *_hist.csv, *_tasks.csv and a runs_summary.csv)
and renders:

    sender_scaling.png         protect/send/encode cost against receivers, plus
                               the per-peer linearity panel, with real and
                               phantom transmit cost drawn apart
    rq1_cost.png               airtime, key state, CPU and frame-deadline
                               misses against receiver count -- the four RQ1
                               dimensions that used to reach no plot at all
    cpu_heap.png               CPU share per core and free heap against receivers
    owd_latency.png            OWD p50/p95/p99 against receivers (G.114 line)
    owd_boxplot.png            full OWD distribution, grouped by receivers
    owd_distribution.png       pooled OWD histogram
    security_cost.png          stage cost per variant, when more than one
                               result directory is given
    <label>__owd.png           per-run OWD and verify/decode time series

    results.md                 copy-paste tables against the loss/jitter targets
    summary.json               the same numbers in machine-readable form

Two conventions, both of which exist because breaking them produced a wrong
table before:

- A cell with no evidence behind it renders as "n/a". It never renders as 0,
  and it never renders as a verdict. A talker-only run has no loss figure; a
  run whose clock estimator never converged has no latency figure.
- Transmit cost measured against phantom peers is drawn and tabulated
  separately from transmit cost measured against real acking peers, because a
  phantom waits out a MAC retry budget and a real peer does not.

    python3 tools/visualize.py results_uni --names uni
    python3 tools/visualize.py results_uni results_nocrypto results_ccm \
        --names uni,nocrypto,ccm --out plots
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys

import numpy as np

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

TARGET_OWD_MS = 150.0
TARGET_JITTER_MS = 40.0
TARGET_LOSS_PCT = 1.0

OWD_SENTINEL = -2147483648
NA = "n/a"

TX_COLS = ["seq", "encode_us", "protect_us", "send_us", "air_us_max",
           "npeer", "nfail", "nreal"]
RX_COLS = ["seq", "owd_us", "verify_us", "decode_us", "rms_err", "jb_depth", "rssi"]


# ----------------------------------------------------------------- loading

def _f(value) -> float | None:
    """Parse a summary cell. 'n/a', '' and junk all mean 'no measurement'."""
    if value is None:
        return None
    s = str(value).strip()
    if not s or s == NA:
        return None
    try:
        v = float(s)
    except ValueError:
        m = re.search(r"[-+]?\d+(?:\.\d+)?", s)
        if not m:
            return None
        v = float(m.group())
    return None if v != v else v


def read_summary(path: str) -> list[dict]:
    rows: list[dict] = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            row = {k: (v or "") for k, v in row.items()}
            try:
                row["_receivers"] = int(row.get("receivers", "") or 0)
            except ValueError:
                row["_receivers"] = 0
            rows.append(row)
    return rows


def group_by_receivers(runs: list[dict]) -> dict[int, list[dict]]:
    groups: dict[int, list[dict]] = {}
    for r in runs:
        groups.setdefault(r["_receivers"], []).append(r)
    return groups


def _metric(runs: dict[int, list[dict]], col: str) -> dict[int, np.ndarray]:
    """Receiver count -> array of values, omitting runs with no measurement."""
    out: dict[int, np.ndarray] = {}
    for n, rs in runs.items():
        vals = [_f(r.get(col)) for r in rs]
        vals = [v for v in vals if v is not None]
        if vals:
            out[n] = np.array(vals)
    return out


def load_rx_matrix(path: str) -> tuple[np.ndarray, np.ndarray]:
    owd: list[tuple[float, float]] = []
    costs: list[tuple[float, float, float]] = []
    try:
        fh = open(path, newline="", encoding="utf-8")
    except FileNotFoundError:
        return np.empty((0, 2)), np.empty((0, 3))
    with fh:
        for row in csv.DictReader(fh):
            try:
                ow = float(row["owd_us"])
                seq = float(row["seq"])
            except (KeyError, ValueError):
                continue
            if ow == OWD_SENTINEL:
                continue
            owd.append((seq, ow / 1000.0))
            try:
                costs.append((seq, float(row["verify_us"]) / 1000.0,
                              float(row["decode_us"]) / 1000.0))
            except (KeyError, ValueError):
                pass
    owd.sort()
    costs.sort()
    if not owd:
        return np.empty((0, 2)), np.empty((0, 3))
    return np.array(owd), np.array(costs)


def _marker(i: int) -> str:
    return "o^sDv*"[i % 6]


def _plot_metric(ax, variants, col, label_fmt, **kw):
    """Plot one summary column against receiver count for every variant."""
    drew = False
    for i, (name, runs) in enumerate(variants):
        metric = _metric(runs, col)
        if not metric:
            continue
        ns = sorted(metric)
        ax.plot(ns, [np.mean(metric[n]) for n in ns], marker=_marker(i),
                label=label_fmt.format(name=name), **kw)
        drew = True
    return drew


def _finish(ax, xlabel="receivers", ylabel="", title="", logx=True):
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    if logx:
        ax.set_xscale("log", base=2)
    if ax.get_legend_handles_labels()[1]:
        ax.legend(fontsize=7)
    ax.grid(alpha=0.3)


# ------------------------------------------------------------------- plots

def sender_scaling(variants, out: str) -> None:
    fig, axes = plt.subplots(1, 3, figsize=(17, 4.5))

    for i, (name, runs) in enumerate(variants):
        for col, ls, tag in (("protect_us_mean", "-", "protect"),
                             ("send_us_mean", "--", "send"),
                             ("encode_us_mean", ":", "encode")):
            metric = _metric(runs, col)
            if not metric:
                continue
            ns = sorted(metric)
            axes[0].plot(ns, [np.mean(metric[n]) for n in ns], marker=_marker(i),
                         ls=ls, label=f"{name} {tag}")
    _finish(axes[0], ylabel="us per frame",
            title="Sender stage cost vs receiver count (RQ1)")

    for i, (name, runs) in enumerate(variants):
        for col, ls, tag in (("protect_us_per_peer", "-", "protect/peer"),
                             ("send_us_per_peer", "--", "send/peer (all)")):
            metric = _metric(runs, col)
            if not metric:
                continue
            ns = sorted(metric)
            axes[1].plot(ns, [np.mean(metric[n]) for n in ns], marker=_marker(i),
                         ls=ls, label=f"{name} {tag}")
    _finish(axes[1], ylabel="us per frame per peer",
            title="Per-peer cost (flat = perfectly linear scaling)")

    # The panel the whole phantom question turns on. If the two lines diverge,
    # the scaling curve in the left panel is measuring retry timeout.
    drew = False
    for i, (name, runs) in enumerate(variants):
        for col, ls, tag in (("send_real_us_per_peer", "-", "real (acking)"),
                             ("send_phantom_us_per_peer", "--", "phantom")):
            metric = _metric(runs, col)
            if not metric:
                continue
            ns = sorted(metric)
            axes[2].plot(ns, [np.mean(metric[n]) for n in ns], marker=_marker(i),
                         ls=ls, label=f"{name} {tag}")
            drew = True
    if not drew:
        axes[2].text(0.5, 0.5, "no real/phantom split in these logs\n"
                               "(pre-#SUMMARY firmware)",
                     ha="center", va="center", transform=axes[2].transAxes,
                     fontsize=8)
    _finish(axes[2], ylabel="us per unicast",
            title="Transmit cost: real vs phantom peer", logx=drew)

    fig.tight_layout()
    fig.savefig(os.path.join(out, "sender_scaling.png"))
    plt.close(fig)


def rq1_cost(variants, out: str) -> None:
    """Airtime, key state, deadline misses and CPU -- the RQ1 dimensions."""
    fig, axes = plt.subplots(2, 2, figsize=(12, 8))

    if not _plot_metric(axes[0][0], variants, "air_bytes_per_s", "{name}"):
        axes[0][0].text(0.5, 0.5, "no airtime data", ha="center", va="center",
                        transform=axes[0][0].transAxes, fontsize=8)
    _finish(axes[0][0], ylabel="offered bytes/s",
            title="Airtime offered vs receiver count")

    if not _plot_metric(axes[0][1], variants, "peer_state_bytes", "{name}"):
        axes[0][1].text(0.5, 0.5, "no key-state data", ha="center", va="center",
                        transform=axes[0][1].transAxes, fontsize=8)
    _finish(axes[0][1], ylabel="bytes",
            title="Key state held (sizeof(peer) x N)")

    if not _plot_metric(axes[1][0], variants, "deadline_miss_pct", "{name}"):
        axes[1][0].text(0.5, 0.5, "no deadline-miss data", ha="center",
                        va="center", transform=axes[1][0].transAxes, fontsize=8)
    axes[1][0].axhline(0.0, color="green", ls=":", lw=1)
    _finish(axes[1][0], ylabel="% of frames over budget",
            title="Frame deadline misses -- the RQ1 scaling limit")

    if not _plot_metric(axes[1][1], variants, "cpu0_run_pct", "{name} core0"):
        axes[1][1].text(0.5, 0.5, "no run-window CPU data\n"
                                  "(pre-#SUMMARY firmware)",
                        ha="center", va="center",
                        transform=axes[1][1].transAxes, fontsize=8)
    _plot_metric(axes[1][1], variants, "cpu1_run_pct", "{name} core1", ls="--")
    _finish(axes[1][1], ylabel="CPU % over the run",
            title="CPU utilisation vs receiver count")

    fig.tight_layout()
    fig.savefig(os.path.join(out, "rq1_cost.png"))
    plt.close(fig)


def cpu_heap(variants, out: str) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    if not _plot_metric(axes[0], variants, "cpu0_run_pct", "{name} core0"):
        axes[0].text(0.5, 0.5, "no run-window CPU data", ha="center",
                     va="center", transform=axes[0].transAxes, fontsize=8)
    _plot_metric(axes[0], variants, "cpu1_run_pct", "{name} core1", ls="--")
    _finish(axes[0], ylabel="CPU %", title="CPU share over the run vs receivers")

    if not _plot_metric(axes[1], variants, "heap_free", "{name} free"):
        axes[1].text(0.5, 0.5, "no heap data", ha="center", va="center",
                     transform=axes[1].transAxes, fontsize=8)
    _plot_metric(axes[1], variants, "heap_min_ever", "{name} min ever", ls="--")
    _finish(axes[1], ylabel="bytes", title="Free heap vs receiver count")

    fig.tight_layout()
    fig.savefig(os.path.join(out, "cpu_heap.png"))
    plt.close(fig)


def owd_latency(variants, out: str) -> None:
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.5))
    any_data = False
    for ax, col, title in ((axes[0], "owd_p50_ms", "OWD p50"),
                           (axes[1], "owd_p95_ms", "OWD p95 (G.114)"),
                           (axes[2], "owd_p99_ms", "OWD p99")):
        drew = _plot_metric(ax, variants, col, "{name}")
        any_data = any_data or drew
        ax.axhline(TARGET_OWD_MS, color="red", ls=":", lw=1)
        _finish(ax, ylabel="ms", title=title, logx=drew)
        if not drew:
            ax.text(0.5, 0.5, "no delivery evidence", ha="center", va="center",
                    transform=ax.transAxes, fontsize=8)
    if not any_data:
        fig.suptitle("No receiver-side logs in this result set", fontsize=9)
    axes[0].set_ylabel("one-way delay ms")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "owd_latency.png"))
    plt.close(fig)


def owd_boxplot(variants, ddirs: list[str], out: str) -> None:
    npanels = len(variants)
    fig, axes = plt.subplots(1, npanels, figsize=(5.5 * npanels, 4.5),
                             squeeze=False)
    for c, ((name, runs), ddir) in enumerate(zip(variants, ddirs)):
        ax = axes[0][c]
        samples: list[np.ndarray] = []
        labels: list[str] = []
        for n in sorted(runs):
            stack: list[float] = []
            for r in runs[n]:
                label = r.get("label", "")
                if not label:
                    continue
                safe = re.sub(r"[^A-Za-z0-9_.-]", "_", label)
                owd, _ = load_rx_matrix(os.path.join(ddir, f"{safe}_rx.csv"))
                if owd.size:
                    stack.extend(owd[:, 1].tolist())
            if stack:
                samples.append(np.array(stack))
                labels.append(str(n))
        if not samples:
            ax.set_title(f"{name}: no rx trace")
            continue
        ax.boxplot(samples, showfliers=False)
        ax.set_xticklabels(labels)
        ax.axhline(TARGET_OWD_MS, color="red", ls=":", lw=1)
        ax.set_title(name)
        ax.set_xlabel("receivers")
        ax.set_ylabel("one-way delay ms")
        ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "owd_boxplot.png"))
    plt.close(fig)


def owd_distribution(variants, ddirs: list[str], out: str) -> None:
    npanels = len(variants)
    fig, axes = plt.subplots(1, npanels, figsize=(5.5 * npanels, 4.5),
                             squeeze=False)
    for c, ((name, runs), ddir) in enumerate(zip(variants, ddirs)):
        ax = axes[0][c]
        pool: list[float] = []
        for rs in runs.values():
            for r in rs:
                label = r.get("label", "")
                if not label:
                    continue
                safe = re.sub(r"[^A-Za-z0-9_.-]", "_", label)
                owd, _ = load_rx_matrix(os.path.join(ddir, f"{safe}_rx.csv"))
                if owd.size:
                    pool.extend(owd[:, 1].tolist())
        if not pool:
            ax.set_title(f"{name}: no rx trace")
            continue
        ax.hist(pool, bins=50, alpha=0.7)
        ax.axvline(TARGET_OWD_MS, color="red", ls=":", lw=1)
        ax.set_title(name)
        ax.set_xlabel("one-way delay ms")
        ax.set_ylabel("frames")
        ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(out, "owd_distribution.png"))
    plt.close(fig)


def security_cost(variants, out: str) -> None:
    if len(variants) < 2:
        return
    common = set(variants[0][1])
    for _, runs in variants[1:]:
        common &= set(runs)
    ns = sorted(common)
    if not ns:
        print("no common receiver count across variants; skipping security_cost.png",
              file=sys.stderr)
        return
    n = ns[-1]

    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    names = [nm for nm, _ in variants]
    # Medians, not means: these are wall-clock timers around preemptible work.
    for ax, col, title in ((axes[0], "protect_us_median", "Sender protect, us/frame (median)"),
                           (axes[1], "verify_us_median", "Receiver verify, us/frame (median)")):
        vals = []
        for _, runs in variants:
            metric = _metric(runs, col)
            vals.append(float(np.mean(metric[n])) if n in metric and metric[n].size
                        else float("nan"))
        x = np.arange(len(names))
        ax.bar(x, vals, color=["#4c72b0", "#dd8452", "#55a868"][:len(names)])
        ax.set_xticks(x, names)
        ax.set_title(title)
        ax.grid(alpha=0.3, axis="y")
        for xi, v in zip(x, vals):
            if v == v:
                ax.text(xi, v, f"{v:.1f}", ha="center", va="bottom", fontsize=8)
    fig.suptitle(f"Security stage cost at {n} receivers (RQ2)")
    fig.tight_layout()
    fig.savefig(os.path.join(out, "security_cost.png"))
    plt.close(fig)


def per_run_timeseries(ddir: str, runs: list[dict], out: str) -> None:
    for r in runs:
        label = r.get("label", "")
        if not label:
            continue
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", label)
        owd, costs = load_rx_matrix(os.path.join(ddir, f"{safe}_rx.csv"))
        if not owd.size:
            continue
        fig, axes = plt.subplots(2, 1, figsize=(10, 5), sharex=True)
        axes[0].plot(owd[:, 0], owd[:, 1], ".", ms=1.5, alpha=0.5)
        axes[0].axhline(TARGET_OWD_MS, color="red", ls=":", lw=1)
        axes[0].set_ylabel("OWD ms")
        p95 = float(np.percentile(owd[:, 1], 95))
        axes[0].axhline(p95, color="orange", ls="-", lw=1,
                        label=f"p95 {p95:.1f} ms (trace)")
        axes[0].legend(fontsize=7)
        if costs.size:
            axes[1].plot(costs[:, 0], costs[:, 1], ".", ms=1.5, alpha=0.5,
                         label="verify")
            axes[1].plot(costs[:, 0], costs[:, 2], ".", ms=1.5, alpha=0.5,
                         label="decode")
            axes[1].legend(fontsize=7)
        axes[1].set_xlabel("seq")
        axes[1].set_ylabel("receive cost ms")
        cov = r.get("rx_trace_coverage", "")
        note = f"  [trace {cov} % complete]" if cov and cov != NA else ""
        fig.suptitle(f"{label}  (n={r.get('_receivers', '')} receivers){note}")
        fig.tight_layout()
        fig.savefig(os.path.join(out, f"{safe}__owd.png"))
        plt.close(fig)


# ------------------------------------------------------------------ tables

def _cell(arr, digits: int = 1) -> str:
    if arr is None or (hasattr(arr, "size") and not arr.size):
        return NA
    a = np.array([x for x in np.atleast_1d(arr) if x == x])
    if not a.size:
        return NA
    return f"{np.mean(a):.{digits}f}"


def _agg(metric: dict[int, np.ndarray], n: int) -> dict | None:
    if n not in metric or not metric[n].size:
        return None
    vals = metric[n][np.isfinite(metric[n])]
    if not vals.size:
        return None
    return {"mean": round(float(np.mean(vals)), 2),
            "sd": round(float(np.std(vals)), 2),
            "n": int(vals.size)}


def results_md(variants, out: str) -> str:
    lines = ["# Results", ""]
    lines.append("`n/a` means the run carried no evidence for that metric -- a "
                 "talker-only log has no loss and no latency. It is not a zero "
                 "and not a pass.")
    lines.append("")
    body: dict[str, dict] = {}

    for name, runs in variants:
        cols = {
            "protect_us": _metric(runs, "protect_us_mean"),
            "protect_us_median": _metric(runs, "protect_us_median"),
            "protect_us_per_peer": _metric(runs, "protect_us_per_peer"),
            "encode_us": _metric(runs, "encode_us_mean"),
            "send_us_per_peer": _metric(runs, "send_us_per_peer"),
            "heap_min_ever": _metric(runs, "heap_min_ever"),
            "cpu1_run_pct": _metric(runs, "cpu1_run_pct"),
            "tx_cb_fail": _metric(runs, "tx_cb_fail"),
            "tx_timeout": _metric(runs, "tx_timeout"),
            "send_us": _metric(runs, "send_us_mean"),
            "send_real_us_per_peer": _metric(runs, "send_real_us_per_peer"),
            "send_phantom_us_per_peer": _metric(runs, "send_phantom_us_per_peer"),
            "verify_us": _metric(runs, "verify_us_mean"),
            "verify_us_median": _metric(runs, "verify_us_median"),
            "decode_us": _metric(runs, "decode_us_mean"),
            "decode_us_median": _metric(runs, "decode_us_median"),
            "owd_p50_ms": _metric(runs, "owd_p50_ms"),
            "owd_p95_ms": _metric(runs, "owd_p95_ms"),
            "owd_p99_ms": _metric(runs, "owd_p99_ms"),
            "jitter_ms": _metric(runs, "jitter_ms"),
            "loss_pct": _metric(runs, "loss_pct"),
            "cpu0_run_pct": _metric(runs, "cpu0_run_pct"),
            "cpu0_burst_pct": _metric(runs, "cpu0_burst_pct"),
            "tx_rate_deficit_pct": _metric(runs, "tx_rate_deficit_pct"),
            "tx_fps_achieved": _metric(runs, "tx_fps_achieved"),
            "heap_free": _metric(runs, "heap_free"),
            "deadline_miss_pct": _metric(runs, "deadline_miss_pct"),
            "air_bytes_per_s": _metric(runs, "air_bytes_per_s"),
            "peer_state_bytes": _metric(runs, "peer_state_bytes"),
            "peer_bytes_per_peer": _metric(runs, "peer_bytes_per_peer"),
        }

        lines.append(f"## {name}")
        lines.append("")
        lines.append("### Voice quality against the targets "
                     "(G.114 150 ms / NIST 40 ms / NIST 1 %)")
        lines.append("| receivers | runs | OWD p50 | p95 | p99 | jitter ms | "
                     "loss % | delivery evidence |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for n in sorted(runs):
            rs = runs[n]
            p95 = _cell(cols["owd_p95_ms"].get(n))
            if p95 != NA and float(p95) > TARGET_OWD_MS:
                p95 += " :warning:"
            jit = _cell(cols["jitter_ms"].get(n), 2)
            if jit != NA and float(jit.split()[0]) > TARGET_JITTER_MS:
                jit += " :warning:"
            loss = _cell(cols["loss_pct"].get(n), 3)
            if loss != NA and float(loss.split()[0]) > TARGET_LOSS_PCT:
                loss += " :warning:"
            eviden = "yes" if any(r.get("has_delivery_evidence") == "yes"
                                  for r in rs) else "no"
            lines.append(
                f"| {n} | {len(rs)} | {_cell(cols['owd_p50_ms'].get(n), 2)} | "
                f"{p95} | {_cell(cols['owd_p99_ms'].get(n), 2)} | {jit} | "
                f"{loss} | {eviden} |")
        lines.append("")

        lines.append("### Sender cost (RQ1)")
        lines.append("| receivers | protect us | send us | send/peer REAL | "
                     "send/peer phantom | deadline miss % | air B/s | "
                     "key state B | B/peer | cpu0 % |")
        lines.append("|---|---|---|---|---|---|---|---|---|---|")
        for n in sorted(runs):
            lines.append(
                f"| {n} | {_cell(cols['protect_us'].get(n))} | "
                f"{_cell(cols['send_us'].get(n))} | "
                f"{_cell(cols['send_real_us_per_peer'].get(n))} | "
                f"{_cell(cols['send_phantom_us_per_peer'].get(n))} | "
                f"{_cell(cols['deadline_miss_pct'].get(n), 2)} | "
                f"{_cell(cols['air_bytes_per_s'].get(n), 0)} | "
                f"{_cell(cols['peer_state_bytes'].get(n), 0)} | "
                f"{_cell(cols['peer_bytes_per_peer'].get(n), 0)} | "
                f"{_cell(cols['cpu0_run_pct'].get(n))} |")
        lines.append("")

        lines.append("### Receiver cost -- median, with the mean beside it")
        lines.append("Stage timers are wall-clock intervals around preemptible "
                     "work, so a few descheduled frames move the mean and leave "
                     "the median where the work is. Quote the median.")
        lines.append("")
        lines.append("| receivers | verify median | verify mean | "
                     "decode median | decode mean |")
        lines.append("|---|---|---|---|---|")
        for n in sorted(runs):
            lines.append(
                f"| {n} | {_cell(cols['verify_us_median'].get(n))} | "
                f"{_cell(cols['verify_us'].get(n))} | "
                f"{_cell(cols['decode_us_median'].get(n))} | "
                f"{_cell(cols['decode_us'].get(n))} |")
        lines.append("")

        # Security events and capture integrity, neither of which had a table.
        lines.append("### Security events and capture integrity")
        lines.append("| receivers | auth fail | replay rejects | unknown epoch "
                     "| malformed | rx trace coverage | malformed rows |")
        lines.append("|---|---|---|---|---|---|---|")
        for n in sorted(runs):
            rs = runs[n]
            def tot(key):
                vals = [_f(r.get(key)) for r in rs]
                vals = [v for v in vals if v is not None]
                return f"{int(sum(vals))}" if vals else NA
            cov = [r.get("rx_trace_coverage", NA) for r in rs]
            cov = [c for c in cov if c and c != NA]
            lines.append(
                f"| {n} | {tot('auth_fail')} | {tot('replay_drop')} | "
                f"{tot('epoch_unknown')} | {tot('malformed')} | "
                f"{(cov[0] + ' %') if cov else NA} | {tot('trace_malformed')} |")
        lines.append("")

        details: dict = {}
        for n in sorted(runs):
            rec = {"runs": len(runs[n])}
            for key, metric in cols.items():
                rec[key] = _agg(metric, n)
            rec["has_delivery_evidence"] = any(
                r.get("has_delivery_evidence") == "yes" for r in runs[n])
            details[str(n)] = rec
        body[name] = details

    md = "\n".join(lines)
    with open(os.path.join(out, "results.md"), "w", encoding="utf-8") as fh:
        fh.write(md)

    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump({"targets": {"owd_p95_ms": TARGET_OWD_MS,
                               "jitter_ms": TARGET_JITTER_MS,
                               "loss_pct": TARGET_LOSS_PCT},
                   "variants": body}, fh, indent=2)
    return md


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dirs", nargs="+", help="result directories from parse_telemetry.py")
    ap.add_argument("--names", default="",
                    help="comma-separated variant names for the directories")
    ap.add_argument("--out", default="plots", help="output directory")
    ap.add_argument("--dpi", type=int, default=140)
    ap.add_argument("--no-timeseries", action="store_true",
                    help="skip the per-run OWD time-series PNGs")
    args = ap.parse_args()

    plt.rcParams["savefig.dpi"] = args.dpi

    names = [x.strip() for x in args.names.split(",") if x.strip()]
    if names and len(names) != len(args.dirs):
        print("--names must have one entry per directory", file=sys.stderr)
        return 2

    variants: list[tuple[str, dict[int, list[dict]]]] = []
    for i, d in enumerate(args.dirs):
        summary = os.path.join(d, "runs_summary.csv")
        if not os.path.isfile(summary):
            print(f"{summary}: not found", file=sys.stderr)
            return 1
        runs = read_summary(summary)
        if not runs:
            print(f"{summary}: no rows", file=sys.stderr)
            return 1
        name = names[i] if names else os.path.basename(os.path.normpath(d))
        variants.append((name, group_by_receivers(runs)))

    os.makedirs(args.out, exist_ok=True)

    sender_scaling(variants, args.out)
    rq1_cost(variants, args.out)
    cpu_heap(variants, args.out)
    owd_latency(variants, args.out)
    owd_boxplot(variants, args.dirs, args.out)
    owd_distribution(variants, args.dirs, args.out)
    security_cost(variants, args.out)

    if not args.no_timeseries:
        for d in args.dirs:
            runs = read_summary(os.path.join(d, "runs_summary.csv"))
            per_run_timeseries(d, runs, args.out)

    md = results_md(variants, args.out)
    print(md)
    print(f"\nplots and results written to {args.out}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
