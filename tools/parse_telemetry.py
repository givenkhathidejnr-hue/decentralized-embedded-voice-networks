#!/usr/bin/env python3
"""
Parse a captured serial log from the vox baseline firmware into tidy CSV.

The firmware emits everything a run needs to be reproducible: a configuration
header, a machine-readable summary, per-frame trace rows, a one-way-delay
histogram and a task table. This turns one or more captured runs into flat
files you can put straight into the results chapter, and prints the summary
that the delay, jitter and loss targets are judged against.

    python3 tools/parse_telemetry.py run.log --outdir results/

Produces, per run label:
    <label>_tx.csv       per-frame sender trace
    <label>_rx.csv       per-frame receiver trace
    <label>_hist.csv     one-way delay histogram
    <label>_tasks.csv    per-task stack high-water marks and CPU share
    runs_summary.csv     one row per run, every config field plus the headline
                         metrics, ready to pivot on receiver count

Three rules this parser follows, each of which exists because breaking it
produced a wrong number in a previous revision:

1. FIRMWARE AGGREGATES BEAT HOST ARITHMETIC. The "#SUMMARY,k=v" lines are
   computed on chip over every frame of the run, in constant memory. The trace
   ring holds only the most recent frames and reaches the host over a UART with
   no flow control, so it can and does arrive incomplete. Where both exist, the
   firmware figure wins and the trace supplies distribution shape only.

2. ABSENCE OF EVIDENCE IS NOT A PASS OR A FAIL. A talker-only log has no
   one-way delay and no loss. Those cells read "n/a", never "0.0" and never
   "no" - both of which previously turned an empty run into a verdict.

3. STAGE TIMINGS ARE REPORTED AS MEDIANS. The timers are wall-clock intervals
   around work that can be preempted; a handful of descheduled frames move the
   mean by an order of magnitude while leaving the median where the work
   actually is. Means are still emitted, next to the median, so the gap is
   visible rather than hidden.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
from collections import OrderedDict

TX_COLS = ["seq", "encode_us", "protect_us", "send_us", "air_us_max",
           "npeer", "nfail", "nreal"]
RX_COLS = ["seq", "owd_us", "verify_us", "decode_us", "rms_err", "jb_depth", "rssi"]

OWD_SENTINEL = -2147483648

# Targets the literature review fixes for acceptable voice.
TARGET_OWD_MS = 150.0     # ITU-T G.114 one-way delay
TARGET_JITTER_MS = 40.0   # NIST
TARGET_LOSS_PCT = 1.0     # NIST

NA = "n/a"


class Run:
    def __init__(self, label: str):
        self.label = label
        self.config: "OrderedDict[str, str]" = OrderedDict()
        self.fw: "OrderedDict[str, str]" = OrderedDict()   # the #SUMMARY block
        self.tx: list[list[int]] = []
        self.rx: list[list[int]] = []
        self.hist: list[tuple[int, str, int]] = []
        self.tasks: list[list[str]] = []
        self.legacy: dict[str, str] = {}      # prose scrape, pre-#SUMMARY logs
        self.tx_rows_declared: int | None = None
        self.rx_rows_declared: int | None = None
        self.tx_rows_malformed = 0
        self.rx_rows_malformed = 0
        self.receivers_disputed: tuple[int, int] | None = None

    # -- typed access to the firmware summary ------------------------------
    def num(self, key: str) -> float | None:
        v = self.fw.get(key)
        if v is None:
            return None
        try:
            return float(v)
        except ValueError:
            return None

    def count(self, key: str) -> int:
        v = self.num(key)
        return int(v) if v is not None else 0


def _strip_ansi(line: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", line)


def _kv_pairs(rest: str) -> list[tuple[str, str]]:
    out = []
    for kv in rest.split(","):
        if "=" in kv:
            k, _, v = kv.partition("=")
            out.append((k.strip(), v.strip()))
    return out


def parse(path: str) -> list[Run]:
    runs: list[Run] = []
    cur: Run | None = None
    mode = None

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = _strip_ansi(raw).strip()
            if not line:
                continue

            # ---- headers -------------------------------------------------
            if line.startswith("#RUN,"):
                label = line.split("label=", 1)[1].strip() if "label=" in line else "run"
                cur = Run(label)
                runs.append(cur)
                mode = None
                continue

            if line.startswith("#") and cur is not None:
                if line.startswith("#CSV_BEGIN"):
                    mode = "csv"
                    # "#CSV_BEGIN,tx_rows=N,rx_rows=M" announces what the board
                    # intended to send, so truncation is detectable.
                    for k, v in _kv_pairs(line[len("#CSV_BEGIN"):].lstrip(",")):
                        if k == "tx_rows":
                            cur.tx_rows_declared = int(v) if v.isdigit() else None
                        elif k == "rx_rows":
                            cur.rx_rows_declared = int(v) if v.isdigit() else None
                    continue
                if line.startswith("#HIST_BEGIN"):
                    mode = "hist"
                    continue
                if line.startswith("#TASKS_BEGIN"):
                    mode = "tasks"
                    continue
                if line.startswith(("#CSV_END", "#HIST_END", "#TASKS_END")):
                    mode = None
                    continue

                body = line[1:]
                section, _, rest = body.partition(",")
                if not rest:
                    continue
                if section == "SUMMARY":
                    # The authoritative numbers. Several lines, one namespace.
                    for k, v in _kv_pairs(rest):
                        cur.fw[k] = v
                else:
                    for k, v in _kv_pairs(rest):
                        cur.config[f"{section.lower()}.{k}"] = v
                continue

            if cur is None:
                continue

            # ---- table bodies --------------------------------------------
            if mode == "csv":
                if line.startswith("dir,"):
                    continue
                parts = line.split(",")
                if parts[0] == "TX":
                    # 8 fields = pre-nreal logs; 9 = current firmware.
                    if len(parts) in (8, 9):
                        try:
                            row = [int(x) for x in parts[1:]]
                            if len(row) == len(TX_COLS) - 1:
                                # Pre-nreal log: the real/phantom composition of
                                # the frame was not recorded. 0 means unknown,
                                # not "no real peers".
                                row.append(0)
                            cur.tx.append(row)
                            continue
                        except ValueError:
                            pass
                    cur.tx_rows_malformed += 1
                elif parts[0] == "RX":
                    if len(parts) == 8:
                        try:
                            cur.rx.append([int(x) for x in parts[1:]])
                            continue
                        except ValueError:
                            pass
                    cur.rx_rows_malformed += 1
                continue

            if mode == "hist":
                if line.startswith("bin_lo_us"):
                    continue
                parts = line.split(",")
                if len(parts) == 3:
                    try:
                        cur.hist.append((int(parts[0]), parts[1], int(parts[2])))
                    except ValueError:
                        pass
                continue

            if mode == "tasks":
                if line.startswith("name,"):
                    continue
                parts = line.split(",")
                if len(parts) == 6:
                    cur.tasks.append(parts)
                continue

            # ---- legacy prose scrape --------------------------------------
            # Only used for logs captured before the firmware emitted
            # #SUMMARY. Kept so old captures still parse; never preferred.
            m = re.match(r"^([a-z][a-z0-9 /()\-.]+?)\s{2,}(.+)$", line)
            if m:
                key = re.sub(r"[^a-z0-9]+", "_", m.group(1).strip()).strip("_")
                cur.legacy.setdefault(key, m.group(2).strip())

    return runs


# ------------------------------------------------------------- statistics

def percentile(values: list[float], q: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    pos = (len(s) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(s) - 1)
    frac = pos - lo
    return s[lo] * (1.0 - frac) + s[hi] * frac


def hist_percentile(hist: list[tuple[int, str, int]], q: float) -> float:
    total = sum(c for _, _, c in hist)
    if total == 0:
        return float("nan")
    target = q * total
    acc = 0
    for lo, hi, count in hist:
        acc += count
        if acc >= target:
            # Report the bin's upper edge: the value is somewhere inside the
            # bin and claiming more precision than the bin width would be
            # false precision.
            return float(lo) if hi == "inf" else float(hi)
    return float(hist[-1][0])


def med(values: list[float]) -> float:
    return percentile(values, 0.50) if values else float("nan")


def iqr(values: list[float]) -> float:
    if not values:
        return float("nan")
    return percentile(values, 0.75) - percentile(values, 0.25)


def fmt(x, digits: int = 2) -> str:
    """Numbers that do not exist print as n/a, never as 0."""
    if x is None:
        return NA
    try:
        if x != x:          # NaN
            return NA
    except TypeError:
        return NA
    return f"{round(float(x), digits)}"


def write_csv(path: str, header: list[str], rows) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


# --------------------------------------------------------------- summarise

# ESP-NOW accepts at most 20 acknowledged unicast peers, mirrored in the
# firmware as VOX_MAX_PEERS. Any trace row claiming more than that is serial
# corruption, not a measurement.
MAX_PEERS = 20


def _label_receivers(label: str) -> int | None:
    """n<N> means N receivers; p<N> means N phantoms on top of one real peer."""
    m = re.search(r"(?:^|[_-])n(\d+)(?:[_-]|$)", label)
    if m:
        return int(m.group(1))
    m = re.search(r"(?:^|[_-])p(\d+)(?:[_-]|$)", label)
    if m:
        return int(m.group(1)) + 1
    return None


def _receivers(run: Run) -> int:
    """
    How many receivers this run's sender was talking to.

    Three sources, in descending order of trust:

    1. The firmware's end-of-run census. Taken at `run stop`, so unlike the
       header's #PEERS line it survives a `phantom N` issued after the run
       window opened.
    2. The most common npeer in the trace. The MODE, not the max: a single
       corrupted row from the serial link would otherwise set the receiver
       count for the whole run, and in the archived logs it did - one run was
       filed under 31143 receivers. Values above the ESP-NOW ceiling are
       discarded outright.
    3. The run label. A receiver-side log has no TX rows at all, and filing
       every one of them under 0 receivers is what kept sender cost and
       delivered quality off the same axis.
    """
    if run.config.get("experiment.architecture") == "group":
        # The full control mesh is not the group audio audience.
        return run.count("group_listeners")
    n = run.count("peers")
    if n:
        return n

    if run.tx:
        counts: dict[int, int] = {}
        for r in run.tx:
            v = r[5]
            if 1 <= v <= MAX_PEERS:
                counts[v] = counts.get(v, 0) + 1
        if counts:
            mode = max(counts, key=lambda k: (counts[k], -k))
            from_label = _label_receivers(run.label)
            # If the label and the trace disagree, trust the label and say so:
            # the label is what the harness asked for, the trace is what
            # survived the UART.
            if from_label is not None and from_label != mode:
                run.receivers_disputed = (mode, from_label)
                return from_label
            return mode

    from_label = _label_receivers(run.label)
    return from_label if from_label is not None else 0


def summarise(run: Run) -> dict:
    has_fw = bool(run.fw)

    # ---- one-way delay ----------------------------------------------------
    owd_trace = [r[1] / 1000.0 for r in run.rx if r[1] != OWD_SENTINEL]
    owd_n_fw = run.count("owd_n")

    # Trace coverage decides whether the trace may supply percentiles at all.
    declared = run.rx_rows_declared
    received = len(run.rx)
    coverage = (received / declared) if declared else (1.0 if received else 0.0)

    p50 = p95 = p99 = float("nan")
    src = "none"
    if owd_trace and coverage >= 0.90 and len(owd_trace) >= 20:
        src = "trace"
        p50, p95, p99 = (percentile(owd_trace, q) for q in (0.50, 0.95, 0.99))
    elif run.hist:
        # The histogram is accumulated on chip over every frame, so it is
        # complete even when the trace dump was truncated. Its resolution is
        # the bin width and the summary says so.
        src = "histogram(+/-2ms)"
        p50, p95, p99 = (hist_percentile(run.hist, q) / 1000.0
                         for q in (0.50, 0.95, 0.99))
    elif owd_trace:
        src = f"trace(partial {coverage:.0%})"
        p50, p95, p99 = (percentile(owd_trace, q) for q in (0.50, 0.95, 0.99))

    have_owd = (owd_n_fw > 0) if has_fw else bool(owd_trace)
    if not have_owd:
        p50 = p95 = p99 = float("nan")
        src = "none"

    # ---- stage timings ----------------------------------------------------
    def tcol(i, rows):
        return [float(r[i]) for r in rows]

    enc_t, pro_t, snd_t = (tcol(i, run.tx) for i in (1, 2, 3))
    ver_t, dec_t = (tcol(i, run.rx) for i in (2, 3))

    npeer = _receivers(run)
    nreal = run.count("peers_real")
    if not nreal and run.tx:
        nreal = max((r[7] for r in run.tx if len(r) > 7), default=0)
    nreal = nreal or None

    # Firmware means are over the whole run; trace medians are robust to the
    # preemption outliers that inflate any mean taken from wall-clock timers.
    def stage(name, trace_vals, fw_mean_key, fw_n_key):
        fw_mean = run.num(fw_mean_key) if has_fw else None
        fw_n = run.count(fw_n_key) if has_fw else 0
        if has_fw and fw_n == 0:
            return {"mean": None, "median": None, "iqr": None, "n": 0}
        return {
            "mean": fw_mean if fw_mean is not None else (
                sum(trace_vals) / len(trace_vals) if trace_vals else None),
            "median": med(trace_vals) if trace_vals else None,
            "iqr": iqr(trace_vals) if trace_vals else None,
            "n": fw_n or len(trace_vals),
        }

    encode = stage("encode", enc_t, "encode_us_mean", "encode_n")
    protect = stage("protect", pro_t, "protect_us_mean", "protect_n")
    send = stage("send", snd_t, "send_us_mean", "send_n")
    verify = stage("verify", ver_t, "verify_us_mean", "verify_n")
    decode = stage("decode", dec_t, "decode_us_mean", "decode_n")

    # RFC 3550 jitter. Pre-#SUMMARY logs only carry it as prose, so fall back
    # to the scrape rather than reporting n/a for an archived capture that
    # genuinely measured it.
    jitter_ms = run.num("rfc3550_jitter_ms") if owd_n_fw else None
    if jitter_ms is None and not has_fw and owd_trace:
        m = re.search(r"([0-9.]+)", run.legacy.get("rfc3550_jitter_ms", "") or "")
        if m:
            jitter_ms = float(m.group(1))

    # ---- delivery ---------------------------------------------------------
    delivery_n = run.count("delivery_n") if has_fw else 0
    loss_complete = run.num("loss_complete")
    complete = loss_complete == 1 if run.num("measurement_schema") == 2 else loss_complete != 0
    loss_pct = run.num("loss_pct") if delivery_n > 0 and complete else None
    if not has_fw:
        m = re.search(r"loss\s+([0-9.]+)", run.legacy.get("played_concealed", "") or "")
        if m and "0 / 0" not in (run.legacy.get("played_concealed") or ""):
            loss_pct = float(m.group(1))
            delivery_n = 1

    # ---- CPU, over the run window and over the burst ----------------------
    cpu_valid = run.count("cpu_run_valid") > 0
    cpu0_run = run.num("cpu0_run_pct") if cpu_valid else None
    cpu1_run = run.num("cpu1_run_pct") if cpu_valid else None
    cpu0_burst = cpu1_burst = None
    dur = run.num("duration_s")
    nominal = run.num("nominal_fps")
    frames = run.count("tx_frames")
    if cpu_valid and dur and frames:
        # Measured burst span where the firmware reports one; the frame-count
        # derivation is only a fallback for older logs, and it assumes the
        # sender kept up, which is exactly what fails at the scaling limit.
        talk_s = run.num("tx_burst_s") or (frames / nominal if nominal else 0)
        if 0 < talk_s <= dur:
            scale = dur / talk_s
            cpu0_burst = min(100.0, (cpu0_run or 0.0) * scale)
            cpu1_burst = min(100.0, (cpu1_run or 0.0) * scale)

    # ---- the corrected sender cost ---------------------------------------
    # A phantom send waits out a MAC retry budget for an address nobody
    # answers. Where a run mixed real and phantom peers, the real peers give
    # the per-listener transmit cost, and projecting it over npeer gives what
    # the same frame would have cost against that many acking receivers.
    # The firmware emits 0.00 for a mean with no samples; the companion *_n
    # field is what says whether the number exists. A receiver-side log has no
    # sends at all, and "0.0 us per peer" would read as a measurement.
    send_real_pp = run.num("send_real_us_per_peer") if run.count("send_real_n") else None
    send_phantom_pp = (run.num("send_phantom_us_per_peer")
                       if run.count("send_phantom_n") else None)
    tx_active = (run.count("tx_frames") > 0) if has_fw else bool(run.tx)
    is_group = run.config.get("experiment.architecture") == "group"
    if is_group:
        nreal = npeer
    n_phantom = 0 if is_group else run.count("peers_phantom")
    projected_frame_us = None
    projected_deadline = NA
    if not is_group and send_real_pp and encode["mean"] is not None and protect["mean"] is not None and npeer:
        protect_pp = protect["mean"] / npeer
        projected_frame_us = encode["mean"] + npeer * (protect_pp + send_real_pp)
        frame_budget_us = (run.num("frame_ms") or 20.0) * 1000.0
        projected_deadline = "over" if projected_frame_us > frame_budget_us else "within"

    out = {
        "label": run.label,
        "architecture": "group" if is_group else "unspecified",
        "receivers": npeer,
        "receivers_real": nreal if nreal is not None else "",
        "receivers_phantom": n_phantom,
        "tx_frames": run.count("tx_frames") if has_fw else len(run.tx),
        "rx_frames": run.count("rx_frames") if has_fw else len(run.rx),
        "tx_fps_achieved": fmt(run.num("tx_fps_achieved")),
        "nominal_fps": fmt(run.num("nominal_fps")),
        "tx_burst_s": fmt(run.num("tx_burst_s")),
        # How far below the nominal rate the sender actually ran. Deadline
        # misses that vTaskDelayUntil absorbs leave this at zero; only when it
        # goes positive has the sender stopped sustaining the stream.
        "tx_rate_deficit_pct": fmt(run.num("tx_rate_deficit_pct"), 3),

        "encode_us_mean": fmt(encode["mean"]),
        "encode_us_median": fmt(encode["median"]),
        "protect_us_mean": fmt(protect["mean"]),
        "protect_us_median": fmt(protect["median"]),
        "protect_us_per_peer": fmt(protect["mean"] / npeer if protect["mean"] and npeer else None),
        "send_us_mean": fmt(send["mean"]),
        "send_us_median": fmt(send["median"]),
        "send_us_per_peer": fmt(run.num("send_us_per_peer") if tx_active else None),
        "send_real_us_per_peer": fmt(send_real_pp),
        "send_phantom_us_per_peer": fmt(send_phantom_pp),

        "verify_us_mean": fmt(verify["mean"]),
        "verify_us_median": fmt(verify["median"]),
        "verify_us_iqr": fmt(verify["iqr"]),
        "decode_us_mean": fmt(decode["mean"]),
        "decode_us_median": fmt(decode["median"]),
        "decode_us_iqr": fmt(decode["iqr"]),

        "owd_p50_ms": fmt(p50),
        "owd_p95_ms": fmt(p95),
        "owd_p99_ms": fmt(p99),
        "owd_mean_ms": fmt(run.num("owd_mean_ms") if owd_n_fw else None),
        "owd_max_ms": fmt(run.num("owd_max_ms") if owd_n_fw else None),
        "owd_n": owd_n_fw or len(owd_trace),
        "owd_source": src,
        "jitter_ms": fmt(jitter_ms, 3),
        "ipdv_max_ms": fmt(run.num("ipdv_max_ms") if owd_n_fw else None, 3),

        "loss_pct": fmt(loss_pct, 3),
        "loss_complete": fmt(loss_complete, 0),
        "playout_loss_pct": fmt(run.num("playout_loss_pct") if loss_complete == 1 else None, 3),
        "measurement_schema": run.num("measurement_schema"),
        "delivery_n": delivery_n,

        # RQ1 metrics that previously reached nothing at all.
        "deadline_miss": run.count("deadline_miss") if (has_fw and tx_active) else "",
        "deadline_miss_pct": fmt(run.num("deadline_miss_pct") if (has_fw and tx_active)
                                 else None, 3),
        "air_bytes": run.count("air_bytes") if (has_fw and tx_active) else "",
        "air_bytes_per_s": fmt(run.num("air_bytes_per_s") if tx_active else None, 1),
        "peer_state_bytes": run.count("peer_state_bytes") if has_fw else "",
        "peer_bytes_per_peer": run.count("peer_bytes_per_peer") if has_fw else "",
        "tx_calls": run.count("tx_calls") if has_fw else "",
        "tx_cb_ok": run.count("tx_cb_ok") if has_fw else "",
        "tx_cb_fail": run.count("tx_cb_fail") if has_fw else "",
        "tx_timeout": run.count("tx_timeout") if has_fw else "",
        "tx_send_fail": run.count("tx_send_fail") if has_fw else "",
        "rx_queue_drop": run.count("rx_queue_drop") if has_fw else "",
        "cpu0_run_pct": fmt(cpu0_run),
        "cpu1_run_pct": fmt(cpu1_run),
        # CPU while the sender was actually talking. The run window brackets
        # the burst with setup and teardown, during which the board is idle, so
        # the run-window average understates the sustained load -- a 30 s burst
        # in a 34 s window dilutes it by about 12 %. RQ1 asks what a listener
        # costs while audio is flowing, which is this.
        "cpu0_burst_pct": fmt(cpu0_burst),
        "cpu1_burst_pct": fmt(cpu1_burst),
        "heap_free": run.count("heap_free") if has_fw else "",
        "heap_min_ever": run.count("heap_min_ever") if has_fw else "",

        "auth_fail": run.count("auth_fail") if has_fw else "",
        "replay_drop": run.count("replay_drop") if has_fw else "",
        "epoch_unknown": run.count("epoch_unknown") if has_fw else "",
        "malformed": run.count("malformed") if has_fw else "",

        "projected_frame_us_real_peers": fmt(projected_frame_us, 1),
        "projected_deadline": projected_deadline,

        # Capture integrity. A percentile from a 40 %-complete trace is not a
        # percentile, and nothing downstream can tell unless this says so.
        "tx_trace_rows": len(run.tx),
        "rx_trace_rows": len(run.rx),
        "tx_trace_declared": run.tx_rows_declared if run.tx_rows_declared is not None else "",
        "rx_trace_declared": run.rx_rows_declared if run.rx_rows_declared is not None else "",
        "trace_malformed": run.tx_rows_malformed + run.rx_rows_malformed,
        "rx_trace_coverage": fmt(coverage * 100.0, 1) if declared else NA,

        # Verdicts, which say n/a when there is nothing to judge.
        "owd_p95_within_g114": (NA if p95 != p95 else
                                ("yes" if p95 <= TARGET_OWD_MS else "no")),
        "jitter_within_nist": (NA if jitter_ms is None else
                               ("yes" if jitter_ms <= TARGET_JITTER_MS else "no")),
        "loss_within_nist": (NA if delivery_n == 0 or loss_pct is None else
                             ("yes" if loss_pct <= TARGET_LOSS_PCT else "no")),
        "has_delivery_evidence": "yes" if delivery_n > 0 else "no",
        "summary_source": "firmware" if has_fw else "legacy-prose-scrape",
    }
    out.update({k: v for k, v in run.config.items()})
    out.update({f"fw_{k}": v for k, v in run.fw.items()})
    if not has_fw:
        out.update({f"fw_{k}": v for k, v in run.legacy.items()})
    return out


def report(run: Run, s: dict) -> None:
    print(f"\n=== {run.label} ===")
    print(f"  source           {s['summary_source']}")
    print(f"  receivers        {s['receivers']}"
          f"  (real {s['receivers_real'] or '?'}, phantom {s['receivers_phantom']})")
    print(f"  tx / rx frames   {s['tx_frames']} / {s['rx_frames']}"
          f"   ({s['tx_fps_achieved']} f/s vs {s['nominal_fps']} nominal"
          f", deficit {s['tx_rate_deficit_pct']} %)")
    print(f"  deadline misses  {s['deadline_miss']}  ({s['deadline_miss_pct']} %)")
    print(f"  protect us/frame {s['protect_us_mean']}"
          f"  (per peer {s['protect_us_per_peer']})")
    print(f"  transmit us/peer real {s['send_real_us_per_peer']}"
          f"   phantom {s['send_phantom_us_per_peer']}")
    print(f"  verify  us/frame median {s['verify_us_median']}"
          f"  (mean {s['verify_us_mean']}, IQR {s['verify_us_iqr']})")
    print(f"  one-way delay ms p50 {s['owd_p50_ms']}"
          f"  p95 {s['owd_p95_ms']}  p99 {s['owd_p99_ms']}  [{s['owd_source']}]")
    print(f"  loss %           {s['loss_pct']}   jitter ms {s['jitter_ms']}")
    print(f"  key state        {s['peer_bytes_per_peer']} B/peer,"
          f" {s['peer_state_bytes']} B total")
    print(f"  airtime          {s['air_bytes_per_s']} B/s offered")
    print(f"  cpu over run     core0 {s['cpu0_run_pct']} %  core1 {s['cpu1_run_pct']} %"
          f"   (during burst: core0 {s['cpu0_burst_pct']} %)")

    # --- warnings the write-up must not miss -----------------------------
    if s["summary_source"] != "firmware":
        print("  !! no #SUMMARY block: this log predates the machine-readable "
              "summary. Numbers came from a prose scrape and are less reliable.")
    if s["rx_trace_declared"] not in ("", None) and s["rx_trace_rows"] < int(s["rx_trace_declared"]):
        print(f"  !! rx trace truncated: {s['rx_trace_rows']} of "
              f"{s['rx_trace_declared']} rows arrived ({s['rx_trace_coverage']} %)."
              " Percentiles fall back to the on-chip histogram.")
    if s["trace_malformed"]:
        print(f"  !! {s['trace_malformed']} malformed trace rows discarded "
              "(serial corruption)")
    if run.receivers_disputed:
        got, want = run.receivers_disputed
        print(f"  !! trace says {got} receivers, label says {want}; using the "
              "label. Check the capture for corruption.")
    if s["receivers_phantom"]:
        print(f"  !! {s['receivers_phantom']} phantom peers: transmit and airtime "
              "figures are upper bounds. Quote send_real_us_per_peer for "
              "per-listener cost.")
        if s["projected_frame_us_real_peers"] != NA:
            print(f"     projected frame cost against {s['receivers']} REAL peers: "
                  f"{s['projected_frame_us_real_peers']} us "
                  f"({s['projected_deadline']} the frame budget)")
    if s["deadline_miss"] not in ("", 0, "0"):
        print(f"  !! sender missed {s['deadline_miss']} frame deadlines "
              "- it is past its scaling limit for this configuration")
    if s["owd_p95_within_g114"] == "no":
        print(f"  !! p95 one-way delay exceeds the {TARGET_OWD_MS:.0f} ms G.114 target")
    if s["loss_within_nist"] == "no":
        print(f"  !! loss exceeds the {TARGET_LOSS_PCT:.0f} % NIST target")
    # Thousands of malformed frames with no authentication failures is not
    # corruption: the AEAD verified, so the keys and the radio are fine, and the
    # frames were thrown away at the codec check. That means the two ends were
    # built for different codecs.
    malformed = s["malformed"] if isinstance(s["malformed"], int) else 0
    if malformed > 50 and (s["auth_fail"] in ("", 0)) and s["rx_frames"] == 0:
        print(f"  !! {malformed} frames rejected as malformed with 0 auth "
              "failures and 0 accepted.")
        print(f"     The AEAD verified, so keys and radio are fine - these were "
              f"discarded at the codec check. This end is built for "
              f"'{s.get('audio.codec', '?')}'; the sender is almost certainly a "
              "different arm. Reflash both ends to the same build.")
    if s["has_delivery_evidence"] == "no":
        print("  -- no delivery evidence in this log (sender-side only); "
              "loss, jitter and OWD read n/a by design")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("logfile", help="captured serial output")
    ap.add_argument("--outdir", default="results", help="output directory")
    args = ap.parse_args()

    runs = parse(args.logfile)
    if not runs:
        print("no runs found. Did the capture include a 'run start' header?",
              file=sys.stderr)
        return 1

    os.makedirs(args.outdir, exist_ok=True)
    summaries = []

    for run in runs:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", run.label)
        if run.tx:
            write_csv(os.path.join(args.outdir, f"{safe}_tx.csv"), TX_COLS, run.tx)
        if run.rx:
            write_csv(os.path.join(args.outdir, f"{safe}_rx.csv"), RX_COLS, run.rx)
        if run.hist:
            write_csv(os.path.join(args.outdir, f"{safe}_hist.csv"),
                      ["bin_lo_us", "bin_hi_us", "count"], run.hist)
        if run.tasks:
            write_csv(os.path.join(args.outdir, f"{safe}_tasks.csv"),
                      ["name", "prio", "core", "stack_hwm_bytes",
                       "runtime_ticks", "runtime_pct"], run.tasks)

        s = summarise(run)
        summaries.append(s)
        report(run, s)

    keys: list[str] = []
    for s in summaries:
        for k in s:
            if k not in keys:
                keys.append(k)
    path = os.path.join(args.outdir, "runs_summary.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=keys)
        w.writeheader()
        for s in summaries:
            w.writerow(s)

    print(f"\n{len(runs)} run(s) written to {args.outdir}/")
    print(f"pivot {path} on 'receivers' for the RQ1 scaling table")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
