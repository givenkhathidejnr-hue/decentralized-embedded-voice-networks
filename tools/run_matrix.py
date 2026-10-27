#!/usr/bin/env python3
"""
Repeatable benchmark matrix on already-flashed boards.

Assumes node<talker> and node<receiver> are ALREADY flashed and both boards
are connected on their own USB-serial cable. For each phantoms count and each
repetition it:

  1. resets both boards from the host (EN pulse -> clean app boot, empty
     peer table and clock estimate - no leftover state between runs)
  2. pairs and runs a full talk burst (equal to tools/twoports.py)
  3. runs pipeline.py so each run gets plots + summary.json

Then it aggregates all repetitions per config into results_matrix/summary.md
(mean +/- sd), which is the repeatability surface: the sd across reps is the
noise; the columns across phantoms are the sender-scaling curve.

    python3 tools/run_matrix.py --phantoms "0 3 5 8" --reps 3 --talk 30 --plot

A phantoms value only exercises sender-side cost on the talker (no counter-
part on the air); real delivery is unchanged. Swap the firmware and re-run to
compare crypto (gcm/ccm/nocrypto, Kconfig VOX_AEAD / VOX_CRYPTO_ENABLED) or
codec (g711u/pcm16, Kconfig VOX_CODEC) variants - same tool, no other change.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import statistics
import subprocess
import sys
import time

import serial

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_twoports():
    spec = importlib.util.spec_from_file_location(
        "twoports", os.path.join(HERE, "twoports.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


tp = _load_twoports()


def reset_board(port: str, serial_baud: int) -> serial.Serial:
    """EN-pulse reset that boots the app (GPIO0 held high), then wait for console."""
    s = serial.Serial(port, serial_baud, timeout=0.2)
    s.setDTR(False)                 # keep GPIO0 high: run, not download mode
    s.setRTS(True)
    time.sleep(0.2)
    s.setRTS(False)
    s.reset_input_buffer()
    return s


def wait_for_console(s: serial.Serial, timeout: float = 15.0) -> bytes:
    out = b""
    last_data = time.time()
    end = time.time() + timeout
    while time.time() < end:
        if b"vox>" in out:
            break
        n = s.in_waiting
        if n:
            out += s.read(n)
            last_data = time.time()
        elif time.time() - last_data >= 2.5:
            break
        else:
            time.sleep(0.05)
    return out


def find_boards() -> dict:
    """node id -> {port, mac, dev} for every board that answered `mac`."""
    sessions: dict[str, dict] = {}
    for port in tp.find_ports():
        try:
            s = tp.open_port(port, 115200)
        except SystemExit:
            continue
        macs = tp.node_from_mac(tp.cmd(s, "mac"))
        if macs:
            sessions[macs[0]] = {"port": port, "mac": macs[1], "dev": s}
            print(f"  {port}: node {macs[0]}  mac {macs[1]}")
        else:
            s.close()
    return sessions


def measure(talker, receiver, talker_mac, receiver_mac,
            talker_id, receiver_id, label, phantoms, talk_s, outdir,
            sync_wait=5.0):
    """One labelled measurement; returns the two log paths."""
    os.makedirs(outdir, exist_ok=True)
    tx_log = os.path.join(outdir, f"{label}_tx.log")
    rx_log = os.path.join(outdir, f"{label}_rx.log")

    parts_rx = tp.cmd(receiver["dev"], f"peer add {talker_mac} {talker_id}")
    parts_rx += tp.cmd(receiver["dev"], f"connect {talker_id}")
    parts_tx = tp.cmd(talker["dev"], f"peer add {receiver_mac} {receiver_id}")
    parts_tx += tp.cmd(talker["dev"], f"connect {receiver_id}")

    if b"session established" not in parts_tx or b"session established" not in parts_rx:
        print("  !! session not established on both sides - check boards")

    # Phantoms and clock convergence both happen BEFORE the run window opens.
    # The run header's peer census is taken at `run start`; adding phantoms
    # after it left every archived matrix run declaring real=1,phantom=0 while
    # its own trace rows said npeer=9.
    if phantoms:
        parts_tx += tp.cmd(talker["dev"], f"phantom {phantoms}", wait=1.0)

    # Boards were just reset, so the clock-offset estimator starts cold at 2 Hz.
    print(f"  waiting {sync_wait:.0f}s for the clock estimator ...")
    time.sleep(sync_wait)
    parts_rx += tp.cmd(receiver["dev"], "sync")

    parts_rx += tp.cmd(receiver["dev"], f"run start rx_{label}")
    parts_tx += tp.cmd(talker["dev"], f"run start tx_{label}")

    print(f"  talking {talk_s:.0f}s (phantoms={phantoms}) ...")
    parts_tx += tp.cmd(talker["dev"], f"talk {int(talk_s)}")
    time.sleep(talk_s + 3.0)
    parts_tx += tp.wait_prompt(talker["dev"], 15.0)
    parts_tx += tp.cmd(talker["dev"], "run stop")
    parts_tx += tp.cmd(talker["dev"], "dump csv", wait=2.0)
    parts_tx += tp.cmd(talker["dev"], "dump hist")
    parts_tx += tp.cmd(talker["dev"], "dump tasks")
    open(tx_log, "wb").write(parts_tx)

    parts_rx += tp.cmd(receiver["dev"], "run stop")
    parts_rx += tp.cmd(receiver["dev"], "dump csv", wait=2.0)
    parts_rx += tp.cmd(receiver["dev"], "dump hist")
    parts_rx += tp.cmd(receiver["dev"], "dump tasks")
    open(rx_log, "wb").write(parts_rx)
    return tx_log, rx_log


def load_summary(outdir: str) -> dict:
    p = os.path.join(outdir, "plots", "summary.json")
    if not os.path.exists(p):
        return {}
    d = json.load(open(p))
    out = {}
    for variant in ("talker", "rx"):
        recs = d.get("variants", {}).get(variant, {})
        if not recs:
            continue
        # One log per variant per run, so one receiver-count bucket. Take the
        # largest, which is the sender's own count rather than a stray zero.
        k = max(recs, key=lambda x: int(x) if x.isdigit() else 0)
        out[variant] = recs[k]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phantoms", default="0", help="space-separated list, e.g. '0 3 5 8'")
    ap.add_argument("--reps", type=int, default=3, help="repetitions per config (default 3)")
    ap.add_argument("--talk", type=float, default=30.0)
    ap.add_argument("--talker", type=int, default=1)
    ap.add_argument("--receiver", type=int, default=2)
    ap.add_argument("--outdir", default="results_matrix", help="output root (default results_matrix)")
    ap.add_argument("--sync-wait", type=float, default=5.0,
                    help="seconds to let the clock-offset estimator converge "
                         "after the reset, before the burst (default 5)")
    ap.add_argument("--plot", action="store_true", help="run pipeline.py per run")
    args = ap.parse_args()

    phantoms = [int(x) for x in args.phantoms.split()]
    os.makedirs(args.outdir, exist_ok=True)

    print(f"== discovering boards ({', '.join(tp.find_ports())}) ==")
    sessions = find_boards()
    if str(args.talker) not in sessions or str(args.receiver) not in sessions:
        sys.exit(f"need node {args.talker} and node {args.receiver}; found: "
                 f"{', '.join(sessions) or 'none'}")
    talker = sessions[str(args.talker)]
    receiver = sessions[str(args.receiver)]
    print(f"  talker {talker['port']} = node {args.talker} {talker['mac']}")
    print(f"  receiver {receiver['port']} = node {args.receiver} {receiver['mac']}")

    py = sys.executable
    pipeline = os.path.join(HERE, "pipeline.py")
    label_base = "m"

    for ph in phantoms:
        for r in range(1, args.reps + 1):
            cfg = f"p{ph}_r{r}"
            print(f"\n== config phantoms={ph} rep {r}/{args.reps} ==")
            for dev in (talker["dev"], receiver["dev"]):
                dev.close()
            print("  resetting boards ...")
            talker["dev"] = reset_board(talker["port"], 115200)
            receiver["dev"] = reset_board(receiver["port"], 115200)
            wait_for_console(talker["dev"])
            wait_for_console(receiver["dev"])
            outdir = os.path.join(args.outdir, cfg)
            tx_log, rx_log = measure(
                talker, receiver, talker["mac"], receiver["mac"],
                args.talker, args.receiver, cfg, ph, args.talk, outdir,
                args.sync_wait)
            if args.plot:
                subprocess.call([py, pipeline, "--logs", tx_log, rx_log,
                                 "--names", "talker,rx", "--outdir", outdir])

    for dev in (talker["dev"], receiver["dev"]):
        dev.close()

    # --- aggregate -----------------------------------------------------
    #
    # Two tables, because the sender's cost and the receiver's experience are
    # measured on different boards and must not be silently mixed. The earlier
    # single table read free heap from the RECEIVER, whose peer count is one in
    # every configuration -- so the memory column of a scaling study was 200
    # bytes of noise around a constant. Sender-side quantities now come from the
    # talker, and key state, airtime and deadline misses have columns of their
    # own.
    def collect(ph):
        variants = {"talker": [], "rx": []}
        for r in range(1, args.reps + 1):
            d = load_summary(os.path.join(args.outdir, f"p{ph}_r{r}"))
            for v in variants:
                if v in d:
                    variants[v].append(d[v])
        return variants["talker"], variants["rx"]

    def stat(key, agg, digits=1):
        """mean +/- sd across repetitions; '-' when nothing measured it."""
        vals = []
        for rec in agg:
            cell = rec.get(key)
            if isinstance(cell, dict) and cell.get("mean") is not None:
                vals.append(cell["mean"])
        if not vals:
            return "-"
        if len(vals) == 1:
            return f"{vals[0]:.{digits}f}"
        return (f"{statistics.mean(vals):.{digits}f} "
                f"± {statistics.stdev(vals):.{digits}f}")

    sender_headers = ["cfg", "reps", "protect us", "protect/peer",
                      "send us", "send/peer REAL", "send/peer phantom",
                      "deadline miss %", "air B/s", "key state B", "B/peer",
                      "cpu0 %", "heap B (talker)"]
    quality_headers = ["cfg", "reps", "verify us (med)", "decode us (med)",
                       "OWD p50", "p95", "p99", "jitter ms", "loss %"]
    sender_rows, quality_rows = [], []

    for ph in phantoms:
        tx_v, rx_v = collect(ph)
        cfg = f"p{ph} (N={ph + 1})"
        sender_rows.append([
            cfg, str(len(tx_v)),
            stat("protect_us", tx_v), stat("protect_us_per_peer", tx_v),
            stat("send_us", tx_v),
            stat("send_real_us_per_peer", tx_v),
            stat("send_phantom_us_per_peer", tx_v),
            stat("deadline_miss_pct", tx_v, 2),
            stat("air_bytes_per_s", tx_v, 0),
            stat("peer_state_bytes", tx_v, 0),
            stat("peer_bytes_per_peer", tx_v, 0),
            stat("cpu0_run_pct", tx_v),
            stat("heap_free", tx_v, 0),
        ])
        quality_rows.append([
            cfg, str(len(rx_v)),
            stat("verify_us_median", rx_v), stat("decode_us_median", rx_v),
            stat("owd_p50_ms", rx_v), stat("owd_p95_ms", rx_v),
            stat("owd_p99_ms", rx_v),
            stat("jitter_ms", rx_v, 2), stat("loss_pct", rx_v, 3),
        ])

    def table(f, headers, rows):
        f.write("| " + " | ".join(headers) + " |\n")
        f.write("|" + "---|" * len(headers) + "\n")
        for r_ in rows:
            f.write("| " + " | ".join(str(x) for x in r_) + " |\n")
        f.write("\n")

    out = os.path.join(args.outdir, "summary.md")
    with open(out, "w") as f:
        f.write("# Benchmark matrix\n\n")
        f.write(f"`{args.reps}` repetitions per configuration, boards reset "
                "between runs. `cfg` is the phantom count; `N` is the total "
                "receiver count including the one real board. Cells read "
                "mean ± sd across repetitions, or `-` where nothing measured "
                "it.\n\n")
        f.write("## Sender cost (talker console) — RQ1\n\n")
        f.write("**send/peer REAL is the per-listener transmit figure to "
                "quote.** A phantom peer never acknowledges, so its unicast "
                "waits out the Wi-Fi MAC retry budget; the `send us` and "
                "`send/peer phantom` columns are upper bounds, not "
                "per-listener costs.\n\n")
        table(f, sender_headers, sender_rows)
        f.write("## Delivered voice quality (receiver console)\n\n")
        f.write("Targets: one-way delay < 150 ms (G.114), jitter < 40 ms "
                "(NIST), loss <= 1 % (NIST). Stage timings are medians — the "
                "timers are wall-clock and include preemption.\n\n")
        table(f, quality_headers, quality_rows)
    print(f"\naggregate written to {out}")
    print(open(out).read())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())