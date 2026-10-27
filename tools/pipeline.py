#!/usr/bin/env python3
"""
End-to-end pipeline: sweep -> parse -> organise -> plot.

Two modes:

  1. Live two-board sweep (recommended once both boards are connected):
     drives run_sweep.py over both ports, then parses and plots.

         python3 tools/pipeline.py --tx-port /dev/ttyUSB0 --rx-port /dev/ttyUSB1 \
             --receivers 1,2,4,8 --seconds 30 --repeats 3 --tag uni

  2. Log replay (what you use with a single board, or to re-render old data):
     parses captured serial logs and plots without touching the hardware.

         python3 tools/pipeline.py --logs sweep_uni.log sweep_nocrypto.log \
             --outdir results --names uni,nocrypto

Everything is written under --outdir: the per-run CSVs, the tables, the PNGs,
and results.md / summary.json for the write-up.

Requires pyserial in mode 1, and numpy + matplotlib in both modes.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys


def _run(cmd: list[str]) -> int:
    print(f"$ {' '.join(cmd)}", file=sys.stderr)
    return subprocess.call(cmd, cwd=_here())


def _here() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tx-port", help="sender serial port, e.g. /dev/ttyUSB0")
    ap.add_argument("--rx-port", help="receiver serial port, e.g. /dev/ttyUSB1")
    ap.add_argument("--logs", nargs="*", default=[],
                    help="captured serial logs, instead of a live sweep")
    ap.add_argument("--log", default="sweep.log", help="log to write during a sweep")
    ap.add_argument("--receivers", default="1,2,4,8,12,16")
    ap.add_argument("--seconds", type=int, default=30)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--tag", default="uni")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--outdir", default="results")
    ap.add_argument("--names", default="",
                    help="comma-separated variant names, one per log directory")
    ap.add_argument("--skip-visualize", action="store_true")
    args = ap.parse_args()

    py = sys.executable
    args.log = os.path.abspath(args.log)
    args.outdir = os.path.abspath(args.outdir)
    logs = [os.path.abspath(l) for l in args.logs]

    if args.tx_port or args.rx_port:
        if not (args.tx_port and args.rx_port):
            ap.error("--tx-port and --rx-port must be used together")
        logs = [args.log]
        cmd = [py, os.path.join(_here(), "run_sweep.py"),
               "--tx", args.tx_port, "--rx", args.rx_port,
               "--baud", str(args.baud),
               "--receivers", args.receivers,
               "--seconds", str(args.seconds),
               "--repeats", str(args.repeats),
               "--tag", args.tag, "--out", args.log]
        if _run(cmd) != 0:
            print("sweep failed", file=sys.stderr)
            return 1

    if not logs:
        ap.error("give --logs or --tx-port/--rx-port")

    os.makedirs(args.outdir, exist_ok=True)

    # Organise: one subdirectory per log, so variants never collide.
    dirs: list[str] = []
    for i, log in enumerate(logs):
        sub = os.path.join(args.outdir, f"run{i + 1:02d}")
        os.makedirs(sub, exist_ok=True)
        cmd = [py, os.path.join(_here(), "parse_telemetry.py"),
               log, "--outdir", sub]
        if _run(cmd) != 0:
            print(f"parse of {log} failed", file=sys.stderr)
            return 1
        dirs.append(sub)

    if args.skip_visualize:
        print("parsed. run tools/visualize.py on", " ".join(dirs))
        return 0

    cmd = [py, os.path.join(_here(), "visualize.py"), *dirs,
           "--out", os.path.join(args.outdir, "plots")]
    if args.names:
        cmd += ["--names", args.names]
    return _run(cmd)


if __name__ == "__main__":
    raise SystemExit(main())