#!/usr/bin/env python3
"""
Drive a single-board micro-benchmark run on a vox_baseline node and capture
the console output to a log that tools/pipeline.py can parse and plot.

The recommended measurement for the scaling table is N peers made of 1 real
receiver (the second board) plus phantom peers, because only sender-side cost
is claimed for phantoms. On a lone board use phantoms only: the TX trace,
security cost and resource figures are valid; RX/OWD stay empty until a second
board is connected.

    python3 tools/capture.py --port /dev/ttyUSB0 --label uni_n1_r1 --out uni.log

Then:

    python3 tools/pipeline.py --logs uni.log --names uni --outdir results_live

The board must already be flashed (idf.py ... flash) and no other program
(idf.py monitor, a terminal serial tool) may hold the serial port.
"""

from __future__ import annotations

import argparse
import sys
import time

import serial


def drain(s: serial.Serial, dur: float = 0.5) -> bytes:
    out = b""
    end = time.time() + dur
    while time.time() < end:
        n = s.in_waiting
        d = s.read(n if n else 1)
        if d:
            out += d
            end = time.time() + 0.3
    return out


def cmd(s: serial.Serial, line: str, wait: float = 1.5) -> bytes:
    s.write((line + "\r\n").encode())
    time.sleep(0.2)
    return drain(s, wait)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default="/dev/ttyUSB0", help="serial port")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--label", default="uni_n1_r1", help="run label (run start <label>)")
    ap.add_argument("--phantoms", type=int, default=4, help="phantom peers for sender-side N")
    ap.add_argument("--talk", type=float, default=30.0, help="talk burst length in seconds")
    ap.add_argument("--out", default="uni.log", help="output log file")
    args = ap.parse_args()

    s = serial.Serial(args.port, args.baud, timeout=0.3)
    s.reset_input_buffer()
    time.sleep(0.5)
    drain(s, 1.0)

    parts: list[bytes] = []
    parts.append(cmd(s, "mac"))
    parts.append(cmd(s, f"phantom {args.phantoms}"))
    parts.append(cmd(s, f"run start {args.label}"))
    s.write(b"talk " + str(int(args.talk)).encode() + b"\r\n")
    time.sleep(1.0)
    parts.append(drain(s, 0.5))
    time.sleep(args.talk + 2.0)          # let the full burst elapse
    parts.append(drain(s, 1.0))
    parts.append(cmd(s, "run stop", 2.0))
    parts.append(cmd(s, "stats"))
    parts.append(cmd(s, "dump csv", 3.0))
    parts.append(cmd(s, "dump hist"))
    parts.append(cmd(s, "dump tasks"))
    s.close()

    full = b"".join(parts)
    with open(args.out, "wb") as fh:
        fh.write(full)

    txt = full.decode("utf-8", "replace")
    tx_rows = sum(1 for l in txt.splitlines() if l.startswith("TX,"))
    rx_rows = sum(1 for l in txt.splitlines() if l.startswith("RX,"))
    print(f"wrote {len(full)} bytes to {args.out}")
    print(f"  tx rows {tx_rows}   rx rows {rx_rows}")
    for l in txt.splitlines():
        if "duration" in l:
            print(" ", l.strip().rstrip("\x1b[0m"))
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())