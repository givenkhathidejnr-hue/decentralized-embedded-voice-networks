#!/usr/bin/env python3
"""
Interact with one vox_baseline board over its console while logging everything
to a file. Used for the one-cable two-board procedure: you unplug the USB
cable between phases, so each phase is a short console session captured into a
log that tools/pipeline.py understands.

    python3 tools/console.py --port /dev/ttyUSB0 --out rx.log      # new log
    python3 tools/console.py --port /dev/ttyUSB0 --out rx.log      # appends

Type console commands at the prompt; Ctrl-D (EOF) ends the session without
disturbing the board's current run. Requires pyserial.
"""

from __future__ import annotations

import argparse
import os
import select
import sys
import time

import serial


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default="/dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--out", required=True, help="log file (appended if it exists)")
    args = ap.parse_args()

    s = serial.Serial(args.port, args.baud, timeout=0.2)
    mode = "ab" if os.path.exists(args.out) else "wb"
    fh = open(args.out, mode)
    print(f"logging to {args.out} ({'append' if mode == 'ab' else 'new'})")
    print("Ctrl-D ends the session; the board keeps running.")
    sys.stdout.flush()

    while True:
        r, _, _ = select.select([s.fileno(), sys.stdin], [], [], 0.2)
        if s.fileno() in r:
            try:
                data = s.read(s.in_waiting or 256)
            except serial.SerialException:
                break
            if data:
                fh.write(data)
                fh.flush()
                sys.stdout.buffer.write(data)
                sys.stdout.flush()
        if sys.stdin in r:
            line = sys.stdin.readline()
            if not line:            # Ctrl-D / EOF
                time.sleep(0.3)     # let in-flight replies arrive
                break
            sys.stdout.write(f">>> {line}")
            sys.stdout.flush()
            s.write(line.encode())

    deadline = time.time() + 1.5
    hard = time.time() + 4.0
    while time.time() < deadline and time.time() < hard:
        n = s.in_waiting
        if n:
            data = s.read(n)
            if data:
                fh.write(data)
                fh.flush()
                sys.stdout.buffer.write(data)
                sys.stdout.flush()
            deadline = time.time() + 0.3
        else:
            time.sleep(0.05)
    fh.close()
    s.close()
    print("\nsession ended, closing log")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())