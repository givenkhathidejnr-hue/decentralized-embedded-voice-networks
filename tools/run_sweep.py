#!/usr/bin/env python3
"""
Drive the receiver-count sweep automatically over both boards' serial ports.

Doing the sweep by hand means typing the same eight commands per data point and
hoping every point got the same treatment. This does it identically every time
and captures one log the parser can read, which is the difference between a
result you can defend and a result you can only describe.

    python3 tools/run_sweep.py --tx COM5 --rx COM6 \
        --receivers 1,2,4,8,12,16 --seconds 30 --out sweep.log

(the same on Linux with `--tx /dev/ttyUSB0 --rx /dev/ttyUSB1`; find them
with `ls /dev/ttyUSB*`)

What it does per point:
    1. sets the sender's phantom peer count so N receivers are active
    2. starts a labelled run on BOTH boards
    3. talks for the requested duration
    4. stops both runs and dumps summary, histogram and task tables
    5. appends everything to one log

The first physical receiver is real; the rest are phantoms, so sender-side cost
is measured at every N while delivery is only ever measured against the one
real board. Every point is labelled with both counts so the write-up cannot
accidentally claim delivery evidence it does not have.

Requires pyserial:  python3 -m pip install pyserial
"""

from __future__ import annotations

import argparse
import sys
import time

try:
    import serial
except ImportError:
    print("pyserial is required:  python3 -m pip install pyserial",
          file=sys.stderr)
    raise SystemExit(1)


class Board:
    def __init__(self, port: str, baud: int, name: str, log):
        self.name = name
        self.log = log
        self.ser = serial.Serial(port, baud, timeout=0.2)
        time.sleep(0.3)
        self.ser.reset_input_buffer()

    def send(self, cmd: str, settle: float = 0.4) -> str:
        self.log.write(f"\n$ [{self.name}] {cmd}\n")
        self.ser.write((cmd + "\r\n").encode())
        self.ser.flush()
        return self.drain(settle)

    def drain(self, seconds: float) -> str:
        end = time.time() + seconds
        buf = []
        while time.time() < end:
            chunk = self.ser.read(4096)
            if chunk:
                text = chunk.decode("utf-8", errors="replace")
                buf.append(text)
                self.log.write(text)
                self.log.flush()
                end = max(end, time.time() + 0.15)   # keep reading while it talks
        return "".join(buf)

    def close(self) -> None:
        self.ser.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tx", required=True,
                    help="sender serial port, e.g. COM5 (Windows) or /dev/ttyUSB0 (Linux)")
    ap.add_argument("--rx", required=True,
                    help="receiver serial port, e.g. COM6 (Windows) or /dev/ttyUSB1 (Linux)")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--receivers", default="1,2,4,8,12,16",
                    help="comma-separated receiver counts to sweep")
    ap.add_argument("--seconds", type=int, default=30, help="talk duration per point")
    ap.add_argument("--repeats", type=int, default=3,
                    help="repetitions per point; report the spread, not one run")
    ap.add_argument("--tag", default="uni", help="label prefix, e.g. uni or uni_nocrypto")
    ap.add_argument("--out", default="sweep.log")
    args = ap.parse_args()

    counts = [int(x) for x in args.receivers.split(",") if x.strip()]

    with open(args.out, "w", encoding="utf-8") as log:
        tx = Board(args.tx, args.baud, "TX", log)
        rx = Board(args.rx, args.baud, "RX", log)

        try:
            print("checking both boards are up...")
            tx.send("mac")
            rx.send("mac")
            tx.send("peer list")
            rx.send("peer list")

            print("waiting for the clock offset estimator to converge...")
            time.sleep(5)
            rx.send("sync")

            for n in counts:
                for rep in range(1, args.repeats + 1):
                    label = f"{args.tag}_n{n}_r{rep}"
                    print(f"--- {label} ---")

                    # One real receiver plus (n-1) phantoms.
                    tx.send(f"phantom {max(n - 1, 0)}", settle=1.0)
                    tx.send("peer list")

                    tx.send(f"run start {label}", settle=0.6)
                    rx.send(f"run start {label}", settle=0.6)

                    tx.send(f"talk {args.seconds}", settle=0.4)
                    time.sleep(args.seconds + 1)
                    tx.drain(0.5)
                    rx.drain(0.5)

                    tx.send("run stop", settle=2.0)
                    rx.send("run stop", settle=2.0)
                    tx.send("dump all", settle=6.0)
                    rx.send("dump all", settle=6.0)

                    time.sleep(1.0)

            print(f"\ndone. now run:\n  python3 tools/parse_telemetry.py {args.out} "
                  f"--outdir results/")
        finally:
            tx.close()
            rx.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
