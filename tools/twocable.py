#!/usr/bin/env python3
"""
Guided one-cable two-board telemetry run.

Drives the manual procedure from docs/USAGE.md (SS 2.3) end to end. You
physically move the USB-serial cable between the two boards; the script waits
for you at each step. No firmware changes.

    python3 tools/twocable.py --label r1 --talk 30 --plot

Flow:
  1. (optional, --flash) flash build/node<talker> then build/node<receiver>
  2. receiver board on the cable : peer add <talker-mac> <talker-id>,
     connect <talker-id>, run start
  3. move the cable to the talker : peer add <receiver-mac> <receiver-id>,
     connect <receiver-id>, run start, talk N, run stop, dump csv/hist/tasks
                                          -> <label>_tx.log
  4. move the cable back to the receiver : run stop, dump csv/hist/tasks
                                          -> <label>_rx.log (appends to phase 2)
  5. (--plot) pipeline.py on both logs

Default roles are talker = node 1, receiver = node 2 (--talker / --receiver
override, e.g. a node-3 receiver joins a node-1 talker automatically).
MACs are collected automatically: the receiver's MAC is read in phase A and
the talker's is taken from --talker-mac (default 8c:94:df:44:d3:b0). Each
phase prints the node number from its own `mac` command so a wrong board on
the cable is obvious. Ctrl-C at any prompt aborts.
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import subprocess
import sys
import time

import serial

TALKER_MAC_DEFAULT = "8c:94:df:44:d3:b0"  # board A (node 1)


def wait_prompt(s: serial.Serial, timeout: float = 30.0) -> bytes:
    out = b""
    quiet = time.time() + 0.4
    end = time.time() + timeout
    while time.time() < end:
        n = s.in_waiting
        if n:
            d = s.read(n)
            out += d
            txt = out.decode("utf-8", "replace")
            if "vox>" in txt:
                quiet = time.time() + 0.4
        elif time.time() >= quiet:
            break
        else:
            time.sleep(0.05)
    return out


def open_port(port: str, baud: int) -> serial.Serial:
    candidates = [port]
    for other in sorted(glob.glob("/dev/ttyUSB*"), key=lambda p: int(re.search(r"\d+$", p).group())):
        if other != port:
            candidates.append(other)
    last = None
    for cand in candidates:
        try:
            s = serial.Serial(cand, baud, timeout=0.2)
            print(f"  serial: {cand}")
            s.reset_input_buffer()
            time.sleep(0.5)
            wait_prompt(s, 3.0)
            return s
        except serial.SerialException as e:
            last = e
    sys.exit(f"cannot open any serial port ({port} failed: {last})\n"
             "Is the board plugged in? Is a stale 'idf.py monitor' holding it? "
             "(lsof /dev/ttyUSB*)")


def cmd(s: serial.Serial, line: str, wait: float = 0.0) -> bytes:
    s.write(line.encode() + b"\r\n")
    if wait:
        time.sleep(wait)
    return wait_prompt(s, timeout=max(30.0, wait + 5.0))


def node_from_mac(out: bytes) -> tuple[str, str] | None:
    m = re.search(rb"node\s+(\d+)\s+mac\s+([0-9a-f:]{17})", out)
    if not m:
        return None
    return m.group(1).decode(), m.group(2).decode()


def confirm(msg: str) -> None:
    try:
        input(f"\n>>> {msg}\n    press Enter when done (Ctrl-C to abort): ")
    except (EOFError, KeyboardInterrupt):
        sys.exit("aborted")


def run_idf(args: list[str]) -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    fw = os.path.join(os.path.dirname(here), "firmware")
    try:
        r = subprocess.run(["idf.py", *args], cwd=fw)
    except FileNotFoundError:
        sys.exit("idf.py not found - source the ESP-IDF v5.3 export first:\n"
                 "  source ~/.espressif/v5.3/esp-idf/export.sh")
    if r.returncode != 0:
        sys.exit("idf.py failed")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", default="/dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--label", default="r1", help="run label; logs <label>_tx.log/.rx")
    ap.add_argument("--talk", type=float, default=30.0)
    ap.add_argument("--phantoms", type=int, default=0,
                    help="phantom peers to add on the talker (sender-cost only)")
    ap.add_argument("--talker", type=int, default=1,
                    help="node id of the talker board (default 1)")
    ap.add_argument("--receiver", type=int, default=2,
                    help="node id of the receiver board (default 2)")
    ap.add_argument("--talker-mac", default=TALKER_MAC_DEFAULT,
                    help="MAC of the talker board (default "
                    f"{TALKER_MAC_DEFAULT})")
    ap.add_argument("--flash", action="store_true",
                    help="flash node<talker> then node<receiver> first (needs activated IDF v5.3)")
    ap.add_argument("--plot", action="store_true", help="run pipeline.py at the end")
    args = ap.parse_args()

    tx_log = f"{args.label}_tx.log"
    rx_log = f"{args.label}_rx.log"
    args.talker_mac = args.talker_mac.lower()

    if args.flash:
        print(f"== flash node{args.talker} ==")
        run_idf(["-B", f"build/node{args.talker}", "-p", args.port, "flash"])
        confirm("move the cable from board A to board B, then:")
        print(f"== flash node{args.receiver} ==")
        run_idf(["-B", f"build/node{args.receiver}", "-p", args.port, "flash"])
        confirm("move the cable back to board A (receiver of phase 2)")

    # ---- phase A: receiver board on the cable ----------------------------
    print(f"== PHASE A: receiver on {args.port} (expect node {args.receiver}) ==")
    s = open_port(args.port, args.baud)
    macs = node_from_mac(cmd(s, "mac"))
    if macs:
        nid, mac = macs
        b_mac = mac
        print(f"  receiver board reports node {nid}  mac {b_mac}")
        if nid != str(args.receiver):
            print(f"  !! expected node {args.receiver} - is the receiver board on the cable?")
    else:
        b_mac = args.talker_mac
        print("  !! could not read node id/mac - pairing guess will be used")
    parts = cmd(s, f"peer add {args.talker_mac} {args.talker}")
    parts += cmd(s, f"connect {args.talker}")
    parts += cmd(s, f"run start rx_{args.label}")
    open(rx_log, "wb").write(parts)
    s.close()
    print(f"  receiver window open; log seed written to {rx_log}")

    confirm("move the USB cable from the receiver (B) to the talker (A); "
            "power the receiver from the power bank")

    # ---- phase B: talker board on the cable ------------------------------
    print(f"== PHASE B: talker on {args.port} (expect node {args.talker}) ==")
    s = open_port(args.port, args.baud)
    macs = node_from_mac(cmd(s, "mac"))
    if macs:
        nid, mac = macs
        print(f"  talker board reports node {nid}  mac {mac}")
        if nid != str(args.talker):
            print(f"  !! expected node {args.talker} - is the talker board on the cable?")
    parts = cmd(s, f"peer add {b_mac} {args.receiver}")
    parts += cmd(s, f"connect {args.receiver}")
    if b"session established" not in parts:
        print("  !! WARNING: no 'session established' - is the receiver powered "
              "(power bank) and still on its original boot? Link will be dead.")
    parts += cmd(s, f"run start tx_{args.label}")
    if args.phantoms:
        parts += cmd(s, f"phantom {args.phantoms}")
    parts += cmd(s, f"talk {int(args.talk)}")
    print(f"  talking for {args.talk:.0f}s ...")
    time.sleep(args.talk + 3.0)
    parts += wait_prompt(s, 15.0)
    parts += cmd(s, "run stop")
    parts += cmd(s, "dump csv", wait=2.0)
    parts += cmd(s, "dump hist")
    parts += cmd(s, "dump tasks")
    open(tx_log, "wb").write(parts)
    s.close()
    print(f"  talker run captured to {tx_log}")

    confirm("move the USB cable back to the receiver (B); unplug the power bank")

    # ---- phase C: receiver again, dump -----------------------------------
    print(f"== PHASE C: receiver on {args.port}, dumping ==")
    s = open_port(args.port, args.baud)
    parts = cmd(s, "run stop")
    parts += cmd(s, "dump csv", wait=2.0)
    parts += cmd(s, "dump hist")
    parts += cmd(s, "dump tasks")
    with open(rx_log, "ab") as fh:
        fh.write(parts)
    s.close()
    print(f"  receiver dumps appended to {rx_log}")

    if args.plot:
        py = sys.executable
        here = "tools"
        subprocess.call([py, f"{here}/pipeline.py", "--logs", tx_log, rx_log,
                         "--names", "talker,rx", "--outdir", f"results_{args.label}"])

    print("\ndone. logs: " + tx_log + " , " + rx_log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())