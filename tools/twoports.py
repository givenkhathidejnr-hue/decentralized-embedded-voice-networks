#!/usr/bin/env python3
"""
Two-cable two-board telemetry run.

Both ESP32s stay powered and connected to this host (one USB-serial cable
each), so no cable moves and no power bank are needed. Boards are identified
by their node id, and both MACs are read from the firmware - nothing is
hardcoded or typed.

    python3 tools/twoports.py --label r1 --talk 30 --plot

Flow:
  1. open every /dev/ttyUSB*, read `mac` on each, assign talker / receiver
     by node id (--talker defaults 1, --receiver defaults 2)
  2. receiver: peer add <talker-mac> <talker-id>, connect <talker-id>
     talker  : peer add <receiver-mac> <receiver-id>, connect <receiver-id>
  3. phantoms added (if any) and the clock estimator given time to converge,
     THEN both windows open: receiver `run start rx_<label>`
                       talker `run start tx_<label>`, talk N, run stop,
                       dump csv/hist/tasks            -> <label>_tx.log
  4. receiver: run stop, dump csv/hist/tasks          -> <label>_rx.log
  5. (--plot) pipeline.py on both logs

If a session does not print "session established", a WARNING is shown before
the talk burst so you can abort instead of wasting the window.
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


def wait_prompt(s: serial.Serial, timeout: float = 30.0) -> bytes:
    out = b""
    quiet = time.time() + 0.4
    end = time.time() + timeout
    while time.time() < end:
        n = s.in_waiting
        if n:
            d = s.read(n)
            out += d
            if b"vox>" in out:
                quiet = time.time() + 0.4
        elif time.time() >= quiet:
            break
        else:
            time.sleep(0.05)
    return out


def open_port(port: str, baud: int) -> serial.Serial:
    try:
        s = serial.Serial(port, baud, timeout=0.2)
        print(f"  serial: {port}")
        s.reset_input_buffer()
        time.sleep(0.5)
        wait_prompt(s, 3.0)
        return s
    except serial.SerialException as e:
        sys.exit(f"cannot open {port}: {e}\n"
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


def find_ports() -> list[str]:
    ports = []
    for p in sorted(glob.glob("/dev/ttyUSB*"), key=lambda x: int(re.search(r"\d+$", x).group())):
        if os.access(p, os.R_OK | os.W_OK):
            ports.append(p)
    if not ports:
        ports.append("/dev/ttyUSB0")
    return ports


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--label", default="r1", help="run label; logs <label>_tx.log/.rx")
    ap.add_argument("--talk", type=float, default=30.0)
    ap.add_argument("--phantoms", type=int, default=0,
                    help="phantom peers to add on the talker (sender-cost only)")
    ap.add_argument("--talker", type=int, default=1, help="node id of the talker (default 1)")
    ap.add_argument("--receiver", type=int, default=2, help="node id of the receiver (default 2)")
    ap.add_argument("--sync-wait", type=float, default=5.0,
                    help="seconds to let the clock-offset estimator converge "
                         "before the burst (default 5)")
    ap.add_argument("--plot", action="store_true", help="run pipeline.py at the end")
    args = ap.parse_args()

    tx_log = f"{args.label}_tx.log"
    rx_log = f"{args.label}_rx.log"

    print(f"== discovering boards on {', '.join(find_ports())} ==")
    sessions: dict[str, tuple[str, str]] = {}   # node id -> (port, mac)
    streams: dict[str, serial.Serial] = {}
    for port in find_ports():
        try:
            s = open_port(port, args.baud)
        except SystemExit:
            continue
        macs = None
        for _ in range(4):                       # boards may still be booting
            macs = node_from_mac(cmd(s, "mac"))
            if macs:
                break
            time.sleep(1.2)
        if not macs:
            print(f"  {port}: no node / mac reply, skipping")
            s.close()
            continue
        nid, mac = macs
        sessions[nid] = (port, mac)
        streams[nid] = s
        print(f"  {port}: node {nid}  mac {mac}")

    talker_s = streams.get(str(args.talker))
    receiver_s = streams.get(str(args.receiver))
    if talker_s is None or receiver_s is None:
        for s in streams.values():
            s.close()
        sys.exit(f"need both node {args.talker} (talker) and node {args.receiver} "
                 f"(receiver) connected; found: "
                 f"{', '.join(sorted(sessions)) or 'none'}")
    talker_mac = sessions[str(args.talker)][1]
    receiver_mac = sessions[str(args.receiver)][1]
    print(f"  talker {talker_s.port} = node {args.talker} {talker_mac}")
    print(f"  receiver {receiver_s.port} = node {args.receiver} {receiver_mac}")

    print("== pairing ==")
    parts_rx = cmd(receiver_s, f"peer add {talker_mac} {args.talker}")
    parts_rx += cmd(receiver_s, f"connect {args.talker}")
    parts_tx = cmd(talker_s, f"peer add {receiver_mac} {args.receiver}")
    parts_tx += cmd(talker_s, f"connect {args.receiver}")

    if b"session established" not in parts_tx:
        print(f"  !! WARNING: talker session not established (receiver {receiver_s.port}"
              " not acking?) - link will be dead")
    if b"session established" not in parts_rx:
        print(f"  !! WARNING: receiver session not established (talker {talker_s.port}"
              " not acking?) - link will be dead")

    # Phantoms BEFORE the run window opens. vox_metrics_print_header() takes the
    # peer census at `run start`, so a `phantom N` issued afterwards leaves the
    # header saying real=1,phantom=0 while the trace rows say npeer=N+1 -- which
    # is exactly the real/phantom split the write-up is supposed to carry.
    if args.phantoms:
        print(f"== adding {args.phantoms} phantom peers (sender-cost only) ==")
        parts_tx += cmd(talker_s, f"phantom {args.phantoms}", wait=1.0)

    # The clock-offset estimator probes at 2 Hz and reports the offset from the
    # smallest-RTT sample it has seen. Talking before it has samples produces a
    # burst whose leading frames have no one-way delay at all.
    print(f"== waiting {args.sync_wait:.0f}s for the clock estimator to converge ==")
    time.sleep(args.sync_wait)
    parts_tx += cmd(talker_s, "sync")
    parts_rx += cmd(receiver_s, "sync")

    print("== opening run windows ==")
    parts_rx += cmd(receiver_s, f"run start rx_{args.label}")
    parts_tx += cmd(talker_s, f"run start tx_{args.label}")

    print(f"== talker talking for {args.talk:.0f}s ==")
    parts_tx += cmd(talker_s, f"talk {int(args.talk)}")
    time.sleep(args.talk + 3.0)
    parts_tx += wait_prompt(talker_s, 15.0)
    parts_tx += cmd(talker_s, "run stop")
    parts_tx += cmd(talker_s, "dump csv", wait=2.0)
    parts_tx += cmd(talker_s, "dump hist")
    parts_tx += cmd(talker_s, "dump tasks")
    open(tx_log, "wb").write(parts_tx)
    print(f"  talker captured to {tx_log}")

    print("== closing the receiver window ==")
    parts_rx += cmd(receiver_s, "run stop")
    parts_rx += cmd(receiver_s, "dump csv", wait=2.0)
    parts_rx += cmd(receiver_s, "dump hist")
    parts_rx += cmd(receiver_s, "dump tasks")
    open(rx_log, "wb").write(parts_rx)
    print(f"  receiver captured to {rx_log}")

    for s in streams.values():
        s.close()

    if args.plot:
        py = sys.executable
        subprocess.call([py, f"{os.path.dirname(os.path.abspath(__file__))}/pipeline.py",
                         "--logs", tx_log, rx_log,
                         "--names", "talker,rx", "--outdir", f"results_{args.label}"])

    print("\ndone. logs: " + tx_log + " , " + rx_log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())