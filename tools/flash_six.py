#!/usr/bin/env python3
"""
tools/flash_six.py — flash the 6-board rig one USB at a time, harvest each
board's MAC from its boot banner, and pause for a human confirm before the
next board gets power. THIS IS THE ONLY TOOL THAT TOUCHES USB POWER; run
it rail-off.

No node is ever flashed with USB power AND rail power at the same moment.
Every step follows exactly the bring-up rules in
docs/UNICAST_PEER_FLOW.md §8 and docs/USAGE.md:

  FLASH phase  (this tool):  ONE board on the USB cable, rail OFF for
                             that board. After its banner prints and a
                             human confirms "UP", the cable moves to the
                             next board. The just-flashed board then gets
                             rail power with NO USB attached.
  RAIL phase   (after all N flashed):  all N boards rail-powered at 5 V /
                             ~2 A bench supply; the only USB cables that
                             stay connected are the talker's (permanent)
                             and one parked receiver (moved per run window).

Building per board (mirrors USAGE.md:44-66 exactly — SDKCONFIG_DEFAULTS
chain + per-node build dir + per-node sdkconfig):

    idf.py -B build/nodeK -D SDKCONFIG=build/nodeK/sdkconfig \
           -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.codec2;sdkconfig.nodeK" \
           build flash

The codec2 fragment is in the chain because the six-board rig runs
codec2_3200 on every board; override with --arm.

Usage:

    python3 tools/flash_six.py --nodes 3                       (first three)
    python3 tools/flash_six.py                                  (all six)
    python3 tools/flash_six.py --nodes 3 --confirm-off          (no pausing,
                                                            say, CI smoke)
    python3 tools/flash_six.py --write macs.csv                (also stash a
                                                            node->MAC map)

What it does per node k (k=1 is ALWAYS the talker, flushed first and
kept on cable A):

    STEP A   ask the human to park the cable on the NEXT board (rail off)
    STEP B   idf.py -B build/nodeK ... build flash        # the flash
    STEP C   open the same serial, trigger a fresh boot banner, read the
             MAC out of it, and cross-check the banner's own invite line
             (the console prints the exact `peer add <mac> <id>` the
             other side must type — see app_main.c:626-635)
    STEP D   print "node k UP <<mac>> ESTABLISHABLE"; pause; confirm
    STEP E   wrap up: write node->MAC map if --write was given

MAC is harvested from the boot banner (app_main.c:626:

    ESP_LOGI(TAG, " node %u  mac " MACSTR, VOX_NODE_ID, MAC2STR(mac));

) — the same string `tools/twoports.py` greps (its node_from_mac regex),
so the two tools agree on what "UP" means. The banner also prints the
one-line command the OTHER board should type -- that is the talker-side
input the reviewer always asks for, so this tool echoes it verbatim.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import subprocess
import sys
import time

import serial

MAC_RE = re.compile(rb" node (\d+)  mac ([0-9a-f]{12}|[0-9a-f:]{17})\b", re.I)

IDF_PY = "idf.py"
PROJ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIRMWARE = os.path.join(PROJ, "firmware")
TOOLS = os.path.join(PROJ, "tools")


def fail(msg: str) -> None:
    print(f"[flash_six] ERROR: {msg}")
    sys.exit(1)


# Fragments chained into SDKCONFIG_DEFAULTS ahead of the per-node one. The
# six-board rig runs codec2_3200 on every board (docs/BRINGUP_CHEATSHEET.md
# section 0), and sdkconfig.codec2 also carries the 32 KB main-task stack the
# codec needs -- omitting it built a different firmware from the one the
# bring-up documents describe.
DEFAULT_ARM = ["sdkconfig.codec2"]


def sdkconfig_chain(node: int, arm: list[str]) -> str:
    return ";".join(["sdkconfig.defaults", *arm, f"sdkconfig.node{node}"])


def build_cmd(node: int, action: str, arm: list[str]) -> list[str]:
    """Node 1 is the talker; every node gets its own build dir + sdkconfig so
    the SDKCONFIG_DEFAULTS chain resolves fresh.

    Note the absence of quotes around the chain. This list is handed to
    subprocess without a shell, so a quoted value would arrive at CMake with
    the quote characters still in it and the first fragment would be looked up
    as a file literally named '"sdkconfig.defaults'.
    """
    return [
        IDF_PY,
        "-B", os.path.join(FIRMWARE, f"build/node{node}"),
        "-D", f"SDKCONFIG=build/node{node}/sdkconfig",
        "-D", f"SDKCONFIG_DEFAULTS={sdkconfig_chain(node, arm)}",
        action,
    ]


def preflight(nodes: int, arm: list[str]) -> None:
    """
    Every fragment in the chain must exist before any board is powered.

    idf.py does not fail loudly on a missing SDKCONFIG_DEFAULTS fragment: the
    build simply falls back to whatever CONFIG_VOX_NODE_ID the build directory
    last saved. The visible result is several boards booting as node 1, which
    only shows up as a silent failure to establish sessions once the rail is
    live and the cables are gone.
    """
    # idf.py comes from ESP-IDF's export.sh. Without it this dies on the first
    # board with a bare FileNotFoundError, halfway through a cable dance.
    if shutil.which(IDF_PY) is None:
        print("[flash_six] idf.py is not on PATH. Source ESP-IDF v5.3 first:")
        print("    source /home/khathide/.espressif/v5.3/esp-idf/export.sh")
        print("  (v6.x ships mbedTLS 4 and will not compile this firmware; if a "
              "shell has ever sourced it, open a fresh one.)")
        fail("no ESP-IDF toolchain in this shell")

    missing = []
    for frag in [*arm, *[f"sdkconfig.node{k}" for k in range(1, nodes + 1)]]:
        if not os.path.exists(os.path.join(FIRMWARE, frag)):
            missing.append(frag)
    if missing:
        print("[flash_six] missing sdkconfig fragments: " + ", ".join(missing))
        node_frags = [m for m in missing if m.startswith("sdkconfig.node")]
        if node_frags:
            ks = " ".join(m[len("sdkconfig.node"):] for m in node_frags)
            print("[flash_six] create them from firmware/ with:")
            print(f"    for k in {ks}; do "
                  "printf 'CONFIG_VOX_NODE_ID=%s\\n' $k > sdkconfig.node$k; done")
        fail("refusing to flash with an incomplete sdkconfig chain")
    print(f"[flash_six] sdkconfig chain per node: "
          f"{sdkconfig_chain(1, arm).replace('node1', 'nodeK')}")


# Set from --arm in main(); the flash helper takes no extra argument so the
# rest of the tool's flow is untouched.
ARM: list[str] = list(DEFAULT_ARM)


def expected_codec(arm: list[str]) -> str | None:
    """Which CONFIG_VOX_CODEC_* the chain should end up selecting."""
    for frag in reversed([*arm, "sdkconfig.defaults"]):
        path = os.path.join(FIRMWARE, frag)
        if not os.path.exists(path):
            continue
        for line in open(path):
            line = line.strip()
            if line.startswith("CONFIG_VOX_CODEC_") and line.endswith("=y"):
                return line.split("=")[0]
    return "CONFIG_VOX_CODEC_G711U"          # the Kconfig default


def clear_stale_sdkconfig(node: int) -> None:
    """
    Remove a saved sdkconfig before building.

    SDKCONFIG_DEFAULTS only SEEDS an sdkconfig that does not exist yet. Once
    build/nodeK/sdkconfig has been written, it wins over the defaults chain --
    so changing --arm and reflashing appears to succeed, reports "Hash of data
    verified", and puts the *old* firmware back on the board. That is how a rig
    ends up with some boards on one codec and some on another, with nothing in
    the output saying so.
    """
    path = os.path.join(FIRMWARE, f"build/node{node}/sdkconfig")
    if os.path.exists(path):
        os.remove(path)
        print(f"[flash_six] cleared build/node{node}/sdkconfig so the "
              "SDKCONFIG_DEFAULTS chain is applied fresh")


def verify_built(node: int, arm: list[str]) -> None:
    """Confirm the generated config is the one that was asked for."""
    path = os.path.join(FIRMWARE, f"build/node{node}/sdkconfig")
    if not os.path.exists(path):
        return
    want_codec = expected_codec(arm)
    got_codec, got_id = None, None
    for line in open(path):
        line = line.strip()
        if line.startswith("CONFIG_VOX_CODEC_") and line.endswith("=y"):
            got_codec = line.split("=")[0]
        elif line.startswith("CONFIG_VOX_NODE_ID="):
            got_id = line.split("=", 1)[1]
    if got_id != str(node):
        fail(f"node {node} built with CONFIG_VOX_NODE_ID={got_id}. "
             "Every board would answer to the same id.")
    if want_codec and got_codec != want_codec:
        fail(f"node {node} built with {got_codec}, expected {want_codec}. "
             "The sdkconfig chain did not take effect.")
    print(f"[flash_six] node {node} verified: id={got_id} "
          f"{got_codec.replace('CONFIG_VOX_CODEC_', 'codec=')}")


def run_flash(node: int) -> None:
    clear_stale_sdkconfig(node)
    cmd = build_cmd(node, "flash", ARM)
    print(f"[flash_six] flashing node {node}:")
    print("    " + " ".join(cmd))
    # Run from the firmware dir like the docs do (idf.py needs the project
    # root cwd), inherit stdout so the user sees the real flash progress +
    # any boot banner it streams.
    rc = subprocess.run(cmd, cwd=FIRMWARE).returncode
    if rc != 0:
        fail(f"node {node} flash returned {rc}")
    verify_built(node, ARM)
    print(f"[flash_six] node {node} flashed OK")


def reset_to_boot(s: serial.Serial) -> bytes:
    """Classic ESP32 works out of idf.py flash already booted into the app;
    this is a safety re-boot in case the monitor was left holding the port.
    Matches the harness reset sequence (setDTR(False); setRTS(True) 200 ms;
    setRTS(False)) used by tools/twoports.py."""
    s.setDTR(False)
    s.setRTS(True)
    time.sleep(0.2)
    s.setRTS(False)
    time.sleep(0.4)
    return read_banner(s)


def read_banner(s: serial.Serial, timeout: float = 10.0) -> bytes:
    s.reset_input_buffer()
    out = b""
    end = time.time() + timeout
    while time.time() < end:
        if s.in_waiting:
            n = min(s.in_waiting, 4096)
            out += s.read(n)
            if b"vox>" in out:
                break
        else:
            time.sleep(0.05)
    return out


def harvest_mac(out: bytes) -> tuple[int, str] | None:
    m = MAC_RE.search(out)
    if not m:
        return None
    mac_nums = [int(m.group(2).decode().replace(":", ""), 16)]
    node = int(m.group(1).decode())
    return node, mac_nums[0].to_bytes(6, "big").hex(":")


def find_one_port() -> str:
    """The ONE USB cable. If the benign-looking script asks which port even
    when you've parked the cable, that is exactly the pause the user wants
    — nothing silently flashes the wrong board."""
    import glob

    ports = sorted(glob.glob("/dev/ttyUSB*"))
    if len(ports) == 1:
        return ports[0]
    if not ports:
        fail("no /dev/ttyUSB* visible — is the flash cable actually parked?")
    print("[flash_six] more than one serial present; auto-usable list:")
    for i, p in enumerate(ports):
        print(f"           [{i}] {p}")
    try:
        sel = int(input("   pick the parked-cable port index: ").strip())
        return ports[sel]
    except (ValueError, IndexError):
        fail("bad selection")




def measure_curve(nods_map: dict[int, str], args: argparse.Namespace) -> None:
    """
    Hand the harvested MAC map to tools/run_scaling.py and let it drive.

    This used to be a second console driver living here, and it did not work:
    it compared compiled regexes against bytes with `in`, called rsplitlines()
    on bytes, referenced an undefined name on its timeout path, and matched a
    peer-add string the firmware does not print. It also called find_one_port(),
    which refuses to run when two ports are present -- so it could not coexist
    with the listener cable, and it read only the talker, leaving one-way
    delay, jitter, loss and decode unmeasured.

    run_scaling.py is that tool, done properly: it joins the headless boards
    from the talker console, instruments the one cabled listener as well, runs
    the numbers through parse/visualize, and keeps a cumulative table across
    every audience size measured.
    """
    macs_path = args.write or os.path.join(PROJ, "macs.csv")
    cmd = [
        sys.executable, os.path.join(TOOLS, "run_scaling.py"),
        "--receivers", ",".join(str(k) for k in range(1, args.nodes)),
        "--talk", str(args.window),
        "--macs", macs_path,
    ]
    print("\n[measure] handing off to run_scaling.py:")
    print("    " + " ".join(cmd))
    print("[measure] cable A stays on the talker; park cable B on whichever "
          "listener you want delivered-quality numbers from.")
    raise SystemExit(subprocess.call(cmd, cwd=PROJ))


def wait_confirm(node: int) -> bool:
    try:
        ans = input(f"   is node {node} UP and ESTABLISHABLE? [y/n]: ").strip().lower()
    except EOFError:
        return True
    if ans in ("y", "yes", ""):
        return True
    if ans in ("n", "no"):
        return False
    return wait_confirm(node)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument(
        "--nodes",
        type=int,
        default=6,
        help="how many boards to flash (1..6). Node 1 is always the "
             "talker. Flash exactly the first N you want rail-powered "
             "before each increment run: --nodes 2 baseline, --nodes 3, "
             "... to grow the receiver set across runs.",
    )
    ap.add_argument(
        "--confirm-off",
        action="store_true",
        help="do not pause for per-node confirmation (CI / dry smoke).",
    )
    ap.add_argument(
        "--measure",
        action="store_true",
        help="after the flash/harvest loop, ALSO drive the talker console "
             "through the whole N-scaling curve: for each new peer k=2..N "
             "do `peer add <mac_k> <k>` + `connect <k>`, wait for the "
             "talker's 'session established' log line (vox_session.c:357), "
             "then run start inc<k>, hold the window, run stop, dump csv. "
             "One CSV block per increment, clean windows (run start resets "
             "s_run), zero reflashes between increments.",
    )
    ap.add_argument(
        "--window",
        type=float,
        default=30.0,
        metavar="SEC",
        help="measure-hold seconds per increment (default 30.0).",
    )
    ap.add_argument("--write", metavar="CSV", default="macs.csv",
                    help="node->MAC map to write (default macs.csv). "
                         "tools/run_scaling.py reads this to join the headless "
                         "boards, which are not on a serial port and whose "
                         "MACs cannot be discovered at run time.")
    ap.add_argument(
        "--arm",
        default=",".join(DEFAULT_ARM),
        help="comma-separated sdkconfig fragments chained between "
             "sdkconfig.defaults and sdkconfig.nodeK. Default "
             f"'{','.join(DEFAULT_ARM)}' matches the six-board bring-up docs. "
             "Pass '' for the plain g711u baseline, or e.g. 'sdkconfig.ccm'.",
    )
    args = ap.parse_args()

    if not 1 <= args.nodes <= 6:
        fail("--nodes must be 1..6")
    if not os.path.exists(FIRMWARE):
        fail(f"firmware tree not found at {FIRMWARE}")

    global ARM
    ARM = [x.strip() for x in args.arm.split(",") if x.strip()]
    preflight(args.nodes, ARM)

    nods_map: dict[int, str] = {}
    prev_mac: str | None = None

    for node in range(1, args.nodes + 1):
        print("\n" + "=" * 70)
        if node == 1:
            print(f"  TALKER node 1  — park cable, keep this one on cable A")
        else:
            print(f"  RECEIVER node {node} — rail OFF for THIS board only;")
            print(f"  others keep rail; you are moving the ONE flash cable.")
        print("=" * 70)

        if not args.confirm_off:
            try:
                input("   press Enter when the cable is parked on this board "
                      f"(rail off) ... ")
            except EOFError:
                pass

        port = find_one_port()
        run_flash(node)

        # Harvest MAC from a fresh boot banner over the SAME port.
        try:
            s = serial.Serial(port, 115200, timeout=0.2)
        except serial.SerialException as e:
            fail(f"cannot open {port}: {e} — is a stale 'idf.py monitor' "
                 "holding it?")
        time.sleep(0.5)
        s.reset_input_buffer()
        out = s.read(s.in_waiting or 0)
        banner = reset_to_boot(s)
        got = harvest_mac(banner)
        s.close()

        if got is None:
            if prev_mac is not None:
                # Stale banner from the PREVIOUS board (flash did not push a
                # fresh app in the window). Re-open and invite a banner once.
                try:
                    s = serial.Serial(port, 115200, timeout=0.2)
                    banner = reset_to_boot(s)
                    s.close()
                    got = harvest_mac(banner)
                except serial.SerialException:
                    got = None
            if got is None:
                fail(f"could not harvest a MAC from node {node} banner; "
                     "flash a banner then re-run with --confirm-off for nonstop")

        node_id, mac = got
        if node_id != node:
            # Should not happen: the banner's node id == the sdkconfig node;
            # if it doesn't, the per-node sdkconfig chain broke. That's a
            # real indicator, surface it, don't hide it.
            fail(f"node {node} flashed but banner says node {node_id} — "
                 "sdkconfig.node chain is wrong; abort before you rail "
                 "these.")
        import re as _r
        print(f"\n   node {node} UP   mac {mac}")
        print(f"   invite line (type this on the TALKER): "
              f"peer add {mac} {node}\n   then:                      connect {node}")

        nods_map[node] = mac
        prev_mac = mac

        if not args.confirm_off:
            if not wait_confirm(node):
                print(f"   [flash_six] node {node} NOT confirmed; moving cable "
                      "is still your call. Re-run the whole thing if you "
                      "believe the flash is wrong.")

    print("\n" + "=" * 70)
    print(f"  all {args.nodes} nodes flashed & MAC-harvested.")
    if nods_map:
        print("  node->MAC map:")
        for n in sorted(nods_map):
            print(f"     {n}  ->  {nods_map[n]}")
        if args.write:
            # Merge, never clobber. `--nodes 2` reflashes only the first two
            # boards, and rewriting the file with just those would throw away
            # the addresses of every board already on the rail -- which are
            # exactly the ones that cannot be rediscovered over serial.
            existing = {}
            if os.path.exists(args.write):
                with open(args.write, newline="") as fh:
                    for row in csv.DictReader(fh):
                        try:
                            existing[int(row["node"])] = row["mac"].strip().lower()
                        except (KeyError, ValueError):
                            continue
            merged = {**existing, **nods_map}
            with open(args.write, "w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(["node", "mac"])
                for n in sorted(merged):
                    w.writerow([n, merged[n]])
            kept = sorted(set(existing) - set(nods_map))
            print(f"  map written to {args.write}"
                  + (f" (kept node(s) {kept} from earlier)" if kept else ""))

    if args.measure:
        # Flash and harvest are done, so the rail can come up and the two
        # measurement cables can go on. Unlike the flash phase this wants TWO
        # ports: cable A on the talker and cable B on whichever listener is to
        # be instrumented. Everything else stays headless on the rail.
        print("\n" + "=" * 70)
        print("  MEASURE phase — rail all boards at 5 V / ~2 A now.")
        print("  Cable A on the talker, cable B on ONE listener, then press")
        print("  Enter. Every other board joins headless from the talker.")
        print("=" * 70)
        try:
            input("  ready? [Enter] ")
        except EOFError:
            pass
        measure_curve(nods_map, args)
        return
    print("=" * 70)
    print("NEXT: rail all of them at 5 V / ~2 A. Only the talker's USB")
    print("stays; park one cable per receiver window. See docs/UNICAST_")
    print("PEER_FLOW.md §8 for the exact console sequence per new node:")


if __name__ == "__main__":
    main()
