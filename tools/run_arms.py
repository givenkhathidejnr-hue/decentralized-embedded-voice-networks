#!/usr/bin/env python3
"""
Capture the same measurement across several firmware arms, verifying each flash.

Comparing build variants — protected against unprotected, GCM against CCM — is
only meaningful if every board is genuinely running the arm it is supposed to
be running, and if all the arms are measured close enough together that
build-to-build drift does not swamp the difference. This does both:

    python3 tools/run_arms.py --arms nocrypto,ccm,gcm --receivers 1,2 --repeats 5

For each arm it flashes every cabled board, **verifies the flash by resetting
the board and reading its boot banner**, and only then runs the sweep. The rig
is left on the arm named by --reference.

WHY IT VERIFIES BY BANNER RATHER THAN BY FLASH OUTPUT. `idf.py flash` prints
"Hash of data verified" once per image it writes — bootloader, partition table,
app. Grepping for that string therefore succeeds even when the application
write failed, and an earlier version of this capture did exactly that: nine
flashes reported success, all three boards were left with an erased app
partition (`invalid segment length 0xffffffff`), and three sweeps ran against
boards stuck in a boot loop before anyone noticed. The only trustworthy
evidence that a board is running the right firmware is the board saying so.

WHY IT FLASHES SLOWLY. The default 460800 baud is fine on a good cable and
unreliable on a marginal one. A flash that has to be done twice costs a minute;
a corrupted campaign costs an hour.

Requires ESP-IDF on PATH (`source .../export.sh`) and pyserial.
"""

from __future__ import annotations

import argparse
import csv
import glob
import os
import re
import shutil
import subprocess
import sys
import time

import serial

HERE = os.path.dirname(os.path.abspath(__file__))
PROJ = os.path.dirname(HERE)
FIRMWARE = os.path.join(PROJ, "firmware")

# What each arm's boot banner must report. The banner is the contract: it is
# printed by the running application, so it cannot be satisfied by a partial
# flash or by a stale build directory.
ARMS = {
    "gcm":      {"fragment": "",                   "aead": "aes128-gcm"},
    "ccm":      {"fragment": "sdkconfig.ccm",      "aead": "aes128-ccm"},
    "nocrypto": {"fragment": "sdkconfig.nocrypto", "aead": "none"},
}
BASE_FRAGMENT = "sdkconfig.codec2"
EXPECT_CODEC = "codec2_3200"


def sh(cmd: list[str], cwd: str) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def build(node: int, arm: str, extra: list[str] = (), tag: str = "") -> str:
    """Build one node's image for one arm, into that arm's own directory.

    `extra` fragments are appended after the arm fragment and before the
    per-node one, so they can override the arm but never the node id. `tag`
    keeps a variant (e.g. 40 ms frames) in its own build directory rather than
    silently overwriting the baseline arm's.
    """
    bdir = f"build/node{node}_{arm}{tag}"
    frag = ARMS[arm]["fragment"]
    chain = ";".join(x for x in (["sdkconfig.defaults", BASE_FRAGMENT, frag]
                                 + list(extra) + [f"sdkconfig.node{node}"]) if x)
    # A saved sdkconfig outranks SDKCONFIG_DEFAULTS, so a stale one would
    # silently keep the previous arm.
    stale = os.path.join(FIRMWARE, bdir, "sdkconfig")
    if os.path.exists(stale):
        os.remove(stale)
    rc, out = sh(["idf.py", "-B", bdir, "-D", f"SDKCONFIG={bdir}/sdkconfig",
                  "-D", f"SDKCONFIG_DEFAULTS={chain}", "build"], FIRMWARE)
    if rc != 0:
        print(out[-1500:])
        sys.exit(f"build failed: node{node} {arm}")
    return bdir


def read_banner(port: str, settle: float = 15.0) -> str:
    """Reset the board and capture whatever it prints on the way up."""
    try:
        s = serial.Serial(port, 115200, timeout=0.3)
    except serial.SerialException as e:
        return f"<<cannot open {port}: {e}>>"
    s.setDTR(False); s.setRTS(True); time.sleep(0.25); s.setRTS(False)
    s.reset_input_buffer()
    out = b""
    end = time.time() + settle
    while time.time() < end:
        if s.in_waiting:
            out += s.read(s.in_waiting)
            if b"console ready" in out or re.search(rb"node\s+\d+\s+mac", out):
                # keep reading briefly so the whole banner lands
                time.sleep(0.4)
                if s.in_waiting:
                    out += s.read(s.in_waiting)
                break
        else:
            time.sleep(0.03)
    s.close()
    return re.sub(r"\x1b\[[0-9;]*m", "", out.decode("utf-8", "replace"))


def verify(port: str, node: int, arm: str, frame_ms: int | None = None) -> tuple[bool, str]:
    """Is the board on `port` really running node `node` of arm `arm`?"""
    txt = read_banner(port)
    if "not bootable" in txt or "invalid segment length" in txt:
        return False, "unbootable image (flash did not complete)"
    m = re.search(r"node\s+(\d+)\s+mac\s+([0-9a-f:]{17})", txt)
    if not m:
        return False, "no boot banner (board silent or still looping)"
    got_node, mac = int(m.group(1)), m.group(2)
    codec = (re.search(r"codec\s+(\S+)\s+frame", txt) or [None, "?"])[1]
    fm = re.search(r"frame\s+(\d+)\s*ms", txt)
    got_frame = int(fm.group(1)) if fm else None
    aead = (re.search(r"aead\s+(\S+)\s+tag", txt) or [None, "?"])[1]
    want = ARMS[arm]["aead"]
    if got_node != node:
        return False, f"reports node {got_node}, expected {node}"
    if codec != EXPECT_CODEC:
        return False, f"codec {codec}, expected {EXPECT_CODEC}"
    if aead != want:
        return False, f"aead {aead}, expected {want}"
    if frame_ms is not None and got_frame != frame_ms:
        return False, f"frame {got_frame} ms, expected {frame_ms} ms"
    return True, (f"node {got_node}  mac {mac}  codec {codec}  aead {aead}"
                  + (f"  frame {got_frame} ms" if got_frame is not None else ""))


def flash(port: str, node: int, arm: str, baud: int, tries: int = 2,
          tag: str = "", frame_ms: int | None = None) -> str:
    """Flash and verify. Returns the board's MAC; aborts the campaign on failure."""
    bdir = f"build/node{node}_{arm}{tag}"
    for attempt in range(1, tries + 1):
        rc, out = sh(["idf.py", "-B", bdir, "-D", f"SDKCONFIG={bdir}/sdkconfig",
                      "-p", port, "-b", str(baud), "flash"], FIRMWARE)
        ok, detail = verify(port, node, arm, frame_ms)
        if ok:
            print(f"    {port}: {detail}")
            return detail.split("mac ")[1].split()[0]
        print(f"    {port}: attempt {attempt} FAILED - {detail}")
        if rc != 0:
            tail = [l for l in out.splitlines() if re.search(r"error|fail|timed out", l, re.I)]
            for l in tail[:3]:
                print(f"      {l.strip()[:100]}")
    sys.exit(f"ABORT: node{node} on {port} is not running arm '{arm}'. "
             "Refusing to measure a rig in an unknown state.")


def save_macs(path: str, macs: dict[int, str]) -> None:
    existing: dict[int, str] = {}
    if os.path.exists(path):
        for row in csv.DictReader(open(path, newline="")):
            try:
                existing[int(row["node"])] = row["mac"]
            except (KeyError, ValueError):
                pass
    merged = {**existing, **macs}
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["node", "mac"])
        for k in sorted(merged):
            w.writerow([k, merged[k]])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--arms", default="nocrypto,ccm,gcm",
                    help="comma-separated, in capture order (default nocrypto,ccm,gcm)")
    ap.add_argument("--reference", default="gcm",
                    help="arm to leave the rig on (default gcm)")
    ap.add_argument("--receivers", default="1,2")
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--talk", type=float, default=30.0)
    ap.add_argument("--baud", type=int, default=115200,
                    help="flash baud (default 115200 - slow and reliable)")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--extra", default="",
                    help="extra sdkconfig fragments, comma-separated, applied "
                         "after the arm fragment (e.g. sdkconfig.frame40)")
    ap.add_argument("--tag", default="",
                    help="suffix for build and results directories, so a "
                         "variant does not overwrite the baseline arm "
                         "(e.g. _f40 -> build/nodeK_gcm_f40, results_gcm_f40)")
    ap.add_argument("--expect-frame-ms", type=int, default=None,
                    help="refuse to proceed unless each board's boot banner "
                         "reports this frame duration")
    args = ap.parse_args()
    extra = [x.strip() for x in args.extra.split(",") if x.strip()]
    for frag in extra:
        if not os.path.exists(os.path.join(FIRMWARE, frag)):
            sys.exit(f"--extra fragment not found: firmware/{frag}")

    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    for a in arms + [args.reference]:
        if a not in ARMS:
            sys.exit(f"unknown arm {a!r}; known: {', '.join(ARMS)}")
    if shutil.which("idf.py") is None:
        sys.exit("idf.py not on PATH - source ESP-IDF v5.3 export.sh first")

    ports = sorted(glob.glob("/dev/ttyUSB*"))
    if len(ports) < 2:
        sys.exit(f"need at least a talker and one listener cabled; found {ports}")
    # Node ids are assigned by port position and then VERIFIED from the banner,
    # so a re-enumerated adapter cannot silently put the wrong image on a board.
    assign = {i + 1: p for i, p in enumerate(ports)}
    print("port assignment (verified after every flash):")
    for n, p in assign.items():
        print(f"  node {n} -> {p}")

    if not args.skip_build:
        print("\n== building ==")
        for arm in dict.fromkeys(arms + [args.reference]):
            for n in assign:
                print(f"  node{n} {arm}")
                build(n, arm, extra, args.tag)

    for arm in arms:
        print(f"\n{'=' * 60}\n== arm: {arm} ==\n{'=' * 60}")
        macs = {}
        for n, p in assign.items():
            print(f"  flashing node{n} -> {p}")
            macs[n] = flash(p, n, arm, args.baud,
                            tag=args.tag, frame_ms=args.expect_frame_ms)
        save_macs(os.path.join(PROJ, "macs.csv"), macs)

        outdir = os.path.join(PROJ, f"results_{arm}{args.tag}")
        rc = subprocess.call([sys.executable, os.path.join(HERE, "run_scaling.py"),
                              "--receivers", args.receivers,
                              "--repeats", str(args.repeats),
                              "--talk", str(args.talk),
                              "--outdir", outdir], cwd=PROJ)
        got = len([d for d in os.listdir(outdir)
                   if re.match(r"n\d+_r\d+$", d)]) if os.path.isdir(outdir) else 0
        want = len(args.receivers.split(",")) * args.repeats
        print(f"  {arm}: {got}/{want} runs captured (sweep rc={rc})")
        if got == 0:
            sys.exit(f"ABORT: arm '{arm}' produced no runs. Not continuing.")

    if arms[-1] != args.reference:
        print(f"\n== restoring the rig to '{args.reference}' ==")
        macs = {}
        for n, p in assign.items():
            macs[n] = flash(p, n, args.reference, args.baud,
                            tag=args.tag, frame_ms=args.expect_frame_ms)
        save_macs(os.path.join(PROJ, "macs.csv"), macs)

    print("\nDONE. Captured: " + ", ".join(f"results_{a}{args.tag}" for a in arms))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
