#!/usr/bin/env python3
"""
Incremental N-scaling on real boards: flash once, cable two, grow the audience.

This is the harness for the six-board rig as it is actually operated:

  - all boards flashed once, from the same tree, differing only in node id
  - all boards powered from the bench rail, never from USB
  - exactly TWO serial cables for the whole campaign: cable A permanently on
    the talker, cable B permanently on ONE instrumented listener
  - every other listener runs headless, joined from the talker console alone

    python3 tools/run_scaling.py --receivers 3       # measure with 3 listeners
    python3 tools/run_scaling.py --receivers 4       # then 4, then 5 ...
    python3 tools/run_scaling.py --receivers 2,3,4,5 # or sweep in one go

Each invocation joins whatever peers are missing, measures, and rebuilds the
cumulative scaling table across every N measured so far. Sessions are RAM-only
and per-peer independent, so **nothing is reset and nothing re-handshakes**:
peers established by an earlier invocation keep their epoch, keys and replay
window untouched while a new one joins. That is the property being measured,
so breaking it to get a clean slate would destroy the measurement.

WHY THE HEADLESS BOARDS NEED NO CONSOLE. A board whose peer table is empty
auto-accepts a SESS_INIT from a MAC it does not know, provided the frame
passes the PMK-derived handshake MAC (vox_session.c, on_sess_init). All boards
are flashed with the same PMK, so one `connect k` on the talker drives the
entire join. The board only ever needs to tell you its MAC once, which it does
in its boot banner during the flash phase.

WHERE THE MACS COME FROM. The headless boards are not on a serial port, so
their MACs cannot be discovered at run time. tools/flash_six.py harvests them
from the boot banners while flashing and writes macs.csv; this reads that.
Override or supplement with --mac 4=aa:bb:cc:dd:ee:ff (repeatable).

WHAT EACH SIDE MEASURES. The talker's console carries the sender-side scaling
curve for the full audience: protect and transmit cost per peer, airtime, key
state, CPU, and the frame-deadline misses that answer RQ1. Cable B's listener
carries delivered quality for itself: one-way delay, jitter, loss, verify and
decode. The firmware has no RF telemetry path, so the other listeners are not
measured - they are load, and the write-up should say so.

Requires pyserial, numpy and matplotlib.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
import re
import subprocess
import sys
import time

import serial

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, f"{name}.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


tp = _load("twoports")

PEER_ROW = re.compile(
    r"^\s*(\d+)\s+([0-9a-f:]{17})\s+(up|init|idle)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(yes|no)",
    re.I | re.M)


# ------------------------------------------------------------------ inputs

def load_macs(path: str | None, overrides: list[str]) -> dict[int, str]:
    """node id -> MAC. From flash_six's macs.csv, plus any --mac overrides."""
    macs: dict[int, str] = {}
    if path and os.path.exists(path):
        with open(path, newline="") as fh:
            for row in csv.DictReader(fh):
                try:
                    macs[int(row["node"])] = row["mac"].strip().lower()
                except (KeyError, ValueError):
                    continue
        print(f"  loaded {len(macs)} MAC(s) from {path}")
    for spec in overrides:
        if "=" not in spec:
            sys.exit(f"--mac wants NODE=MAC, got {spec!r}")
        k, _, v = spec.partition("=")
        macs[int(k)] = v.strip().lower()
    return macs


def parse_peers(text: str) -> dict[int, dict]:
    out: dict[int, dict] = {}
    for m in PEER_ROW.finditer(text):
        out[int(m.group(1))] = {
            "mac": m.group(2).lower(), "state": m.group(3).lower(),
            "epoch": int(m.group(4)), "txseq": int(m.group(5)),
            "authfail": int(m.group(6)), "replay": int(m.group(7)),
            "phantom": m.group(8).lower() == "yes",
        }
    return out


# ------------------------------------------------------------------- setup

def open_quiet(port: str, baud: int):
    """
    Open a console without holding the board in reset.

    pyserial asserts DTR and RTS on open, and on a dev board those lines drive
    EN and GPIO0 through the auto-reset transistors -- so merely opening the
    port reboots the ESP32. Deasserting both immediately lets it boot normally;
    the caller then has to wait for it, which is what probe_identity does.
    """
    s = serial.Serial()
    s.port = port
    s.baudrate = baud
    s.timeout = 0.3
    s.dtr = False
    s.rts = False
    s.open()
    s.dtr = False
    s.rts = False
    return s


def probe_identity(port: str, baud: int, settle: float = 12.0):
    """
    Ask a board who it is, allowing for the reboot that opening the port causes.

    The shared wait_prompt() gives up after 400 ms of silence, which is fine
    for a board already at its prompt and useless for one that is still
    booting: a cold ESP32 says nothing for a second or two and then prints its
    banner. That 400 ms window is why a perfectly healthy node 2 was reported
    as "no reply to `mac`" and dropped from the campaign.
    """
    try:
        s = open_quiet(port, baud)
    except serial.SerialException as e:
        print(f"  {port}: cannot open ({e})")
        return None

    deadline = time.time() + settle
    buf = b""
    asked = 0.0
    while time.time() < deadline:
        n = s.in_waiting
        if n:
            buf += s.read(n)
            got = tp.node_from_mac(buf)
            if got:
                return s, int(got[0]), got[1].lower()
        else:
            # Re-ask about once a second. A board that booted before we opened
            # the port will never volunteer its banner, so asking is the only
            # way to hear from it; a board still booting ignores us harmlessly.
            if time.time() - asked > 1.0:
                s.reset_input_buffer()
                buf = b""
                s.write(b"\r\nmac\r\n")
                s.flush()
                asked = time.time()
            time.sleep(0.05)
    s.close()
    return None


def save_macs(path: str, macs: dict[int, str]) -> None:
    """
    Persist the node->MAC map, merging rather than replacing.

    Every board that is ever on a cable announces itself, so cabling one even
    briefly is enough to record it forever. That is what makes the headless
    workflow practical: park cable B on each board once during bring-up and the
    map builds itself, instead of needing a full flash_six harvest to recover a
    single address.
    """
    existing: dict[int, str] = {}
    if os.path.exists(path):
        with open(path, newline="") as fh:
            for row in csv.DictReader(fh):
                try:
                    existing[int(row["node"])] = row["mac"].strip().lower()
                except (KeyError, ValueError):
                    continue
    merged = {**existing, **macs}
    if merged == existing:
        return
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["node", "mac"])
        for k in sorted(merged):
            w.writerow([k, merged[k]])
    added = sorted(set(merged) - set(existing))
    if added:
        print(f"  recorded MAC(s) for node(s) {added} in {path}")


def discover(baud: int, talker_id: int) -> tuple[dict, dict | None, dict[int, str]]:
    """The cabled boards. Everything else on the rail is invisible here."""
    boards: dict[int, dict] = {}
    for port in tp.find_ports():
        got = probe_identity(port, baud)
        if got is None:
            print(f"  {port}: no reply to `mac` after 12 s. Is it flashed with "
                  "this firmware, powered, and not held by idf.py monitor?")
            continue
        s, nid, mac = got
        boards[nid] = {"port": port, "mac": mac, "dev": s}
        print(f"  {port}: node {nid}  mac {mac}")

    talker = boards.pop(talker_id, None)
    if talker is None:
        for b in boards.values():
            b["dev"].close()
        sys.exit(f"talker (node {talker_id}) is not on a serial port. "
                 f"Found: {sorted(boards) or 'nothing'}")
    # Everything seen on a cable, including boards that are not the chosen
    # listener, is worth keeping: their MACs are exactly what the headless
    # joins need later.
    seen = {talker_id: talker["mac"]}
    seen.update({k: v["mac"] for k, v in boards.items()})

    listener = None
    if boards:
        nid = sorted(boards)[0]
        listener = boards.pop(nid)
        listener["node"] = nid
        for k, extra in boards.items():
            print(f"  node {k} is also cabled; its MAC is recorded but it will "
                  "not be instrumented (one listener console per campaign)")
            extra["dev"].close()
    return talker, listener, seen


def discover_peers(talker: dict, window_ms: int, log: list[bytes]) -> dict[int, dict]:
    """
    Broadcast one authenticated invite and let every listener answer.

    This is the runtime MAC registration a headless rig needs: the boards that
    are on no serial cable cannot tell the host their addresses, and ESP-NOW has
    no discovery of its own, so the talker asks over the air instead. Anything
    that answers has already completed the handshake by the time this returns.
    """
    print(f"  broadcasting a discovery invite ({window_ms} ms) ...")
    out = tp.cmd(talker["dev"], f"discover {window_ms}",
                 wait=(window_ms / 1000.0) + 1.5)
    log.append(out)
    txt = out.decode("utf-8", "replace")
    for line in txt.splitlines():
        if "answered" in line or "peer(s)" in line:
            print(f"    {line.strip()}")
    return parse_peers(tp.cmd(talker["dev"], "peer list").decode("utf-8", "replace"))


def bootstrap_macs(talker: dict, macs: dict[int, str], window_ms: int,
                   talker_id: int, log: list[bytes]) -> dict[int, str]:
    """
    One broadcast invite at the start of a campaign, to learn addresses.

    Discovery answers "who is out there", which is a different question from
    "who is in this data point". Every powered listener answers an invite, so
    using it to decide membership would make `--receivers 1` measure however
    many boards happened to be on the bench. The sessions it creates are
    therefore cleared straight away and each N then adds exactly what it needs
    -- which also means an ascending sweep only ever adds peers, never
    re-handshakes one, preserving the per-peer independence being measured.
    """
    peers = discover_peers(talker, window_ms, log)
    found = {k: v["mac"] for k, v in peers.items()
             if not v["phantom"] and k != talker_id}
    if found:
        macs.update(found)
        print(f"  discovered node(s) {sorted(found)}; clearing their sessions "
              "so each N establishes its own audience")
        for k in sorted(found):
            log.append(tp.cmd(talker["dev"], f"peer del {k}", wait=0.3))
    return macs


def join_missing(talker: dict, macs: dict[int, str], want: int,
                 talker_id: int, log: list[bytes],
                 pin: int | None = None) -> dict[int, dict]:
    """
    Bring the talker's peer table up to `want` listeners.

    Only peers that are not already `up` are touched. An established peer is
    left strictly alone - adding a peer mid-session must not disturb the
    epochs or replay windows of the ones already being measured, and that
    independence is one of the claims the rig exists to demonstrate.
    """
    out = tp.cmd(talker["dev"], "peer list")
    log.append(out)
    peers = parse_peers(out.decode("utf-8", "replace"))

    # Membership is the experiment's variable, so it is decided here and not by
    # whoever happens to be powered. Discovery runs once per campaign, purely to
    # learn addresses; anything it established was cleared afterwards. The
    # target set is the N lowest-numbered listeners, which makes the audience at
    # a given N reproducible across campaigns.
    candidates = sorted(k for k in macs if k != talker_id)
    # The board holding cable B is the only one whose delivered quality can be
    # read, so it goes into the audience first regardless of its node id.
    # Otherwise a rig cabled to, say, node 5 would measure sender cost at N=3
    # against nodes 2-4 and report no latency or loss at all.
    if pin is not None and pin in candidates:
        candidates = [pin] + [k for k in candidates if k != pin]
    target = candidates[:want]

    for k, v in sorted(peers.items()):
        if v["phantom"] or v["state"] != "up" or k in target:
            continue
        print(f"  dropping node {k}: not part of the N={want} audience")
        log.append(tp.cmd(talker["dev"], f"peer del {k}", wait=0.3))
    if any(v["state"] == "up" and not v["phantom"] and k not in target
           for k, v in peers.items()):
        out = tp.cmd(talker["dev"], "peer list")
        log.append(out)
        peers = parse_peers(out.decode("utf-8", "replace"))
    if len(candidates) < want:
        print(f"  !! only {len(candidates)} listener MAC(s) known "
              f"({candidates}), asked for {want}. Re-run flash_six.py to "
              "harvest the boot banners, or pass --mac NODE=MAC.")

    def n_up() -> int:
        return len([n for n, v in peers.items()
                    if v["state"] == "up" and not v["phantom"]])

    for k in target:
        if n_up() >= want:
            break
        if k in peers and peers[k]["state"] == "up":
            continue
        mac = macs[k]
        print(f"  joining node {k} ({mac}) ...")
        log.append(tp.cmd(talker["dev"], f"peer add {mac} {k}", wait=0.4))
        out = tp.cmd(talker["dev"], f"connect {k}", wait=2.0)
        log.append(out)
        time.sleep(1.0)
        if b"session established" not in out:
            print(f"  !! node {k} did not establish. Is it rail-powered and "
                  "flashed with the same PMK?")
        refreshed = tp.cmd(talker["dev"], "peer list")
        log.append(refreshed)
        peers = parse_peers(refreshed.decode("utf-8", "replace"))

    return peers


# ----------------------------------------------------------------- measure

class ArmMismatch(Exception):
    """Both ends of a run must be the same build; they were not."""


CFG_FIELDS = (("#AUDIO", "codec"), ("#AUDIO", "frame_ms"), ("#AUDIO", "rate"),
              ("#SEC", "aead"), ("#SEC", "tag_len"), ("#SEC", "crypto"))


def _cfg(blob: bytes, section: str, key: str) -> str | None:
    for line in blob.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line.startswith(section + ","):
            continue
        for kv in line[len(section) + 1:].split(","):
            k, _, v = kv.partition("=")
            if k.strip() == key:
                return v.strip()
    return None


def arm_mismatch(tx_start: bytes, rx_start: bytes) -> list[tuple[str, str, str]]:
    """Config fields where the two ends disagree, from their run headers."""
    bad = []
    for section, key in CFG_FIELDS:
        a, b = _cfg(tx_start, section, key), _cfg(rx_start, section, key)
        if a is not None and b is not None and a != b:
            bad.append((f"{section[1:].lower()}.{key}", a, b))
    return bad


# sdkconfig fragment that selects each codec, for the reflash advice.
ARM_FOR_CODEC = {"g711u": "", "pcm16": "sdkconfig.pcm16", "codec2_3200": "sdkconfig.codec2"}


def report_mismatch(bad: list[tuple[str, str, str]], talker_id: int,
                    listener_id: int) -> None:
    """Say which board disagrees and give the command that fixes it."""
    print("  !! ARM MISMATCH: the two ends are different builds.")
    for field, a, b in bad:
        print(f"       {field:<16} node {talker_id} (talker) = {a}"
              f"   node {listener_id} (listener) = {b}")
    print("     The listener receives the frames and passes the AEAD, then "
          "discards every one at the codec check. It reports `malformed` in "
          "the thousands and no delivered quality at all - which looks like a "
          "radio fault and is not one.")
    codec = next((a for f, a, _ in bad if f.endswith("codec")), None)
    if codec is not None:
        arm = ARM_FOR_CODEC.get(codec)
        if arm is not None:
            flag = f"--arm '{arm}'" if arm else "--arm ''"
            print(f"     Every board must be the talker's arm ({codec}). "
                  "Reflash them all in one pass:")
            print(f"       python3 tools/flash_six.py --nodes 6 {flag}")
    print("     Headless boards cannot be checked this way - nothing in the "
          "handshake carries the codec - so flash the whole rig together "
          "rather than board by board.")


def one_run(talker: dict, listener: dict | None, label: str, talk_s: float,
            sync_wait: float, outdir: str,
            talker_id: int = 1) -> tuple[str, str | None]:
    os.makedirs(outdir, exist_ok=True)
    tx_log = os.path.join(outdir, f"{label}_tx.log")
    rx_log = os.path.join(outdir, f"{label}_rx.log") if listener else None
    tx_parts: list[bytes] = []
    rx_parts: list[bytes] = []

    # The estimator probes at 2 Hz and keeps the smallest-RTT sample. Talking
    # before it has samples produces leading frames with no one-way delay.
    print(f"  letting the clock estimator settle ({sync_wait:.0f}s) ...")
    time.sleep(sync_wait)
    tx_parts.append(tp.cmd(talker["dev"], "sync"))
    if listener:
        rx_parts.append(tp.cmd(listener["dev"], "sync"))

    # `run start` prints the config header, so the two ends can be compared
    # BEFORE the burst rather than after it.
    rx_start = b""
    if listener:
        rx_start = tp.cmd(listener["dev"], f"run start rx_{label}", wait=0.5)
        rx_parts.append(rx_start)
    tx_start = tp.cmd(talker["dev"], f"run start tx_{label}", wait=0.5)
    tx_parts.append(tx_start)

    if listener:
        bad = arm_mismatch(tx_start, rx_start)
        if bad:
            # A listener built for a different codec receives the frames, passes
            # the AEAD, and then discards every one of them at the codec check.
            # It reports `malformed` in the thousands and no delivered quality
            # at all, which looks like a radio problem and is not one.
            report_mismatch(bad, talker_id, listener["node"])
            if listener:
                tp.cmd(listener["dev"], "run stop", wait=1.0)
            tp.cmd(talker["dev"], "run stop", wait=1.0)
            raise ArmMismatch(bad)

    print(f"  talking {talk_s:.0f}s ...")
    tx_parts.append(tp.cmd(talker["dev"], f"talk {int(talk_s)}"))
    time.sleep(talk_s + 3.0)
    tx_parts.append(tp.wait_prompt(talker["dev"], 15.0))

    tx_parts.append(tp.cmd(talker["dev"], "run stop", wait=2.0))
    tx_parts.append(tp.cmd(talker["dev"], "peer list"))
    tx_parts.append(tp.cmd(talker["dev"], "dump csv", wait=2.0))
    tx_parts.append(tp.cmd(talker["dev"], "dump hist"))
    tx_parts.append(tp.cmd(talker["dev"], "dump tasks"))
    with open(tx_log, "wb") as fh:
        fh.write(b"".join(tx_parts))

    if listener:
        rx_parts.append(tp.cmd(listener["dev"], "run stop", wait=2.0))
        rx_parts.append(tp.cmd(listener["dev"], "dump csv", wait=2.0))
        rx_parts.append(tp.cmd(listener["dev"], "dump hist"))
        rx_parts.append(tp.cmd(listener["dev"], "dump tasks"))
        with open(rx_log, "wb") as fh:
            fh.write(b"".join(rx_parts))

    return tx_log, rx_log


def render(tx_log: str, rx_log: str | None, outdir: str) -> None:
    cmd = [sys.executable, os.path.join(HERE, "pipeline.py"), "--logs", tx_log]
    names = "talker"
    if rx_log:
        cmd.append(rx_log)
        names = "talker,rx"
    cmd += ["--names", names, "--outdir", outdir]
    subprocess.call(cmd)


# ------------------------------------------------------- cumulative table

def run_arm(run_dir: str, label: str) -> str:
    """
    Which firmware build produced this run, read back from its own log.

    A results directory accumulates across reflashes, and averaging a codec2
    run with a g711u one produces a number that describes neither -- a decode
    mean of 6137 +/- 5296 us is not noise, it is two populations. Every run
    therefore carries its arm, and the campaign table groups by it.
    """
    path = os.path.join(run_dir, f"{label}_tx.log")
    codec = aead = None
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if codec is None and line.startswith("#AUDIO,"):
                    m = re.search(r"codec=([^,]+)", line)
                    if m:
                        codec = m.group(1)
                elif aead is None and line.startswith("#SEC,"):
                    m = re.search(r"aead=([^,]+)", line)
                    if m:
                        aead = m.group(1)
                if codec and aead:
                    break
    except OSError:
        pass
    return f"{codec or 'unknown'} + {aead or 'unknown'}"


def collect(root: str) -> list[dict]:
    """Re-read every run this campaign has produced, in receiver order."""
    rows: list[dict] = []
    for entry in sorted(os.listdir(root)):
        d = os.path.join(root, entry)
        sj = os.path.join(d, "plots", "summary.json")
        if not os.path.isdir(d) or not os.path.exists(sj):
            continue
        m = re.match(r"n(\d+)_r(\d+)$", entry)
        if not m:
            continue
        try:
            data = json.load(open(sj))
        except (json.JSONDecodeError, OSError):
            continue
        rec = {"n": int(m.group(1)), "rep": int(m.group(2)), "dir": entry,
               "arm": run_arm(d, entry)}
        for variant in ("talker", "rx"):
            buckets = data.get("variants", {}).get(variant, {})
            if not buckets:
                continue
            k = max(buckets, key=lambda x: int(x) if x.isdigit() else 0)
            rec[variant] = buckets[k]
        rows.append(rec)
    return rows


def contributing(rows: list[dict], side: str, key: str) -> int:
    """
    How many repetitions actually produced this metric.

    The bucket's run count and the metric's sample count are not the same
    thing: a listener built for a different codec discards every frame, so its
    run lands in the bucket and contributes nothing. Printing the bucket size
    beside a mean taken over fewer runs overstates how much evidence is behind
    it -- a quality row read "3 runs" when two boards had answered and one had
    thrown away all 1500 frames.
    """
    n = 0
    for r in rows:
        rec = (r.get(side) or {}).get(key)
        if isinstance(rec, dict) and rec.get("mean") is not None:
            n += 1
    return n


def cell(rows: list[dict], side: str, key: str, digits: int = 1) -> str:
    vals = []
    for r in rows:
        rec = (r.get(side) or {}).get(key)
        if isinstance(rec, dict) and rec.get("mean") is not None:
            vals.append(rec["mean"])
    if not vals:
        return "n/a"
    if len(vals) == 1:
        return f"{vals[0]:.{digits}f}"
    import statistics
    return f"{statistics.mean(vals):.{digits}f} ± {statistics.stdev(vals):.{digits}f}"


def scaling_table(root: str, listener_node: int | None) -> str:
    rows = collect(root)
    if not rows:
        return "# Scaling campaign\n\nNo completed runs yet.\n"

    by_arm: dict[str, list[dict]] = {}
    for r in rows:
        by_arm.setdefault(r["arm"], []).append(r)

    out = ["# Real-board scaling campaign", ""]
    if len(by_arm) > 1:
        out.append("> **This directory holds runs from more than one firmware "
                   "build.** They are tabulated separately below and must never "
                   "be averaged together or compared as one curve: the arm is "
                   "the variable that changed, not the audience size. Archive "
                   "the runs you are not using, or point `--outdir` somewhere "
                   "new per arm.")
        out.append("")
        for arm, rs in sorted(by_arm.items()):
            ns = sorted({r["n"] for r in rs})
            out.append(f"> - `{arm}`: {len(rs)} run(s) at N={ns}")
        out.append("")

    for arm in sorted(by_arm, key=lambda a: -len(by_arm[a])):
        out.extend(_arm_section(arm, by_arm[arm], listener_node,
                                len(by_arm) > 1))
    return "\n".join(out)


def _arm_section(arm: str, rows: list[dict], listener_node: int | None,
                 titled: bool) -> list[str]:
    by_n: dict[int, list[dict]] = {}
    for r in rows:
        by_n.setdefault(r["n"], []).append(r)

    out: list[str] = []
    if titled:
        out.append(f"# Arm: {arm}")
        out.append("")
    out.append(f"Build: **{arm}**. All listeners are real, acknowledged "
               "ESP-NOW peers - no phantoms - so the transmit column is a "
               "genuine per-listener cost and not a MAC retry timeout.")
    out.append("")
    if listener_node is not None:
        out.append(f"Delivered quality is measured on **node {listener_node} "
                   "only**, the one listener holding cable B. The other "
                   "listeners are real load but are not instrumented: the "
                   "firmware has no RF telemetry path back to the talker. "
                   "Say so in the write-up.")
    out.append("")

    out.append("## Sender cost vs audience size (RQ1)")
    out.append("")
    out.append("| listeners | runs | protect us | protect/peer | send us | "
               "send/peer | deadline miss % | air B/s | key state B | B/peer | "
               "cpu0 % (burst) | heap B |")
    out.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for n in sorted(by_n):
        rs = by_n[n]
        out.append(
            f"| {n} | {contributing(rs,'talker','protect_us')} | "
            f"{cell(rs,'talker','protect_us')} | "
            f"{cell(rs,'talker','protect_us_per_peer')} | "
            f"{cell(rs,'talker','send_us')} | "
            f"{cell(rs,'talker','send_real_us_per_peer')} | "
            f"{cell(rs,'talker','deadline_miss_pct', 2)} | "
            f"{cell(rs,'talker','air_bytes_per_s', 0)} | "
            f"{cell(rs,'talker','peer_state_bytes', 0)} | "
            f"{cell(rs,'talker','peer_bytes_per_peer', 0)} | "
            f"{cell(rs,'talker','cpu0_burst_pct')} | "
            f"{cell(rs,'talker','heap_free', 0)} |")
    out.append("")

    out.append("## Delivered voice quality at the instrumented listener")
    out.append("")
    out.append("Targets: one-way delay < 150 ms (G.114), jitter < 40 ms "
               "(NIST), loss <= 1 % (NIST).")
    out.append("")
    out.append("| listeners | runs | OWD p50 | p95 | p99 | jitter ms | "
               "loss % | verify us (med) | decode us (med) |")
    out.append("|---|---|---|---|---|---|---|---|---|")
    for n in sorted(by_n):
        rs = by_n[n]
        p95 = cell(rs, "rx", "owd_p95_ms", 2)
        loss = cell(rs, "rx", "loss_pct", 3)
        try:
            if float(p95.split()[0]) > 150.0:
                p95 += " :warning:"
        except (ValueError, IndexError):
            pass
        try:
            if float(loss.split()[0]) > 1.0:
                loss += " :warning:"
        except (ValueError, IndexError):
            pass
        nq = contributing(rs, 'rx', 'owd_p50_ms')
        flag = "" if nq == len(rs) else f" (of {len(rs)} attempted)"
        out.append(
            f"| {n} | {nq}{flag} | {cell(rs,'rx','owd_p50_ms', 2)} | {p95} | "
            f"{cell(rs,'rx','owd_p99_ms', 2)} | {cell(rs,'rx','jitter_ms', 2)} | "
            f"{loss} | {cell(rs,'rx','verify_us_median')} | "
            f"{cell(rs,'rx','decode_us_median')} |")
    out.append("")

    # The headline: where the sender runs out of frame interval.
    #
    # "First non-zero" is too eager a test. One or two stray frames in 1500 is
    # 0.07 % and is scheduling noise, not a wall -- reporting it as the RQ1
    # answer would put the limit several listeners too early. The wall is where
    # misses become sustained, so require a real rate; anything below that is
    # reported separately as what it is.
    WALL_PCT = 1.0
    wall = trace = None
    for n in sorted(by_n):
        v = cell(by_n[n], "talker", "deadline_miss_pct", 3)
        try:
            pct = float(v.split()[0])
        except (ValueError, IndexError):
            continue
        if pct > WALL_PCT and wall is None:
            wall = (n, pct)
        elif 0.0 < pct <= WALL_PCT and trace is None:
            trace = (n, pct)

    # --------------------------------------------------------------- limits
    #
    # Three different things were being conflated under one heading.
    #
    #   strain   the sender starts missing frame deadlines. Up to a point
    #            vTaskDelayUntil absorbs this completely: the frames still go
    #            out, 1500 of them in 30 s, and the listener never knows.
    #   rate     the sender stops sustaining the nominal frame rate. Now frames
    #            are genuinely not produced, and the deficit is real.
    #   quality  delivered audio leaves the G.114/NIST envelope. This is the one
    #            RQ1 means by "at constant voice quality and latency".
    #
    # Reporting only the first understates the usable limit; reporting only the
    # last hides how much headroom was already gone.
    def first_where(key, side, thresh, worst=False):
        """
        (N, value) for the first audience size that crosses `thresh`, or None.

        `seen` distinguishes "no run crossed it" from "no run recorded it at
        all" -- logs from firmware that predates a metric would otherwise be
        reported as having held the threshold, which is a claim the data does
        not support.
        """
        seen = False
        for n in sorted(by_n):
            vals = []
            for r in by_n[n]:
                rec = (r.get(side) or {}).get(key)
                if isinstance(rec, dict) and rec.get("mean") is not None:
                    vals.append(rec["mean"])
            if not vals:
                continue
            seen = True
            v = max(vals) if worst else sum(vals) / len(vals)
            if v > thresh:
                return n, v
        return None if seen else "unmeasured"

    def crossed(x):
        return isinstance(x, tuple)

    strain  = first_where("deadline_miss_pct", "talker", 1.0)
    rate    = first_where("tx_rate_deficit_pct", "talker", 0.5)
    q_loss  = first_where("loss_pct", "rx", 1.0, worst=True)
    q_owd   = first_where("owd_p95_ms", "rx", 150.0, worst=True)
    q_jit   = first_where("jitter_ms", "rx", 40.0, worst=True)
    hits = [x for x in (q_loss, q_owd, q_jit) if crossed(x)]
    quality = min(hits, key=lambda x: x[0]) if hits else None

    ns = sorted(by_n)
    out.append("## Limits")
    out.append("")
    out.append("| threshold | first N | value | what it means |")
    out.append("|---|---|---|---|")
    def row(label, res, crossed_note, held_note):
        if crossed(res):
            return f"| {label} | {res[0]} | {res[1]:.3f} | {crossed_note} |"
        if res == "unmeasured":
            return (f"| {label} | — | not recorded | this metric postdates these "
                    "logs; reflash and re-run to measure it |")
        return f"| {label} | not reached | - | {held_note} |"

    out.append(row("deadline misses > 1 %", strain,
                   "sender under strain, but absorbing it",
                   "sender never strained"))
    out.append(row("frame rate deficit > 0.5 %", rate,
                   "sender no longer sustains the stream",
                   "rate held at every N"))
    if quality:
        which = ("loss" if quality is q_loss else
                 "one-way delay" if quality is q_owd else "jitter")
        out.append(f"| {which} outside target | {quality[0]} | {quality[1]:.3f} | "
                   "delivered audio leaves the envelope (worst run) |")
    else:
        out.append("| quality outside target | not reached | - | "
                   "every target held at every N measured |")
    out.append("")

    usable = None
    if quality:
        below = [n for n in ns if n < quality[0]]
        usable = max(below) if below else None
    elif ns:
        usable = ns[-1]

    if usable is not None and quality:
        out.append(f"**RQ1 answer for this arm: {usable} listeners.** That is the "
                   "largest audience this sender sustains at constant voice "
                   f"quality; at {quality[0]} the delivered stream leaves the "
                   "target envelope.")
    elif usable is not None:
        out.append(f"**No limit reached.** Every target held through {usable} "
                   "listeners, the largest audience measured. The limit lies "
                   "above what this rig can host.")

    if crossed(strain) and crossed(rate) and strain[0] < rate[0]:
        out.append("")
        out.append(f"Note the gap between {strain[0]} and {rate[0]} listeners: the "
                   "sender is already missing frame deadlines but recovers "
                   "within the next interval, so the frame count and the "
                   "listener are unaffected. A deadline-miss count on its own "
                   "therefore overstates how close the system is to failing.")
    out.append("")
    return out


# -------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--receivers", default="",
                    help="listener count(s) to measure, e.g. '3' or '2,3,4,5'. "
                         "Default: however many are currently reachable.")
    ap.add_argument("--talk", type=float, default=30.0, help="burst seconds")
    ap.add_argument("--repeats", type=int, default=1,
                    help="repetitions per N; report the spread, not one run")
    ap.add_argument("--talker", type=int, default=1, help="node id of the talker")
    ap.add_argument("--macs", default="macs.csv",
                    help="node->MAC map from flash_six.py (default macs.csv)")
    ap.add_argument("--mac", action="append", default=[], metavar="NODE=MAC",
                    help="supply or override one MAC; repeatable")
    ap.add_argument("--outdir", default="results_scaling")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--sync-wait", type=float, default=6.0,
                    help="seconds for the clock estimator before each burst")
    ap.add_argument("--discover-ms", type=int, default=3000,
                    help="broadcast-invite window in ms (default 3000). The "
                         "talker asks over the air who is listening, so boards "
                         "that are on no serial cable still join and their MACs "
                         "are learned at run time.")
    ap.add_argument("--no-discover", action="store_true",
                    help="skip the broadcast invite and join only from the MAC "
                         "map (older firmware has no `discover` command)")
    ap.add_argument("--no-plot", action="store_true")
    args = ap.parse_args()

    macs = load_macs(args.macs, args.mac)

    print(f"== cabled boards on {', '.join(tp.find_ports())} ==")
    talker, listener, seen = discover(args.baud, args.talker)
    macs.update(seen)
    save_macs(args.macs, macs)
    if listener is None:
        print("  !! only the talker is cabled. Sender cost will be measured, "
              "but there will be NO delivered-quality evidence at all - no "
              "one-way delay, no jitter, no loss. Park cable B on a listener.")
    else:
        print(f"  talker   node {args.talker}  {talker['mac']}  ({talker['port']})")
        print(f"  listener node {listener['node']}  {listener['mac']}  "
              f"({listener['port']})  <- the instrumented one")
    macs.setdefault(args.talker, talker["mac"])
    if listener:
        macs.setdefault(listener["node"], listener["mac"])

    # Opening a serial port toggles DTR/RTS, and on a dev board those lines
    # drive EN through the auto-reset transistors, so the cabled boards reboot
    # the moment this script attaches. `stty -hupcl` does not prevent it. The
    # consequence is operational rather than fatal: the talker comes up with an
    # empty peer table, so every invocation re-joins the whole audience from
    # the MAC map. The headless boards are on no cable and do not reboot.
    #
    # It does mean sessions cannot persist ACROSS invocations. To measure a
    # curve where peers genuinely accumulate without re-handshaking -- which is
    # the per-peer-independence property the study claims -- sweep in ONE
    # invocation: --receivers 1,2,3,4,5
    print("  note: attaching to a board reboots it, so the talker starts with "
          "an empty peer table and every listener is re-joined below.")

    if args.receivers.strip():
        counts = [int(x) for x in args.receivers.replace(",", " ").split()]
    else:
        peers = parse_peers(tp.cmd(talker["dev"], "peer list").decode("utf-8", "replace"))
        n_up = len([k for k, v in peers.items() if v["state"] == "up" and not v["phantom"]])
        counts = [max(n_up, 1)]
        print(f"  no --receivers given; measuring at the current audience ({counts[0]})")

    os.makedirs(args.outdir, exist_ok=True)
    rc = 0
    boot_log: list[bytes] = []
    if not args.no_discover:
        macs = bootstrap_macs(talker, macs, args.discover_ms, args.talker, boot_log)
        save_macs(args.macs, macs)

    try:
        # Check the builds match BEFORE joining anyone. A one-second probe run
        # prints both config headers; without it the sweep joins peers at every
        # N and fails identically each time.
        if listener:
            probe_tx = tp.cmd(talker["dev"], "run start __armprobe", wait=0.5)
            probe_rx = tp.cmd(listener["dev"], "run start __armprobe", wait=0.5)
            tp.cmd(talker["dev"], "run stop", wait=1.0)
            tp.cmd(listener["dev"], "run stop", wait=1.0)
            bad = arm_mismatch(probe_tx, probe_rx)
            if bad:
                report_mismatch(bad, args.talker, listener["node"])
                return 1

        for n in counts:
            print(f"\n=== {n} listener(s) ===")
            log: list[bytes] = []
            log.extend(boot_log)
            boot_log = []
            peers = join_missing(talker, macs, n, args.talker, log,
                                 pin=listener["node"] if listener else None)
            up = {k: v for k, v in peers.items()
                  if v["state"] == "up" and not v["phantom"]}
            roster = ", ".join(f"node {k} epoch {v['epoch']}"
                               for k, v in sorted(up.items()))
            print(f"  peer table: {len(up)} real listener(s) up ({roster})")
            if not up:
                # A talker with no peers encodes 1500 frames and transmits
                # none of them. There is nothing to measure and the run would
                # land in the campaign table as a meaningless N=0 row.
                print("  !! NO listeners established. Refusing to run.")
                missing = sorted(k for k in macs if k != talker_id)
                if not missing:
                    print("     No listener MACs are known at all. Either park "
                          "cable B on a listener so it can be discovered, or "
                          "supply the headless boards' MACs:")
                    print("       --mac 2=aa:bb:cc:dd:ee:ff --mac 3=...")
                    print("     flash_six.py writes macs.csv for you during the "
                          "flash phase; it has not run to completion yet.")
                else:
                    print(f"     Known listener MACs: {missing}. None of them "
                          "answered the handshake - check they are rail-powered "
                          "and flashed with the same PMK.")
                rc = 1
                continue

            if len(up) != n:
                print(f"  !! asked for {n} listener(s), have {len(up)}. "
                      "Measuring at the TRUE count - the run is labelled "
                      f"n{len(up)} and the run header records it - but this is "
                      f"not the N={n} data point you asked for.")
                known = sorted(k for k in macs if k != args.talker)
                if len(known) < n:
                    print(f"     Only {len(known)} listener MAC(s) known "
                          f"({known}). Power up more boards before the "
                          "discovery invite, or add them with --mac NODE=MAC.")
                else:
                    print(f"     MACs are known for {known} - the ones that did "
                          "not come up are powered off or on a different PMK.")
                rc = 1
            if listener and listener["node"] not in up:
                print(f"  !! the instrumented listener (node {listener['node']}) "
                      "is not an established peer, so this run will have no "
                      "delivered-quality evidence.")

            for rep in range(1, args.repeats + 1):
                label = f"n{len(up)}_r{rep}"
                sub = os.path.join(args.outdir, label)
                print(f"  -- {label} --")
                try:
                    tx_log, rx_log = one_run(talker, listener, label, args.talk,
                                             args.sync_wait, sub, args.talker)
                except ArmMismatch:
                    # Nothing about this is per-N: the builds cannot change
                    # between data points, so continuing would join more peers
                    # and print the same failure once per audience size.
                    print("  -- campaign aborted; nothing measured --")
                    raise
                with open(os.path.join(sub, "join.log"), "wb") as fh:
                    fh.write(b"".join(log))
                if not args.no_plot:
                    render(tx_log, rx_log, sub)
    except ArmMismatch:
        rc = 1
    finally:
        talker["dev"].close()
        if listener:
            listener["dev"].close()

    table = scaling_table(args.outdir, listener["node"] if listener else None)
    out = os.path.join(args.outdir, "scaling_summary.md")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(table)
    print("\n" + table)
    print(f"campaign table: {out}")
    print("Add another board to the rail, then re-run with a higher "
          "--receivers. Within one invocation established peers are left "
          "untouched; across invocations the talker reboots on attach, so "
          "sweep --receivers 1,2,3,4,5 in one go if you want the peers to "
          "accumulate without re-handshaking.")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
