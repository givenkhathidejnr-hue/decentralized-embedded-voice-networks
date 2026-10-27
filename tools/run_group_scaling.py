#!/usr/bin/env python3
"""
Group steady-state N-scaling on real boards (docs/DRAFT_CH4_GROUP_METHODOLOGY.md
Sec 4.3.1): flash once, cable every board, grow the GROUP's real membership and
measure at each audience size -- the group-architecture analogue of
tools/run_scaling.py's unicast campaign.

    python3 tools/run_group_scaling.py --pilot                     # quick check
    python3 tools/run_group_scaling.py --reps 10 --burst 30 --sustained 300

Unlike run_scaling.py's two-cable rig, this assumes every board is on its own
serial cable (the testbed as currently prepared), so EVERY node's telemetry is
captured on EVERY run, not just one instrumented listener and the talker. That
exceeds Sec 4.3.1's stated minimum ("rotate the instrumented listener"); it is
reported as an improvement on the base rig, not a shortfall.

WHAT THIS MEASURES. Steady-state cost only: encode/protect/broadcast-transmit
timing, delivery, loss, jitter, one-way delay, resource usage -- the media
path. Control-plane cost (join/rekey/recover/coordinator-claim) is a SEPARATE
dataset (Sec 4.4/4.6's own cost terms must not be folded into the steady-state
figure): the #GRPOP lines each real join emits while membership is being grown
here are captured into a second output file rather than mixed into the
per-burst summary rows.

GROWTH IS MONOTONIC AND NEVER RESET, exactly as run_scaling.py's unicast
campaign: once a member has joined the group, it stays joined for every larger
N measured afterward. Breaking that to get a "clean" group each time would
measure session/key re-establishment instead of steady-state audience cost.

Requires pyserial.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, f"{name}.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


tp = _load("twoports")

SUMMARY_KV = re.compile(r"#SUMMARY,([^\r\n]+)")
GRPOP = re.compile(r"#GRPOP,([^\r\n]+)")
KV = re.compile(r"([a-zA-Z0-9_]+)=([^,]*)")


def parse_kv_line(rest: str) -> dict:
    return {k: v for k, v in KV.findall(rest)}


def parse_summary(text: str) -> dict:
    """Every #SUMMARY,... line's key=value pairs merged into one dict (the
    firmware spreads one run's summary across several lines)."""
    out: dict[str, str] = {}
    for m in SUMMARY_KV.finditer(text):
        out.update(parse_kv_line(m.group(1)))
    return out


def parse_grpops(text: str) -> list[dict]:
    rows = []
    for m in GRPOP.finditer(text):
        rows.append(parse_kv_line(m.group(1)))
    return rows


def numf(d: dict, k: str, default=""):
    v = d.get(k)
    if v is None:
        return default
    try:
        return float(v)
    except ValueError:
        return v


# --------------------------------------------------------------- bring-up

def discover(baud: int) -> dict[int, dict]:
    """node id -> {port, serial, mac}."""
    nodes: dict[int, dict] = {}
    for port in tp.find_ports():
        try:
            s = tp.open_port(port, baud)
        except SystemExit:
            continue
        macs = None
        for _ in range(4):
            macs = tp.node_from_mac(tp.cmd(s, "mac"))
            if macs:
                break
            time.sleep(1.2)
        if not macs:
            print(f"  {port}: no node/mac reply, skipping")
            s.close()
            continue
        nid, mac = macs
        nodes[int(nid)] = {"port": port, "serial": s, "mac": mac}
        print(f"  {port}: node {nid}  mac {mac}")
    return nodes


def ensure_pairwise(nodes: dict[int, dict], ids: list[int]) -> None:
    """Full mesh among `ids`. Lower id always initiates `connect`; the
    responder auto-adds the peer from the authenticated SESS_INIT (see
    vox_session.c's on_sess_init -- no 'peer add' needed on that side)."""
    ids = sorted(ids)
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            a, b = ids[i], ids[j]
            sa, mb = nodes[a]["serial"], nodes[b]["mac"]
            out = tp.cmd(sa, f"peer add {mb} {b}")
            out += tp.cmd(sa, f"connect {b}", wait=0.5)
            tag = "OK" if b"session established" in out else "WARNING: not established"
            print(f"  pairwise {a}<->{b}: {tag}")


def ensure_group(nodes: dict[int, dict], coordinator: int, members: list[int]) -> list[tuple[int, bytes]]:
    """Returns [(member_id, raw_join_output)] for members actually joined
    just now -- the #GRPOP,op=join line lives in THAT output, not in any
    later query, so the caller must parse it from here, not re-fetch it."""
    coord_s = nodes[coordinator]["serial"]
    out = tp.cmd(coord_s, "group status", wait=0.3)
    if b"no active group" in out:
        out = tp.cmd(coord_s, "group create", wait=0.5)
        print(f"  node {coordinator}: group create -> "
              f"{'ok' if b'group created' in out or b'group create' in out else out[:120]}")

    joined: list[tuple[int, bytes]] = []
    for m in members:
        ms = nodes[m]["serial"]
        status = tp.cmd(ms, "group status", wait=0.3)
        if b"no active group" not in status:
            continue  # already a member (or was, and locally still thinks so)
        out = tp.cmd(ms, f"group join {coordinator}", wait=1.0)
        ok = b"group installed" in out or b"#GRPOP" in out
        print(f"  node {m}: group join {coordinator} -> {'ok' if ok else out[-200:]}")
        joined.append((m, out))
    return joined


# ------------------------------------------------------------------- runs

def drain_fixed(s, seconds: float) -> bytes:
    """Read for a FIXED wall-clock window, no quiet-based early exit. The
    quiet-based heuristic in twoports.wait_prompt (0.4s of silence => done)
    is what caused the original bug: sending the next command before a busy
    console has finished responding to this one does not corrupt the
    device's execution, but it DOES corrupt the HOST's read framing -- the
    next command's bytes land on the wire while the previous response is
    still arriving, and parsing results then get attributed to the wrong
    exchange. A fixed window that does not care about gaps sidesteps that
    race entirely, at the cost of being slower than the best case."""
    out = b""
    end = time.time() + seconds
    while time.time() < end:
        n = s.in_waiting
        if n:
            out += s.read(n)
        else:
            time.sleep(0.05)
    return out


def send_and_collect(s, line: str, settle: float = 1.5, window: float = 4.0) -> bytes:
    """Drain any stale backlog from a prior exchange (settle), THEN send
    the command, THEN collect for a fixed window regardless of gaps. This
    replaces tp.cmd()'s quiet-based wait_prompt for the two commands
    (`run start` / `run stop`) whose mistiming actually corrupted
    duration_s -- see drain_fixed()'s docstring."""
    drain_fixed(s, settle)
    s.write(line.encode() + b"\r\n")
    return drain_fixed(s, window)


def run_start_verified(s, label: str, tries: int = 4) -> bytes:
    """`run start` with confirmation, using the race-free fixed-window read
    (see send_and_collect/drain_fixed) rather than trusting the send."""
    out = b""
    for attempt in range(1, tries + 1):
        out = send_and_collect(s, f"run start {label}", settle=1.5, window=4.0)
        if b"started" in out:
            return out
        print(f"      !! 'run start {label}' not acknowledged "
              f"(attempt {attempt}/{tries}), retrying ...")
    print(f"      !! giving up on 'run start {label}' after {tries} attempts "
          f"-- duration_s for this board/rep will be unreliable")
    return out


def run_stop_verified(s, tries: int = 4) -> bytes:
    """`run stop` with confirmation. THIS, not `run start`, turned out to be
    the actual source of the runaway duration_s values seen in early pilot
    runs: vox_metrics_run_stop() is a no-op when the firmware's own
    `running` flag is already false (guards a double-stop), so a silently
    dropped `run stop` leaves t_stop_us at 0 -- the next `dump summary`
    then computes duration against CURRENT time instead of the real stop
    time. The per-frame counters (rx_frames, OWD, jitter, loss) are
    unaffected either way, since those stop changing the moment real
    traffic stops regardless of this command's fate -- only the
    duration-derived fields are at risk."""
    out = b""
    for attempt in range(1, tries + 1):
        out = send_and_collect(s, "run stop", settle=1.5, window=5.0)
        if b"run summary" in out:
            return out
        print(f"      !! 'run stop' not acknowledged (attempt {attempt}/{tries}), retrying ...")
    print(f"      !! giving up on 'run stop' after {tries} attempts "
          f"-- duration_s for this board/rep will be unreliable")
    return out


def run_burst(nodes: dict[int, dict], active_ids: list[int], coordinator: int,
              duration: int, label: str, logdir: str) -> dict[int, bytes]:
    """One group talk burst. `active_ids` = coordinator + every currently
    joined member; every one of them is instrumented (full serial rig)."""
    logs: dict[int, bytes] = {}
    start_logs: dict[int, bytes] = {}
    # Let any jitter-buffer backlog from the PREVIOUS burst fully drain before
    # starting the next one -- a receiver still decoding queued frames is
    # exactly the busy-console condition run_start_verified has to retry
    # around, so avoiding it here means fewer retries, not just tolerance.
    time.sleep(1.5)
    for nid in active_ids:
        start_logs[nid] = run_start_verified(nodes[nid]["serial"], f"{label}_n{nid}")

    send_and_collect(nodes[coordinator]["serial"], f"talk group {duration}",
                     settle=1.0, window=2.0)
    time.sleep(duration + 3.0)
    for nid in active_ids:
        drain_fixed(nodes[nid]["serial"], 2.0)

    for nid in active_ids:
        s = nodes[nid]["serial"]
        out = start_logs.get(nid, b"")
        out += run_stop_verified(s)
        out += send_and_collect(s, "dump summary", settle=1.0, window=3.0)
        out += send_and_collect(s, "dump csv", settle=1.0, window=4.0)
        logs[nid] = out
        path = os.path.join(logdir, f"{label}_node{nid}.log")
        with open(path, "wb") as fh:
            fh.write(out)
    return logs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--coordinator", type=int, default=1)
    ap.add_argument("--members", default="2,3",
                    help="comma list of node ids to join, in growth order (default 2,3 -> N=1,2,3)")
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--burst", type=int, default=30, help="seconds per repeated trial")
    ap.add_argument("--sustained", type=int, default=0,
                    help="seconds for one sustained run per N (0 = skip)")
    ap.add_argument("--pilot", action="store_true",
                    help="shorthand: reps=2, burst=10, sustained=0 -- validate the harness first")
    ap.add_argument("--outdir", default="results_group_scaling")
    ap.add_argument("--sync-wait", type=float, default=5.0)
    args = ap.parse_args()

    if args.pilot:
        args.reps, args.burst, args.sustained = 2, 10, 0

    os.makedirs(args.outdir, exist_ok=True)
    logdir = os.path.join(args.outdir, "logs")
    os.makedirs(logdir, exist_ok=True)

    member_ids = [int(x) for x in args.members.split(",") if x.strip() != ""]
    all_ids = [args.coordinator] + member_ids

    print(f"== discovering boards ==")
    nodes = discover(args.baud)
    missing = [i for i in all_ids if i not in nodes]
    if missing:
        for n in nodes.values():
            n["serial"].close()
        sys.exit(f"missing node(s) {missing} on serial -- found {sorted(nodes)}")

    print(f"== pairwise mesh among {all_ids} ==")
    ensure_pairwise(nodes, all_ids)

    print(f"== letting the clock estimator converge ({args.sync_wait:.0f}s) ==")
    time.sleep(args.sync_wait)

    summary_rows = []
    grpop_rows = []

    active = [args.coordinator]
    print(f"== N=1 (coordinator {args.coordinator} alone): group create ==")
    ensure_group(nodes, args.coordinator, [])

    for n_idx, new_member in enumerate([None] + member_ids):
        if new_member is not None:
            print(f"== joining node {new_member} ==")
            joined = ensure_group(nodes, args.coordinator, [new_member])
            active.append(new_member)
            for mid, raw in joined:
                for row in parse_grpops(raw.decode(errors="replace")):
                    row["event_node"] = mid
                    row["context"] = "join_during_scaling_setup"
                    grpop_rows.append(row)

        n = len(active)
        print(f"== N={n}: members {active} ==")
        for rep in range(1, args.reps + 1):
            label = f"n{n}_rep{rep}"
            print(f"   -- rep {rep}/{args.reps}, {args.burst}s burst --")
            logs = run_burst(nodes, active, args.coordinator, args.burst, label, logdir)
            for nid, raw in logs.items():
                text = raw.decode(errors="replace")
                summ = parse_summary(text)
                summ["n"] = n
                summ["rep"] = rep
                summ["node_id"] = nid
                summ["role"] = "coordinator" if nid == args.coordinator else "member"
                summary_rows.append(summ)
                for row in parse_grpops(text):
                    row["event_node"] = nid
                    row["context"] = label
                    grpop_rows.append(row)

        if args.sustained > 0:
            label = f"n{n}_sustained"
            print(f"   -- sustained run, {args.sustained}s --")
            logs = run_burst(nodes, active, args.coordinator, args.sustained, label, logdir)
            for nid, raw in logs.items():
                text = raw.decode(errors="replace")
                summ = parse_summary(text)
                summ["n"] = n
                summ["rep"] = "sustained"
                summ["node_id"] = nid
                summ["role"] = "coordinator" if nid == args.coordinator else "member"
                summary_rows.append(summ)

    # ------------------------------------------------------------- output
    all_keys = []
    seen = set()
    for row in summary_rows:
        for k in row:
            if k not in seen:
                seen.add(k)
                all_keys.append(k)
    front = ["n", "rep", "node_id", "role"]
    cols = front + [k for k in all_keys if k not in front]

    csv_path = os.path.join(args.outdir, "group_scaling.csv")
    with open(csv_path, "w") as fh:
        fh.write(",".join(cols) + "\n")
        for row in summary_rows:
            fh.write(",".join(str(row.get(c, "")) for c in cols) + "\n")
    print(f"\nwrote {csv_path} ({len(summary_rows)} rows)")

    if grpop_rows:
        gkeys = []
        gseen = set()
        for row in grpop_rows:
            for k in row:
                if k not in gseen:
                    gseen.add(k)
                    gkeys.append(k)
        gpath = os.path.join(args.outdir, "group_control_costs.csv")
        with open(gpath, "w") as fh:
            fh.write(",".join(gkeys) + "\n")
            for row in grpop_rows:
                fh.write(",".join(str(row.get(c, "")) for c in gkeys) + "\n")
        print(f"wrote {gpath} ({len(grpop_rows)} rows)")

    for n in nodes.values():
        n["serial"].close()

    print("\ndone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
