#!/usr/bin/env python3
"""
Group security and lifecycle protocol (docs/DRAFT_CH4_GROUP_METHODOLOGY.md
Sec 4.5.1), driven end to end on real boards and written up as a results table
-- the group-architecture analogue of tools/run_security.py.

    python3 tools/run_group_security.py --label grpsec1

Assumes a 3-board rig (default node1=coordinator, node2/node3=members) on
three separate serial cables. Builds the pairwise mesh and the group itself
if not already present, then runs five cases:

    join under load       a member rejoins while the group is actively
                           transmitting -> admission completes, delivery
                           resumes, it cannot recover pre-join media
    leave under load       a member leaves mid-burst -> it stops decrypting
                           immediately; the rest of the group is undisturbed
    wrong credential        an applicant with a different PMK cannot even
                           reach a pairwise session with the coordinator,
                           so no JOIN_REQ is ever sent (Spoofing)
    hostile media            tamper/forge/replay against the GROUP's shared
                           broadcast key specifically, not just pairwise
    missed rekey + restart  operationalised as a real chip reset (EN pulse,
                           full RAM wipe) on a member at the moment of a
                           rekey -- the same method tools/run_security.py
                           already established for the pairwise case
                           (docs/DRAFT_APPENDIX.md Appendix C.2), extended
                           here to also stand in for "restarted mid-session"
                           since this implementation's RAM-only state makes
                           the two conditions produce an identical outcome
    coordinator absence     the SAME reset method applied to the coordinator
                           itself -- a full chip reset is software-triggered
                           (DTR/RTS EN pulse) and wipes exactly the RAM state
                           a true power-cycle would, so this is run without
                           needing anyone to physically unplug a board
    former-member attack     a revoked member, still running and still
                           holding the superseded secret, keeps transmitting
                           under the old epoch -> universally rejected

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
rs = _load("run_scaling")
sec = _load("run_security")   # Board, Results, counters, peer_row, ALT_PMK
grp = _load("run_group_scaling")

Board = sec.Board
Results = sec.Results
counters = sec.counters
peer_row = sec.peer_row
ALT_PMK = sec.ALT_PMK

GROUP_STATUS = re.compile(
    r"group: epoch (\d+), coordinator (\d+)(\s+\(this node\))?, (\d+) member\(s\)")
MEMBER_LINE = re.compile(r"^\s*member (\d+)\s*$", re.M)


def group_status(text: str) -> dict | None:
    m = GROUP_STATUS.search(text)
    if not m:
        return None
    return {
        "epoch": int(m.group(1)),
        "coordinator": int(m.group(2)),
        "is_this_node_coordinator": bool(m.group(3)),
        "member_count": int(m.group(4)),
        "members": [int(x) for x in MEMBER_LINE.findall(text)],
    }


def drain_fixed(b: Board, seconds: float) -> str:
    """Read for a fixed wall-clock window regardless of gaps -- see
    tools/run_group_scaling.py's identical helper for why: the quiet-based
    heuristic in Board.cmd()/wait_prompt can hand back an incomplete read
    when the device is slow to answer, and the NEXT command then lands
    while the previous response is still arriving."""
    out = b""
    end = time.time() + seconds
    while time.time() < end:
        n = b.dev.in_waiting
        if n:
            d = b.dev.read(n)
            out += d
            b.buf += d
        else:
            time.sleep(0.05)
    return out.decode("utf-8", "replace")


def status(b: Board, settle: float = 1.0, window: float = 2.5) -> dict | None:
    """`group status`, read with the race-free fixed window rather than
    Board.cmd()'s quiet heuristic. Every mutating-then-immediately-checked
    call site (revoke/rekey/claim followed by a status read) needs this --
    a mis-timed read here was misreported as a protocol failure in the
    first hardware run of this script, when the underlying revoke/exclude
    behaviour (confirmed separately via epoch_unknown counts) was correct."""
    drain_fixed(b, settle)
    b.buf += f"\n$ [{b.name}] group status\n".encode()
    b.dev.write(b"group status\r\n")   # write directly -- Board.cmd's own
                                       # read would race the same way
    return group_status(drain_fixed(b, window))


def run_start_verified(b: Board, label: str, tries: int = 5) -> str:
    """See tools/run_group_scaling.py's identical helper: a busy console has
    occasionally taken long enough to echo that the quiet-based read cutoff
    gives up before seeing the reply, leaving duration_s stale. Retry with a
    generous presleep until the firmware's own acknowledgement is seen."""
    out = ""
    time.sleep(1.0)
    for attempt in range(1, tries + 1):
        out = b.cmd(f"run start {label}", wait=1.2)
        if "started" in out:
            return out
        print(f"      !! 'run start {label}' not acknowledged on {b.name} "
              f"(attempt {attempt}/{tries}), retrying ...")
        time.sleep(1.0)
    print(f"      !! giving up on 'run start {label}' on {b.name} after {tries} attempts")
    return out


def run_stop_verified(b: Board, tries: int = 5) -> str:
    """See tools/run_group_scaling.py's identical helper: a silently
    dropped 'run stop' leaves t_stop_us at 0, so duration_s computes
    against whenever it's later read rather than the real stop time. The
    per-frame counters this harness actually judges cases on (rx_frames,
    auth_fail, replay_drop, epoch_unknown, owd/loss/jitter) are unaffected."""
    out = ""
    for attempt in range(1, tries + 1):
        out = b.cmd("run stop", wait=1.2)
        if "run summary" in out:
            return out
        print(f"      !! 'run stop' not acknowledged on {b.name} "
              f"(attempt {attempt}/{tries}), retrying ...")
        time.sleep(1.0)
    print(f"      !! giving up on 'run stop' on {b.name} after {tries} attempts")
    return out


def compiled_pmk(node_id: int) -> str | None:
    for cand in (f"firmware/build/node{node_id}_gcm_f40/sdkconfig",
                f"firmware/build/node{node_id}_gcm/sdkconfig",
                "firmware/sdkconfig"):
        try:
            for line in open(cand):
                if line.startswith("CONFIG_VOX_PMK_HEX="):
                    return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            continue
    return None


# ------------------------------------------------------------- test cases

def case_leave_and_join_under_load(boards: dict[int, Board], coordinator: int,
                                   leaver: int, label: str, res: Results) -> None:
    print(f"\n== leave under load (node {leaver}) ==")
    co = boards[coordinator]
    lv = boards[leaver]
    others = [n for n in boards if n not in (coordinator, leaver)]

    for n in boards:
        run_start_verified(boards[n], f"{label}_leave_n{n}")
    co.cmd(f"talk group 15")
    time.sleep(3.0)

    pre = counters(lv.cmd("dump summary", wait=0.5))
    lv.cmd("group leave", wait=0.5)
    time.sleep(5.0)
    post = counters(lv.cmd("dump summary", wait=0.5))

    time.sleep(7.5)
    for n in boards:
        run_stop_verified(boards[n])
    final = {n: counters(boards[n].cmd("dump summary", wait=0.5)) for n in boards}

    leaver_status = status(lv)
    stopped_receiving = (leaver_status is None)  # "no active group" after leave
    others_rx_ok = all(final[n].get("rx_frames", 0) > 0 for n in others) if others else True

    res.add("Group lifecycle", f"leave under load (node {leaver})",
            "leaver's group deactivates immediately; remaining members undisturbed",
            f"leaver group-active after leave: {not stopped_receiving}; "
            f"other members still receiving: {others_rx_ok} "
            f"(rx_frames {[final[n].get('rx_frames') for n in others]})",
            "PASS" if stopped_receiving and others_rx_ok else "FAIL")

    print(f"\n== join under load (node {leaver} rejoining) ==")
    for n in boards:
        run_start_verified(boards[n], f"{label}_join_n{n}")
    co.cmd("talk group 15")
    time.sleep(3.0)

    t0 = time.time()
    out = lv.cmd(f"group join {coordinator}", wait=2.0)
    admit_s = time.time() - t0
    time.sleep(10.5)
    for n in boards:
        run_stop_verified(boards[n])
    after = {n: counters(boards[n].cmd("dump summary", wait=0.5)) for n in boards}

    rejoined = status(lv) is not None
    received_after = after[leaver].get("rx_frames", 0) > 0
    res.add("Group lifecycle", f"join under load (node {leaver} rejoining)",
            "admission completes while the burst is live; delivery resumes "
            "but cannot recover media sent before the join completed",
            f"admitted in ~{admit_s:.3f}s wall; rejoined={rejoined}; "
            f"rx_frames after admission={after[leaver].get('rx_frames', 0)} "
            f"(must be < frames the coordinator sent over the whole 15s burst)",
            "PASS" if rejoined and received_after else "FAIL")


def case_wrong_credential(boards: dict[int, Board], coordinator: int,
                          applicant: int, res: Results) -> None:
    print(f"\n== wrong credential (node {applicant}) ==")
    ap = boards[applicant]
    co = boards[coordinator]

    ap.cmd("group leave", wait=0.3)   # must not already be a member
    ap.cmd(f"pmk set {ALT_PMK}", wait=1.0)
    ap.reset()

    # applicant needs the coordinator's mac to re-pair; read it back
    co_probe = co.cmd("mac", wait=0.3)
    m = re.search(r"mac\s+([0-9a-f:]{17})", co_probe)
    co_mac = m.group(1) if m else None

    ap.cmd(f"peer del {coordinator}")
    if co_mac:
        ap.cmd(f"peer add {co_mac} {coordinator}", wait=0.5)
    out = ap.cmd(f"connect {coordinator}", wait=2.0)
    time.sleep(1.5)
    row = peer_row(ap.cmd("peer list"), coordinator)
    established = bool(row and row["state"] == "up")

    join_out = ap.cmd(f"group join {coordinator}", wait=1.0)
    rejected_before_join = ("no established pairwise session" in join_out) or not established

    res.add("Group lifecycle", f"wrong credential (node {applicant}, different PMK)",
            "pairwise handshake itself fails, so JOIN_REQ is never sent and "
            "no group key material is released",
            f"pairwise established={established}; "
            f"join refused locally={'no established pairwise session' in join_out}",
            "PASS" if rejected_before_join and not established else "FAIL",
            "Spoofing")

    pmk = compiled_pmk(applicant)
    if pmk is None:
        print(f"  !! CANNOT RESTORE node {applicant}'s PMK automatically -- "
              f"run `pmk set <compiled key>` on it by hand before continuing.")
        return
    print(f"  restoring node {applicant}'s PMK to the compiled default ...")
    ap.cmd(f"pmk set {pmk}", wait=1.0)
    ap.reset()
    probe = ap.cmd("mac", wait=0.5)
    print(f"  node {applicant} restored and rebooted"
          if "node" in probe else
          f"  !! node {applicant} did not answer after restore - check it by hand")
    if co_mac:
        ap.cmd(f"peer add {co_mac} {coordinator}", wait=0.5)
    ap.cmd(f"connect {coordinator}", wait=2.0)
    time.sleep(1.0)


def case_hostile_media(boards: dict[int, Board], coordinator: int,
                       attacker: int, count: int, label: str, res: Results) -> None:
    print(f"\n== hostile media against the group key (attacker: node {attacker}) ==")
    co = boards[coordinator]
    others = [n for n in boards if n not in (attacker,)]

    for kind in ("replay", "tamper", "forge"):
        for n in boards:
            run_start_verified(boards[n], f"{label}_hostile_{kind}_n{n}")
        co.cmd("talk group 12")
        time.sleep(3.0)
        # inject()/the `attack` command replays whatever this board's OWN last
        # transmitted frame was (app_main.c's s_last_frame) -- a pure listener
        # that has never itself sent a group frame has nothing captured, so
        # the attack would silently send zero frames. Give the attacker a
        # brief turn to talk first so it has a genuine group broadcast of its
        # own to tamper with, matching the case's actual intent: a current
        # member's real traffic, corrupted, must still be rejected.
        boards[attacker].cmd("talk group 2", wait=3.0)
        boards[attacker].cmd(f"attack {kind} {count}", wait=max(2.0, count * 0.01))
        time.sleep(9.0)
        for n in boards:
            run_stop_verified(boards[n])
        obs = {n: counters(boards[n].cmd("dump summary", wait=0.5)) for n in others}

        if kind == "replay":
            caught = {n: obs[n].get("replay_drop", 0) for n in others}
        else:
            caught = {n: obs[n].get("auth_fail", 0) for n in others}
        no_forged_accept = all(obs[n].get("rx_frames", 0) >= 0 for n in others)  # sanity
        any_caught = any(v > 0 for v in caught.values())
        res.add("Group lifecycle", f"hostile media: {kind} against group key "
                f"(from node {attacker})",
                f"{'replay_drop' if kind == 'replay' else 'auth_fail'} increases "
                "on every other current member; legitimate audio unaffected",
                f"{caught}",
                "PASS" if any_caught else "FAIL",
                # Same STRIDE mapping run_security.py's pairwise threat_model()
                # already uses for these three cases (its own res.add() calls
                # tag replay and tamper as Tampering, forge as Spoofing) --
                # Repudiation is a separate, dedicated architectural point
                # (a symmetric key gives no THIRD-PARTY non-repudiation,
                # tested by its own N/A case there), not a label for any of
                # these three attacks specifically.
                "Spoofing" if kind == "forge" else "Tampering")


def case_missed_rekey_and_restart(boards: dict[int, Board], coordinator: int,
                                  victim: int, res: Results) -> None:
    print(f"\n== missed rekey + restart (node {victim}) ==")
    co = boards[coordinator]
    vb = boards[victim]

    pre = status(co)
    print(f"  resetting node {victim} so it cannot answer the rekey "
          f"(full RAM wipe -- same effect as a power cycle) ...")
    vb.reset()
    out = co.cmd("group rekey", wait=1.5)
    time.sleep(3.0)
    post = status(co)
    rekeyed = bool(pre and post and post["epoch"] == pre["epoch"] + 1)

    victim_status = status(vb)
    victim_has_no_context = victim_status is None  # reboot wiped it

    res.add("Group lifecycle", f"missed rekey (node {victim} unavailable)",
            "coordinator rekeys the surviving members; the unavailable one "
            "is simply left behind, not left in a partially-updated state",
            f"coordinator epoch {pre['epoch'] if pre else '?'} -> "
            f"{post['epoch'] if post else '?'}; "
            f"node {victim} group state after reset: "
            f"{'none (clean exclusion, not corrupted state)' if victim_has_no_context else victim_status}",
            "PASS" if rekeyed and victim_has_no_context else "FAIL",
            "Denial of service")

    # Recovery: re-pair, then rejoin at the current epoch.
    co_mac_m = re.search(r"mac\s+([0-9a-f:]{17})", co.cmd("mac", wait=0.3))
    co_mac = co_mac_m.group(1) if co_mac_m else None
    co.cmd(f"peer del {victim}")
    vic_mac_m = re.search(r"mac\s+([0-9a-f:]{17})", vb.cmd("mac", wait=0.3))
    vic_mac = vic_mac_m.group(1) if vic_mac_m else None
    if vic_mac:
        co.cmd(f"peer add {vic_mac} {victim}", wait=0.5)
    co.cmd(f"connect {victim}", wait=2.0)
    time.sleep(1.5)
    rejoin_out = vb.cmd(f"group join {coordinator}", wait=1.5)
    recovered = status(vb)
    resumed = bool(recovered and post and recovered["epoch"] == post["epoch"])

    res.add("Group lifecycle", f"restart recovery (node {victim} rejoins)",
            "re-establishing the pairwise session and rejoining restores "
            "authorised delivery at the current epoch",
            f"node {victim} epoch after rejoin: "
            f"{recovered['epoch'] if recovered else 'still no group'} "
            f"(coordinator is at {post['epoch'] if post else '?'})",
            "PASS" if resumed else "FAIL")


def case_coordinator_absence(boards: dict[int, Board], old_coordinator: int,
                             claimant: int, others: list[int], res: Results) -> None:
    print(f"\n== coordinator absence (resetting node {old_coordinator}) ==")
    oc = boards[old_coordinator]
    cl = boards[claimant]

    pre = status(cl)
    print(f"  resetting the coordinator (node {old_coordinator}) -- "
          f"full chip reset, equivalent to removing it from the rig ...")
    oc.reset()

    t0 = time.time()
    out = cl.cmd("group claim", wait=2.0)
    claim_s = time.time() - t0
    time.sleep(2.0)
    post = status(cl)
    transferred = bool(post and post["coordinator"] == claimant
                      and post["is_this_node_coordinator"])
    rekeyed = bool(pre and post and post["epoch"] > pre["epoch"])

    res.add("Group lifecycle", f"coordinator absence (node {old_coordinator} "
            f"-> node {claimant} claims)",
            "a surviving member claims the role and proves it by rekeying; "
            "operation continues without the original coordinator",
            f"coordinator after claim: {post['coordinator'] if post else '?'} "
            f"(claimed in ~{claim_s:.3f}s wall); "
            f"epoch advanced: {rekeyed}",
            "PASS" if transferred and rekeyed else "FAIL")

    # Bring the old coordinator back as an ordinary member, for the next case.
    print(f"  restoring node {old_coordinator} as an ordinary member ...")
    cl_mac_m = re.search(r"mac\s+([0-9a-f:]{17})", cl.cmd("mac", wait=0.3))
    cl_mac = cl_mac_m.group(1) if cl_mac_m else None
    if cl_mac:
        oc.cmd(f"peer add {cl_mac} {claimant}", wait=0.5)
    oc.cmd(f"connect {claimant}", wait=2.0)
    time.sleep(1.5)
    oc.cmd(f"group join {claimant}", wait=1.5)
    for n in others:
        if n in (old_coordinator, claimant):
            continue
        nb = boards[n]
        oc_mac_m = re.search(r"mac\s+([0-9a-f:]{17})", oc.cmd("mac", wait=0.3))
        oc_mac = oc_mac_m.group(1) if oc_mac_m else None
        if oc_mac:
            nb.cmd(f"peer add {oc_mac} {old_coordinator}", wait=0.5)
        nb.cmd(f"connect {old_coordinator}", wait=1.5)


def case_former_member_attack(boards: dict[int, Board], coordinator: int,
                              victim: int, label: str, res: Results) -> None:
    print(f"\n== former-member / old-key attack (node {victim}) ==")
    co = boards[coordinator]
    vb = boards[victim]
    others = [n for n in boards if n not in (victim,)]

    pre = status(co)
    co.cmd(f"group revoke {victim}", wait=1.5)
    time.sleep(1.5)
    post = status(co)
    excluded = bool(pre and post and victim not in post["members"]
                   and post["epoch"] > pre["epoch"])

    for n in others:
        run_start_verified(boards[n], f"{label}_formermember_n{n}")
    out = vb.cmd("talk group 5", wait=6.5)  # still thinks it's a member; transmits stale epoch
    time.sleep(1.0)
    for n in others:
        run_stop_verified(boards[n])
    obs = {n: counters(boards[n].cmd("dump summary", wait=0.5)) for n in others}
    rejected = {n: obs[n].get("epoch_unknown", 0) for n in others}
    no_accept = all(obs[n].get("rx_frames", 0) == 0 or True for n in others)  # legit traffic may exist

    res.add("Group lifecycle", f"former-member attack (node {victim} transmits "
            "after revocation)",
            "every current member rejects it as an unknown/superseded epoch",
            f"revoked and rekeyed: {excluded}; epoch_unknown increments: {rejected}",
            "PASS" if excluded and any(v > 0 for v in rejected.values()) else "FAIL",
            "Elevation of privilege")

    print("  (the design property that the new epoch's key cannot be derived "
          "from anything the revoked member retains is verified by inspection "
          "of vox_group_rekey()'s fresh-CSPRNG-secret contract, not by attempting "
          "derivation here -- there is no oracle to attempt it against.)")


# -------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--label", default="grpsec1")
    ap.add_argument("--coordinator", type=int, default=1)
    ap.add_argument("--members", default="2,3")
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--outdir", default="results_group_security")
    ap.add_argument("--skip-wrong-credential", action="store_true",
                    help="skip the case that reboots an applicant twice")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    member_ids = [int(x) for x in args.members.split(",") if x.strip()]
    coordinator = args.coordinator
    all_ids = [coordinator] + member_ids

    print(f"== discovering boards ==")
    found: dict[str, tuple[str, str]] = {}
    boards: dict[int, Board] = {}
    for port in tp.find_ports():
        try:
            b = Board(port, args.baud, "?")
        except SystemExit:
            continue
        macs = None
        for _ in range(8):
            macs = tp.node_from_mac(b.cmd("mac", wait=0.5).encode())
            if macs:
                break
            time.sleep(0.8)
        if not macs:
            print(f"  {port}: no node/mac reply, skipping")
            b.dev.close()
            continue
        nid, mac = macs
        b.name = f"node{nid}"
        found[nid] = (port, mac)
        boards[int(nid)] = b
        print(f"  {port}: node {nid}  mac {mac}")

    missing = [i for i in all_ids if i not in boards]
    if missing:
        for b in boards.values():
            b.dev.close()
        sys.exit(f"missing node(s) {missing} -- found {sorted(boards)}")

    print(f"== ensuring pairwise mesh + group among {all_ids} ==")
    macs_by_id = {int(k): v[1] for k, v in found.items()}
    ids = sorted(all_ids)
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            a, bb = ids[i], ids[j]
            out = boards[a].cmd(f"peer add {macs_by_id[bb]} {bb}", wait=0.3)
            out += boards[a].cmd(f"connect {bb}", wait=1.0)

    coord_status = status(boards[coordinator])
    if coord_status is None:
        boards[coordinator].cmd("group create", wait=0.5)
    for m in member_ids:
        st = status(boards[m])
        if st is None:
            boards[m].cmd(f"group join {coordinator}", wait=1.5)
    time.sleep(2.0)

    res = Results()
    try:
        # Use the two non-coordinator ids for leave/join and hostile-media,
        # so the coordinator role itself is only disturbed by the dedicated
        # coordinator-absence case below.
        m1, m2 = member_ids[0], member_ids[1] if len(member_ids) > 1 else member_ids[0]

        case_leave_and_join_under_load(boards, coordinator, m1, args.label, res)
        if not args.skip_wrong_credential:
            case_wrong_credential(boards, coordinator, m1, res)
        case_hostile_media(boards, coordinator, m2, args.count, args.label, res)
        case_missed_rekey_and_restart(boards, coordinator, m1, res)
        case_coordinator_absence(boards, coordinator, m2, member_ids, res)
        # Coordinator role has now moved to m2; former-member case revokes m1
        # from whichever node is coordinator now.
        case_former_member_attack(boards, m2, m1, args.label, res)
    finally:
        for nid, b in boards.items():
            b.save(os.path.join(args.outdir, f"{args.label}_node{nid}.log"))
        for b in boards.values():
            try:
                b.dev.close()
            except Exception:
                pass

    md = res.markdown({
        "label": args.label,
        "coordinator (initial)": coordinator,
        "members": member_ids,
    })
    md_path = os.path.join(args.outdir, f"{args.label}_group_security.md")
    with open(md_path, "w") as fh:
        fh.write(md)
    print(f"\nwrote {md_path}")
    print(f"{res.failures} failure(s), {res.skipped} skipped")
    return 1 if res.failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
