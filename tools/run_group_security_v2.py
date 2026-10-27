#!/usr/bin/env python3
"""Strict per-node hardware smoke tests for protocol-2 group protection/lifecycle.
This is not a complete security certification; reboot/fault cases also have host tests.
"""
import argparse
from pathlib import Path
from board_v2 import connect_boards, records, merged_summary, group_consistent, wait_until
from run_group_scaling_v2 import initialise_group, add_member, run_burst, idle_wait, write_rows


def rejection_result(summary, expected_counter, sent):
    required = {"rx_frames", "auth_fail", "replay_drop", "epoch_unknown", "malformed"}
    if not required <= summary.keys() or sent <= 0:
        return "INCONCLUSIVE"
    if int(summary["rx_frames"]) != 0:
        return "FAIL"
    counters = {k: int(summary[k]) for k in required - {"rx_frames"}}
    if counters[expected_counter] == sent and sum(counters.values()) == sent:
        return "PASS"
    # Broadcast completion proves enqueue/callback success, not receiver delivery.
    return "INCONCLUSIVE"


def quiet_attack(boards, attacker, receivers, kind, counter, outdir, label, rows, count=20):
    if kind == "replay" and counter == "replay_drop":
        capture = records(boards[attacker].command("attack info"), "CAPTURE")[-1]
        if capture.get("valid") != "1" or capture.get("group") != "1":
            raise RuntimeError("no captured group packet")
        seq = int(capture["seq"])
        for i in receivers:
            windows = records(boards[i].command("group status"), "GROUP_REPLAY")
            w = next((w for w in windows if w["member"] == str(attacker)), None)
            age = int(w["highest"]) - seq if w else -1
            if not w or w["primed"] != "1" or age < 0 or (age < 64 and not (int(w["bitmap"], 16) & (1 << age))):
                raise RuntimeError(f"node {i}: captured packet was not observed; repeat positive baseline before replay test")
    started = []
    try:
        for i in receivers:
            boards[i].command(f"run start {label}_n{i}")
            started.append(i)
        output = boards[attacker].command(f"attack {kind} {count}")
        evidence = records(output, "ATTACK")
        if len(evidence) != 1:
            raise RuntimeError("missing actual injection count")
        sent = int(evidence[0]["sent"])
        idle_wait(boards, 1)
    finally:
        for i in started:
            boards[i].command("run stop")
    for i in receivers:
        raw = boards[i].command("dump summary")
        (outdir / f"{label}_node{i}.log").write_text(raw)
        summary = merged_summary(raw)
        result = rejection_result(summary, counter, sent)
        rows.append({"case": label, "node": i, "result": result, "injected": sent, "expected_counter": counter, **summary})
        print(f"{label}: node {i}: {result}")
    write_rows(outdir / "security.csv", rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--nodes", default="1,2,3,4,5,6")
    ap.add_argument("--ports", nargs="+")
    ap.add_argument("--outdir", type=Path, default=Path("results_group_security_v2"))
    args = ap.parse_args()
    ids = [int(i) for i in args.nodes.split(",")]
    if not 4 <= len(ids) <= 8 or len(set(ids)) != len(ids):
        ap.error("use 4..8 distinct nodes; first is coordinator, last is revocation target")
    args.outdir.mkdir(parents=True, exist_ok=False)
    rows = []
    with connect_boards(ids, args.ports, logdir=args.outdir / "continuous") as boards:
        co, victim = ids[0], ids[-1]
        try:
            initialise_group(boards, co)
            active = [co]
            for member in ids[1:]:
                active = add_member(boards, active, member, co)
            run_burst(boards, active, co, 2, "positive", args.outdir)
            for kind, counter in [("replay", "replay_drop"), ("tamper", "auth_fail"), ("forge", "auth_fail")]:
                quiet_attack(boards, co, ids[1:], kind, counter, args.outdir, kind, rows)
                run_burst(boards, active, co, 2, f"after_{kind}", args.outdir)
            boards[co].command("group rekey")
            wait_until(lambda: group_consistent(boards, active, co), description="rekey completion on every node")
            run_burst(boards, active, co, 2, "after_rekey", args.outdir)
            boards[victim].command("group leave")
            remaining = [i for i in active if i != victim]
            wait_until(lambda: group_consistent(boards, remaining, co), description="leave completion")
            wait_until(lambda: boards[victim].group().get("busy") == "0", description="leave acknowledgement")
            active = add_member(boards, remaining, victim, co)
            run_burst(boards, active, co, 2, "after_rejoin", args.outdir)
            # Capture a packet from the soon-to-be-revoked member under the old key.
            boards[victim].command("talk group 2")
            idle_wait(boards, 3)
            boards[co].command(f"group revoke {victim}")
            wait_until(lambda: group_consistent(boards, remaining, co), description="revocation completion")
            quiet_attack(boards, victim, remaining, "replay", "epoch_unknown", args.outdir, "revoked_key", rows)
            boards[victim].command(f"group join {co}")
            idle_wait(boards, 17)
            status = boards[co].group()
            if str(victim) in status["allowed"].split(";") or not group_consistent(boards, remaining, co):
                raise RuntimeError("revoked member readmitted or membership diverged")
            candidate = remaining[1]
            survivors = [i for i in remaining if i != co]
            for i in survivors:
                boards[i].command(f"group expect {candidate}")
            boards[candidate].command("group claim")
            wait_until(lambda: group_consistent(boards, survivors, candidate), description="authorized coordinator transfer")
            run_burst(boards, survivors, candidate, 2, "after_transfer", args.outdir)
            rows.append({"case": "rekey_leave_rejoin_revoke_transfer", "node": "all", "result": "PASS"})
            write_rows(args.outdir / "security.csv", rows)
            if any(row["result"] != "PASS" for row in rows):
                raise RuntimeError("one or more cases failed or lack complete per-node evidence; inspect security.csv")
            (args.outdir / "COMPLETE").write_text("All implemented hardware smoke cases passed.\n")
        except BaseException as exc:
            (args.outdir / "FAILED.txt").write_text(f"{type(exc).__name__}: {exc}\n")
            raise
        finally:
            for b in boards.values():
                try:
                    b.command("talk off")
                except Exception:
                    pass


if __name__ == "__main__":
    main()
