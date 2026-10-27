#!/usr/bin/env python3
"""Protocol-2 group scaling: persistent connections and strict per-node evidence.
Counts R listeners and M=R+1 total members. Requires all selected boards cabled.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
import json
import time
from pathlib import Path
from board_v2 import connect_boards, ensure_mesh, group_consistent, wait_until, records, merged_summary


def write_rows(path, rows):
    if not rows:
        return
    fields = list(dict.fromkeys(k for row in rows for k in row))
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def idle_wait(boards, seconds):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        for b in boards.values():
            b.check()
        time.sleep(min(0.2, max(0, until - time.monotonic())))


def require_sync(boards, listeners, talker):
    def ready():
        for i in listeners:
            rows = records(boards[i].command("sync"), "SYNC")
            if not any(r.get("peer") == str(talker) and r.get("valid") == "1" for r in rows):
                return False
        return True
    wait_until(ready, 25, "all listener clocks to converge")


def initialise_group(boards, coordinator):
    if any(b.group().get("active") != "0" for b in boards.values()):
        raise RuntimeError("start with freshly rebooted boards (NVS credentials persist); existing groups would change the membership experiment")
    ensure_mesh(boards)
    boards[coordinator].command("group create")
    for i in boards:
        if i != coordinator:
            boards[coordinator].command(f"group allow {i}")
    wait_until(lambda: group_consistent(boards, [coordinator], coordinator))


def add_member(boards, active, member, coordinator):
    boards[member].command(f"group join {coordinator}")
    intended = active + [member]
    wait_until(lambda: group_consistent(boards, intended, coordinator), description=f"all rosters to contain {intended}")
    return intended


def commands_all(boards, commands):
    # Independent UARTs: minimize differences between per-node run windows.
    with ThreadPoolExecutor(max_workers=len(commands)) as pool:
        futures = {i: pool.submit(boards[i].command, command) for i, command in commands.items()}
        return {i: future.result() for i, future in futures.items()}


def run_burst(boards, active, talker, seconds, label, outdir):
    if not group_consistent(boards, active, talker):
        raise RuntimeError("membership diverged before trial")
    listeners = [i for i in active if i != talker]
    require_sync(boards, listeners, talker)
    before = {i: boards[i].group() for i in active}
    starts, summaries = {}, {}
    try:
        starts = commands_all(boards, {i: f"run start {label}_n{i}" for i in active})
        boards[talker].command(f"talk group {seconds}")
        idle_wait(boards, seconds + 1)
    finally:
        try:
            boards[talker].command("talk off")
        finally:
            commands_all(boards, {i: "run stop" for i in active})
    for i in active:
        raw = boards[i].command("dump csv", timeout=35)
        (outdir / f"{label}_node{i}.log").write_text(starts[i] + f"\n#EXPERIMENT,architecture=group,R_listeners={len(listeners)},M_total={len(active)}\n" + raw)
        summary = merged_summary(raw)
        if summary.get("measurement_schema") != "2" or summary.get("label") != f"{label}_n{i}":
            raise RuntimeError(f"node {i}: wrong or missing summary label/schema")
        if boards[i].group() != before[i]:
            raise RuntimeError(f"node {i}: membership/key state changed during steady-state trial")
        if i == talker:
            if int(summary.get("tx_frames", "0")) <= 0:
                raise RuntimeError("talker produced no measured frames")
        else:
            if int(summary.get("rx_frames", "0")) <= 0 or summary.get("loss_complete") != "1":
                raise RuntimeError(f"node {i}: no reception or missing authenticated burst end; trial invalid")
            if int(summary.get("owd_n", "0")) <= 0:
                raise RuntimeError(f"node {i}: no clock-corrected delay samples")
        summaries[i] = {"R_listeners": len(listeners), "M_total": len(active), "trial": label,
                        "node_id": i, "role": "talker" if i == talker else "listener", **summary}
    return list(summaries.values())


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--coordinator", type=int, default=1)
    ap.add_argument("--members", default="2,3,4,5,6")
    ap.add_argument("--ports", nargs="+")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--burst", type=int, default=30)
    ap.add_argument("--sustained", type=int, default=0)
    ap.add_argument("--pilot", action="store_true")
    ap.add_argument("--outdir", type=Path, default=Path("results_group_v2"))
    args = ap.parse_args()
    if args.pilot:
        args.reps, args.burst, args.sustained = 2, 10, 0
    ids = [args.coordinator] + [int(i) for i in args.members.split(",")]
    if not 2 <= len(ids) <= 8 or len(set(ids)) != len(ids) or args.reps <= 0 or args.burst <= 0 or args.sustained < 0:
        ap.error("use 2..8 distinct nodes, positive reps/burst, and nonnegative sustained duration")
    args.outdir.mkdir(parents=True, exist_ok=False)
    rows = []
    with connect_boards(ids, args.ports, args.baud, args.outdir / "continuous") as boards:
        manifest = {"protocol": 2, "measurement_schema": 2, "requested_members": ids,
                    "config": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
                    "devices": {i: b.device for i, b in boards.items()}}
        (args.outdir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        try:
            initialise_group(boards, args.coordinator)
            active = [args.coordinator]
            for member in ids[1:]:
                active = add_member(boards, active, member, args.coordinator)
                R = len(active) - 1
                trials = [(f"r{R}_rep{r}", args.burst) for r in range(1, args.reps + 1)]
                if args.sustained:
                    trials.append((f"r{R}_sustained", args.sustained))
                for label, seconds in trials:
                    print(f"{label}: R={R} listeners, M={len(active)} total, {seconds}s", flush=True)
                    rows.extend(run_burst(boards, active, args.coordinator, seconds, label, args.outdir))
                    write_rows(args.outdir / "group_scaling.csv", rows)
            (args.outdir / "COMPLETE").write_text("All requested trials passed evidence checks.\n")
        except BaseException as exc:
            (args.outdir / "FAILED.txt").write_text(f"{type(exc).__name__}: {exc}\n")
            raise
        finally:
            ops = [{"event_node": i, **row} for i, b in boards.items() for row in records(b._text, "GRPOP")]
            write_rows(args.outdir / "group_control_costs.csv", ops)
    print(f"Saved {len(rows)} per-node summaries to {args.outdir}")


if __name__ == "__main__":
    main()
