#!/usr/bin/env python3
"""Sustained 300 s trials at M=4 and M=5, closing the specific gap the
16-18 October recheck named: the M=4/M=5 extension had three short 30 s
trials per size but no sustained run, unlike the matched M=2/M=3 baseline
(ten reps + one sustained run each). Reuses run_group_scaling_v2.py's own
audited helpers (same evidence checks, same CSV schema) rather than
reimplementing them.
"""
import json
from pathlib import Path
from board_v2 import connect_boards, records
from run_group_scaling_v2 import initialise_group, add_member, run_burst, write_rows


def main() -> None:
    out = Path(__file__).resolve().parents[1] / "results_group_v2_sustained_ext"
    out.mkdir(exist_ok=False)
    ids = [1, 2, 3, 5, 6]
    coordinator = 1
    rows = []
    with connect_boards(ids, logdir=out / "continuous") as boards:
        manifest = {"protocol": 2, "measurement_schema": 2, "purpose": "sustained M=4/M=5 extension",
                    "devices": {i: b.device for i, b in boards.items()}}
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        try:
            initialise_group(boards, coordinator)
            active = [coordinator]
            for member in [2, 3, 5]:
                active = add_member(boards, active, member, coordinator)
            print(f"M={len(active)} formed: {active}; running 300 s sustained trial", flush=True)
            rows.extend(run_burst(boards, active, coordinator, 300, "m4_sustained", out))
            write_rows(out / "group_scaling.csv", rows)

            active = add_member(boards, active, 6, coordinator)
            print(f"M={len(active)} formed: {active}; running 300 s sustained trial", flush=True)
            rows.extend(run_burst(boards, active, coordinator, 300, "m5_sustained", out))
            write_rows(out / "group_scaling.csv", rows)

            (out / "COMPLETE").write_text("Both sustained trials passed evidence checks.\n")
        except BaseException as exc:
            (out / "FAILED.txt").write_text(f"{type(exc).__name__}: {exc}\n")
            raise
        finally:
            ops = [{"event_node": i, **row} for i, b in boards.items() for row in records(b._text, "GRPOP")]
            write_rows(out / "group_control_costs.csv", ops)
    print(f"Saved {len(rows)} per-node summaries to {out}")


if __name__ == "__main__":
    main()
