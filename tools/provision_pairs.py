#!/usr/bin/env python3
"""Generate independent pair credentials and provision every connected endpoint.
Keys never appear in stdout or capture logs. Reusing --keys reuses that key set.
"""
import argparse
import itertools
import json
import os
import secrets
from pathlib import Path
from board_v2 import connect_boards, ensure_mesh


def key_file(path: Path, ids):
    expected = {f"{a}-{b}" for a, b in itertools.combinations(sorted(ids), 2)}
    if path.exists():
        if path.stat().st_mode & 0o077:
            raise ValueError(f"restrict {path} to owner access (chmod 600) before using it")
        data = json.loads(path.read_text())
        if set(data.get("pairs", {})) != expected or data.get("schema") != 2:
            raise ValueError("existing key file covers a different node set; use a separate file")
        values = list(data["pairs"].values())
        if len(set(values)) != len(values) or any(len(bytes.fromhex(k)) != 32 for k in values):
            raise ValueError("keys must be distinct 32-byte hex values")
        return data
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = {"schema": 2, "nodes": sorted(ids), "pairs": {pair: secrets.token_hex(32) for pair in sorted(expected)}}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    return data


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--nodes", default="1,2,3,4,5,6")
    ap.add_argument("--ports", nargs="+")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--keys", type=Path, default=Path(".secrets/pairwise_keys.json"))
    ap.add_argument("--generate-only", action="store_true")
    args = ap.parse_args()
    ids = [int(i) for i in args.nodes.split(",")]
    if len(ids) != len(set(ids)) or not 2 <= len(ids) <= 8 or any(not 1 <= i < 65535 for i in ids):
        ap.error("use 2..8 distinct valid node IDs")
    data = key_file(args.keys, ids)
    print(f"Independent credentials ready in {args.keys} (owner access only)")
    if args.generate_only:
        return
    with connect_boards(ids, args.ports, args.baud) as boards:
        if any(b.group().get("active") != "0" for b in boards.values()):
            raise RuntimeError("provision before creating groups; reboot the boards first")
        for pair, key in data["pairs"].items():
            a, b = map(int, pair.split("-"))
            boards[a].command(f"psk set {b} {key}", secret=True)
            boards[b].command(f"psk set {a} {key}", secret=True)
            print(f"Provisioned pair {a}<->{b}")
        ensure_mesh(boards)
        print("All pairs authenticated with independent credentials; NVS persists across reboot.")


if __name__ == "__main__":
    main()
