#!/usr/bin/env python3
"""
Drive the threat-model and RQ3 test cases end to end, and write the table.

Everything here was previously a manual console procedure documented in
docs/BASELINE_ARCHITECTURE.md section 7 but never automated and never captured,
which left a third of the project (RQ3) and the entire security evaluation
without evidence. This runs them identically every time and records what the
counters actually did.

    python3 tools/run_security.py --label sec1

Two boards on two USB-serial cables, node 1 the talker and node 2 the
receiver (override with --talker / --receiver). Produces:

    <label>_tx.log          everything typed and printed on the talker
    <label>_rx.log          everything typed and printed on the receiver
    <label>_security.md     the results table, PASS/FAIL per case

THREAT MODEL. Each case runs on the sender while the receiver has a run window
open, and is judged on the receiver's own rejection counters:

    replay   the previous frame re-sent verbatim   -> replay_drop +N, rx_frames +0
    tamper   one ciphertext bit flipped            -> auth_fail   +N, rx_frames +0
    forge    random ciphertext under a fresh seq   -> auth_fail   +N, rx_frames +0

If any of these raises rx_frames, the protection is broken and the run is a
finding rather than a measurement. The tool says so in as many words.

RQ3. Membership, rekeying and recovery, managed between the endpoints with no
controller:

    authorised join     peer add + connect            -> state up, handshake timed
    rekey under load    rekey mid-burst               -> epoch +1, no loss spike
    missed rekey        rekey a peer that never acks  -> stays on the old epoch
    leave / revocation  peer del                      -> peer gone, state freed
    recovery            reconnect after a peer reset  -> fresh session at epoch 0
    rejected join       different PMK (--include-pmk-reject, opt-in: it writes
                        NVS on the receiver and reboots it twice)

Requires pyserial. The boards must already be flashed with the same arm.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
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
rs = _load("run_scaling")   # for the robust serial probe

ALT_PMK = "de" * 32         # the wrong key, so the join gets rejected


def compiled_pmk() -> str | None:
    """
    The PMK the firmware was built with, read back from its own sdkconfig.

    Restoring after the rejected-join test MUST write this exact value.
    A provisioned PMK in NVS overrides CONFIG_VOX_PMK_HEX
    (sec/vox_keys.c), so writing any other key -- including an
    all-zero placeholder -- does not undo the test. It silently leaves the
    board holding a key no other board shares, and it will refuse to pair with
    the rig until someone works out why.
    """
    for cand in ("firmware/build/node2_gcm/sdkconfig",
                 "firmware/build/node2/sdkconfig",
                 "firmware/sdkconfig"):
        path = os.path.join(PROJ, cand) if "PROJ" in globals() else cand
        try:
            for line in open(path):
                if line.startswith("CONFIG_VOX_PMK_HEX="):
                    return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            continue
    return None


# --------------------------------------------------------------- plumbing

class Board:
    """One console, with everything it printed kept for the log."""

    def __init__(self, port: str, baud: int, name: str):
        self.port = port
        self.baud = baud
        self.name = name
        # open_quiet deasserts DTR/RTS so attaching does not hold the board in
        # reset, and the caller waits the board out rather than giving up after
        # 400 ms of silence the way twoports.open_port does. A board that
        # rebooted on attach is quiet for a second or two and then prints its
        # banner; the shorter wait reports a perfectly healthy board as absent.
        self.dev = rs.open_quiet(port, baud)
        self.buf = bytearray()

    def cmd(self, line: str, wait: float = 0.0) -> str:
        self.buf += f"\n$ [{self.name}] {line}\n".encode()
        out = tp.cmd(self.dev, line, wait=wait)
        self.buf += out
        return out.decode("utf-8", "replace")

    def drain(self, seconds: float) -> str:
        out = tp.wait_prompt(self.dev, seconds)
        self.buf += out
        return out.decode("utf-8", "replace")

    def reset(self) -> str:
        """EN pulse with GPIO0 high: boots the app, not the downloader."""
        self.buf += f"\n$ [{self.name}] <hardware reset>\n".encode()
        self.dev.close()
        s = serial.Serial(self.port, self.baud, timeout=0.2)
        s.setDTR(False)
        s.setRTS(True)
        time.sleep(0.2)
        s.setRTS(False)
        s.reset_input_buffer()
        self.dev = s
        out = b""
        end = time.time() + 15.0
        last = time.time()
        while time.time() < end:
            if b"vox>" in out:
                break
            n = s.in_waiting
            if n:
                out += s.read(n)
                last = time.time()
            elif time.time() - last >= 2.5:
                break
            else:
                time.sleep(0.05)
        self.buf += out
        return out.decode("utf-8", "replace")

    def save(self, path: str) -> None:
        with open(path, "wb") as fh:
            fh.write(bytes(self.buf))


def counters(text: str) -> dict[str, float]:
    """
    Rejection counters from a `run stop`.

    Prefers the machine-readable #SUMMARY block; falls back to the human
    summary so this still works against firmware built before that block
    existed.
    """
    # Values stay floats: loss_pct is a fraction of a percent and truncating it
    # to an int turned every loss figure into 0.
    out: dict[str, float] = {}
    for m in re.finditer(r"#SUMMARY,(.+)", text):
        for kv in m.group(1).split(","):
            if "=" not in kv:
                continue
            k, _, v = kv.partition("=")
            try:
                out[k.strip()] = float(v.strip())
            except ValueError:
                pass
    if out:
        return out

    prose = {
        "auth_fail": r"auth failures\s+(\d+)",
        "replay_drop": r"replay rejects\s+(\d+)",
        "epoch_unknown": r"unknown epoch\s+(\d+)",
        "malformed": r"malformed\s+(\d+)",
        "rx_frames": r"frames accepted\s+(\d+)",
    }
    for key, pat in prose.items():
        m = re.search(pat, text)
        if m:
            out[key] = float(m.group(1))
    m = re.search(r"loss ([0-9.]+) %", text)
    if m:
        out["loss_pct"] = float(m.group(1))
    return out


def peer_row(text: str, peer_id: int) -> dict | None:
    """One row of `peer list`: id mac state epoch txseq authfail replay phantom."""
    for line in text.splitlines():
        m = re.match(r"\s*(\d+)\s+([0-9a-f:]{17})\s+(up|init|idle)\s+(\d+)\s+(\d+)"
                     r"\s+(\d+)\s+(\d+)\s+(yes|no)", line.strip(), re.I)
        if m and int(m.group(1)) == peer_id:
            return {"id": int(m.group(1)), "mac": m.group(2), "state": m.group(3),
                    "epoch": int(m.group(4)), "txseq": int(m.group(5)),
                    "authfail": int(m.group(6)), "replay": int(m.group(7)),
                    "phantom": m.group(8).lower() == "yes"}
    return None


# STRIDE, as the report commits to it: the six categories and the property each
# one is about. Every test case declares which category it exercises, so the
# report can show coverage rather than a list of attacks that happens to be
# incomplete in ways nobody notices.
STRIDE = [
    ("Spoofing",               "authenticity"),
    ("Tampering",              "integrity"),
    ("Repudiation",            "non-repudiability"),
    ("Information disclosure", "confidentiality"),
    ("Denial of service",      "availability"),
    ("Elevation of privilege", "authorisation"),
]


class Results:
    def __init__(self):
        self.rows: list[tuple[str, str, str, str, str, str]] = []
        self.failures = 0
        self.skipped = 0

    def add(self, group: str, case: str, expected: str, observed: str,
            verdict: str, stride: str = "") -> None:
        self.rows.append((group, case, expected, observed, verdict, stride))
        if verdict == "FAIL":
            self.failures += 1
        elif verdict in ("SKIP", "N/A"):
            self.skipped += 1
        mark = {"PASS": "  ok  ", "FAIL": " FAIL ", "SKIP": " skip ",
                "N/A": " n/a  "}[verdict]
        tag = f"{stride[:4].upper():<5}" if stride else "     "
        print(f"[{mark}] {tag} {case}: {observed}")

    def markdown(self, meta: dict) -> str:
        lines = ["# Security test results (STRIDE)", ""]
        for k, v in meta.items():
            lines.append(f"- **{k}**: {v}")
        lines.append("")
        if self.failures:
            lines.append(f"> **{self.failures} case(s) FAILED.** A failing "
                         "threat-model case is a finding about the protection, "
                         "not a measurement. Do not publish performance numbers "
                         "from this build until it is understood.")
            lines.append("")

        # --- coverage against the six categories -------------------------
        lines.append("## STRIDE coverage")
        lines.append("")
        lines.append("The report adopts STRIDE as its organising lens, so "
                     "coverage is reported against all six categories -- "
                     "including the ones this system does not address, which "
                     "are stated rather than omitted.")
        lines.append("")
        lines.append("| category | property | cases | outcome |")
        lines.append("|---|---|---|---|")
        for cat, prop in STRIDE:
            mine = [r for r in self.rows if r[5] == cat]
            if not mine:
                lines.append(f"| **{cat}** | {prop} | — | *no case defined* |")
                continue
            verdicts = [r[4] for r in mine]
            if "FAIL" in verdicts:
                outcome = f"**{verdicts.count('FAIL')} FAILED** of {len(mine)}"
            elif all(v == "N/A" for v in verdicts):
                outcome = "out of scope — see notes"
            elif "SKIP" in verdicts:
                outcome = f"{verdicts.count('PASS')} pass, {verdicts.count('SKIP')} not run"
            else:
                outcome = f"all {len(mine)} pass"
            lines.append(f"| **{cat}** | {prop} | {len(mine)} | {outcome} |")
        lines.append("")

        # --- detail, grouped by category ---------------------------------
        for cat, _ in STRIDE:
            mine = [r for r in self.rows if r[5] == cat]
            if not mine:
                continue
            lines.append(f"## {cat}")
            lines.append("")
            lines.append("| case | expected | observed | verdict |")
            lines.append("|---|---|---|---|")
            for _, case, expected, observed, verdict, _s in mine:
                lines.append(f"| {case} | {expected} | {observed} | {verdict} |")
            lines.append("")

        loose = [r for r in self.rows if not r[5]]
        if loose:
            lines.append("## Uncategorised")
            lines.append("")
            lines.append("| case | expected | observed | verdict |")
            lines.append("|---|---|---|---|")
            for _, case, expected, observed, verdict, _s in loose:
                lines.append(f"| {case} | {expected} | {observed} | {verdict} |")
            lines.append("")
        return "\n".join(lines)


# ------------------------------------------------------------- test cases

def threat_model(tx: Board, rx: Board, n: int, label: str, res: Results) -> None:
    """
    Each attack gets its own run window so its counters are isolated.

    A short talk burst runs first and OUTSIDE the window: the injector replays
    the sender's last real frame, so there has to be one, and counting it would
    put rx_frames on the board for a window that is supposed to see none.
    """
    print("\n== threat model ==")
    tx.cmd("talk 2")
    time.sleep(3.0)
    tx.drain(5.0)

    cases = [
        ("replay", "replay_drop", "replay window, before any decryption"),
        ("tamper", "auth_fail", "AEAD tag"),
        ("forge", "auth_fail", "AEAD tag"),
    ]
    for attack, counter, caught_by in cases:
        rx.cmd(f"run start sec_{label}_{attack}", wait=0.5)
        sent = tx.cmd(f"attack {attack} {n}", wait=max(2.0, n * 0.01))
        m = re.search(r"(?:replayed|sent)\s+(\d+)", sent)
        n_sent = int(m.group(1)) if m else 0
        time.sleep(1.0)
        out = rx.cmd("run stop", wait=2.0)
        c = counters(out)

        got = int(c.get(counter, 0))
        frames = int(c.get("rx_frames", 0))
        if n_sent == 0:
            res.add("Threat model", f"`attack {attack} {n}`",
                    f"{counter} +{n}, rx_frames +0",
                    "sender injected nothing (no captured frame to replay "
                    "- did the talk burst reach a real peer?)", "SKIP",
                    "Spoofing" if attack == "forge" else "Tampering")
            continue
        observed = f"{counter} +{got} of {n_sent} injected, rx_frames +{frames}"
        if frames > 0:
            observed += "  <- ACCEPTED A MALICIOUS FRAME"
            verdict = "FAIL"
        elif got >= n_sent:
            verdict = "PASS"
        else:
            # Under-count is usually radio loss on the injected frames rather
            # than a protection failure, but it is not a clean pass.
            observed += f" (caught by {caught_by}; {n_sent - got} never arrived)"
            verdict = "PASS" if got >= n_sent * 0.9 else "FAIL"
        res.add("Threat model", f"`attack {attack} {n}`",
                f"{counter} +{n_sent}, rx_frames +0", observed, verdict,
                "Spoofing" if attack == "forge" else "Tampering")


def availability_flood(tx: Board, rx: Board, rx_id: int, rx_mac: str, count: int,
                       label: str, res: Results, atk: Board | None = None) -> None:
    """
    Denial of service: what does rejecting frames cost the legitimate stream?

    The other three attacks each prove a malicious frame is *refused*, which
    says nothing about the price of refusing thousands. Forged frames carry a
    fresh sequence number, so they clear the replay window cheaply and force a
    full AEAD verification each -- the expensive rejection path, and the one an
    attacker would choose.

    The test floods during a live burst and then asks the receiver what
    happened to the audio. The pass condition is not "the frames were
    rejected" -- they always are -- it is that delivered voice stayed inside
    the NIST loss target while the receiver was under attack.
    """
    print("\n== STRIDE: denial of service ==")

    # Who does the flooding decides what the result means.
    #
    # Running it on the legitimate talker is convenient and WRONG for this
    # particular question: the injector contends for the sender's own transmit
    # lock, so audio frames are delayed before they ever reach the air. That
    # shows up as inflated one-way delay and looks like the receiver buckling
    # under load when it is nothing of the kind. Measured side by side, the
    # same 2000-frame flood gave 186.9 ms peak delay and 1.533 % loss from the
    # talker, against 12.0 ms and 0.100 % from a separate board.
    #
    # A third cabled board is therefore used as an independent attacker radio
    # whenever one exists. It needs one real frame of its own to mutate, so it
    # establishes a session with the victim and talks briefly first.
    attacker, origin = (atk, "independent radio") if atk else (tx, "the talker itself")
    if atk is not None:
        print("  arming the independent attacker (it needs one real frame to mutate)")
        atk.cmd(f"peer add {rx_mac} {rx_id}", wait=0.5)
        atk.cmd(f"connect {rx_id}", wait=2.0)
        atk.cmd("talk 2")
        time.sleep(4.0)
        atk.drain(2.0)

    rx.cmd(f"run start sec_{label}_flood", wait=0.5)
    tx.cmd("talk 20")
    time.sleep(5.0)
    print(f"  flooding {count} forged frames mid-burst from {origin} ...")
    out = attacker.cmd(f"attack flood {count}", wait=max(6.0, count * 0.006))
    m = re.search(r"flooded (\d+) forged frames in (\d+) us \(([0-9.]+) frames/s", out)
    sent, rate = (int(m.group(1)), float(m.group(3))) if m else (0, 0.0)
    time.sleep(18.0)
    tx.drain(5.0)
    stop = rx.cmd("run stop", wait=2.0)
    c = counters(stop)

    if sent == 0:
        res.add("Threat model", f"`attack flood {count}` (availability)",
                "audio stays inside the loss target while under attack",
                "sender injected nothing", "SKIP", "Denial of service")
        return

    rejected = int(c.get("auth_fail", 0)) + int(c.get("replay_drop", 0))
    delivered = int(c.get("delivery_n", 0))
    accepted = int(c.get("rx_frames", 0))
    loss = c.get("loss_pct")
    observed = (f"{sent} forged frames at {rate:.0f}/s; receiver rejected "
                f"{rejected}, accepted {accepted} legitimate, "
                f"loss {loss:.3f} %" if loss is not None else
                f"{sent} forged at {rate:.0f}/s; rejected {rejected}")
    # Rejecting is mandatory; surviving is the actual question.
    survived = (delivered > 0 and loss is not None and loss <= 1.0
                and accepted > 0)
    note = f" [flooded from {origin}]"
    if atk is None:
        note += ("; NOTE: the attacker shares the talker's radio and transmit "
                 "lock, so this OVERSTATES the impact - cable a third board "
                 "for an independent measurement")
    res.add("Threat model", f"`attack flood {count}` (availability)",
            "malicious frames refused AND delivered audio stays within "
            "the 1 % NIST loss target",
            observed + note + ("" if survived else "  <- STREAM DEGRADED BEYOND TARGET"),
            "PASS" if survived else "FAIL", "Denial of service")


def declared_scope(res: Results, crypto_on: bool, tag_len: int) -> None:
    """
    The two STRIDE categories this system does not test, and why.

    Omitting them would leave a coverage table that looks complete because the
    gaps are invisible. Both are design positions, not oversights, and both are
    already stated in the report's scope -- so they are recorded as decided
    rather than silently missing.
    """
    res.add("Threat model", "per-sender non-repudiation",
            "a third party can prove which endpoint sent a frame",
            "NOT PROVIDED BY DESIGN. A pairwise symmetric key authenticates a "
            "sender to its peer but gives no third-party proof; either endpoint "
            "could have produced any frame. A group arm sharing one key is "
            "weaker still -- per-message signatures are the remedy, and they "
            "are the expensive part of Group OSCORE's group mode. Out of scope "
            "per the report's stated claims.",
            "N/A", "Repudiation")

    res.add("Threat model", "payload confidentiality and metadata exposure",
            "speech is unreadable; metadata exposure is bounded and declared",
            (f"payload protected (crypto={int(crypto_on)}, {tag_len} B tag). "
             "The 12-byte header is cleartext BY DESIGN -- the receiver must "
             "read src_id, epoch and seq to pick a key and run the replay check "
             "before it can verify anything. It is covered by the tag, so it "
             "cannot be altered undetected, but a radio-range observer sees "
             "timing, frame length and identifiers. No test asserts this; it is "
             "a declared property of the wire format."),
            "N/A", "Information disclosure")


def rq3_membership(tx: Board, rx: Board, tx_id: int, rx_id: int,
                   rx_mac: str, tx_mac: str, label: str, res: Results) -> None:
    print("\n== RQ3: membership, rekeying, recovery ==")

    # --- authorised join -------------------------------------------------
    lst = tx.cmd("peer list")
    row = peer_row(lst, rx_id)
    hs = re.search(r"session established in (\d+) us", tx.buf.decode("utf-8", "replace"))
    res.add("RQ3 membership", "authorised join (`peer add` + `connect`)",
            "state up, handshake timed",
            (f"state {row['state']}, epoch {row['epoch']}"
             + (f", handshake {hs.group(1)} us" if hs else ""))
            if row else "peer not in table",
            "PASS" if row and row["state"] == "up" else "FAIL", "Elevation of privilege")

    # --- rekey under load ------------------------------------------------
    before = peer_row(tx.cmd("peer list"), rx_id)
    rx.cmd(f"run start sec_{label}_rekey", wait=0.5)
    tx.cmd("talk 12")
    time.sleep(5.0)                       # rekey squarely inside the burst
    out = tx.cmd(f"rekey {rx_id}", wait=1.5)
    time.sleep(9.0)
    tx.drain(5.0)
    after = peer_row(tx.cmd("peer list"), rx_id)
    stop = rx.cmd("run stop", wait=2.0)
    c = counters(stop)
    loss = c.get("loss_pct")
    concealed = int(c.get("jb_concealed", 0))
    delivered = int(c.get("delivery_n", 0))
    advanced = bool(before and after and after["epoch"] > before["epoch"])
    lossy = concealed > 5 if delivered else False
    res.add("RQ3 membership", "rekey under load (`rekey` mid-burst)",
            "epoch +1, no loss spike",
            f"epoch {before['epoch'] if before else '?'} -> "
            f"{after['epoch'] if after else '?'}, "
            f"{concealed} concealed of {delivered} delivered"
            + (f" (loss {loss:.3f} %)" if loss is not None else ""),
            "PASS" if advanced and not lossy else "FAIL", "Denial of service")

    # --- missed rekey ----------------------------------------------------
    # A REAL peer that cannot answer. Resetting the receiver wipes its RAM-only
    # session, so the EPOCH_REQ arrives at a board with no security context for
    # this link: it cannot produce a valid EPOCH_ACK. That is the "peer powered
    # off during a rekey" condition, reached without a switchable supply.
    #
    # An earlier version of this test used a phantom peer, which was wrong.
    # vox_session_rekey() has an explicit phantom fast-path that advances the
    # epoch immediately and by design -- a phantom has no counterpart to
    # acknowledge -- so the test exercised a different code path from the one
    # the claim is about, and reported a failure the firmware had not committed.
    pre = peer_row(tx.cmd("peer list"), rx_id)
    print("  resetting the receiver so it cannot answer the rekey ...")
    rx.reset()
    out = tx.cmd(f"rekey {rx_id}", wait=1.5)
    time.sleep(4.0)
    post = peer_row(tx.cmd("peer list"), rx_id)
    held = bool(pre and post and post["epoch"] == pre["epoch"])
    res.add("RQ3 membership", "missed rekey (real peer cannot answer)",
            "initiator stays on the old epoch and retries",
            f"epoch {pre['epoch'] if pre else '?'} -> "
            f"{post['epoch'] if post else '?'} "
            f"({'held - no one-sided switch' if held else 'SWITCHED ONE-SIDEDLY'})",
            "PASS" if held else "FAIL", "Denial of service")

    # Put the link back so the cases after this one have a session to use.
    tx.cmd(f"peer del {rx_id}")
    tx.cmd(f"peer add {rx_mac} {rx_id}", wait=0.5)
    tx.cmd(f"connect {rx_id}", wait=2.0)
    time.sleep(1.5)

    # --- leave / revocation ----------------------------------------------
    pre_list = tx.cmd("peer list")
    m = re.search(r"(\d+) peers \((\d+) real\), (\d+) B state", pre_list)
    pre_state = int(m.group(3)) if m else None
    tx.cmd(f"peer del {rx_id}", wait=0.5)
    post_list = tx.cmd("peer list")
    m = re.search(r"(\d+) peers \((\d+) real\), (\d+) B state", post_list)
    post_state = int(m.group(3)) if m else None
    gone = peer_row(post_list, rx_id) is None
    res.add("RQ3 membership", "leave / revocation (`peer del`)",
            "peer removed, key state freed",
            f"peer {'removed' if gone else 'STILL PRESENT'}, "
            f"state {pre_state} -> {post_state} B",
            "PASS" if gone and (post_state or 0) < (pre_state or 0) else "FAIL", "Elevation of privilege")

    # --- recovery --------------------------------------------------------
    # The receiver is reset, so it comes back with an empty peer table: the
    # real "board rebooted" case, not a simulated one.
    print("  resetting the receiver to test recovery ...")
    rx.reset()
    tx.cmd(f"peer add {rx_mac} {rx_id}", wait=0.5)
    tx.cmd(f"connect {rx_id}", wait=2.0)
    time.sleep(1.5)
    row = peer_row(tx.cmd("peer list"), rx_id)
    res.add("RQ3 membership", "recovery (reconnect after a peer reboot)",
            "fresh session at epoch 0",
            f"state {row['state']}, epoch {row['epoch']}" if row
            else "peer not in table",
            "PASS" if row and row["state"] == "up" and row["epoch"] == 0 else "FAIL", "Denial of service")


def peer_independence(tx: Board, rx: Board, rx_id: int, rx_mac: str,
                      other_id: int, other_mac: str, label: str,
                      res: Results) -> None:
    """
    Rekeying one peer must not disturb another.

    This is the claim the whole six-board story rests on: each receiver is an
    independent pairwise arm, so adding, rekeying or dropping one never touches
    another's epoch, keys or replay window (docs/UNICAST_PEER_FLOW.md section 1).
    Until now it was argued from the code -- there is no shared session epoch
    and no broadcast rekey -- and supported by the RQ1 campaign's clean
    per-peer scaling, but never tested directly.

    The test rekeys the OTHER peer in the middle of a live burst and then asks
    the instrumented one whether anything happened to it. A shared epoch, a
    shared replay window, or a rekey that touched the wrong slot would all show
    up here as a moved counter or a loss spike.
    """
    print("\n== RQ3: per-peer independence ==")
    tx.cmd(f"peer add {rx_mac} {rx_id}", wait=0.4)
    tx.cmd(f"connect {rx_id}", wait=2.0)
    tx.cmd(f"peer add {other_mac} {other_id}", wait=0.4)
    tx.cmd(f"connect {other_id}", wait=2.0)
    time.sleep(1.5)

    peers = tx.cmd("peer list")
    a0, b0 = peer_row(peers, rx_id), peer_row(peers, other_id)
    if not a0 or not b0 or a0["state"] != "up" or b0["state"] != "up":
        res.add("RQ3 membership", "per-peer independence (rekey one, check the other)",
                "untouched peer keeps its epoch, window and delivery",
                f"could not establish both peers (node {rx_id}="
                f"{a0['state'] if a0 else 'absent'}, node {other_id}="
                f"{b0['state'] if b0 else 'absent'})", "SKIP")
        return

    rx.cmd(f"run start sec_{label}_indep", wait=0.5)
    tx.cmd("talk 20")
    time.sleep(6.0)
    print(f"  rekeying node {other_id} mid-burst; node {rx_id} must not notice")
    tx.cmd(f"rekey {other_id}", wait=1.5)
    time.sleep(15.0)
    tx.drain(5.0)
    stop = rx.cmd("run stop", wait=2.0)
    c = counters(stop)

    peers = tx.cmd("peer list")
    a1, b1 = peer_row(peers, rx_id), peer_row(peers, other_id)
    moved = []
    if a1["epoch"] != a0["epoch"]:
        moved.append(f"epoch {a0['epoch']}->{a1['epoch']}")
    if a1["authfail"] != a0["authfail"]:
        moved.append(f"authfail +{a1['authfail'] - a0['authfail']}")
    if a1["replay"] != a0["replay"]:
        moved.append(f"replay +{a1['replay'] - a0['replay']}")
    if int(c.get("auth_fail", 0)) or int(c.get("epoch_unknown", 0)):
        moved.append(f"receiver auth_fail={int(c.get('auth_fail',0))} "
                     f"epoch_unknown={int(c.get('epoch_unknown',0))}")
    loss = c.get("loss_pct")
    if loss is not None and loss > 1.0:
        moved.append(f"loss {loss:.3f} %")

    other_advanced = b1 and b1["epoch"] > b0["epoch"]
    ok = (not moved) and other_advanced
    res.add("RQ3 membership", "per-peer independence (rekey one, check the other)",
            f"node {other_id} epoch +1; node {rx_id} epoch, window and delivery untouched",
            (f"node {other_id} epoch {b0['epoch']}->{b1['epoch']}; "
             f"node {rx_id} " + ("UNTOUCHED" if not moved else "DISTURBED: " + ", ".join(moved))
             + (f", loss {loss:.3f} %" if loss is not None else "")),
            "PASS" if ok else "FAIL", "Elevation of privilege")


def rejected_join(tx: Board, rx: Board, rx_id: int, rx_mac: str,
                  res: Results) -> None:
    """
    A board holding a different PMK must not be admitted.

    Opt-in because it writes NVS on the receiver and reboots it twice. If this
    aborts midway the receiver is left holding ALT_PMK and will refuse to pair
    until you restore it by hand:  pmk set <the original>  then reset.
    """
    print("\n== RQ3: rejected join (writes NVS on the receiver) ==")
    rx.cmd(f"pmk set {ALT_PMK}", wait=1.0)
    rx.reset()
    tx.cmd(f"peer del {rx_id}")
    tx.cmd(f"peer add {rx_mac} {rx_id}", wait=0.5)
    out = tx.cmd(f"connect {rx_id}", wait=3.0)
    time.sleep(2.0)
    row = peer_row(tx.cmd("peer list"), rx_id)
    established = bool(row and row["state"] == "up")
    rx_saw = rx.drain(1.0)
    rejected = "failed authentication" in rx_saw or not established
    res.add("RQ3 membership", "rejected join (different PMK)",
            "handshake fails, no session",
            f"talker state {row['state'] if row else '?'}; "
            f"receiver {'logged an authentication failure' if 'failed authentication' in rx_saw else 'stayed silent'}",
            "PASS" if rejected and not established else "FAIL", "Spoofing")

    pmk = compiled_pmk()
    if pmk is None:
        print("  !! CANNOT RESTORE: CONFIG_VOX_PMK_HEX not found in any sdkconfig.")
        print("     The receiver is holding ALT_PMK and will not pair until you")
        print("     run `pmk set <the key every other board uses>` on it.")
        return
    print(f"  restoring the receiver's PMK to the compiled default ...")
    rx.cmd(f"pmk set {pmk}", wait=1.0)
    rx.reset()
    ok, _ = (True, None)
    probe = rx.cmd("mac", wait=0.5)
    print("  receiver restored and rebooted"
          if "node" in probe else
          "  !! receiver did not answer after restore - check it by hand")


# -------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--label", default="sec1", help="run label and log prefix")
    ap.add_argument("--talker", type=int, default=1, help="node id of the talker")
    ap.add_argument("--receiver", type=int, default=2, help="node id of the receiver")
    ap.add_argument("--count", type=int, default=100,
                    help="frames per attack (default 100)")
    ap.add_argument("--outdir", default=".", help="where to write the logs and table")
    ap.add_argument("--include-pmk-reject", action="store_true",
                    help="also run the rejected-join case. Writes NVS on the "
                         "receiver and reboots it twice; leaves it holding a "
                         "development PMK that you must replace before measuring.")
    ap.add_argument("--flood", type=int, default=2000,
                    help="forged frames for the denial-of-service case "
                         "(default 2000)")
    ap.add_argument("--skip-flood", action="store_true",
                    help="skip the availability case (it degrades a live burst "
                         "on purpose)")
    ap.add_argument("--skip-threat", action="store_true")
    ap.add_argument("--skip-rq3", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    print(f"== discovering boards on {', '.join(tp.find_ports())} ==")
    found: dict[str, tuple[str, str]] = {}
    boards: dict[str, Board] = {}
    for port in tp.find_ports():
        try:
            b = Board(port, args.baud, "?")
        except SystemExit:
            continue
        macs = None
        deadline = time.time() + 15.0
        while time.time() < deadline:
            macs = tp.node_from_mac(b.cmd("mac", wait=0.5).encode())
            if macs:
                break
            time.sleep(0.8)
        if not macs:
            print(f"  {port}: no node / mac reply, skipping")
            b.dev.close()
            continue
        nid, mac = macs
        found[nid] = (port, mac)
        b.name = f"node{nid}"
        boards[nid] = b
        print(f"  {port}: node {nid}  mac {mac}")

    tx = boards.get(str(args.talker))
    rx = boards.get(str(args.receiver))
    if tx is None or rx is None:
        for b in boards.values():
            b.dev.close()
        sys.exit(f"need node {args.talker} (talker) and node {args.receiver} "
                 f"(receiver); found: {', '.join(sorted(found)) or 'none'}")
    tx.name, rx.name = "TX", "RX"
    tx_mac = found[str(args.talker)][1]
    rx_mac = found[str(args.receiver)][1]

    # Any third cabled board becomes the peer that gets rekeyed in the
    # independence test. It needs no console of its own during the test - only
    # its MAC, so the talker can establish it.
    second = None
    for nid, (port, mac) in sorted(found.items(), key=lambda kv: int(kv[0])):
        if nid not in (str(args.talker), str(args.receiver)):
            second = (int(nid), mac)
            break
    if second:
        print(f"  second listener for the independence test: node {second[0]} {second[1]}")

    print("== pairing ==")
    rx.cmd(f"peer add {tx_mac} {args.talker}", wait=0.5)
    rx.cmd(f"connect {args.talker}", wait=2.0)
    tx.cmd(f"peer add {rx_mac} {args.receiver}", wait=0.5)
    paired = tx.cmd(f"connect {args.receiver}", wait=2.0)
    time.sleep(1.5)
    if "session established" not in paired and "session established" not in tx.buf.decode("utf-8", "replace"):
        print("  !! WARNING: no 'session established' on the talker. "
              "Every case below will fail for the same reason.")

    res = Results()
    try:
        if not args.skip_threat:
            threat_model(tx, rx, args.count, args.label, res)
            if not args.skip_flood:
                atk = None
                if second is not None:
                    port = found[str(second[0])][0]
                    try:
                        atk = Board(port, args.baud, "ATK")
                        for _ in range(12):
                            if tp.node_from_mac(atk.cmd("mac", wait=0.5).encode()):
                                break
                            time.sleep(0.8)
                    except Exception:
                        atk = None
                availability_flood(tx, rx, args.receiver, rx_mac, args.flood,
                                   args.label, res, atk)
                if atk is not None:
                    try:
                        atk.dev.close()
                    except Exception:
                        pass
        declared_scope(res, crypto_on=True, tag_len=16)
        if not args.skip_rq3:
            rq3_membership(tx, rx, args.talker, args.receiver,
                           rx_mac, tx_mac, args.label, res)
            if second is not None:
                peer_independence(tx, rx, args.receiver, rx_mac,
                                  second[0], second[1], args.label, res)
            else:
                res.add("RQ3 membership",
                        "per-peer independence (rekey one, check the other)",
                        "untouched peer keeps its epoch, window and delivery",
                        "needs a second cabled listener; only one was found",
                        "SKIP", "Elevation of privilege")
            if args.include_pmk_reject:
                rejected_join(tx, rx, args.receiver, rx_mac, res)
            else:
                res.add("RQ3 membership", "rejected join (different PMK)",
                        "handshake fails, no session",
                        "not run (pass --include-pmk-reject; it writes NVS)",
                        "SKIP", "Spoofing")
    finally:
        tx_log = os.path.join(args.outdir, f"{args.label}_tx.log")
        rx_log = os.path.join(args.outdir, f"{args.label}_rx.log")
        tx.save(tx_log)
        rx.save(rx_log)
        for b in boards.values():
            try:
                b.dev.close()
            except Exception:
                pass
        print(f"\nlogs: {tx_log} , {rx_log}")

    meta = {
        "label": args.label,
        "talker": f"node {args.talker} ({tx_mac})",
        "receiver": f"node {args.receiver} ({rx_mac})",
        "frames per attack": args.count,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    md = res.markdown(meta)
    out = os.path.join(args.outdir, f"{args.label}_security.md")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(md)
    print("\n" + md)
    print(f"table written to {out}")

    if res.failures:
        print(f"\n{res.failures} case(s) FAILED - treat this as a finding, "
              "not a measurement.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
