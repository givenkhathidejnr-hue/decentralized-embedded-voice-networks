"""Persistent, framed protocol-2 console connections. Never pulses reset lines."""
from __future__ import annotations
import contextlib
import glob
import re
import secrets
import threading
import time
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def records(text: str, kind: str) -> list[dict[str, str]]:
    text = ANSI.sub("", text)
    return [dict(field.split("=", 1) for field in line.split(",") if "=" in field)
            for line in re.findall(r"#" + re.escape(kind) + r",([^\r\n]+)", text)]


def merged_summary(text: str) -> dict[str, str]:
    result = {}
    for row in records(text, "SUMMARY"):
        result.update(row)
    return result


class Board:
    def __init__(self, port: str, baud=115200, logdir: Path | None = None):
        import serial
        self.port = port
        self.device = {}
        self.mac = ""
        self._cv = threading.Condition()
        self._command_lock = threading.Lock()
        self._text = ""
        self._secret = False
        self._error = None
        self._closed = False
        self._boot_baseline = None
        self._log = None
        self.serial = serial.Serial(port=None, baudrate=baud, timeout=0.1, write_timeout=2)
        # Set desired line states BEFORE open. USB drivers can still glitch;
        # the boot detector makes any subsequent restart invalidate the run.
        self.serial.dtr = False
        self.serial.rts = False
        self.serial.port = port
        self.serial.open()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        try:
            # Despite the line states set above, opening this port has been
            # observed to still pulse the target's EN line via its
            # USB-serial adapter's auto-reset circuit (hardware-specific,
            # not something either dtr/rts state reliably prevents on this
            # rig). A command sent immediately lands before the console
            # driver exists and is silently lost, not merely delayed -- the
            # UART driver is not yet listening, so there is nothing to
            # retry into. Wait out a full boot cycle first, then probe with
            # retries, rather than trusting the single 12 s wait to outlast
            # an unknown amount of pre-command silence.
            # The console appears about four seconds after a reset on this
            # testbed. Do not send the first probe into boot/terminal setup.
            time.sleep(6.0)
            deadline = time.monotonic() + 15
            reply = None
            last_exc = None
            while time.monotonic() < deadline:
                try:
                    reply = self.command("mac", timeout=5)
                    last_exc = None
                    break
                except TimeoutError as exc:
                    last_exc = exc
                    time.sleep(1.0)
            if reply is None:
                raise last_exc or TimeoutError(f"{port}: no response after boot settle")
            dev = records(reply, "DEVICE")
            match = re.search(r"node (\d+)\s+mac ([0-9a-fA-F:]{17})", reply)
            if len(dev) != 1 or dev[0].get("protocol") != "2" or not match:
                raise RuntimeError(f"{port}: protocol-2 identity missing; reflash all boards")
            self.device = dev[0]
            self.node = int(self.device["node"])
            if self.node != int(match[1]):
                raise RuntimeError(f"{port}: conflicting node identities")
            self.mac = match[2].lower()
            with self._cv:
                self._boot_baseline = len(records(self._text, "BOOT"))
                if logdir:
                    logdir.mkdir(parents=True, exist_ok=True)
                    self._log = (logdir / f"node{self.node}.log").open("x", buffering=1)
                    self._log.write(self._text)
        except BaseException:
            self.close()
            raise

    def _read(self):
        try:
            while not self._closed:
                chunk = self.serial.read(self.serial.in_waiting or 1).decode(errors="replace")
                if not chunk:
                    continue
                with self._cv:
                    self._text += chunk
                    if self._log and not self._secret:
                        self._log.write(chunk)
                    self._cv.notify_all()
        except Exception as exc:
            if not self._closed:
                with self._cv:
                    self._error = exc
                    self._cv.notify_all()

    def check(self):
        if self._error:
            raise RuntimeError(f"{self.port}: serial reader failed") from self._error
        if self._boot_baseline is not None and len(records(self._text, "BOOT")) != self._boot_baseline:
            raise RuntimeError(f"node {self.node}: reboot detected; discard this trial")

    def command(self, line: str, timeout=10, secret=False) -> str:
        if "\n" in line or "\r" in line:
            raise ValueError("one command per call")
        token = secrets.token_hex(4)
        wire = f"host {token} {line}\r\n".encode()
        if len(wire) > 126:
            raise ValueError("console command too long")
        with self._command_lock, self._cv:
            self.check()
            start = len(self._text)
            self._secret = secret
            self.serial.write(wire)
            deadline = time.monotonic() + timeout
            while True:
                self.check()
                reply = self._text[start:]
                done = [r for r in records(reply, "HOST") if r.get("token") == token and "rc" in r]
                # Require the newline, so a partial numeric return code is not accepted.
                if done and re.search(rf"#HOST,token={token},rc=-?\d+\r?\n", reply):
                    rc = int(done[-1]["rc"])
                    if secret:
                        self._text = self._text[:start] + "[credential command and echo redacted]\n"
                        reply = "[credential command redacted]"
                    self._secret = False
                    if rc:
                        raise RuntimeError(f"{self.port}: {'credential command' if secret else line!r} failed (rc={rc})" + ("" if secret else f"\n{reply}"))
                    return reply
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"{self.port}: missing completion for {'credential command' if secret else line!r}")
                self._cv.wait(min(remaining, 0.2))

    def group(self):
        rows = records(self.command("group status"), "GROUP")
        if len(rows) != 1:
            raise RuntimeError(f"node {self.node}: missing group status")
        return rows[0]

    def sessions(self):
        return {int(r["peer"]): r for r in records(self.command("peer list"), "SESSION")}

    def transcript(self):
        with self._cv:
            self.check()
            return self._text

    def close(self):
        self._closed = True
        if hasattr(self, "_reader"):
            self._reader.join(timeout=1)
        self.serial.close()
        if self._log:
            self._log.close()


@contextlib.contextmanager
def connect_boards(ids: list[int], ports=None, baud=115200, logdir=None):
    if len(ids) != len(set(ids)) or not ids or any(i <= 0 or i >= 65535 for i in ids):
        raise ValueError("supply distinct node IDs in 1..65534")
    ports = ports or sorted(glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*"))
    boards = {}
    opened = []
    try:
        for port in ports:
            board = Board(port, baud, Path(logdir) if logdir else None)
            opened.append(board)
            if board.node in boards:
                raise RuntimeError(f"duplicate node ID {board.node}; check flashed configs")
            boards[board.node] = board
            print(f"{port}: node {board.node}, protocol 2, {board.mac}")
        missing = set(ids) - boards.keys()
        if missing:
            raise RuntimeError(f"missing required boards {sorted(missing)}; no trial started")
        selected = {i: boards[i] for i in ids}
        formats = {(b.device["codec"], b.device["frame_ms"], b.device.get("crypto"), b.device.get("tag")) for b in selected.values()}
        if len(formats) != 1:
            raise RuntimeError("boards have different codec/frame/security configurations")
        yield selected
    finally:
        for b in opened:
            b.close()


def wait_until(predicate, seconds=18, description="state transition"):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    raise TimeoutError(f"timed out waiting for {description}")


def ensure_mesh(boards):
    ids = sorted(boards)
    for index, a in enumerate(ids):
        for b in ids[index + 1:]:
            boards[a].command(f"peer add {boards[b].mac} {b}")
            boards[a].command(f"connect {b}")
            def up():
                ab, ba = boards[a].sessions().get(b, {}), boards[b].sessions().get(a, {})
                return all(p.get("state") == "up" and p.get("isolated") == "1" and p.get("phantom") == "0" for p in (ab, ba))
            wait_until(up, 7, f"isolated session {a}<->{b}")


def group_consistent(boards, active, coordinator):
    states = [boards[i].group() for i in active]
    if any(s.get("active") != "1" or s.get("ready") != "1" or s.get("busy") != "0" for s in states):
        return False
    expected = set(active)
    if any({int(i) for i in s.get("members", "").split(";") if i} != expected for s in states):
        return False
    return len({(s["group_id"], s["generation"], s["allowed"], s["coordinator"]) for s in states}) == 1 and states[0]["coordinator"] == str(coordinator)
