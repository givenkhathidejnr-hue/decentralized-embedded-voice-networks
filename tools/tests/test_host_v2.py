"""Regression tests for strict host evidence and no-reset serial framing."""
import contextlib
import io
import json
import os
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from board_v2 import Board, records, merged_summary, group_consistent
from provision_pairs import key_file
from parse_telemetry import Run, summarise, _receivers
from run_group_security_v2 import rejection_result


class FakeSerial:
    def __init__(self, **kwargs):
        self.data = bytearray()
        self.cv = threading.Condition()
        self.closed = False
        self.dtr = self.rts = True
        self.opened_without_reset = False
    def open(self):
        self.opened_without_reset = self.dtr is False and self.rts is False
        assert self.opened_without_reset
    @property
    def in_waiting(self):
        return min(3, len(self.data))  # fragments even the return-code digits
    def read(self, n):
        with self.cv:
            if not self.data:
                self.cv.wait(0.01)
            data = bytes(self.data[:n])
            del self.data[:n]
            return data
    def write(self, data):
        _, token, command = data.decode().strip().split(" ", 2)
        if command == "timeout":
            return len(data)
        body = data.decode()  # real terminals echo credentials too
        if command == "mac":
            body += "node 1  mac 02:00:00:00:00:01\n#DEVICE,node=1,protocol=2,frame_ms=40,codec=codec2_3200,sha=abc,crypto=gcm,tag=16\n"
        if command == "reboot":
            body += "#BOOT,node=1,protocol=2,boot=222,reset_reason=3\n"
        rc = 12 if command == "fail" else 0
        body += f"\n#HOST,token={token},rc={rc}\nvox>"
        with self.cv:
            self.data.extend(body.encode())
            self.cv.notify_all()
        return len(data)
    def close(self):
        self.closed = True


class HostTests(unittest.TestCase):
    def board(self, logdir=None):
        with patch.dict(sys.modules, {"serial": types.SimpleNamespace(Serial=FakeSerial)}):
            return Board("fake-port", logdir=logdir)
    def test_serial_never_resets_and_handles_fragmented_replies(self):
        b = self.board()
        try:
            self.assertTrue(b.serial.opened_without_reset)
            self.assertEqual(b.node, 1)
            self.assertIn("rc=0", b.command("sync"))
        finally:
            b.close()
    def test_nonzero_rc_is_failure(self):
        b = self.board()
        try:
            with self.assertRaisesRegex(RuntimeError, "rc=12"):
                b.command("fail")
        finally:
            b.close()
    def test_timeout_is_failure(self):
        b = self.board()
        try:
            with self.assertRaises(TimeoutError):
                b.command("timeout", timeout=0.03)
        finally:
            b.close()
    def test_reboot_invalidates_connection(self):
        b = self.board()
        try:
            with self.assertRaisesRegex(RuntimeError, "reboot detected"):
                b.command("reboot")
        finally:
            b.close()
    def test_credential_echo_not_logged(self):
        with tempfile.TemporaryDirectory() as tmp:
            b = self.board(Path(tmp))
            key = "ab" * 32
            try:
                out = b.command(f"psk set 2 {key}", secret=True)
                self.assertNotIn(key, out)
                self.assertNotIn(key, b.transcript())
                b.command("sync")
            finally:
                b.close()
            self.assertNotIn(key, (Path(tmp) / "node1.log").read_text())
    def test_credentials_independent_persistent_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "keys.json"
            data = key_file(path, [1, 2, 3, 4, 5, 6])
            self.assertEqual(len(data["pairs"]), 15)
            self.assertEqual(len(set(data["pairs"].values())), 15)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(data, key_file(path, [1, 2, 3, 4, 5, 6]))
            with self.assertRaises(ValueError):
                key_file(path, [1, 2, 3])
    def test_wide_permissions_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "keys.json"
            key_file(path, [1, 2])
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                key_file(path, [1, 2])
    def test_each_receiver_requires_all_rejections(self):
        s = dict(rx_frames="0", auth_fail="20", replay_drop="0", epoch_unknown="0", malformed="0")
        self.assertEqual(rejection_result(s, "auth_fail", 20), "PASS")
        self.assertEqual(rejection_result({**s, "auth_fail": "19"}, "auth_fail", 20), "INCONCLUSIVE")
        self.assertEqual(rejection_result({**s, "rx_frames": "1"}, "auth_fail", 20), "FAIL")
        self.assertEqual(rejection_result({}, "auth_fail", 20), "INCONCLUSIVE")
    def test_summary_fields_merge_without_matching_other_markers(self):
        s = "#SUMMARY,label=r1\n#SUMMARY,rx_frames=5,loss_complete=0\n#GROUP_REPLAY,member=1\n"
        self.assertEqual(merged_summary(s), dict(label="r1", rx_frames="5", loss_complete="0"))
        self.assertEqual(records(s, "GROUP"), [])
    def test_missing_end_never_becomes_zero_loss(self):
        r = Run("r1_rep1_n1")
        r.fw.update(measurement_schema="2", delivery_n="100", loss_pct="0", peers="5", group_listeners="1")
        r.config["experiment.architecture"] = "group"
        self.assertEqual(_receivers(r), 1)
        self.assertEqual(summarise(r)["loss_pct"], "n/a")
        r.fw["loss_complete"] = "0"
        self.assertEqual(summarise(r)["loss_pct"], "n/a")
        r.fw["loss_complete"] = "1"
        self.assertEqual(float(summarise(r)["loss_pct"]), 0.0)
    def test_all_rosters_and_generations_required(self):
        state = dict(active="1", ready="1", busy="0", group_id="abc", generation="5", coordinator="1", members="1;2;3", allowed="1;2;3")
        boards = {i: types.SimpleNamespace(group=lambda s=dict(state): s) for i in [1, 2, 3]}
        self.assertTrue(group_consistent(boards, [1, 2, 3], 1))
        boards[3].group = lambda: {**state, "generation": "4"}
        self.assertFalse(group_consistent(boards, [1, 2, 3], 1))
        boards[3].group = lambda: {**state, "members": "1;3"}
        self.assertFalse(group_consistent(boards, [1, 2, 3], 1))


if __name__ == "__main__":
    unittest.main()
