"""AWG install diagnostics regression tests; no SSH, network or production DB."""
from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from manual_edge_journal import ManualEdgeJournal
from manual_edge_wizard import ManualEdgeWizard
from nvl_awg_install_diagnostics import classify, describe, receipt
from nvl_awg_provision import (
    AWGProvisionHold, _preflight_registry, _remote,
)


class FakeChannel:
    def __init__(self, stdout=b"", stderr=b"", status=1):
        self.stdout = [stdout] if stdout else []
        self.stderr = [stderr] if stderr else []
        self.status = status

    def exit_status_ready(self):
        return True

    def recv_ready(self):
        return bool(self.stdout)

    def recv_stderr_ready(self):
        return bool(self.stderr)

    def recv(self, _size):
        return self.stdout.pop(0)

    def recv_stderr(self, _size):
        return self.stderr.pop(0)

    def recv_exit_status(self):
        return self.status


class FakeSSH:
    def __init__(self, channel):
        self.channel = channel

    def exec_command(self, *_args, **_kwargs):
        return None, SimpleNamespace(channel=self.channel), None


class DiagnosticTests(unittest.TestCase):
    def test_only_symbolic_safe_data_reaches_operator(self):
        code = receipt("CORE_PEER", "CORE_AWG_CONFIG_CHANGED")
        message = describe(code, "deadbeef1234")
        self.assertIn("ثبت Peer جدید در Core", message)
        self.assertIn("CORE_AWG_CONFIG_CHANGED", message)
        self.assertIn("deadbeef1234", message)
        self.assertNotIn("PrivateKey", message)
        self.assertNotIn("ssh-password", message)
        self.assertEqual(
            receipt("CORE_PEER", "token private=secret\nx"),
            "AWG:CORE_PEER:UNEXPECTED_FAILURE",
        )
        self.assertEqual(describe("AWG:CORE_PEER:foo<script>", "id"), "")

    def test_classify_never_surfaces_raw_exception(self):
        self.assertEqual(
            classify(ValueError("password=SHOULD_NEVER_BE_VISIBLE")),
            "UNEXPECTED_FAILURE",
        )
        self.assertEqual(classify(AWGProvisionHold("AWG_NAT_PERSISTENCE_UNVERIFIED")),
                         "AWG_NAT_PERSISTENCE_UNVERIFIED")

    def test_remote_installer_hold_is_symbolic_and_not_raw_stderr(self):
        raw = b"private=SECRET\nAWG_NEW_EDGE_HOLD: EXISTING_AWG_CONFIG\n"
        with self.assertRaisesRegex(AWGProvisionHold, "EDGE_INSTALL_EXISTING_AWG_CONFIG") as caught:
            _remote(FakeSSH(FakeChannel(stderr=raw)), "safe")
        self.assertNotIn("SECRET", str(caught.exception))

    def test_remote_apt_failure_reports_last_safe_checkpoint(self):
        stdout = b"AWG_EDGE_PROGRESS=START\nAWG_EDGE_PROGRESS=BASE_PACKAGES\n"
        with self.assertRaisesRegex(AWGProvisionHold, "EDGE_INSTALL_AFTER_BASE_PACKAGES"):
            _remote(FakeSSH(FakeChannel(stdout=stdout, stderr=b"token SECRET")), "safe")

    def test_remote_noninstaller_failure_never_leaks_secret(self):
        with self.assertRaisesRegex(AWGProvisionHold, "EDGE_REMOTE_COMMAND_FAILED") as caught:
            _remote(FakeSSH(FakeChannel(stderr=b"root password=very-secret")), "safe")
        self.assertNotIn("very-secret", str(caught.exception))

    def test_remote_timeout_returns_fixed_code(self):
        with self.assertRaisesRegex(AWGProvisionHold, "EDGE_INSTALL_TIMEOUT"):
            _remote(FakeSSH(FakeChannel(status=124)), "safe")

    def test_preflight_rejects_existing_host_before_remote_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "check.db"
            factory = lambda: sqlite3.connect(path)
            with factory() as db:
                db.execute("CREATE TABLE settings(key TEXT,value TEXT)")
                db.execute("CREATE TABLE host_pool(host TEXT)")
                db.execute(
                    "CREATE TABLE manual_edge_operations("
                    "ip TEXT,status TEXT,tunnel_backend TEXT)"
                )
                db.execute(
                    "INSERT INTO manual_edge_operations VALUES "
                    "('203.0.113.99','INSTALLING','amneziawg')"
                )
                db.execute("INSERT INTO host_pool VALUES('203.0.113.99')")
            with self.assertRaisesRegex(AWGProvisionHold, "EDGE_POOL_ALREADY_REGISTERED"):
                _preflight_registry(factory, "203.0.113.99")
            with factory() as db:
                db.execute("DELETE FROM host_pool")
            _preflight_registry(factory, "203.0.113.99")


class WizardFailureDisplayTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = Path(self.temp.name) / "journal.db"
        self.db = lambda: sqlite3.connect(path)
        self.op = {
            "id": "abcdef123456", "ip": "203.0.113.99",
            "actor": 77, "chat": 77, "status": "INSTALLING",
            "admin_port": 22, "pin_type": "ssh-ed25519",
            "pin_base64": "trusted-host-key",
            "tunnel_backend": "amneziawg", "route_job": None,
            "archived_at": None, "reason": None,
        }
        self.provider = AsyncMock(return_value=(
            False, "AWG_NEW_EDGE_REQUIRES_MANUAL_REVIEW", {
                "failure_stage": "CORE_PEER",
                "failure_code": "CORE_AWG_CONFIG_CHANGED",
            },
        ))
        self.wizard = ManualEdgeWizard(
            db=self.db, preflight=lambda: (2252, "legacy"),
            awg_preflight=lambda: (2252, "awg"),
            provision=AsyncMock(),
            awg_provision=self.provider,
            awg_check=lambda *_: False,
            verify=AsyncMock(return_value=True),
            probe=lambda *_: False, nat=lambda *_: False,
            queue=None,
            key_reader=lambda *_: ("ssh-ed25519","trusted-host-key","SHA256:xyz"),
            is_core_host=lambda *_: False,
            os_check=lambda *_: True,
        )
        self.wizard.journal.get = MagicMock(return_value=self.op)
        self.wizard.journal.begin_install = MagicMock()
        self.wizard.journal.install_hold = MagicMock()
        self.wizard._tls_port = lambda: 2088

    async def test_immediate_telegram_message_shows_stage_code_and_case(self):
        delivery = MagicMock()
        delivery.send = AsyncMock(return_value=42)
        with patch.dict(os.environ, {"NVL_AWG_NEW_EDGE_ENABLED": "1"}), \
             patch("manual_edge_wizard.ManualHtmlDelivery", return_value=delivery):
            await self.wizard._install_task(
                SimpleNamespace(bot=object()), "abcdef123456", 77, 77, "SECRET_PASSWORD"
            )
        text = delivery.send.call_args.kwargs["text"]
        self.assertIn("ثبت Peer جدید در Core", text)
        self.assertIn("CORE_AWG_CONFIG_CHANGED", text)
        self.assertIn("abcdef123456", text)
        self.assertNotIn("SECRET_PASSWORD", text)
        self.wizard.journal.install_hold.assert_called_once_with(
            "abcdef123456", 77, 77,
            "AWG:CORE_PEER:CORE_AWG_CONFIG_CHANGED",
        )

    async def test_opening_failed_case_shows_same_persisted_receipt(self):
        self.op["status"] = "INSTALL_HOLD"
        self.op["reason"] = "AWG:CORE_PEER:CORE_AWG_CONFIG_CHANGED"
        self.wizard.journal.display_state = MagicMock(return_value="JOURNAL")
        self.wizard._view = AsyncMock(return_value="OK")
        with patch.dict(os.environ, {"NVL_AWG_NEW_EDGE_ENABLED": "1"}):
            await self.wizard._detail(None, 77, 77, "abcdef123456")
        text = self.wizard._view.call_args.args[1]
        self.assertIn("ثبت Peer جدید در Core", text)
        self.assertIn("CORE_AWG_CONFIG_CHANGED", text)


class CancellationRetentionTests(unittest.TestCase):
    def test_force_cancel_keeps_existing_awg_failure_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ops.db"
            factory = lambda: sqlite3.connect(path)
            journal = ManualEdgeJournal(factory)
            op = journal.start(77, 77, tunnel_backend="amneziawg")
            with factory() as db:
                db.execute(
                    "UPDATE manual_edge_operations "
                    "SET status='INSTALL_HOLD',ip='203.0.113.99', "
                    "reason='AWG:CORE_PEER:CORE_AWG_CONFIG_CHANGED' "
                    "WHERE id=?", (op,),
                )
            journal.force_cancel(op, 77, 77)
            with factory() as db:
                row = db.execute(
                    "SELECT status,reason FROM manual_edge_operations "
                    "WHERE id=?", (op,),
                ).fetchone()
            self.assertEqual(row, (
                "CANCELLED", "AWG:CORE_PEER:CORE_AWG_CONFIG_CHANGED"
            ))


if __name__ == "__main__":
    unittest.main()
