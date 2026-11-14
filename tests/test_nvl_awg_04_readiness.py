"""AWG-04 offline regression: witness, live gate, and backend reuse."""
import os
from contextlib import nullcontext
from pathlib import Path
import sqlite3
import stat
import subprocess
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from manual_edge_journal import ManualEdgeHold, ManualEdgeJournal
from manual_edge_wizard import ManualEdgeWizard
from nvl_awg_limiter_witness import (
    LimiterWitnessHold, _approved_source, _registered_binding,
    _write_marker, attest,
)
from nvl_awg_target import core_limiter_canary_ready
from nvl_tunnel_backend import SCHEMA

EDGE = "8.8.4.4"
KEY = "B" * 43 + "="
SOURCE = "10.203.77.2"


class LimiterWitnessTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def test_pinned_installed_source_must_match_promoter_template(self):
        expected = "def is_shared_edge_ip(ip):\n    return True\n"
        source = self.root / "ip_limiter.py"
        promoter = self.root / "promote_edge_to_core.sh"
        source.write_text(expected)
        promoter.write_text(
            "cat << 'EOF' > /root/ip_limiter.py\n" + expected + "EOF\n"
        )
        with patch("nvl_awg_limiter_witness._trusted_file",
                   side_effect=lambda p: (p.read_bytes(), p.stat())):
            self.assertEqual(_approved_source(source, promoter).st_size,
                             source.stat().st_size)
            source.write_text("def is_shared_edge_ip(ip): return False\n")
            with self.assertRaisesRegex(
                    LimiterWitnessHold, "RUNNING_LIMITER_SOURCE_MISMATCH"):
                _approved_source(source, promoter)

    def test_registered_binding_requires_managed_standby(self):
        dbfile = self.root / "nvl.db"
        with sqlite3.connect(dbfile) as db:
            db.executescript(SCHEMA)
            db.execute(
                "CREATE TABLE manual_edge_operations(ip TEXT, status TEXT, "
                "tunnel_backend TEXT)"
            )
            db.execute(
                "CREATE TABLE host_pool(host TEXT, active INTEGER, "
                "is_default INTEGER, is_standby INTEGER)"
            )
            db.execute(
                "INSERT INTO edge_tunnel_bindings VALUES (?,?,?,?,?,?,?,?)",
                (EDGE, "amneziawg", "awg0", "10.203.77.1",
                 SOURCE, KEY, "VERIFIED", int(time.time())),
            )
            db.execute(
                "INSERT INTO manual_edge_operations VALUES (?,?,?)",
                (EDGE, "STANDBY", "amneziawg"),
            )
            db.execute(
                "INSERT INTO host_pool VALUES (?,?,?,?)",
                (EDGE, 1, 0, 1),
            )
        self.assertEqual(_registered_binding(EDGE, dbfile).edge_tunnel_ip,
                         SOURCE)
        with sqlite3.connect(dbfile) as db:
            db.execute("UPDATE edge_tunnel_bindings SET state='HOLD'")
        with self.assertRaises(Exception):
            _registered_binding(EDGE, dbfile)

    def test_witness_success_creates_only_private_exact_source_marker(self):
        marker = self.root / "witness"
        binding = SimpleNamespace(edge_tunnel_ip=SOURCE)
        with (patch("nvl_awg_limiter_witness.os.geteuid", return_value=0),
              patch("nvl_awg_limiter_witness._witness_guard",
                    return_value=nullcontext()),
              patch("nvl_awg_limiter_witness._registered_binding",
                    return_value=binding),
              patch("nvl_awg_limiter_witness.probe_binding",
                    return_value={"wg_peer_ok": True, "core_path_ok": True}),
              patch("nvl_awg_limiter_witness._approved_source",
                    return_value=SimpleNamespace(st_mtime=0)),
              patch("nvl_awg_limiter_witness._live_service_matches_script"),
              patch("nvl_awg_limiter_witness._functional_test",
                    return_value=True),
              patch("nvl_awg_limiter_witness._unblocked",
                    return_value=True)):
            self.assertEqual(attest(EDGE, marker=marker), SOURCE)
        self.assertEqual(marker.read_text(),
                         "NVL_AWG_LIMITER_READY " + SOURCE + "\n")
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)

    def test_failed_check_revokes_previous_marker(self):
        marker = self.root / "witness"
        marker.write_text("NVL_AWG_LIMITER_READY " + SOURCE + "\n")
        with (patch("nvl_awg_limiter_witness.os.geteuid", return_value=0),
              patch("nvl_awg_limiter_witness._witness_guard",
                    return_value=nullcontext()),
              patch("nvl_awg_limiter_witness._registered_binding",
                    side_effect=LimiterWitnessHold("NO_BINDING"))):
            with self.assertRaises(LimiterWitnessHold):
                attest(EDGE, marker=marker)
        self.assertFalse(marker.exists())


class CutoverGateTests(unittest.TestCase):
    def test_wizard_cannot_advertise_awg_cutover_when_gate_off(self):
        wizard = object.__new__(ManualEdgeWizard)
        wizard._awg_cutover_ready = lambda host: False
        self.assertTrue(wizard._cutover_visible(
            {"tunnel_backend": "wireguard", "ip": EDGE}))
        self.assertFalse(wizard._cutover_visible(
            {"tunnel_backend": "amneziawg", "ip": EDGE}))

    def test_marker_requires_current_running_limiter_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "marker"
            marker.write_text("NVL_AWG_LIMITER_READY " + SOURCE + "\n")
            real_stat = Path.stat

            def owned_stat(path, *args, **kwargs):
                result = real_stat(path, *args, **kwargs)
                if path == marker:
                    return SimpleNamespace(
                        st_uid=0, st_mode=stat.S_IFREG | 0o600,
                        st_size=result.st_size, st_mtime=time.time())
                return result

            with patch.object(Path, "stat", owned_stat):
                dead = lambda *a, **kw: subprocess.CompletedProcess(
                    a[0], 1, "", "")
                live = lambda *a, **kw: subprocess.CompletedProcess(
                    a[0], 0, "", "")
                self.assertFalse(core_limiter_canary_ready(
                    SOURCE, marker_path=str(marker), runner=dead))
                self.assertTrue(core_limiter_canary_ready(
                    SOURCE, marker_path=str(marker), runner=live))
                self.assertFalse(core_limiter_canary_ready(
                    "10.203.77.8", marker_path=str(marker), runner=live))

    def test_former_awg_without_binding_never_falls_back_to_wg(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.execute(
            "CREATE TABLE manual_edge_operations(id TEXT,actor INTEGER,"
            "chat INTEGER,ip TEXT,status TEXT,admin_port INTEGER,"
            "pin_type TEXT,pin_base64 TEXT,archived_at INTEGER,"
            "tunnel_backend TEXT)"
        )
        db.execute(
            "INSERT INTO manual_edge_operations VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("id", 42, 42, EDGE, "ACTIVE", 22,
             "ssh-ed25519", "PINNED", None, "amneziawg"),
        )
        journal = object.__new__(ManualEdgeJournal)
        with self.assertRaisesRegex(
                ManualEdgeHold, "FORMER_BACKEND_UNVERIFIED"):
            journal._former_standby_checks(db, "id", 42, 42, 2252)


if __name__ == "__main__":
    unittest.main()
