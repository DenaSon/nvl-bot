"""Real Core startup/portal/M1/checkpoint assembly on disposable SQLite.

Root filesystem/signature/OS inputs are synthetic; no system service, route,
PAM file, live user, Telegram connection or external host is modified.
"""
import base64
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import edge_egress_k2_core_runtime as runtime
import edge_egress_k2_root_direct as direct
from edge_egress_k2_core_prerequisites import CoreUIDSnapshotSource
from edge_egress_k2_m2_ingress_journal import IngressRecord, encode_records
from edge_egress_k2_m42_evidence import SignedExternalEvidence, WitnessAccount, PRE_ATTACH_CHECKS
from edge_egress_k2_m4_telegram import _operator_runtime_released
from edge_egress_k2_m3_waves import build_wave_plan
from edge_egress_k2_migration_inventory import select_migration
from edge_egress_k2_runtime_release import CoreReleaseProfile
from edge_egress_v1_ingress import IngressPeer
from ops.k2_p3_module_stage import REQUIRED
from tests import test_edge_egress_k2_migration_inventory as fixture

NOW, SOURCE, TARGET = fixture.NOW, fixture.SOURCE, fixture.TARGET


class CoreStartupTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fx = fixture.K2M1InventoryTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.fx.c.executescript("""
            CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
            INSERT INTO settings VALUES('admin_chat_ids','11');
            INSERT INTO settings VALUES('edge_egress_protected_mode','0');
        """)
        self.app = SimpleNamespace(bot_data={})
        self.profile = CoreReleaseProfile(True, "a"*64)
        self.blobs = {n: b"from __future__ import annotations\n" for n in REQUIRED}
        key = base64.b64encode(bytes(range(32))).decode()
        peer = IngressPeer("s8", SOURCE, "10.77.0.8", key)
        journal = encode_records({"nvl0555": IngressRecord(
            "nvl0555", 1636, "s8", SOURCE, "10.77.0.8", key, NOW-1,
        )})
        self.proof = SignedExternalEvidence(
            "b"*64, NOW-1, NOW+25, "e9", TARGET, PRE_ATTACH_CHECKS,
            (WitnessAccount("nvl0555", 1636, "s8", SOURCE, 0),), "PRE_ATTACH",
        )
        overrides = (
            patch.object(runtime, "load_core_profile", return_value=self.profile),
            patch.object(runtime, "verify_reviewed_release", return_value="d"*40),
            patch.object(runtime, "_read_checked", return_value=json.dumps({"files": {
                "edge_egress_v1_admission.py": "a"*64,
            }}).encode()),
            patch.object(runtime, "read_reviewed_module_bundle", return_value=self.blobs),
            patch.object(runtime, "_ensure_secret", return_value=b"fixture-secret-"+b"k"*48),
            patch.object(runtime, "load_external_evidence", side_effect=lambda **kw: self.proof),
            patch("os.geteuid", return_value=0),
            patch("time.time", return_value=NOW),
            patch("pwd.getpwnam", side_effect=lambda n: SimpleNamespace(pw_uid=self.fx.uids[n])),
            patch("edge_egress_k2_m2_ingress_journal.read_root_journal", return_value=journal),
            patch("edge_egress_v1_ingress.load_registry", return_value=(peer,)),
            patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=key+" 10.77.0.8/32\n")),
            patch.object(direct, "_ACTIVE_APPLICATION", None),
            patch.object(direct, "_ACTIVE_CLIENT", None),
        )
        for setting in overrides:
            setting.start()
            self.addCleanup(setting.stop)
        # Test runner cleanup owns every release switch, including a failed
        # or successful explicit startup, so no later test inherits release.
        for module, name in runtime._single_switches():
            setting = patch.object(module, name, False)
            setting.start()
            self.addCleanup(setting.stop)

    def start(self):
        return runtime.start_core_single_runtime(
            self.app, db_conn=self.fx.db,
            source_root=Path(__file__).resolve().parents[1],
        )

    async def test_startup_binds_real_original_portal_with_no_secret_in_persistence(self):
        result = self.start()
        self.assertEqual((result.state, result.release_sha), ("SINGLE_REGISTERED", "d"*40))
        self.assertEqual(self.app.bot_data, {})
        client = direct.bound_root_client(self.app)
        root = client.portal.execute_single.__self__
        self.assertIsInstance(root.ports.port_factory.read_root_snapshot, CoreUIDSnapshotSource)
        self.assertIs(root.ports.acquire_6g.__self__, root.ports.journal_6g.__self__)
        self.assertIs(root.ports.db_conn, self.fx.db)
        selected = select_migration("SINGLE", ("nvl0555",), "e9")
        reviewed = root.review(selected)
        self.assertTrue(reviewed.inventory_clear)
        self.assertTrue(_operator_runtime_released(build_wave_plan(reviewed)))
        prepared = await client.request("PREPARE", actor_id=11, chat_id=11,
                                        selection=selected)
        self.assertEqual(prepared["state"], "PREPARED")
        cancelled = await client.request("CANCEL", actor_id=11, chat_id=11,
                                         request_id=prepared["request_id"])
        self.assertEqual(cancelled["state"], "CANCELLED")
        self.assertEqual(self.fx.c.execute("SELECT COUNT(*) FROM failover_operations").fetchone(), (0,))
        self.assertEqual(self.fx.c.execute("SELECT value FROM settings WHERE key='edge_egress_protected_mode'").fetchone(), ("0",))
        self.assertFalse(direct.K2_ROOT_DIRECT_BATCH_ENABLED)

    def test_missing_or_disabled_profile_does_not_register_or_touch_the_host(self):
        with patch.object(runtime, "load_core_profile", return_value=CoreReleaseProfile(False, "")), patch.object(
            runtime, "verify_reviewed_release",
        ) as verify:
            self.assertEqual(self.start().state, "OFF")
            verify.assert_not_called()
        self.assertIsNone(direct._ACTIVE_CLIENT)

    def test_release_source_hash_failure_prevents_every_execution_flag(self):
        with patch.object(runtime, "verify_reviewed_release", side_effect=ValueError("HASH")):
            with self.assertRaisesRegex(ValueError, "HASH"):
                self.start()
        self.assertTrue(all(getattr(m, n) is False for m, n in runtime._single_switches()))
        self.assertIsNone(direct._ACTIVE_CLIENT)

    def test_profile_pam_digest_must_match_the_reviewed_source(self):
        with patch.object(runtime, "load_core_profile", return_value=CoreReleaseProfile(True, "f"*64)):
            with self.assertRaisesRegex(runtime.CoreRuntimeHold, "DIGEST_DRIFT"):
                self.start()
        self.assertIsNone(direct._ACTIVE_CLIENT)

    def test_failure_during_registration_rolls_back_all_in_process_release_switches(self):
        with patch.object(runtime, "register_root_portal", side_effect=ValueError("BIND")):
            with self.assertRaisesRegex(ValueError, "BIND"):
                self.start()
        self.assertTrue(all(getattr(m, n) is False for m, n in runtime._single_switches()))
        self.assertIsNone(direct._ACTIVE_CLIENT)

    async def test_current_admin_revoke_and_replayed_confirmation_are_still_denied(self):
        self.start()
        client = direct.bound_root_client(self.app)
        selected = select_migration("SINGLE", ("nvl0555",), "e9")
        prepared = await client.request("PREPARE", actor_id=11, chat_id=11, selection=selected)
        self.fx.c.execute("UPDATE settings SET value='42' WHERE key='admin_chat_ids'")
        with self.assertRaises(ValueError):
            await client.request("CONFIRM", actor_id=11, chat_id=11,
                                 request_id=prepared["request_id"])
        self.assertFalse(self.fx.c.execute("SELECT * FROM failover_operations").fetchall())

    def test_existing_bot_invokes_optional_startup_and_never_creates_another_poller(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "bot_final_v49-2.py").read_text()
        startup = source[source.index("async def _post_init(app):"):source.index("async def _post_shutdown(app):")]
        self.assertIn("start_core_single_runtime, app, db_conn=db_conn", startup)
        self.assertIn("except Exception as exc:", startup)
        self.assertNotIn("run_polling", startup)
        self.assertNotIn("ApplicationBuilder", startup)


if __name__ == "__main__":
    unittest.main()
