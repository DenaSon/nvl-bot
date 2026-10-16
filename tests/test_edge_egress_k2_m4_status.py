"""M4 status is a read-only original-6G projection, never packet proof."""
from __future__ import annotations

import unittest
from pathlib import Path

from edge_egress_k2_m4_status import (
    M4StatusHold, inspect_telegram_wave_status, status_html,
    root_checkpoint_status_html,
)
from edge_egress_k2_migration_inventory import select_migration
from tests.test_edge_egress_k2_migration_inventory import (
    K2M1InventoryTests,TARGET,
)


class M4WaveStatusTests(unittest.TestCase):
    def setUp(self):
        self.fx=K2M1InventoryTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.selection=select_migration("SINGLE",("nvl0555",),"e9")

    def test_missing_runtime_is_never_reported_verified(self):
        state=inspect_telegram_wave_status(self.fx.db,self.selection)
        self.assertFalse(state.verified_runtime)
        self.assertEqual(state.accounts[0].state,"NOT_STARTED")
        self.assertIn("هنوز شروع نشده",status_html(state))
        self.assertNotIn("اتصال تأیید شد",status_html(state))

    def test_original_6g_running_refuses_false_idle_status(self):
        self.fx.c.execute("INSERT INTO failover_operations VALUES(99,'RUNNING')")
        state=inspect_telegram_wave_status(self.fx.db,self.selection)
        self.assertTrue(state.global_busy)
        self.assertIn("عملیات در جریان",status_html(state))

    def test_protected_metadata_only_means_pending_packet_verification(self):
        self.fx.c.execute(
            "INSERT INTO edge_egress_uid_runtime "
            "VALUES('nvl0555',1636,'e9',?,'PROTECTED')",(TARGET,))
        self.fx.c.execute(
            "INSERT INTO edge_egress_uid_bindings "
            "VALUES('nvl0555',1636,'e9',?,'PROTECTED')",(TARGET,))
        state=inspect_telegram_wave_status(self.fx.db,self.selection)
        self.assertEqual(state.accounts[0].state,"REGISTERED")
        self.assertFalse(state.verified_runtime)
        self.assertIn("اتصال باید تأیید شود",status_html(state))

    def test_inconsistent_mapping_is_hold(self):
        self.fx.c.execute(
            "INSERT INTO edge_egress_uid_runtime "
            "VALUES('nvl0555',1636,'e9',?,'PROTECTED')",(TARGET,))
        state=inspect_telegram_wave_status(self.fx.db,self.selection)
        self.assertEqual(state.accounts[0].state,"HOLD")

    def test_root_checkpoint_status_is_receipt_not_packet_proof(self):
        response={
            "state":"STATUS","edge_id":"e9","wave_state":"RECEIPTS_RECORDED",
            "busy":False,"unresolved":False,
            "users":[{"username":"nvl0555","state":"RECEIPT_SCOPED"}],
            "note":"REQUIRES_INDEPENDENT_PACKET_PROOF",
        }
        display=root_checkpoint_status_html(response,self.selection)
        self.assertIn("رسید اصلی ثبت و تطبیق شد",display)
        self.assertIn("اتصال واقعی باید جداگانه تأیید شود",display)
        response["wave_state"]="UNKNOWN_INFLIGHT"
        response["unresolved"]=True
        response["users"][0]["state"]="UNKNOWN"
        display=root_checkpoint_status_html(response,self.selection)
        self.assertIn("دوباره منتقل نکنید",display)
        response["users"][0]["username"]="nvl0557"
        with self.assertRaises(M4StatusHold):
            root_checkpoint_status_html(response,self.selection)

    def test_bot_uses_root_status_when_released_no_silent_fallback(self):
        source=(Path(__file__).resolve().parents[1]/
                "bot_final_v49-2.py").read_text(encoding="utf-8")
        a=source.index('    elif d.startswith("hpeg_m4_"):')
        b=source.index('    elif d.startswith("hpeg_transfer_"):',a)
        handler=source[a:b]
        self.assertIn("k2_root_direct_flags.K2_ROOT_DIRECT_ENABLED",handler)
        self.assertIn("k2_root_direct_client(context.application).request(",handler)
        self.assertIn('"STATUS",actor_id=actor_id,chat_id=chat_id',handler)
        self.assertIn("k2_m44_root_status_html(root_result,selection)",handler)
        self.assertLess(handler.index("if role != 'admin':"),
                        handler.index('"STATUS",actor_id=actor_id'))
        self.assertNotIn("run_migration_wave(",handler)

    def test_bot_status_callback_role_gate_and_read_only(self):
        source=(Path(__file__).resolve().parents[1]/
                "bot_final_v49-2.py").read_text(encoding="utf-8")
        a=source.index('    elif d.startswith("hpeg_m4_"):')
        b=source.index('    elif d.startswith("hpeg_transfer_"):',a)
        handler=source[a:b]
        self.assertIn("k2_m4_readonly_status",handler)
        self.assertLess(handler.index("if role != 'admin':"),
                        handler.index("k2_m4_readonly_status"))
        self.assertNotIn("execute_relay_switch(",handler)


if __name__=="__main__":
    unittest.main()
