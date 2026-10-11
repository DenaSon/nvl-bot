import pathlib
import sqlite3
import tempfile
import unittest

from egress_manager import (
    EgressIntentError, ensure_schema, register_draft_target, list_targets,
    plan_switch, pending_intent_for_user, get_intent, cancel_plan,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]


class EgressIntentManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.conn = sqlite3.connect(str(pathlib.Path(self.tmp.name) / "nvl.db"))
        self.conn.execute("""
            CREATE TABLE ssh_accounts (
                username TEXT PRIMARY KEY,
                host TEXT,
                service_type TEXT,
                status TEXT
            )""")
        self.conn.executemany(
            "INSERT INTO ssh_accounts VALUES (?,?,?,?)",
            [
                ("nvl0557", "203.0.113.11", "ssh", "🟢 فعال"),
                ("nvlinactive", "203.0.113.11", "ssh", "🔴 غیرفعال"),
                ("nvlv2ray", "203.0.113.11", "v2ray", "🟢 فعال"),
            ]
        )
        self.conn.commit()
        self.register()

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def register(self, tid="edgea", port=22284):
        register_draft_target(
            self.conn, target_id=tid,
            edge_public_ip="216.126.229.12", namespace="nvl-egress-stg1",
            internal_ip="10.78.111.2", local_port=port,
        )
        self.conn.commit()

    def plan(self, **changes):
        kwargs = dict(username="nvl0557", target_id="edgea",
                      actor_telegram_id=12345, role="admin")
        kwargs.update(changes)
        return plan_switch(self.conn, **kwargs)

    def test_schema_additive_and_no_host_mutation(self):
        self.assertEqual(len(list_targets(self.conn)), 1)
        ensure_schema(self.conn)
        operation = self.plan()
        self.assertEqual(operation["status"], "PLANNED")
        self.assertFalse(operation["route_changed"])
        host, = self.conn.execute("SELECT host FROM ssh_accounts WHERE username='nvl0557'").fetchone()
        self.assertEqual(host, "203.0.113.11")
        self.assertEqual(
            {r[0] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")},
            {"ssh_accounts", "ssh_egress_targets", "ssh_egress_intents"},
        )

    def test_admin_only_and_bad_actor(self):
        for values in (
            {"role": "agent"}, {"role": "accountant"},
            {"actor_telegram_id": 0}, {"actor_telegram_id": True},
        ):
            with self.subTest(values=values), self.assertRaises(EgressIntentError):
                self.plan(**values)
        self.assertIsNone(pending_intent_for_user(self.conn, "nvl0557"))

    def test_only_active_ssh_can_plan(self):
        for name in ("nvlinactive", "nvlv2ray", "unknown"):
            with self.subTest(username=name), self.assertRaisesRegex(EgressIntentError, "ACTIVE_SSH_ACCOUNT_REQUIRED"):
                self.plan(username=name)

    def test_stale_target_is_rejected(self):
        with self.assertRaisesRegex(EgressIntentError, "TARGET_NOT_REGISTERED"):
            self.plan(target_id="missing")

    def test_single_pending_plan_and_can_cancel(self):
        op = self.plan()
        self.assertEqual(pending_intent_for_user(self.conn, "nvl0557")["operation_id"], op["operation_id"])
        with self.assertRaisesRegex(EgressIntentError, "PLAN_ALREADY_PENDING"):
            self.plan()
        self.assertTrue(cancel_plan(self.conn, operation_id=op["operation_id"], role="admin", actor_telegram_id=12345))
        self.assertEqual(get_intent(self.conn, op["operation_id"])["status"], "CANCELLED")
        self.assertIsNone(pending_intent_for_user(self.conn, "nvl0557"))
        self.assertNotEqual(self.plan()["operation_id"], op["operation_id"])

    def test_forbidden_cancel_and_invalid_operation(self):
        op = self.plan()
        with self.assertRaisesRegex(EgressIntentError, "ADMIN_ONLY"):
            cancel_plan(self.conn, operation_id=op["operation_id"], role="agent", actor_telegram_id=10)
        with self.assertRaisesRegex(EgressIntentError, "INVALID_OPERATION_ID"):
            cancel_plan(self.conn, operation_id="' OR 1=1", role="admin", actor_telegram_id=10)
        self.assertEqual(get_intent(self.conn, op["operation_id"])["status"], "PLANNED")

    def test_blocks_parallel_phase6g_failover(self):
        self.conn.execute("CREATE TABLE failover_operations (status TEXT)")
        self.conn.execute("INSERT INTO failover_operations VALUES ('RUNNING')")
        self.conn.commit()
        with self.assertRaisesRegex(EgressIntentError, "FAILOVER_IN_PROGRESS"):
            self.plan()
        self.assertIsNone(pending_intent_for_user(self.conn, "nvl0557"))

    def test_registration_rejects_shell_tokens_private_ip_duplicates(self):
        candidates = [
            {"target_id": "A; touch /tmp/pwn"},
            {"namespace": "edge 1"},
            {"internal_ip": "1.1.1.1"},
            {"edge_public_ip": "10.0.0.5"},
            {"local_port": 22},
        ]
        for i, change in enumerate(candidates):
            kw = dict(target_id="edgez", edge_public_ip="216.126.229.12",
                      namespace="nvl-egress-stg1", internal_ip="10.78.111.2", local_port=22285)
            kw.update(change)
            with self.subTest(i=i), self.assertRaises(EgressIntentError):
                register_draft_target(self.conn, **kw)
        with self.assertRaisesRegex(EgressIntentError, "TARGET_ALREADY_EXISTS_OR_PORT_CONFLICT"):
            self.register(tid="edgez", port=22284)

    def test_cli_module_contains_no_route_or_dns_operations(self):
        src = (ROOT / "egress_manager.py").read_text()
        self.assertNotIn("subprocess.", src)
        self.assertNotIn("systemctl ", src)
        self.assertNotIn("UPDATE ssh_accounts", src)
        self.assertNotIn("UPDATE host_pool", src)


class EgressBotContractTests(unittest.TestCase):
    def test_bot_feature_flag_and_admin_only_callback(self):
        bot = (ROOT / "bot_final_v49-2.py").read_text()
        self.assertIn("NVL_EGRESS_INTENTS_UI", bot)
        self.assertIn("if d.startswith('egx_'):", bot)
        self.assertIn("if role != 'admin':", bot)
        self.assertIn("egress_manager.plan_switch(", bot)
        self.assertIn("egress_manager.cancel_plan(", bot)
        self.assertIn("callback_data=f\"egx_user_{username}\"", bot)


if __name__ == "__main__":
    unittest.main()
