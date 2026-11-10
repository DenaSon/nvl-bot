"""Fail-closed real bot_access Super Admin authorization and legacy revocation."""
import ast
import asyncio
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nvl_superadmin_access import (
    REVOKED_LEGACY_ADMIN_ID,
    active_superadmin_ids, is_active_superadmin, is_private_superadmin,
    is_revoked_principal, permitted_notification_ids,
)
from critical_operation_notice import _recipients, send_critical_notice

ROOT = Path(__file__).resolve().parents[1]
ADMIN_IDS = (5981086716, 75610890, 1252512320)


class SuperAdminAccessTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dbfile = Path(tmp.name) / "master_bot.db"
        with sqlite3.connect(self.dbfile) as db:
            db.execute("""CREATE TABLE bot_access (
                telegram_id INTEGER PRIMARY KEY, role TEXT NOT NULL,
                active INTEGER NOT NULL, label TEXT, created_at TEXT, updated_at TEXT
            )""")
            db.execute("""CREATE TABLE agents (id INTEGER, telegram_id INTEGER)""")
            db.execute("""CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)""")
            db.executemany(
                "INSERT INTO bot_access (telegram_id, role, active) VALUES (?, ?, ?)",
                [(value, "super_admin", 1) for value in ADMIN_IDS]
                + [(777, "admin", 1), (888, "super_admin", 0)],
            )
            # The 2 valid Super Admins overlapping agents remain authorized.
            db.executemany("INSERT INTO agents VALUES (?, ?)", [
                (1, 75610890), (2, 1252512320)
            ])
            db.execute("INSERT INTO settings VALUES ('admin_chat_ids', ?)", (
                ",".join(map(str, (*ADMIN_IDS, REVOKED_LEGACY_ADMIN_ID))),))

    def test_all_three_registered_can_access_their_own_private_chat(self):
        self.assertEqual(active_superadmin_ids(str(self.dbfile)), frozenset(ADMIN_IDS))
        for uid in ADMIN_IDS:
            with self.subTest(uid=uid):
                self.assertTrue(is_active_superadmin(str(self.dbfile), uid))
                self.assertTrue(is_private_superadmin(str(self.dbfile), uid, uid, "private"))

    def test_no_ordinary_agent_accountant_chat_impersonation(self):
        for uid in (777, 888, REVOKED_LEGACY_ADMIN_ID):
            self.assertFalse(is_active_superadmin(str(self.dbfile), uid))
        self.assertFalse(is_private_superadmin(str(self.dbfile), ADMIN_IDS[0], ADMIN_IDS[1], "private"))
        self.assertFalse(is_private_superadmin(str(self.dbfile), ADMIN_IDS[0], ADMIN_IDS[0], "group"))
        self.assertFalse(is_private_superadmin(str(self.dbfile), ADMIN_IDS[0], ADMIN_IDS[0], None))
        self.assertFalse(is_private_superadmin(str(self.dbfile), str(ADMIN_IDS[0]), ADMIN_IDS[0], "private"))

    def test_revoked_id_denied_even_if_reinserted_in_bot_access(self):
        with sqlite3.connect(self.dbfile) as db:
            db.execute(
                "INSERT INTO bot_access (telegram_id, role, active) VALUES (?, 'super_admin', 1)",
                (REVOKED_LEGACY_ADMIN_ID,),
            )
        self.assertNotIn(REVOKED_LEGACY_ADMIN_ID, active_superadmin_ids(str(self.dbfile)))
        self.assertFalse(is_active_superadmin(str(self.dbfile), REVOKED_LEGACY_ADMIN_ID))
        self.assertTrue(is_revoked_principal(REVOKED_LEGACY_ADMIN_ID))
        self.assertFalse(is_revoked_principal(str(REVOKED_LEGACY_ADMIN_ID)))

    def test_role_revocation_is_seen_immediately_without_restart(self):
        with sqlite3.connect(self.dbfile) as db:
            db.execute("UPDATE bot_access SET active=0 WHERE telegram_id=?", (ADMIN_IDS[1],))
        self.assertFalse(is_active_superadmin(str(self.dbfile), ADMIN_IDS[1]))
        self.assertEqual(active_superadmin_ids(str(self.dbfile)), frozenset((ADMIN_IDS[0], ADMIN_IDS[2])))

    def test_database_unavailable_and_missing_registry_fail_closed(self):
        missing = self.dbfile.parent / "missing.sqlite"
        self.assertEqual(active_superadmin_ids(str(missing)), frozenset())
        self.assertFalse(missing.exists())
        with sqlite3.connect(self.dbfile) as db:
            db.execute("DROP TABLE bot_access")
        self.assertEqual(active_superadmin_ids(str(self.dbfile)), frozenset())
        self.assertFalse(is_active_superadmin(str(self.dbfile), ADMIN_IDS[0]))

    def test_all_admin_notifications_strip_revoked_but_keep_other_legacy_admins(self):
        recipients = permitted_notification_ids(
            str(self.dbfile), (*ADMIN_IDS, REVOKED_LEGACY_ADMIN_ID, 777)
        )
        self.assertEqual(recipients, frozenset((*ADMIN_IDS, 777)))
        self.assertNotIn(REVOKED_LEGACY_ADMIN_ID, recipients)

    def test_code_registers_global_deny_and_does_not_use_legacy_constant(self):
        source = (ROOT / "bot_final_v49-2.py").read_text(encoding="utf-8")
        self.assertNotIn(str(REVOKED_LEGACY_ADMIN_ID), source)
        self.assertNotIn("update.effective_chat.id == SUPER_ADMIN_ID", source)
        self.assertNotIn("if chat_id == SUPER_ADMIN_ID:", source)
        self.assertIn("TypeHandler(Update, _nvl_revoked_admin_guard), group=-2", source)
        self.assertIn("_is_superadmin_update(update, context)", source)
        self.assertIn("return set(permitted_notification_ids(DB_PATH, out))", source)

    def test_extracted_live_guard_clears_old_persisted_session_and_stops(self):
        source = (ROOT / "bot_final_v49-2.py").read_text(encoding="utf-8")
        root = ast.parse(source)
        guard = next(node for node in root.body
                     if isinstance(node, ast.AsyncFunctionDef) and
                     node.name == "_nvl_revoked_admin_guard")
        namespace = {
            "is_revoked_principal": is_revoked_principal,
            "ApplicationHandlerStop": type("ApplicationHandlerStop", (Exception,), {}),
        }
        module = ast.Module(body=[
            ast.ImportFrom(module="__future__", names=[
                ast.alias(name="annotations")
            ], level=0), guard], type_ignores=[])
        exec(compile(ast.fix_missing_locations(module), "guard.py", "exec"), namespace)
        guard_fn = namespace["_nvl_revoked_admin_guard"]
        ctx = SimpleNamespace(user_data={"logged_in": True, "role": "admin"})
        old = SimpleNamespace(effective_user=SimpleNamespace(id=REVOKED_LEGACY_ADMIN_ID))
        with self.assertRaises(namespace["ApplicationHandlerStop"]):
            asyncio.run(guard_fn(old, ctx))
        self.assertEqual(ctx.user_data, {})
        ctx = SimpleNamespace(user_data={"logged_in": True, "role": "admin"})
        allowed = SimpleNamespace(effective_user=SimpleNamespace(id=ADMIN_IDS[0]))
        asyncio.run(guard_fn(allowed, ctx))
        self.assertTrue(ctx.user_data["logged_in"])

    def test_critical_notice_ignores_stale_primary_and_env(self):
        old = REVOKED_LEGACY_ADMIN_ID
        with patch.dict("os.environ", {"NVL_CRITICAL_SUPERADMIN_IDS": str(old)}):
            self.assertEqual(_recipients(old, authorized_superadmin_ids=ADMIN_IDS), ADMIN_IDS)
            self.assertEqual(_recipients(old), ())
        self.assertEqual(_recipients(ADMIN_IDS[0], extra=f"{old},{ADMIN_IDS[1]}"),
                         ADMIN_IDS[:2])


class CriticalNoticeDeliveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_current_db_super_admins_receive_alert(self):
        class Bot:
            def __init__(self):
                self.sent = []
            async def send_message(self, *, chat_id, **kwargs):
                self.sent.append(chat_id)
        bot = Bot()
        app = SimpleNamespace(bot=bot, bot_data={})
        await send_critical_notice(
            app, event="ROUTE_CHANGED",
            primary_super_admin_id=REVOKED_LEGACY_ADMIN_ID,
            authorized_superadmin_ids=ADMIN_IDS, now=10.0
        )
        self.assertEqual(set(bot.sent), set(ADMIN_IDS))
        self.assertNotIn(REVOKED_LEGACY_ADMIN_ID, bot.sent)


if __name__ == "__main__":
    unittest.main()
