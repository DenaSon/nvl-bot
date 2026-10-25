"""CZ-08 Cloudzy inventory / deletion tests. All provider writes are mocked."""
import asyncio
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from cloudzy_admin_panel import CloudzyAdminPanel
from cloudzy_cz08_vps_delete import CloudzyDeleteGuard
from cloudzy_service import CloudzyUncertainError, CloudzyAPIError

MAIN = "144.172.119.24"
OLD = "153.75.90.152"


class Query:
    def __init__(self):
        self.edits = []
        self.message = self
        self.sent = []
    async def edit_message_text(self, text, **kwargs):
        self.edits.append((text, kwargs))
    async def reply_text(self, text, **kwargs):
        self.sent.append(text)
    @property
    def text(self):
        return self.edits[-1][0]
    @property
    def callbacks(self):
        return [cb for row in self.edits[-1][1]["reply_markup"] for _name, cb in row]


class Context:
    def __init__(self):
        self.user_data = {}


class Provider:
    def __init__(self):
        self.items = [
            {"id": "primary-id", "hostname": "current-relay", "primaryIpv4": MAIN,
             "state": "active"},
            {"id": "old-id", "hostname": "old-edge", "primaryIpv4": OLD,
             "state": "active"},
        ]
        self.deleted = []
        self.fail = None
    def list_servers(self):
        return {"data": list(self.items)}
    def get_server(self, server_id):
        return {"data": next(x.copy() for x in self.items if x["id"] == server_id)}
    def delete_server(self, server_id, *, confirm=False):
        assert confirm is True
        if self.fail:
            raise self.fail
        self.deleted.append(server_id)
        self.items = [x for x in self.items if x["id"] != server_id]
        return None


def markup(rows):
    for row in rows:
        for _, callback in row:
            assert len(callback.encode()) <= 64
    return rows


class DeleteFlowTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "db.sqlite"
        self.connect = lambda: sqlite3.connect(path)
        with self.connect() as db:
            db.executescript("""
              CREATE TABLE host_pool(host TEXT,active INTEGER,is_default INTEGER,
                is_standby INTEGER,provider TEXT,provider_instance_id TEXT);
              CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
              CREATE TABLE ssh_accounts(host TEXT,status TEXT,service_type TEXT);
              CREATE TABLE failover_operations(id TEXT,status TEXT);
              CREATE TABLE cloudzy_cz04b_operations(id TEXT,status TEXT);
              CREATE TABLE cloudzy_cz07_jobs(id TEXT,status TEXT);
              CREATE TABLE cloudzy_cz04a_actions(id TEXT,status TEXT);
              CREATE TABLE cloudzy_edge_operations(provider_server_id TEXT,status TEXT);
            """)
            db.executemany("INSERT INTO host_pool VALUES (?,?,?,?,?,?)", [
                (MAIN, 1, 1, 0, "cloudzy", "primary-id"),
                (OLD, 1, 0, 0, "cloudzy", "old-id")
            ])
            db.executemany("INSERT INTO settings VALUES (?,?)", [
                ("dns_current_ip", MAIN), ("hosts", MAIN),
                ("core_wg_public_ip", "91.107.170.239")
            ])
        self.clock = [1000.]
        self.provider = Provider()
        self.guard = CloudzyDeleteGuard(self.connect, now=lambda: self.clock[0])
        self.panel = CloudzyAdminPanel(
            factory=lambda: self.provider, now=lambda: self.clock[0],
            delete_guard=self.guard,
        )
        self.context = Context()
        self.query = Query()

    def cb(self, name, *, role="admin", actor=12, chat=34):
        asyncio.run(self.panel.handle_callback(
            self.query, self.context, name, role=role, actor=actor,
            chat=chat, markup=markup,
        ))

    def detail(self, which):
        self.cb("apps_cz_servers_0")
        tokens = dict(self.context.user_data["cz_refs"]["items"])
        tok = next(t for t, data in tokens.items() if data[1] == which)
        self.cb("apps_cz_sv_" + tok)
        return tok

    def test_active_relay_visible_and_never_has_delete_button(self):
        self.cb("apps_cz_servers_0")
        self.assertIn("رله اصلی", self.query.text)
        token = self.detail("primary-id")
        self.assertIn("رله اصلی NVL", self.query.text)
        self.assertFalse(any(x.startswith("apps_cz_del_") for x in self.query.callbacks))
        self.cb("apps_cz_del_" + token)
        self.assertFalse(self.provider.deleted)
        self.assertTrue(self.query.sent)

    def test_secondary_delete_two_steps_and_database_marks_inactive(self):
        token = self.detail("old-id")
        self.assertIn("apps_cz_del_" + token, self.query.callbacks)
        self.cb("apps_cz_del_" + token)
        self.assertEqual(self.provider.deleted, [])
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_yes_"))
        self.cb(confirm)
        self.assertEqual(self.provider.deleted, ["old-id"])
        self.assertIn("درخواست حذف Cloudzy پذیرفته شد", self.query.text)
        with self.connect() as db:
            self.assertEqual(db.execute(
                "SELECT active,is_default,is_standby FROM host_pool WHERE host=?",
                (OLD,)).fetchone(), (0, 0, 0))
            self.assertEqual(db.execute(
                "SELECT status FROM cloudzy_cz08_deletions").fetchone()[0], "DONE")
            self.assertEqual(db.execute(
                "SELECT value FROM settings WHERE key='dns_current_ip'").fetchone()[0], MAIN)
        self.cb(confirm)
        self.assertEqual(self.provider.deleted, ["old-id"])

    def test_relay_changes_during_confirmation_are_blocked(self):
        token = self.detail("old-id")
        self.cb("apps_cz_del_" + token)
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_yes_"))
        with self.connect() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host=?", (MAIN,))
            db.execute("UPDATE host_pool SET is_default=1 WHERE host=?", (OLD,))
            db.execute("UPDATE settings SET value=? WHERE key IN ('dns_current_ip','hosts')", (OLD,))
        self.cb(confirm)
        self.assertEqual(self.provider.deleted, [])
        self.assertIn("PRIMARY_RELAY", self.query.sent[-1])

    def test_expiration_and_owner_binding(self):
        token = self.detail("old-id")
        self.cb("apps_cz_del_" + token)
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_yes_"))
        self.cb(confirm, actor=99)
        self.assertEqual(self.provider.deleted, [])
        token = self.detail("old-id")
        self.cb("apps_cz_del_" + token)
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_yes_"))
        self.clock[0] += 91
        self.cb(confirm)
        self.assertEqual(self.provider.deleted, [])

    def test_active_customer_blocks_delete(self):
        with self.connect() as db:
            db.execute("INSERT INTO ssh_accounts VALUES (?,?,?)", (OLD, "فعال", "ssh"))
        token = self.detail("old-id")
        self.assertNotIn("apps_cz_del_" + token, self.query.callbacks)
        self.assertIn("ACTIVE_ACCOUNTS_ASSIGNED", self.query.text)

    def test_default_dns_mismatch_disables_all_delete(self):
        with self.connect() as db:
            db.execute("UPDATE settings SET value=? WHERE key='dns_current_ip'", (OLD,))
        token = self.detail("old-id")
        self.assertNotIn("apps_cz_del_" + token, self.query.callbacks)
        self.assertIn("DEFAULT_ROUTE_MISMATCH", self.query.text)

    def test_cutover_busy_disables_delete(self):
        with self.connect() as db:
            db.execute("INSERT INTO cloudzy_cz07_jobs VALUES ('job','ROUTING')")
        token = self.detail("old-id")
        self.assertNotIn("apps_cz_del_" + token, self.query.callbacks)
        self.assertIn("MIGRATION_BUSY", self.query.text)

    def test_uncertain_provider_result_is_held_no_blind_retry(self):
        self.provider.fail = CloudzyUncertainError("DELETE /services/old-id")
        token = self.detail("old-id")
        self.cb("apps_cz_del_" + token)
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_yes_"))
        self.cb(confirm)
        self.assertFalse(self.provider.deleted)
        with self.connect() as db:
            self.assertEqual(db.execute(
                "SELECT status FROM cloudzy_cz08_deletions").fetchone()[0], "HOLD")
        token = self.detail("old-id")
        self.assertNotIn("apps_cz_del_" + token, self.query.callbacks)
        self.assertIn("DELETION_HOLD", self.query.text)

    def test_auto_failover_enabled_allows_retired_old_edge_after_migration(self):
        # After CZ07: all active accounts have moved to the new Default,
        # and the old host is no longer in DNS/hosts or the standby pool.
        with self.connect() as db:
            db.execute("INSERT INTO settings VALUES ('phase6h_auto_failover_enabled','1')")
            db.execute("INSERT INTO settings VALUES ('auto_failover_mode','1')")
            db.execute("INSERT INTO ssh_accounts VALUES (?,?,?)", (MAIN, "فعال", "ssh"))
            db.execute("INSERT INTO cloudzy_cz07_jobs VALUES ('j1','DONE')")
        token = self.detail("old-id")
        self.assertIn("apps_cz_del_" + token, self.query.callbacks)
        self.cb("apps_cz_del_" + token)
        confirm = next(c for c in self.query.callbacks if c.startswith("apps_cz_yes_"))
        self.cb(confirm)
        self.assertEqual(self.provider.deleted, ["old-id"])
        with self.connect() as db:
            self.assertEqual(db.execute(
                "SELECT active,is_default,is_standby FROM host_pool WHERE host=?",
                (OLD,)).fetchone(), (0, 0, 0))
            self.assertEqual(db.execute(
                "SELECT host FROM ssh_accounts WHERE status='فعال'").fetchall(),
                [(MAIN,)])

    def test_standby_vps_is_protected_even_when_failover_disabled(self):
        with self.connect() as db:
            db.execute("UPDATE host_pool SET is_standby=1 WHERE host=?", (OLD,))
        token = self.detail("old-id")
        self.assertNotIn("apps_cz_del_" + token, self.query.callbacks)
        self.assertIn("STANDBY_FAILOVER_TARGET", self.query.text)

    def test_unknown_host_remains_protected_with_auto_failover_enabled(self):
        with self.connect() as db:
            db.execute("INSERT INTO settings VALUES ('phase6h_auto_failover_enabled','1')")
            db.execute("DELETE FROM host_pool WHERE host=?", (OLD,))
        token = self.detail("old-id")
        self.assertNotIn("apps_cz_del_" + token, self.query.callbacks)
        self.assertIn("AUTOMATIC_FAILOVER_ENABLED", self.query.text)

    def test_active_account_blocks_delete_even_with_auto_failover_enabled(self):
        with self.connect() as db:
            db.execute("INSERT INTO settings VALUES ('phase6h_auto_failover_enabled','1')")
            db.execute("INSERT INTO ssh_accounts VALUES (?,?,?)", (OLD, "فعال", "ssh"))
        token = self.detail("old-id")
        self.assertNotIn("apps_cz_del_" + token, self.query.callbacks)
        self.assertIn("ACTIVE_ACCOUNTS_ASSIGNED", self.query.text)

    def test_definite_provider_rejection_is_not_ambiguous_hold(self):
        self.provider.fail = CloudzyAPIError(403, "no delete permission")
        token = self.detail("old-id")
        self.cb("apps_cz_del_" + token)
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_yes_"))
        self.cb(confirm)
        with self.connect() as db:
            self.assertEqual(db.execute(
                "SELECT status FROM cloudzy_cz08_deletions").fetchone()[0], "REJECTED")
        self.assertFalse(self.provider.deleted)

    def test_live_list_absence_prevents_delete(self):
        token = self.detail("old-id")
        self.cb("apps_cz_del_" + token)
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_yes_"))
        self.provider.items = self.provider.items[:1]
        self.cb(confirm)
        self.assertEqual(self.provider.deleted, [])
        self.assertIn("SERVER_NOT_IN_LIVE_INVENTORY", self.query.sent[-1])

    def test_read_only_role_cannot_delete(self):
        token = self.detail("old-id")
        self.cb("apps_cz_del_" + token, role="agent")
        self.assertEqual(self.provider.deleted, [])
        self.assertIn("فقط مدیر", self.query.sent[-1])


if __name__ == "__main__":
    unittest.main()
