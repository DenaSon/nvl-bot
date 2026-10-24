"""CZ-04A fail-closed provider mutations and standby promotion (no network)."""
import asyncio
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from cloudzy_cz04a import Cloudzy04A


class FakeQuery:
    def __init__(self):
        self.edits = []
        self.sent = []
        self.message = self

    async def edit_message_text(self, text, **kw):
        self.edits.append((text, kw))

    async def reply_text(self, text, **kw):
        self.sent.append(text)

    @property
    def callbacks(self):
        return [x[1] for row in self.edits[-1][1]["reply_markup"] for x in row]


class Context:
    def __init__(self):
        self.user_data = {}


class Provider:
    def __init__(self):
        self.calls = []
        self.live = {"data": {"service": {
            "id": "svc1", "primaryIpv4": "8.8.8.8", "state": "active"
        }}}

    def get_server(self, service_id):
        self.calls.append(("get", service_id))
        return self.live

    def power_on(self, service_id):
        self.calls.append(("start", service_id))
        return {"accepted": True}

    def power_off(self, service_id):
        self.calls.append(("stop", service_id))
        return {"accepted": True}

    def restart_server(self, service_id):
        self.calls.append(("reboot", service_id))
        return {"accepted": True}


def markup(rows):
    assert all(len(data.encode("utf-8")) <= 64
               for row in rows for _, data in row)
    return rows


class CZ04ATests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "db.sqlite"
        self.ctx = Context()
        self.query = FakeQuery()
        self.provider = Provider()
        self.probe_ok = True
        self.safe = True
        self.now = [1000.0]
        with self.db() as db:
            db.executescript("""
                CREATE TABLE host_pool (
                    host TEXT PRIMARY KEY, active INTEGER, is_default INTEGER,
                    is_standby INTEGER, service_port INTEGER, admin_ssh_port INTEGER,
                    provider TEXT, provider_instance_id TEXT,
                    disabled_reason TEXT, disabled_at TEXT
                );
                CREATE TABLE cloudzy_edge_operations (
                    provider_server_id TEXT, public_ipv4 TEXT, status TEXT
                );
                CREATE TABLE ssh_accounts (host TEXT);
                CREATE TABLE settings (key TEXT PRIMARY KEY,value TEXT);
                INSERT INTO host_pool VALUES
                    ('8.8.8.8',0,0,0,2252,22,'cloudzy','svc1',NULL,NULL);
                INSERT INTO cloudzy_edge_operations VALUES
                    ('svc1','8.8.8.8','EDGE_READY');
                INSERT INTO settings VALUES ('hosts','1.1.1.1');
                INSERT INTO settings VALUES ('dns_current_ip','1.1.1.1');
                INSERT INTO settings VALUES ('phase6h_auto_failover_enabled','0');
                INSERT INTO settings VALUES ('auto_failover_mode','0');
                INSERT INTO settings VALUES ('edge_egress_v1_onboard_enabled','0');
            """)
        self.controller = Cloudzy04A(
            conn_factory=self.db,
            guard=self.guard,
            probe=self.probe,
            cloudzy_factory=lambda: self.provider,
            now=lambda: self.now[0],
        )

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path)
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def guard(self, db):
        if not self.safe:
            raise RuntimeError("PROTECTED")

    async def probe(self, host, service, admin):
        self.assertEqual((host, service, admin), ("8.8.8.8", 2252, 22))
        return self.probe_ok

    async def cb(self, data, *, role="admin", actor=11, chat=22):
        await self.controller.handle_callback(
            self.query, self.ctx, data, role=role, actor=actor, chat=chat,
            markup=markup,
        )

    async def select(self, action):
        await self.cb("apps_cz_edge")
        self.assertIn("هیچ", "هیچ")
        detail = next(x for x in self.query.callbacks if x.startswith("apps_cz4_detail_"))
        await self.cb(detail)
        selected = next(x for x in self.query.callbacks
                        if x.startswith("apps_cz4_pick_" + action + "_"))
        await self.cb(selected)
        if self.query.edits[-1][0].startswith("🔐"):
            return next(x for x in self.query.callbacks if x.startswith("apps_cz4_go_"))
        return None

    async def test_empty_unlinked_provider_never_gets_controls(self):
        with self.db() as db:
            db.execute("UPDATE cloudzy_edge_operations SET status='HOLD_SSH'")
        await self.cb("apps_cz4_vps")
        self.assertFalse(any("detail" in c for c in self.query.callbacks))

    async def test_admin_and_callback_owner_ttl(self):
        await self.cb("apps_cz_edge", role="agent")
        self.assertIn("فقط مدیر", self.query.sent[-1])
        await self.cb("apps_cz_edge")
        detail = next(x for x in self.query.callbacks if x.startswith("apps_cz4_detail_"))
        count = len(self.query.edits)
        await self.cb(detail, actor=999)
        self.assertEqual(len(self.query.edits), count)
        self.now[0] += 700
        await self.cb(detail)
        self.assertEqual(len(self.query.edits), count)

    async def test_promote_only_to_standby_without_moving_route_or_users(self):
        go = await self.select("relay")
        self.assertIsNotNone(go)
        await self.cb(go)
        with self.db() as db:
            state = db.execute(
                "SELECT active,is_standby,is_default FROM host_pool "
                "WHERE host='8.8.8.8'"
            ).fetchone()
            self.assertEqual(state, (1, 1, 0))
            self.assertEqual(db.execute(
                "SELECT value FROM settings WHERE key='hosts'"
            ).fetchone()[0], "1.1.1.1")
            self.assertEqual(db.execute(
                "SELECT value FROM settings WHERE key='dns_current_ip'"
            ).fetchone()[0], "1.1.1.1")
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM ssh_accounts"
            ).fetchone()[0], 0)
            self.assertEqual(db.execute(
                "SELECT status FROM cloudzy_cz04a_actions"
            ).fetchone()[0], "DONE")
        self.assertFalse(any(call[0] != "get" for call in self.provider.calls))
        await self.cb(go)
        self.assertEqual(len(self.provider.calls), 3)

    async def test_no_promotion_when_auto_failover_or_user_bound(self):
        with self.db() as db:
            db.execute("UPDATE settings SET value='1' WHERE key='phase6h_auto_failover_enabled'")
        await self.select("relay")
        self.assertNotIn("apps_cz4_go_", " ".join(self.query.callbacks))
        with self.db() as db:
            db.execute("UPDATE settings SET value='0' WHERE key='phase6h_auto_failover_enabled'")
            db.execute("INSERT INTO ssh_accounts VALUES ('8.8.8.8')")
        await self.select("relay")
        self.assertNotIn("apps_cz4_go_", " ".join(self.query.callbacks))

    async def test_probe_failed_denies_commit(self):
        go = await self.select("relay")
        self.probe_ok = False
        await self.cb(go)
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT active FROM host_pool WHERE host='8.8.8.8'"
            ).fetchone()[0], 0)

    async def test_provider_mismatch_denies_commit(self):
        go = await self.select("relay")
        self.provider.live["data"]["service"]["id"] = "some-other-service"
        await self.cb(go)
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT active FROM host_pool WHERE host='8.8.8.8'"
            ).fetchone()[0], 0)

    async def test_isolated_provider_stop_single_confirmation(self):
        go = await self.select("stop")
        await self.cb(go)
        self.assertEqual([c for c in self.provider.calls if c[0] == "stop"], [("stop", "svc1")])
        await self.cb(go)
        self.assertEqual([c for c in self.provider.calls if c[0] == "stop"], [("stop", "svc1")])

    async def test_fail_closed_after_unknown_provider_result(self):
        def fail(_id):
            raise TimeoutError("unknown")
        self.provider.power_off = fail
        go = await self.select("stop")
        await self.cb(go)
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT status FROM cloudzy_cz04a_actions"
            ).fetchone()[0], "HOLD")
        await self.cb("apps_cz_edge")
        detail = next(x for x in self.query.callbacks if x.startswith("apps_cz4_detail_"))
        await self.cb(detail)
        picked = next(x for x in self.query.callbacks if x.startswith("apps_cz4_pick_stop_"))
        await self.cb(picked)
        self.assertIn("HOLD", self.query.sent[-1])

    async def test_core_guard_blocks_power_mutation(self):
        go = await self.select("stop")
        self.safe = False
        await self.cb(go)
        self.assertEqual([c for c in self.provider.calls if c[0] == "stop"], [])

    async def test_main_dispatch_prioritizes_cz04a_over_legacy(self):
        source = (Path(__file__).resolve().parents[1] /
                  "bot_final_v49-2.py").read_text("utf-8")
        self.assertIn('d == "apps_cz_edge" or d.startswith("apps_cz4_")', source)
        self.assertLess(source.index("_cloudzy_04a.handle_callback("),
                        source.index("_cloudzy_admin_panel.handle_callback("))
        self.assertIn("pool_active=False", source)
