"""CZ-04B safe route/user migration behavior with strictly mocked network ports."""
import asyncio
from contextlib import contextmanager
import copy
import json
from io import BytesIO
from urllib.error import HTTPError
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from cloudzy_cz04b import Cloudzy04B
from cloudzy_cz04b_dns import CloudflareExactDNS, DNSHold


class FakeDNS:
    def __init__(self, old="203.0.113.11"):
        self.records = [
            {"name": "ssh.example.test", "id": "d1", "ip": old, "ttl": 60},
            {"name": "tls.example.test", "id": "d2", "ip": old, "ttl": 60},
        ]
        self.fail_after = None
        self.calls = []
        self.fail_rollback = False

    def snapshot(self):
        return copy.deepcopy(self.records)

    def set_all(self, expected, ip):
        if self.fail_rollback and ip == "203.0.113.11":
            raise DNSHold("ROLLBACK_FAILURE")
        for i, (now, old) in enumerate(zip(self.records, expected)):
            if now != old:
                raise DNSHold("CONCURRENT_DNS_CHANGED")
            self.records[i]["ip"] = ip
            self.calls.append(("write", ip, i))
            if self.fail_after is not None and i == self.fail_after:
                self.fail_after = None
                raise DNSHold("TEST_PARTIAL_UPDATE")
        return self.snapshot()


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
        return [data for row in self.edits[-1][1]["reply_markup"]
                for _, data in row]


class FakeContext:
    def __init__(self):
        self.user_data = {}


def markup(rows):
    assert all(len(str(data).encode("utf-8")) <= 64
               for row in rows for _, data in row)
    return rows


class CZ04BTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "test.sqlite"
        self.dns = FakeDNS()
        self.safe = True
        self.enable = True
        self.probe_good = True
        self.provider_good = True
        self.nat_good = True
        self.q = FakeQuery()
        self.ctx = FakeContext()
        self.now = [10000]
        self.net_calls = []
        with self.db() as db:
            db.executescript("""
            CREATE TABLE host_pool(
                host TEXT PRIMARY KEY, active INTEGER, is_default INTEGER,
                is_standby INTEGER, service_port INTEGER, admin_ssh_port INTEGER,
                provider TEXT, provider_instance_id TEXT
            );
            CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
            CREATE TABLE ssh_accounts(
                username TEXT PRIMARY KEY, host TEXT, status TEXT, service_type TEXT
            );
            CREATE TABLE cloudzy_edge_operations(
                provider_server_id TEXT, public_ipv4 TEXT, status TEXT,
                host_key_type TEXT, host_key_base64 TEXT
            );
            CREATE TABLE cloudzy_cz04a_actions(status TEXT, host TEXT);
            CREATE TABLE failover_operations(
                id INTEGER PRIMARY KEY AUTOINCREMENT, mode TEXT,
                source_host TEXT, target_host TEXT, status TEXT,
                started_at TEXT, updated_at TEXT, finished_at TEXT,
                account_count INTEGER, moved_count INTEGER,
                previous_default_host TEXT, previous_dns_ip TEXT,
                core_fallback_ip TEXT, error TEXT, detail_json TEXT
            );
            INSERT INTO host_pool VALUES
              ('203.0.113.11',1,1,0,2252,22,NULL,NULL),
              ('203.0.113.12',1,0,1,2252,22,'cloudzy','sv1');
            INSERT INTO cloudzy_edge_operations VALUES
              ('sv1','203.0.113.12','EDGE_READY','ssh-ed25519','YWJjZA==');
            INSERT INTO settings VALUES
              ('hosts','203.0.113.11'),
              ('dns_current_ip','203.0.113.11'),
              ('core_wg_public_ip','203.0.113.100'),
              ('tls_port','2088'),
              ('tls_passthrough','1'),
              ('phase6h_auto_failover_enabled','0'),
              ('auto_failover_mode','0'),
              ('edge_egress_v1_onboard_enabled','0');
            INSERT INTO ssh_accounts VALUES
              ('alice','203.0.113.11','🟢 فعال','ssh'),
              ('bob',NULL,'🟢 فعال','ssh'),
              ('carol','203.0.113.11','🔴 غیرفعال','ssh'),
              ('v2_user','203.0.113.11','🟢 فعال','v2ray');
            """)
        self.manager = Cloudzy04B(
            db_conn=self.db, guard=self.guard,
            provider=self.provider, probe=self.probe, nat=self.nat,
            dns=self.dns, enabled=lambda: self.enable,
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

    async def provider(self, ip, pid):
        self.net_calls.append("provider")
        self.assertEqual((ip, pid), ("203.0.113.12", "sv1"))
        return self.provider_good

    async def probe(self, ip, port, management):
        self.net_calls.append("probe")
        self.assertEqual((ip, port, management), ("203.0.113.12", 2252, 22))
        return self.probe_good

    async def nat(self, ip, management, port, tls, trusted_key):
        self.net_calls.append("nat")
        self.assertEqual((ip, management, port, tls),
                         ("203.0.113.12", 22, 2252, 2088))
        self.assertEqual(trusted_key, ("ssh-ed25519", "YWJjZA=="))
        return self.nat_good

    async def cb(self, data, role="admin", actor=7, chat=8):
        await self.manager.handle_callback(
            self.q, self.ctx, data, role=role, actor=actor, chat=chat,
            markup=markup,
        )

    async def confirmed_route(self):
        await self.cb("apps_cz5_home")
        chosen = next(x for x in self.q.callbacks if x.startswith("apps_cz5_target_"))
        await self.cb(chosen)
        confirm = next(x for x in self.q.callbacks if x.startswith("apps_cz5_go_"))
        await self.cb(confirm)
        return confirm

    async def test_manual_edge_routes_and_moves_without_any_cloudzy_calls(self):
        # One existing manual standby, pinned SSH identity, no provider VPS
        # ownership is forged. Keep Cloudflare/6G/CAS exactly the same.
        with self.db() as db:
            db.execute("""CREATE TABLE manual_edge_operations(
                id TEXT,ip TEXT, pin_type TEXT,pin_base64 TEXT,status TEXT)""")
            db.execute(
                "INSERT INTO manual_edge_operations VALUES "
                "('manual-op','203.0.113.12','ssh-ed25519','YWJjZA==','STANDBY')")
            db.execute(
                "UPDATE host_pool SET provider='manual',provider_instance_id=NULL "
                "WHERE host='203.0.113.12'")
            db.execute("DELETE FROM cloudzy_edge_operations")
        async def forbidden_cloudzy(_ip,_provider):
            raise AssertionError("CLOUDZY_API_MUST_NOT_RUN")
        self.manager.provider=forbidden_cloudzy
        state=self.manager._state("203.0.113.12")
        self.assertEqual(state["provider_id"],"manual:manual-op")
        self.assertEqual(self.manager._targets(),[("203.0.113.12","manual:manual-op")])
        result=await self.manager._run_route(7,8,"203.0.113.12")
        self.assertEqual(result,"READY")
        self.assertEqual(self.manager._route_ready(),
                         ("203.0.113.11","203.0.113.12","manual:manual-op"))
        self.assertEqual({r["ip"] for r in self.dns.records},{"203.0.113.12"})
        rows,fp=self.manager._migration_snapshot("203.0.113.11","203.0.113.12")
        self.assertEqual(len(rows),2)
        moved=await self.manager._run_users(
            7,8,["alice","bob"],fp,check_provider=False)
        self.assertEqual(moved,2)
        self.assertNotIn("provider",self.net_calls)
        self.assertTrue({"probe","nat"}.issubset(self.net_calls))
        with self.db() as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM cloudzy_edge_operations").fetchone()[0],0)
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM ssh_accounts "
                           "WHERE host='203.0.113.12' AND service_type='ssh' "
                           "AND status='🟢 فعال'").fetchone()[0],2)
            self.assertEqual(
                db.execute("SELECT provider,provider_instance_id,is_default "
                           "FROM host_pool WHERE host='203.0.113.12'").fetchone(),
                ("manual",None,1))
            self.assertEqual(
                db.execute("SELECT value FROM settings WHERE key='dns_current_ip'"
                           ).fetchone()[0],"203.0.113.12")

    async def test_manual_route_rejects_partial_cloudflare_write_without_user_move(self):
        with self.db() as db:
            db.execute("""CREATE TABLE manual_edge_operations(
                id TEXT,ip TEXT,pin_type TEXT,pin_base64 TEXT,status TEXT)""")
            db.execute(
                "INSERT INTO manual_edge_operations VALUES "
                "('m1','203.0.113.12','ssh-ed25519','YWJjZA==','STANDBY')")
            db.execute(
                "UPDATE host_pool SET provider='manual',provider_instance_id=NULL "
                "WHERE host='203.0.113.12'")
            db.execute("DELETE FROM cloudzy_edge_operations")
        async def forbidden(*_):
            raise AssertionError("CLOUDZY_SHOULD_NOT_BE_QUERIED")
        self.manager.provider=forbidden
        self.dns.fail_after=0
        from cloudzy_cz04b import CutoverHold
        with self.assertRaises(CutoverHold):
            await self.manager._run_route(7,8,"203.0.113.12")
        with self.db() as db:
            self.assertEqual(db.execute("SELECT host FROM host_pool "
                            "WHERE is_default=1").fetchall(),[("203.0.113.11",)])
            self.assertEqual(db.execute("SELECT host FROM ssh_accounts WHERE "
                            "username='alice'").fetchone()[0],"203.0.113.11")
        self.assertEqual({r["ip"] for r in self.dns.records},{"203.0.113.11"})

    async def test_successful_route_keeps_users_and_source_unchanged(self):
        await self.confirmed_route()
        self.assertIn("Relay پیش‌فرض", self.q.edits[-1][0])
        with self.db() as db:
            rows = db.execute(
                "SELECT host,active,is_default,is_standby FROM host_pool ORDER BY host"
            ).fetchall()
            self.assertEqual(rows, [
                ("203.0.113.11", 1, 0, 0),
                ("203.0.113.12", 1, 1, 0),
            ])
            vals = dict(db.execute("SELECT key,value FROM settings"))
            self.assertEqual(vals["dns_current_ip"], "203.0.113.12")
            self.assertEqual(vals["hosts"], "203.0.113.12,203.0.113.11")
            self.assertEqual(db.execute(
                "SELECT host FROM ssh_accounts WHERE username='alice'"
            ).fetchone()[0], "203.0.113.11")
            self.assertIsNone(db.execute(
                "SELECT host FROM ssh_accounts WHERE username='bob'"
            ).fetchone()[0])
            status = db.execute(
                "SELECT status FROM cloudzy_cz04b_operations"
            ).fetchone()[0]
            self.assertEqual(status, "READY")
            self.assertEqual(db.execute(
                "SELECT status FROM failover_operations"
            ).fetchone()[0], "SUCCEEDED")
        self.assertEqual([r["ip"] for r in self.dns.records], ["203.0.113.12"]*2)

    async def test_user_single_then_remaining_batch_preserves_other_types(self):
        await self.confirmed_route()
        await self.cb("apps_cz5_users_0")
        self.assertIn("باقیمانده: 2", self.q.edits[-1][0])
        alice = next(x for x in self.q.callbacks if x.startswith("apps_cz5_one_"))
        await self.cb(alice)
        go = next(x for x in self.q.callbacks if x.startswith("apps_cz5_go_"))
        await self.cb(go)
        await self.cb("apps_cz5_users_0")
        self.assertIn("باقیمانده: 1", self.q.edits[-1][0])
        await self.cb("apps_cz5_all")
        go = next(x for x in self.q.callbacks if x.startswith("apps_cz5_go_"))
        await self.cb(go)
        with self.db() as db:
            users = dict(db.execute(
                "SELECT username,host FROM ssh_accounts ORDER BY username"
            ).fetchall())
            self.assertEqual(users["alice"], "203.0.113.12")
            self.assertEqual(users["bob"], "203.0.113.12")
            self.assertEqual(users["carol"], "203.0.113.11")
            self.assertEqual(users["v2_user"], "203.0.113.11")
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM cloudzy_cz04b_operations WHERE kind='users' "
                "AND status='DONE'"
            ).fetchone()[0], 2)

    async def test_zero_users_is_successful_route_no_user_actions(self):
        with self.db() as db:
            db.execute("DELETE FROM ssh_accounts")
        await self.confirmed_route()
        await self.cb("apps_cz5_users_0")
        self.assertIn("باقیمانده: 0", self.q.edits[-1][0])
        self.assertNotIn("apps_cz5_all", self.q.callbacks)

    async def test_dns_partial_failure_rolls_back_and_keeps_db_unchanged(self):
        self.dns.fail_after = 0
        await self.confirmed_route()
        self.assertIn("متوقف شد", self.q.sent[-1])
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT status FROM cloudzy_cz04b_operations"
            ).fetchone()[0], "ABORTED")
            self.assertEqual(db.execute(
                "SELECT host FROM host_pool WHERE is_default=1"
            ).fetchone()[0], "203.0.113.11")
            self.assertEqual(db.execute(
                "SELECT status FROM failover_operations"
            ).fetchone()[0], "FAILED")
        self.assertEqual([r["ip"] for r in self.dns.records], ["203.0.113.11"]*2)

    async def test_unknown_dns_rollback_holds_shared_6g(self):
        self.dns.fail_after = 0
        self.dns.fail_rollback = True
        await self.confirmed_route()
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT status FROM cloudzy_cz04b_operations"
            ).fetchone()[0], "HOLD")
            r = db.execute(
                "SELECT status,detail_json FROM failover_operations"
            ).fetchone()
            self.assertEqual(r[0], "RUNNING")
            self.assertIn("EGRESS_RECOVERY_REQUIRED", r[1])
        self.assertEqual(self.manager._targets(), [("203.0.113.12", "sv1")])


    async def test_post_commit_dns_uncertainty_holds_without_false_rollback(self):
        def broken_postcheck(target):
            raise RuntimeError("postcheck unavailable")
        self.manager._route_db_postcheck = broken_postcheck
        await self.confirmed_route()
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT host FROM host_pool WHERE is_default=1"
            ).fetchone()[0], "203.0.113.12")
            self.assertEqual(db.execute(
                "SELECT status FROM cloudzy_cz04b_operations"
            ).fetchone()[0], "HOLD")
            status, detail = db.execute(
                "SELECT status,detail_json FROM failover_operations"
            ).fetchone()
            self.assertEqual(status, "RUNNING")
            self.assertIn("EGRESS_RECOVERY_REQUIRED", detail)
        self.assertTrue(all(r["ip"] == "203.0.113.12" for r in self.dns.records))

    async def test_user_postcommit_uncertainty_preserves_hold_for_review(self):
        await self.confirmed_route()
        await self.cb("apps_cz5_users_0")
        await self.cb("apps_cz5_all")
        go = next(x for x in self.q.callbacks if x.startswith("apps_cz5_go_"))
        def broken_shared(*args, **kwargs):
            raise RuntimeError("shared journal uncertain")
        self.manager._shared_finish = broken_shared
        await self.cb(go)
        with self.db() as db:
            op = db.execute(
                "SELECT status FROM cloudzy_cz04b_operations "
                "WHERE kind='users'"
            ).fetchone()
            self.assertEqual(op[0], "HOLD")
            self.assertEqual(db.execute(
                "SELECT host FROM ssh_accounts WHERE username='alice'"
            ).fetchone()[0], "203.0.113.12")
            self.assertEqual(db.execute(
                "SELECT status FROM failover_operations ORDER BY id DESC LIMIT 1"
            ).fetchone()[0], "RUNNING")

    async def test_wrong_provider_nat_and_protected_veto_without_dns_write(self):
        for name in ("provider_good", "nat_good", "probe_good", "safe"):
            setattr(self, name, False)
            await self.cb("apps_cz5_home")
            chosen = next(x for x in self.q.callbacks if x.startswith("apps_cz5_target_"))
            await self.cb(chosen)
            self.assertEqual(self.dns.calls, [])
            self.assertFalse(any(x.startswith("apps_cz5_go_")
                                 for x in self.q.callbacks))
            setattr(self, name, True)
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM failover_operations"
            ).fetchone()[0], 0)

    async def test_cz07_batch_uses_pinned_ssh_network_not_cloudzy_api(self):
        # Initial route approval still verifies provider ownership.
        await self.confirmed_route()
        self.net_calls.clear()
        async def forbidden_provider(ip, pid):
            raise AssertionError("BATCH_MUST_NOT_CALL_CLOUDZY")
        self.manager.provider = forbidden_provider
        rows, fp = self.manager._migration_snapshot(
            "203.0.113.11", "203.0.113.12")
        count = await self.manager._run_users(
            7,8,["alice"],fp,check_provider=False)
        self.assertEqual(count,1)
        self.assertEqual(self.net_calls,["probe","nat"])
        with self.db() as db:
            self.assertEqual(
                db.execute("SELECT host FROM ssh_accounts WHERE username='alice'").fetchone()[0],
                "203.0.113.12",
            )

    async def test_cz07_provider_free_batch_rejects_bad_nat_without_move(self):
        await self.confirmed_route()
        self.net_calls.clear()
        self.provider_good = False
        self.nat_good = False
        rows, fp = self.manager._migration_snapshot(
            "203.0.113.11", "203.0.113.12")
        from cloudzy_cz04b import CutoverHold
        with self.assertRaisesRegex(CutoverHold,"PINNED_SSH_NAT_RULES_NOT_VERIFIED"):
            await self.manager._run_users(
                7,8,["alice"],fp,check_provider=False)
        self.assertEqual(self.net_calls,["probe","nat"])
        with self.db() as db:
            self.assertEqual(
                db.execute("SELECT host FROM ssh_accounts WHERE username='alice'").fetchone()[0],
                "203.0.113.11",
            )

    async def test_duplicate_and_stale_confirmations_one_use(self):
        go = await self.confirmed_route()
        self.assertEqual(len(self.dns.calls), 2)
        await self.cb(go)
        self.assertEqual(len(self.dns.calls), 2)
        await self.cb("apps_cz5_home", role="reseller")
        self.assertIn("مدیر", self.q.sent[-1])
        self.assertEqual(len(self.dns.calls), 2)

    async def test_foreign_user_or_chat_cannot_use_pending_confirm(self):
        await self.cb("apps_cz5_home")
        chosen = next(x for x in self.q.callbacks if x.startswith("apps_cz5_target_"))
        await self.cb(chosen)
        go = next(x for x in self.q.callbacks if x.startswith("apps_cz5_go_"))
        await self.cb(go, actor=100)
        await self.cb(go, chat=22)
        self.assertEqual(self.dns.calls, [])
        self.assertEqual(len(self.q.edits), 2)

    async def test_expired_confirm_and_explicit_feature_flag(self):
        await self.cb("apps_cz5_home")
        chosen = next(x for x in self.q.callbacks if x.startswith("apps_cz5_target_"))
        await self.cb(chosen)
        go = next(x for x in self.q.callbacks if x.startswith("apps_cz5_go_"))
        self.now[0] += 181
        await self.cb(go)
        self.assertFalse(self.dns.calls)
        self.now[0] -= 181
        self.enable = False
        await self.cb("apps_cz5_home")
        chosen = next(x for x in self.q.callbacks if x.startswith("apps_cz5_target_"))
        await self.cb(chosen)
        go = next(x for x in self.q.callbacks if x.startswith("apps_cz5_go_"))
        await self.cb(go)
        self.assertEqual(self.dns.calls, [])
        self.assertEqual(self.manager._latest(), None)

    async def test_source_account_change_blocks_commit_and_rolls_back_dns(self):
        original_commit = self.manager._commit_route
        def inject(op, state):
            with self.db() as db:
                db.execute("INSERT INTO ssh_accounts VALUES "
                           "('late','203.0.113.11','🟢 فعال','ssh')")
            return original_commit(op, state)
        self.manager._commit_route = inject
        await self.confirmed_route()
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT host FROM host_pool WHERE is_default=1"
            ).fetchone()[0], "203.0.113.11")
            self.assertEqual(db.execute(
                "SELECT status FROM cloudzy_cz04b_operations"
            ).fetchone()[0], "ABORTED")
        self.assertEqual([r["ip"] for r in self.dns.records], ["203.0.113.11"]*2)

    async def test_stale_user_selection_does_not_move_customers(self):
        await self.confirmed_route()
        await self.cb("apps_cz5_users_0")
        await self.cb("apps_cz5_all")
        go = next(x for x in self.q.callbacks if x.startswith("apps_cz5_go_"))
        with self.db() as db:
            db.execute("INSERT INTO ssh_accounts VALUES "
                       "('late','203.0.113.11','🟢 فعال','ssh')")
        await self.cb(go)
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT host FROM ssh_accounts WHERE username='alice'"
            ).fetchone()[0], "203.0.113.11")

    async def test_live_dns_changes_before_route_preflight_denied(self):
        self.dns.records[0]["ip"] = "198.51.100.77"
        await self.cb("apps_cz5_home")
        chosen = next(x for x in self.q.callbacks if x.startswith("apps_cz5_target_"))
        await self.cb(chosen)
        self.assertFalse(self.dns.calls)
        self.assertIn("متوقف شد", self.q.sent[-1])

    async def test_routing_menu_has_separate_confirm_and_journal(self):
        await self.cb("apps_cz5_home")
        self.assertIn("apps_cz5_status", self.q.callbacks)
        self.assertIn("apps_cz5_users_0", self.q.callbacks)
        self.assertIn("apps_cz5_target_", " ".join(self.q.callbacks))
        self.assertEqual(self.dns.calls, [])


class DNSPortTests(unittest.TestCase):
    def setUp(self):
        self.state = {
            "zone": "zone1", "token": "testtoken", "public_domain": "ssh.example.test",
            "tls_domain": "tls.example.test", "tls_passthrough": "1",
        }
        self.db = {"ssh.example.test": "1.2.3.4", "tls.example.test": "1.2.3.4"}
        self.calls = []

    def transport(self, url, headers, payload=None, method="GET"):
        self.calls.append((method, url))
        if method == "GET":
            name = url.rsplit("name=", 1)[-1]
            return {"success": True, "result": [
                {"id": name+"-id", "name": name, "type": "A",
                 "content": self.db[name], "ttl": 60, "proxied": False}
            ]}
        record = json.loads(payload)
        self.db[record["name"]] = record["content"]
        return {"success": True}

    def test_snapshot_update_and_live_postcheck(self):
        import json
        p = CloudflareExactDNS(lambda: self.state, transport=self.transport)
        a = p.snapshot()
        b = p.set_all(a, "2.3.4.5")
        self.assertTrue(all(r["ip"] == "2.3.4.5" for r in b))
        self.assertEqual([t for t, _ in self.calls].count("PUT"), 2)

    def test_email_with_api_token_still_uses_bearer(self):
        """A leftover cf_email must not turn a valid API Token into a Global Key."""
        self.state["email"] = "legacy@example.test"
        observed = []

        def observe(url, headers, payload=None, method="GET"):
            observed.append((method, dict(headers)))
            assert headers.get("Authorization") == "Bearer testtoken"
            assert "X-Auth-Email" not in headers
            return self.transport(url, headers, payload, method)

        port = CloudflareExactDNS(lambda: self.state, transport=observe)
        before = port.snapshot()
        port.set_all(before, "2.3.4.5")
        self.assertTrue(any(method == "PUT" for method, _ in observed))
        self.assertTrue(all("Authorization" in headers for _, headers in observed))

    def test_legacy_global_key_fallback_only_on_auth_error_from_read(self):
        """A genuine legacy Global API Key can still perform verified reads/writes."""
        self.state["email"] = "legacy@example.test"
        observed = []

        def mixed(url, headers, payload=None, method="GET"):
            observed.append((method, dict(headers)))
            if "Authorization" in headers:
                assert method == "GET"
                error = json.dumps({
                    "success": False,
                    "errors": [{"code": 9106, "message": "Authentication failed"}],
                }).encode()
                raise HTTPError(url, 400, "Bad Request", {}, BytesIO(error))
            assert headers.get("X-Auth-Email") == "legacy@example.test"
            assert headers.get("X-Auth-Key") == "testtoken"
            return self.transport(url, headers, payload, method)

        port = CloudflareExactDNS(lambda: self.state, transport=mixed)
        before = port.snapshot()
        port.set_all(before, "2.3.4.5")
        self.assertEqual(sum("Authorization" in headers
                             for _, headers in observed), 1)
        self.assertTrue(all("X-Auth-Key" in headers
                            for method, headers in observed if method == "PUT"))

    def test_non_auth_cloudflare_failure_does_not_fallback(self):
        """An unrelated Cloudflare 400 must never switch to Global-Key auth."""
        self.state["email"] = "legacy@example.test"
        observed = []

        def failure(url, headers, payload=None, method="GET"):
            observed.append((method, dict(headers)))
            error = json.dumps({
                "success": False,
                "errors": [{"code": 1004, "message": "Invalid zone"}],
            }).encode()
            raise HTTPError(url, 400, "Bad Request", {}, BytesIO(error))

        port = CloudflareExactDNS(lambda: self.state, transport=failure)
        with self.assertRaises(DNSHold):
            port.snapshot()
        self.assertEqual(len(observed), 1)
        self.assertNotIn("X-Auth-Key", observed[0][1])

    def test_failed_both_auth_modes_never_attempts_put(self):
        self.state["email"] = "legacy@example.test"
        observed = []

        def failure(url, headers, payload=None, method="GET"):
            observed.append((method, dict(headers)))
            if method != "GET":
                raise AssertionError("DNS mutation after auth failure")
            return {
                "success": False,
                "errors": [{"code": 9106, "message": "Authentication failed"}],
            }

        port = CloudflareExactDNS(lambda: self.state, transport=failure)
        with self.assertRaises(DNSHold):
            port.snapshot()
        self.assertEqual([method for method, _ in observed], ["GET", "GET"])

    def test_rotating_credentials_discards_prior_auth_mode(self):
        self.state["email"] = "legacy@example.test"
        observed = []

        def mixed(url, headers, payload=None, method="GET"):
            observed.append(dict(headers))
            if headers.get("Authorization") == "Bearer testtoken":
                return {"success": False, "errors": [{"code": 9106}]}
            return self.transport(url, headers, payload, method)

        port = CloudflareExactDNS(lambda: self.state, transport=mixed)
        port.snapshot()
        self.assertEqual(port._auth_mode, "global")
        self.state["token"] = "rotated-token"
        port.snapshot()
        self.assertEqual(port._auth_mode, "bearer")
        self.assertEqual(observed[-1].get("Authorization"), "Bearer rotated-token")

    def test_credential_change_after_get_before_put_blocks_write(self):
        """Never PUT with an unverified token if settings change mid-operation."""
        self.state["tls_passthrough"] = "0"
        observed = []
        get_count = [0]

        def rotate(url, headers, payload=None, method="GET"):
            observed.append(method)
            result = self.transport(url, headers, payload, method)
            if method == "GET":
                get_count[0] += 1
                if get_count[0] == 2:
                    # First GET sets up baseline; second is the write preflight.
                    self.state["token"] = "rotated-token"
            return result

        port = CloudflareExactDNS(lambda: self.state, transport=rotate)
        baseline = port.snapshot()
        with self.assertRaisesRegex(DNSHold, "DNS_AUTH_NOT_VERIFIED"):
            port.set_all(baseline, "2.3.4.5")
        self.assertNotIn("PUT", observed)

    def test_proxied_records_are_rejected(self):
        def proxy(url, headers, payload=None, method="GET"):
            return {"success": True, "result": [
                {"id": "x", "name": "ssh.example.test", "type": "A",
                 "content": "1.2.3.4", "proxied": True}
            ]}
        self.state["tls_passthrough"] = "0"
        p = CloudflareExactDNS(lambda: self.state, transport=proxy)
        with self.assertRaises(DNSHold):
            p.snapshot()

if __name__ == "__main__":
    unittest.main()
