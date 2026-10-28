"""P5 opt-in guarded CZ04B tests against the same SQLite/FakeDNS fixtures.

No live Cloudflare, provider, Core network or SSH mutations. Existing CZ04B
legacy tests remain unchanged for backwards compatibility and risk review.
"""
import unittest

from cloudzy_cz04b import CutoverHold
from cloudzy_cz04b_guarded import GuardedCloudzy04B
from tests.test_cloudzy_cz04b import CZ04BTests

SRC = "203.0.113.11"
DST = "203.0.113.12"

class GuardedRouteTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fixture = CZ04BTests(methodName="test_successful_route_keeps_users_and_source_unchanged")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        fixture.manager = GuardedCloudzy04B(
            db_conn=fixture.db, guard=fixture.guard, provider=fixture.provider,
            probe=fixture.probe, nat=fixture.nat, dns=fixture.dns,
            enabled=lambda: fixture.enable, now=lambda: fixture.now[0])

    async def route(self):
        await self.fixture.confirmed_route()

    async def preview_only(self):
        await self.fixture.cb("apps_cz5_home")
        chosen = next(c for c in self.fixture.q.callbacks
                      if c.startswith("apps_cz5_target_"))
        await self.fixture.cb(chosen)

    def state(self):
        with self.fixture.db() as db:
            route = db.execute(
                "SELECT host FROM host_pool WHERE is_default=1").fetchone()[0]
            status = db.execute(
                "SELECT status FROM cloudzy_cz04b_operations "
                "WHERE kind='route'").fetchone()
            lease = db.execute(
                "SELECT status FROM failover_operations ORDER BY id DESC LIMIT 1"
            ).fetchone()
            return route, status[0] if status else None, lease[0] if lease else None

    async def test_success_route_uses_original_6g_and_preserves_customers(self):
        await self.route()
        self.assertEqual(self.state(), (DST,"READY","SUCCEEDED"))
        self.assertEqual([x["ip"] for x in self.fixture.dns.records],[DST,DST])
        with self.fixture.db() as db:
            self.assertEqual(
                db.execute("SELECT host FROM ssh_accounts WHERE username='alice'").fetchone()[0],
                SRC)
        self.assertEqual(len(self.fixture.dns.calls), 2)

    async def test_partial_first_dns_write_holds_without_any_rollback(self):
        self.fixture.dns.fail_after = 0
        await self.route()
        self.assertEqual(self.state(),(SRC,"HOLD","RUNNING"))
        self.assertEqual([x["ip"] for x in self.fixture.dns.records],[DST,SRC])
        self.assertEqual(self.fixture.dns.calls,[("write",DST,0)])
        self.assertIn("متوقف شد",self.fixture.q.sent[-1])

    async def test_dns_provider_changed_after_intent_remains_held(self):
        self.fixture.dns.fail_after = 1
        await self.route()
        self.assertEqual(self.state(),(SRC,"HOLD","RUNNING"))
        self.assertEqual(len(self.fixture.dns.calls), 2)
        self.assertEqual({r["ip"] for r in self.fixture.dns.records},{DST})
        # An accepted remote write followed by local failure is never undone.

    async def test_preintent_dns_identity_drift_releases_unused_lease(self):
        dns = self.fixture.dns
        orig = dns.snapshot
        calls = [0]
        def changed_record_id():
            calls[0] += 1
            data = orig()
            if calls[0] == 2:
                data[0]["id"] = "unexpected-record-id"
            return data
        dns.snapshot = changed_record_id
        await self.route()
        self.assertEqual(self.state(),(SRC,None,"FAILED"))
        self.assertEqual(dns.calls, [])

    async def test_provider_read_veto_before_lease(self):
        self.fixture.provider_good = False
        await self.preview_only()
        self.assertEqual(self.state(),(SRC,None,None))
        self.assertEqual(self.fixture.dns.calls, [])

    async def test_source_customer_fingerprint_drift_before_commit_holds(self):
        fixture = self.fixture
        original = fixture.manager._commit_route
        def modified(opid, state):
            with fixture.db() as db:
                db.execute(
                    "INSERT INTO ssh_accounts VALUES "
                    "('late',?,'🟢 فعال','ssh')", (SRC,))
            return original(opid, state)
        fixture.manager._commit_route = modified
        await self.route()
        self.assertEqual(self.state(),(SRC,"HOLD","RUNNING"))
        self.assertEqual([x["ip"] for x in fixture.dns.records],[DST,DST])
        self.assertEqual(len(fixture.dns.calls), 2)

    async def test_db_commit_then_dns_postcheck_fails_holds_target(self):
        fixture = self.fixture
        fixture.manager._route_db_postcheck = lambda *_: (
            (_ for _ in ()).throw(RuntimeError("postcheck unavailable")))
        await self.route()
        self.assertEqual(self.state(),(DST,"HOLD","RUNNING"))
        self.assertEqual([x["ip"] for x in fixture.dns.records],[DST,DST])

    async def test_legacy_host_order_and_standby_leak_block_before_dns(self):
        for new_hosts in ("203.0.113.13,203.0.113.11",
                          "203.0.113.11,203.0.113.12",
                          "203.0.113.11,203.0.113.20"):
            with self.subTest(hosts=new_hosts):
                with self.fixture.db() as db:
                    db.execute("UPDATE settings SET value=? WHERE key='hosts'",
                               (new_hosts,))
                await self.preview_only()
                self.assertEqual(self.state(),(SRC,None,None))
                self.assertEqual(self.fixture.dns.calls,[])
                with self.fixture.db() as db:
                    db.execute("UPDATE settings SET value=? WHERE key='hosts'",
                               (SRC,))

    async def test_original_6g_running_stops_another_route(self):
        with self.fixture.db() as db:
            db.execute(
                "INSERT INTO failover_operations "
                "(mode,source_host,target_host,status) VALUES "
                "('manual',?,?,'RUNNING')",(SRC,DST))
        await self.preview_only()
        self.assertEqual(self.fixture.dns.calls, [])
        self.assertEqual(self.state(),(SRC,None,"RUNNING"))

if __name__ == "__main__":
    unittest.main()
