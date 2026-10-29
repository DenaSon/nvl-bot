"""CZ-07 offline queue tests: SQLite journal and fail-closed gates."""
from contextlib import contextmanager
from tempfile import TemporaryDirectory
from pathlib import Path
import sqlite3
import unittest

from cloudzy_cz07_queue import DurableCutoverQueue, CZ07Hold, BATCH_SIZE


class Fake04B:
    def __init__(self):
        self.source = "source.example"
        self.target = "target.example"
    def enabled(self):
        return True
    def guard(self, db):
        pass
    def _settings(self, db):
        return dict(db.execute("SELECT key,value FROM settings"))
    def _guard_settings(self, st):
        if st.get("auto_failover_mode") == "1":
            raise CZ07Hold("AUTO_FAILOVER_ENABLED")
    def _open(self, db):
        return None
    def _source_accounts(self, db, source):
        return db.execute("SELECT username,host,status FROM ssh_accounts "
                          "WHERE host=? ORDER BY username", (source,)).fetchall()
    def _expect_dns(self, values, target):
        if not values or any(value["ip"] != target for value in values):
            raise CZ07Hold("DNS_CHANGED")


class FakeDNS:
    def __init__(self, source, target):
        self.current, self.source, self.target = source, source, target
    def snapshot(self):
        return [{"name": "dns.example", "ip": self.current}]


class DryRun04B(Fake04B):
    def __init__(self, db):
        super().__init__()
        self.db = db
        self.dns = FakeDNS(self.source, self.target)
        self.route_calls = 0
        self.batch_sizes = []
    def _state(self, target):
        with self.db() as db:
            rows=self._source_accounts(db,self.source)
        return {"source":self.source,"target":self.target,
                "provider_id":"provider-1","users":rows}
    async def _run_route(self, actor, chat, target):
        self.route_calls += 1
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host=?", (self.source,))
            db.execute("UPDATE host_pool SET is_default=1,is_standby=0 WHERE host=?", (self.target,))
            db.execute("UPDATE settings SET value=? WHERE key='hosts'",
                       (self.target+","+self.source,))
            db.execute("UPDATE settings SET value=? WHERE key='dns_current_ip'",
                       (self.target,))
        self.dns.current = target
        return "READY"
    def _route_ready(self):
        return self.source,self.target,"provider-1"
    def _expect_dns(self, values, target):
        if any(value["ip"] != target for value in values):
            raise CZ07Hold("DNS_CHANGED")
    def _migration_snapshot(self, source, target):
        from cloudzy_cz04b import _digest
        with self.db() as db:
            rows = self._source_accounts(db,source)
        return rows,_digest(rows)
    def _ready_probe_state(self, source, target, pid):
        return {}
    async def _fresh(self, state):
        return
    async def _run_users(self, actor, chat, names, fingerprint):
        from cloudzy_cz04b import _digest
        with self.db() as db:
            rows = self._source_accounts(db,self.source)
            if _digest(rows) != fingerprint:
                raise CZ07Hold("ACCOUNT_CAS_CHANGED")
            for name in names:
                db.execute("UPDATE ssh_accounts SET host=? WHERE username=? AND host=?",
                           (self.target,name,self.source))
        self.batch_sizes.append(len(names))
        return len(names)


class OfflineApp:
    class Bot:
        async def send_message(self, chat, text):
            return
    bot = Bot()


class QueueTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name)/"test.db"
        @contextmanager
        def factory():
            db = sqlite3.connect(path)
            try:
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()
        self.factory = factory
        with factory() as db:
            db.executescript("""
                CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
                CREATE TABLE host_pool(host TEXT,active INTEGER,is_default INTEGER,
                    is_standby INTEGER,provider TEXT,provider_instance_id TEXT);
                CREATE TABLE ssh_accounts(username TEXT,host TEXT,status TEXT,service_type TEXT);
                CREATE TABLE cloudzy_cz06_runs(operation_id TEXT,actor_id INTEGER,
                    chat_id INTEGER,stage TEXT,updated_at INTEGER);
                CREATE TABLE cloudzy_edge_operations(id TEXT,status TEXT,
                    public_ipv4 TEXT,provider_server_id TEXT);
                CREATE TABLE failover_operations(status TEXT);
                CREATE TABLE cloudzy_cz04a_actions(status TEXT, host TEXT);
                CREATE TABLE cloudzy_cz04b_operations(
                    source TEXT,target TEXT,status TEXT,started_at INTEGER);
            """)
            db.executemany("INSERT INTO settings VALUES(?,?)", [
                ("hosts","source.example"),("dns_current_ip","source.example"),
                ("auto_failover_mode","0")])
            db.executemany("INSERT INTO host_pool VALUES(?,?,?,?,?,?)", [
                ("source.example",1,1,0,"",""),
                ("target.example",1,0,1,"cloudzy","provider-1")])
            db.execute("INSERT INTO cloudzy_cz06_runs VALUES (?,?,?,?,?)",
                       ("purchase-1",7,8,"READY",1))
            db.execute("INSERT INTO cloudzy_edge_operations VALUES (?,?,?,?)",
                       ("purchase-1","EDGE_READY","target.example","provider-1"))
            db.executemany("INSERT INTO ssh_accounts VALUES(?,?,?,?)",[
                (f"user{i:04}","source.example","active","ssh") for i in range(473)])
        self.fake=Fake04B()
        self.q=DurableCutoverQueue(db_conn=factory,cz04b=self.fake,
                                   enabled=lambda:True,now=lambda:100)

    def test_capacity_bound_and_exact_candidate(self):
        self.assertEqual(BATCH_SIZE, 200)
        self.assertEqual(self.q.candidate()[:3],
                         ("purchase-1","target.example","provider-1"))

    def test_readiness_reports_exact_standby_prerequisites(self):
        self.assertTrue(self.q.readiness()["ready"])
        with self.factory() as db:
            db.execute("UPDATE cloudzy_cz06_runs SET stage='HOLD'")
        state = self.q.readiness()
        self.assertFalse(state["ready"])
        self.assertEqual(state["code"], "CZ06_HOLD")
        self.assertTrue(state["manual_standby"])
        with self.factory() as db:
            db.execute("UPDATE cloudzy_cz06_runs SET stage='READY'")
            db.execute("UPDATE host_pool SET active=0,is_standby=0 WHERE host='target.example'")
        state = self.q.readiness()
        self.assertFalse(state["ready"])
        self.assertEqual(state["code"], "STANDBY_NOT_READY")
        with self.factory() as db:
            db.execute("DELETE FROM cloudzy_cz06_runs")
        self.assertEqual(self.q.readiness()["code"], "NO_CZ06_RUN")

    def test_cancelled_cz06_receipt_never_becomes_a_destination(self):
        """Real operator feedback: cancelled .127, newer manual .157."""
        with self.factory() as db:
            db.execute("UPDATE cloudzy_cz06_runs SET stage='CANCELLED'")
            db.execute(
                "UPDATE cloudzy_edge_operations SET public_ipv4='144.172.68.127' "
                "WHERE id='purchase-1'"
            )
            db.execute(
                "INSERT INTO cloudzy_edge_operations "
                "(id,status,public_ipv4,provider_server_id) VALUES (?,?,?,?)",
                ("manual-2","EDGE_READY","144.172.68.157","provider-2")
            )
            db.execute(
                "INSERT INTO host_pool VALUES (?,?,?,?,?,?)",
                ("144.172.68.157",0,0,0,"cloudzy","provider-2")
            )
        state = self.q.readiness()
        self.assertFalse(state["ready"])
        self.assertIsNone(state["target"])
        self.assertEqual(state["code"], "CZ06_CANCELLED")
        self.assertEqual(state["last_quick_ip"], "144.172.68.127")
        with self.assertRaisesRegex(CZ07Hold, "NO_VERIFIED_CZ06_STANDBY"):
            self.q.candidate()

        from asyncio import run
        class Query:
            def __init__(self):
                self.message = self
                self.text = ""
                self.callbacks = []
            async def edit_message_text(self, text, **kwargs):
                self.text = text
                self.callbacks = [
                    value for row in kwargs["reply_markup"] for _, value in row
                ]
            async def reply_text(self, text, **kwargs):
                self.text = text

        query = Query()
        context = type("Ctx", (), {"user_data": {}})()
        run(self.q.handle_callback(
            query, context, "apps_cz7_home", role="admin",
            actor=7, chat=8, markup=lambda rows: rows, app=None
        ))
        self.assertIn("مقصد معتبر برای CZ-07", query.text)
        self.assertIn("وجود ندارد", query.text)
        self.assertIn("آخرین پرونده Quick Relay (لغوشده)", query.text)
        self.assertIn("144.172.68.127", query.text)
        self.assertIn("این IP مقصد انتقال نیست", query.text)
        self.assertNotIn("مقصد: <code>144.172.68.127</code>", query.text)
        self.assertNotIn("مقصد: <code>144.172.68.157</code>", query.text)
        self.assertNotIn("apps_cz7_preview", query.callbacks)
        self.assertIn("apps_cz4_vps", query.callbacks)
        self.assertIn("apps_cz_operations", query.callbacks)
        # Idempotent read-only navigation: no job reserved, no migration.
        self.assertIsNone(self.q.latest())

    def test_unqualified_recent_standby_is_not_presented_as_destination(self):
        with self.factory() as db:
            db.execute("UPDATE cloudzy_cz06_runs SET stage='HOLD'")
        snapshot = self.q.readiness()
        self.assertEqual(snapshot["code"], "CZ06_HOLD")
        self.assertIsNone(snapshot["target"])
        self.assertEqual(snapshot["last_quick_ip"], "target.example")
        self.assertTrue(snapshot["manual_standby"])

    def test_verified_candidate_still_presents_its_actual_destination(self):
        snapshot = self.q.readiness()
        self.assertTrue(snapshot["ready"])
        self.assertEqual(snapshot["target"], "target.example")
        self.assertNotIn("last_quick_ip", snapshot)

    def test_fresh_install_without_cz06_tables_shows_help(self):
        with self.factory() as db:
            db.execute("DROP TABLE cloudzy_cz06_runs")
            db.execute("DROP TABLE cloudzy_edge_operations")
        state = self.q.readiness()
        self.assertEqual(state["code"], "NO_CZ06_RUN")
        self.assertFalse(state["ready"])

    def test_cz07_entry_shows_guidance_without_errors_or_mutations(self):
        class Query:
            def __init__(self):
                self.message = self
                self.text = ""
                self.callbacks = []

            async def edit_message_text(self, text, **kw):
                self.text = text
                self.callbacks = [callback for row in kw["reply_markup"]
                                  for _label, callback in row]

            async def reply_text(self, text, **_kw):
                self.text = text

        async def view(actor=7):
            query = Query()
            ctx = type("Ctx", (), {"user_data": {}})()
            await self.q.handle_callback(
                query, ctx, "apps_cz7_home", role="admin", actor=actor,
                chat=8, markup=lambda rows: rows, app=None)
            return query

        from asyncio import run
        ready = run(view())
        self.assertIn("CZ-07 | آمادگی", ready.text)
        self.assertIn("apps_cz7_preview", ready.callbacks)
        other = run(view(actor=99))
        self.assertNotIn("apps_cz7_preview", other.callbacks)
        self.assertIn("ثبت‌کننده", other.text)
        with self.factory() as db:
            db.execute("UPDATE cloudzy_cz06_runs SET stage='HOLD'")
        blocked = run(view())
        self.assertIn("توقف", blocked.text)
        self.assertIn("apps_cz_operations", blocked.callbacks)
        self.assertIn("apps_cz5_home", blocked.callbacks)
        self.assertNotIn("apps_cz7_preview", blocked.callbacks)
        # Repeat navigation edits a single message; no paid or route operation.
        self.assertIsNone(self.q.latest())

    def test_cz07_status_screen_uses_persian_stage_and_guarded_actions(self):
        from cloudzy_cz04b import _digest
        from asyncio import run

        class Query:
            def __init__(self):
                self.text, self.callbacks = "", []

            async def edit_message_text(self, text, **kw):
                self.text = text
                self.callbacks = [callback for row in kw["reply_markup"]
                                  for _label, callback in row]

        with self.factory() as db:
            rows = self.fake._source_accounts(db, "source.example")
        job_id = self.q.reserve(self.q.candidate(), "source.example",
                                actor=7, chat=8, expected_fp=_digest(rows),
                                expected_count=473)
        self.q.transition(job_id, "QUEUED", "ROUTING", code="ROUTE_START")
        query = Query()
        run(self.q._show_status(query, self.q.get(job_id),
                                lambda rows: rows, 7, 8))
        self.assertIn("در حال بررسی و تنظیم مسیر", query.text)
        self.assertIn("apps_cz7_status", query.callbacks)
        self.assertFalse(any(x.startswith("apps_cz7_resume_") for x in query.callbacks))
        self.q.transition(job_id, "ROUTING", "HOLD", code="ROUTE_UNVERIFIED")
        run(self.q._show_status(query, self.q.get(job_id),
                                lambda rows: rows, 7, 8))
        self.assertIn("توقف امن", query.text)
        self.assertIn("ROUTE_UNVERIFIED", query.text)
        self.assertNotIn("ادامه امن صف", query.text)

    def test_authorization_one_job_and_durable_events(self):
        from cloudzy_cz04b import _digest
        with self.factory() as db:
            rows = self.fake._source_accounts(db,"source.example")
        candidate = self.q.candidate()
        with self.assertRaises(CZ07Hold):
            self.q.reserve(candidate,"source.example",actor=20,chat=8,
                           expected_fp=_digest(rows),expected_count=473)
        job=self.q.reserve(candidate,"source.example",actor=7,chat=8,
                           expected_fp=_digest(rows),expected_count=473)
        self.assertEqual(self.q.get(job)["status"],"QUEUED")
        self.q.transition(job,"QUEUED","ROUTING",code="ROUTE_START")
        self.assertEqual(self.q.get(job)["status"],"ROUTING")
        with self.assertRaises(CZ07Hold):
            self.q.transition(job,"QUEUED","MIGRATING")
        with self.assertRaises(CZ07Hold):
            self.q.reserve(candidate,"source.example",actor=7,chat=8,
                           expected_fp=_digest(rows),expected_count=473)
        self.assertEqual(len(self.q.events(job)),2)

    def test_host_pin_guard_without_verified_cutover(self):
        from cloudzy_cz04b import _digest
        with self.factory() as db:
            rows=self.fake._source_accounts(db,"source.example")
        job=self.q.reserve(self.q.candidate(),"source.example",actor=7,chat=8,
                           expected_fp=_digest(rows),expected_count=473)
        self.q.transition(job,"QUEUED","MIGRATING",code="TEST_ONLY")
        with self.assertRaises(CZ07Hold):
            self.q.route_pin(job)
        with self.factory() as db:
            self.assertEqual(db.execute(
                "SELECT value FROM settings WHERE key='hosts'").fetchone()[0],
                "source.example")

    def test_dry_run_473_accounts_through_bounded_worker(self):
        from cloudzy_cz04b import _digest
        import asyncio
        dry=DryRun04B(self.factory)
        self.q.cz04b=dry
        with self.factory() as db:
            rows=dry._source_accounts(db,dry.source)
        job=self.q.reserve(self.q.candidate(),dry.source,actor=7,chat=8,
                           expected_fp=_digest(rows),expected_count=len(rows))
        asyncio.run(self.q._work(job,OfflineApp(),resume=False))
        final=self.q.get(job)
        self.assertEqual(final["status"],"VERIFYING")
        self.assertEqual((final["moved"],final["total"]),(473,473))
        self.assertEqual(dry.route_calls,1)
        self.assertEqual(dry.batch_sizes,[200,200,73])
        with self.factory() as db:
            self.assertEqual(db.execute("SELECT value FROM settings WHERE key='hosts'").fetchone()[0],
                             dry.target)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM ssh_accounts WHERE host=?",
                                        (dry.target,)).fetchone()[0],473)


    def test_completed_transport_unlocks_new_standby_without_fake_e2e_done(self):
        from cloudzy_cz04b import _digest
        import asyncio
        dry = DryRun04B(self.factory)
        self.q.cz04b = dry
        with self.factory() as db:
            rows = dry._source_accounts(db, dry.source)
        job = self.q.reserve(self.q.candidate(), dry.source, actor=7, chat=8,
                             expected_fp=_digest(rows), expected_count=len(rows))
        asyncio.run(self.q._work(job, OfflineApp(), resume=False))
        old = self.q.get(job)
        self.assertEqual(old["status"], "VERIFYING")
        with self.factory() as db:
            db.execute("INSERT INTO cloudzy_cz06_runs VALUES(?,?,?,?,?)",
                       ("purchase-2",7,8,"READY",2))
            db.execute("INSERT INTO cloudzy_edge_operations VALUES (?,?,?,?)",
                       ("purchase-2","EDGE_READY","next.example","provider-2"))
            db.execute("INSERT INTO host_pool VALUES(?,?,?,?,?,?)",
                       ("next.example",1,0,1,"cloudzy","provider-2"))
        # The next transfer stays blocked until the old transport is audited.
        with self.factory() as db:
            next_rows = dry._source_accounts(db, dry.target)
        with self.assertRaisesRegex(CZ07Hold, "ANOTHER_CZ07_JOB_UNRESOLVED"):
            self.q.reserve(self.q.candidate(), dry.target, actor=7, chat=8,
                           expected_fp=_digest(next_rows),
                           expected_count=len(next_rows))
        self.assertTrue(self.q.complete_transport(
            job, actor=7, chat=8, expected_updated_at=old["updated_at"]))
        record = self.q.get(job)
        self.assertEqual(record["status"], "MOVED")
        self.assertEqual(record["code"], "TRANSPORT_VERIFIED_POSTCHECK_PENDING")
        with self.factory() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM cloudzy_cz07_acceptance"
            ).fetchone()[0], 0)
        with self.assertRaisesRegex(CZ07Hold, "TRANSPORT_NOT_READY"):
            self.q.complete_transport(
                job, actor=7, chat=8, expected_updated_at=old["updated_at"])
        # The original 485-style cohort is not transferred again.
        self.assertEqual(dry.batch_sizes, [200, 200, 73])
        new_job = self.q.reserve(self.q.candidate(), dry.target,
                                 actor=7, chat=8,
                                 expected_fp=_digest(next_rows),
                                 expected_count=len(next_rows))
        self.assertEqual(self.q.get(new_job)["status"], "QUEUED")
        self.assertEqual(self.q.get(job)["status"], "MOVED")

    def test_transfer_cannot_close_on_moved_count_alone_or_wrong_owner(self):
        from cloudzy_cz04b import _digest
        import asyncio
        dry = DryRun04B(self.factory)
        self.q.cz04b = dry
        with self.factory() as db:
            rows = dry._source_accounts(db, dry.source)
        job = self.q.reserve(self.q.candidate(), dry.source, actor=7, chat=8,
                             expected_fp=_digest(rows), expected_count=len(rows))
        asyncio.run(self.q._work(job, OfflineApp(), resume=False))
        version = self.q.get(job)["updated_at"]
        with self.assertRaisesRegex(CZ07Hold, "TRANSPORT_OWNER_MISMATCH"):
            self.q.complete_transport(
                job, actor=99, chat=8, expected_updated_at=version)
        dry.dns.current = dry.source
        with self.assertRaisesRegex(CZ07Hold, "DNS_CHANGED"):
            self.q.complete_transport(
                job, actor=7, chat=8, expected_updated_at=version)
        dry.dns.current = dry.target
        with self.factory() as db:
            db.execute("UPDATE ssh_accounts SET host=? WHERE username=?",
                       (dry.source, "user0001"))
        with self.assertRaisesRegex(CZ07Hold, "TRANSPORT_SOURCE_NOT_EMPTY|ACTIVE_SSH_OUTSIDE_TARGET"):
            self.q.complete_transport(
                job, actor=7, chat=8, expected_updated_at=version)
        self.assertEqual(self.q.get(job)["status"], "VERIFYING")
        with self.factory() as db:
            db.execute("UPDATE ssh_accounts SET host=? WHERE username=?",
                       (dry.target, "user0001"))
        self.assertTrue(self.q.complete_transport(
            job, actor=7, chat=8, expected_updated_at=version))

    def test_verifying_to_moved_callback_requires_fresh_checks_and_one_time_approval(self):
        from cloudzy_cz04b import _digest
        import asyncio

        class Query:
            def __init__(self):
                self.text = ""
                self.callbacks = []
            async def edit_message_text(self, text, **kwargs):
                self.text = text
                self.callbacks = [cb for row in kwargs["reply_markup"]
                                  for _label, cb in row]

        dry = DryRun04B(self.factory)
        self.q.cz04b = dry
        with self.factory() as db:
            rows = dry._source_accounts(db, dry.source)
        job = self.q.reserve(self.q.candidate(), dry.source, actor=7, chat=8,
                             expected_fp=_digest(rows), expected_count=len(rows))
        asyncio.run(self.q._work(job, OfflineApp(), resume=False))
        query = Query()
        ctx = type("Ctx", (), {"user_data": {}})()
        async def click(data, actor=7, chat=8):
            await self.q.handle_callback(query, ctx, data, role="admin",
                                         actor=actor, chat=chat,
                                         markup=lambda rows: rows, app=None)
        asyncio.run(self.q._show_status(query, self.q.get(job),
                                        lambda rows: rows, 7, 8))
        self.assertIn("apps_cz7_transport_review_"+job, query.callbacks)
        asyncio.run(click("apps_cz7_transport_review_"+job, actor=9, chat=9))
        self.assertEqual(self.q.get(job)["status"], "VERIFYING")
        asyncio.run(click("apps_cz7_transport_review_"+job))
        confirm = next(x for x in query.callbacks
                       if x.startswith("apps_cz7_transport_go_"))
        self.assertEqual(self.q.get(job)["status"], "VERIFYING")
        dry.dns.current = dry.source
        asyncio.run(click(confirm))
        self.assertEqual(self.q.get(job)["status"], "VERIFYING")
        dry.dns.current = dry.target
        asyncio.run(click("apps_cz7_transport_review_"+job))
        confirm = next(x for x in query.callbacks
                       if x.startswith("apps_cz7_transport_go_"))
        asyncio.run(click(confirm))
        self.assertEqual(self.q.get(job)["status"], "MOVED")
        self.assertIn("apps_cz7_home", query.callbacks)
        asyncio.run(click(confirm))
        self.assertEqual(self.q.get(job)["status"], "MOVED")
        self.assertEqual(dry.batch_sizes, [200, 200, 73])

    def test_200_batch_boundary_and_independent_business_acceptance(self):
        from cloudzy_cz04b import _digest
        import asyncio

        dry = DryRun04B(self.factory)
        self.q.cz04b = dry
        with self.factory() as db:
            rows = dry._source_accounts(db, dry.source)
        job = self.q.reserve(self.q.candidate(), dry.source, actor=7, chat=8,
                             expected_fp=_digest(rows), expected_count=len(rows))
        asyncio.run(self.q._work(job, OfflineApp(), resume=False))
        self.assertEqual(self.q.get(job)["status"], "VERIFYING")
        self.assertEqual(dry.batch_sizes, [200, 200, 73])
        with self.assertRaisesRegex(CZ07Hold, "INDEPENDENT_BUSINESS_VERIFIER_REQUIRED"):
            self.q.accept_business(
                job, actor=7, chat=8, create_ref="create-ref-001",
                renew_ref="renew-ref-001", client_ref="client-ref-001")
        with self.assertRaisesRegex(CZ07Hold, "BUSINESS_E2E_NOT_VERIFIED"):
            self.q.accept_business(
                job, actor=7, chat=8, create_ref="create-ref-001",
                renew_ref="renew-ref-001", client_ref="client-ref-001",
                independent_verify=lambda **kw: False)
        self.assertEqual(self.q.get(job)["status"], "VERIFYING")
        captured = []
        def independently_confirm(**kwargs):
            captured.append(kwargs)
            return kwargs["target"] == dry.target
        self.assertTrue(self.q.accept_business(
            job, actor=7, chat=8, create_ref="create-ref-001",
            renew_ref="renew-ref-001", client_ref="client-ref-001",
            independent_verify=independently_confirm))
        self.assertEqual(self.q.get(job)["status"], "DONE")
        self.assertEqual(self.q.get(job)["code"], "BUSINESS_E2E_ACCEPTED")
        self.assertEqual(len(captured), 1)
        with self.factory() as db:
            self.assertEqual(db.execute(
                "SELECT create_ref,renew_ref,client_ref "
                "FROM cloudzy_cz07_acceptance WHERE job_id=?",
                (job,)).fetchone(),
                ("create-ref-001", "renew-ref-001", "client-ref-001"))

    def test_verifying_has_safe_acceptance_action_and_missing_witness_never_closes(self):
        from cloudzy_cz04b import _digest
        import asyncio

        class Query:
            def __init__(self):
                self.text = ""
                self.callbacks = []

            async def edit_message_text(self, text, **kwargs):
                self.text = text
                self.callbacks = [cb for row in kwargs["reply_markup"]
                                  for _label, cb in row]

        dry = DryRun04B(self.factory)
        self.q.cz04b = dry
        with self.factory() as db:
            rows = dry._source_accounts(db, dry.source)
        job = self.q.reserve(self.q.candidate(), dry.source, actor=7, chat=8,
                             expected_fp=_digest(rows), expected_count=len(rows))
        asyncio.run(self.q._work(job, OfflineApp(), resume=False))
        self.assertEqual(self.q.get(job)["status"], "VERIFYING")
        query = Query()
        asyncio.run(self.q._show_status(query, self.q.get(job),
                                        lambda rows: rows, 7, 8))
        self.assertIn("apps_cz7_accept_review_" + job, query.callbacks)
        ctx = type("Ctx", (), {"user_data": {}})()
        asyncio.run(self.q.handle_callback(
            query, ctx, "apps_cz7_accept_review_" + job,
            role="admin", actor=7, chat=8,
            markup=lambda rows: rows, app=None))
        self.assertIn("منبع مستقل شواهد", query.text)
        self.assertEqual(self.q.get(job)["status"], "VERIFYING")
        self.assertNotIn("apps_cz7_accept_go_", str(query.callbacks))
        # A different admin cannot access the signed evidence review.
        asyncio.run(self.q.handle_callback(
            query, ctx, "apps_cz7_accept_review_" + job,
            role="admin", actor=9, chat=9,
            markup=lambda rows: rows, app=None))
        self.assertEqual(self.q.get(job)["status"], "VERIFYING")

    def test_authenticated_witness_acceptance_requires_confirm_and_fresh_receipt(self):
        from cloudzy_cz04b import _digest
        from cloudzy_cz07_acceptance import AcceptanceReview
        import asyncio

        class Witness:
            def __init__(self):
                self.stale = False
            def review(self, job):
                return AcceptanceReview(True, "TRUSTED_WITNESS_VERIFIED",
                    "create-proof-1001", "renew-proof-1002", "client-proof-1003",
                    "b" * 64 if self.stale else "a" * 64)
            def verify(self, job, *, create_ref, renew_ref, client_ref, fingerprint):
                return (job["status"] == "VERIFYING" and not self.stale
                        and fingerprint == "a" * 64
                        and (create_ref, renew_ref, client_ref) ==
                            ("create-proof-1001", "renew-proof-1002", "client-proof-1003"))

        class Query:
            def __init__(self):
                self.text = ""
                self.callbacks = []
            async def edit_message_text(self, text, **kwargs):
                self.text = text
                self.callbacks = [cb for row in kwargs["reply_markup"]
                                  for _label, cb in row]

        dry = DryRun04B(self.factory)
        self.q.cz04b = dry
        with self.factory() as db:
            rows = dry._source_accounts(db, dry.source)
        job = self.q.reserve(self.q.candidate(), dry.source, actor=7, chat=8,
                             expected_fp=_digest(rows), expected_count=len(rows))
        asyncio.run(self.q._work(job, OfflineApp(), resume=False))
        witness = Witness()
        self.q.acceptance_witness = witness
        ctx = type("Ctx", (), {"user_data": {}})()
        query = Query()
        async def press(action):
            await self.q.handle_callback(query, ctx, action, role="admin",
                                         actor=7, chat=8,
                                         markup=lambda rows: rows, app=None)
        asyncio.run(press("apps_cz7_accept_review_" + job))
        self.assertIn("شواهد مستقل تأیید شدند", query.text)
        confirm = next(cb for cb in query.callbacks
                       if cb.startswith("apps_cz7_accept_go_"))
        self.assertEqual(self.q.get(job)["status"], "VERIFYING")
        witness.stale = True
        asyncio.run(press(confirm))
        self.assertEqual(self.q.get(job)["status"], "VERIFYING")
        self.assertNotIn("DONE", query.text)
        witness.stale = False
        asyncio.run(press("apps_cz7_accept_review_" + job))
        confirm = next(cb for cb in query.callbacks
                       if cb.startswith("apps_cz7_accept_go_"))
        asyncio.run(press(confirm))
        self.assertEqual(self.q.get(job)["status"], "DONE")
        self.assertIn("apps_cz7_home", query.callbacks)
        with self.factory() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM cloudzy_cz07_acceptance WHERE job_id=?",
                (job,)).fetchone()[0], 1)
        asyncio.run(self.q._show_status(query, self.q.get(job),
                                        lambda rows: rows, 7, 8))
        self.assertIn("apps_cz7_home", query.callbacks)
        self.assertNotIn("apps_cz7_accept_review_" + job, query.callbacks)

    def test_safe_cancel_after_batch_and_guarded_resume(self):
        from cloudzy_cz04b import _digest
        import asyncio
        dry = DryRun04B(self.factory)
        self.q.cz04b = dry
        with self.factory() as db:
            rows = dry._source_accounts(db, dry.source)
        job = self.q.reserve(self.q.candidate(), dry.source, actor=7, chat=8,
                             expected_fp=_digest(rows), expected_count=len(rows))
        async def ask_stop(_seconds):
            self.assertTrue(self.q.request_cancel(job, actor=7, chat=8))
            self.assertFalse(self.q.request_cancel(job, actor=7, chat=8))
        self.q.pause = ask_stop
        asyncio.run(self.q._work(job, OfflineApp(), resume=False))
        self.assertEqual(self.q.get(job)["status"], "PAUSED_SAFE")
        self.assertEqual(self.q.get(job)["moved"], 200)
        self.assertEqual(dry.batch_sizes, [200])
        with self.assertRaisesRegex(CZ07Hold, "RESUME_OWNER_MISMATCH"):
            self.q.resume_paused(job, actor=99, chat=8)
        self.q.resume_paused(job, actor=7, chat=8)
        async def no_delay(_seconds):
            return None
        self.q.pause = no_delay
        asyncio.run(self.q._work(job, OfflineApp(), resume=True))
        self.assertEqual(self.q.get(job)["status"], "VERIFYING")
        self.assertEqual(dry.batch_sizes, [200, 200, 73])

    def test_crash_after_committed_batch_reconstructs_remaining_from_sqlite(self):
        from cloudzy_cz04b import _digest
        import asyncio
        class CrashOnce(DryRun04B):
            crashed = False
            async def _run_users(self, actor, chat, names, fp):
                result = await super()._run_users(actor, chat, names, fp)
                if not self.crashed:
                    self.crashed = True
                    raise SystemExit("SIMULATED_PROCESS_DEATH_AFTER_CAS")
                return result
        dry = CrashOnce(self.factory)
        self.q.cz04b = dry
        with self.factory() as db:
            rows = dry._source_accounts(db, dry.source)
        job = self.q.reserve(self.q.candidate(), dry.source, actor=7, chat=8,
                             expected_fp=_digest(rows), expected_count=len(rows))
        with self.assertRaisesRegex(SystemExit, "SIMULATED_PROCESS_DEATH_AFTER_CAS"):
            asyncio.run(self.q._work(job, OfflineApp(), resume=False))
        self.assertEqual(self.q.get(job)["status"], "MIGRATING")
        self.assertEqual(self.q.get(job)["moved"], 0)
        remaining, derived_moved = self.q.remaining(job)
        self.assertEqual((len(remaining), derived_moved), (273, 200))
        # A restarted process replays no DNS PUT and recovers DB counts.
        fresh = DurableCutoverQueue(db_conn=self.factory, cz04b=dry,
                                    enabled=lambda: True, now=lambda: 120)
        async def no_delay(_seconds):
            return None
        fresh.pause = no_delay
        asyncio.run(fresh._work(job, OfflineApp(), resume=True))
        self.assertEqual(fresh.get(job)["status"], "VERIFYING")
        self.assertEqual(dry.batch_sizes, [200, 200, 73])
        self.assertEqual(dry.route_calls, 1)

    def test_batch_boundaries_do_not_limit_total_job_size(self):
        from cloudzy_cz04b import _digest
        import asyncio
        for count in (0, 1, 50, 51, 200, 201, 493, 495):
            with self.subTest(count=count):
                with self.factory() as db:
                    self.q._init(db)
                    db.execute("DELETE FROM cloudzy_cz07_events")
                    db.execute("DELETE FROM cloudzy_cz07_jobs")
                    db.execute("DELETE FROM cloudzy_cz07_acceptance")
                    db.execute("DELETE FROM ssh_accounts")
                    db.executemany("INSERT INTO ssh_accounts VALUES(?,?,?,?)", [
                        (f"case{idx:04}", "source.example", "active", "ssh")
                        for idx in range(count)])
                    db.execute("UPDATE host_pool SET is_default=CASE "
                               "WHEN host='source.example' THEN 1 ELSE 0 END, "
                               "is_standby=CASE WHEN host='target.example' "
                               "THEN 1 ELSE 0 END")
                    db.execute("UPDATE settings SET value='source.example' "
                               "WHERE key IN ('hosts','dns_current_ip')")
                dry = DryRun04B(self.factory)
                self.q.cz04b = dry
                with self.factory() as db:
                    rows = dry._source_accounts(db, dry.source)
                job = self.q.reserve(self.q.candidate(), dry.source,
                                     actor=7, chat=8,
                                     expected_fp=_digest(rows),
                                     expected_count=count)
                async def no_delay(_seconds):
                    return None
                self.q.pause = no_delay
                asyncio.run(self.q._work(job, OfflineApp(), resume=False))
                self.assertEqual(self.q.get(job)["status"], "VERIFYING")
                self.assertEqual(self.q.get(job)["moved"], count)
                expected = ([200] * (count // 200)
                            + ([count % 200] if count % 200 else []))
                self.assertEqual(dry.batch_sizes, expected)

    def _stale_route(self):
        from cloudzy_cz04b import _digest
        self.fake.dns = FakeDNS(self.fake.source, self.fake.target)
        with self.factory() as db:
            rows = self.fake._source_accounts(db, self.fake.source)
        job = self.q.reserve(self.q.candidate(), self.fake.source,
                             actor=7, chat=8, expected_fp=_digest(rows),
                             expected_count=len(rows))
        self.q.transition(job, "QUEUED", "ROUTING", code="ROUTE_START")
        self.q.now = lambda: 400
        return job

    def test_cloudzy_timeout_journals_hold_instead_of_stuck_routing(self):
        from cloudzy_cz04b import _digest
        from cloudzy_service import CloudzyError
        import asyncio
        class TimedOut04B(DryRun04B):
            async def _run_route(self, actor, chat, target):
                self.route_calls += 1
                raise CloudzyError("Cloudzy read request failed: TimeoutError")
        dry = TimedOut04B(self.factory)
        self.q.cz04b = dry
        with self.factory() as db:
            rows = dry._source_accounts(db, dry.source)
        job = self.q.reserve(self.q.candidate(), dry.source, actor=7, chat=8,
                             expected_fp=_digest(rows), expected_count=len(rows))
        asyncio.run(self.q._work(job, OfflineApp(), resume=False))
        record = self.q.get(job)
        self.assertEqual(record["status"], "HOLD")
        self.assertEqual(record["code"], "CLOUDZY_PROVIDER_UNAVAILABLE")
        self.assertEqual(record["moved"], 0)
        self.assertEqual(self.q.events(job)[0][:2],
                         ("HOLD", "CLOUDZY_PROVIDER_UNAVAILABLE"))
        self.assertEqual(dry.dns.current, dry.source)
        self.assertEqual(dry.route_calls, 1)

    def test_safe_stale_close_and_fresh_approval_rearm_same_cz06(self):
        from cloudzy_cz04b import _digest
        job = self._stale_route()
        with self.assertRaisesRegex(CZ07Hold, "RECOVERY_OWNER_MISMATCH"):
            self.q.recovery_preview(job, 9, 8)
        preview = self.q.recovery_preview(job, 7, 8)
        with self.assertRaisesRegex(CZ07Hold, "RECOVERY_PREVIEW_EXPIRED"):
            self.q.close_stale_route(job, 7, 8, preview["updated_at"]+1)
        self.q.close_stale_route(job, 7, 8, preview["updated_at"])
        closed = self.q.get(job)
        self.assertEqual((closed["status"], closed["code"], closed["moved"]),
                         ("ABORTED", "SAFE_STALE_ROUTING_CLOSED", 0))
        with self.factory() as db:
            db.execute("DELETE FROM ssh_accounts WHERE username='user0000'")
            rows = self.fake._source_accounts(db, self.fake.source)
        # The initial total is now stale, but a fresh independently approved
        # snapshot is allowed. UNIQUE cz06_operation must NOT block it.
        rearmed = self.q.reserve(self.q.candidate(), self.fake.source,
                                 actor=7, chat=8, expected_fp=_digest(rows),
                                 expected_count=len(rows))
        self.assertEqual(rearmed, job)
        item = self.q.get(job)
        self.assertEqual((item["status"], item["total"], item["moved"]),
                         ("QUEUED", 472, 0))
        self.assertEqual(self.q.events(job)[0][:2],
                         ("QUEUED", "RESTART_APPROVED_AFTER_SAFE_ABORT"))
        self.assertTrue(any(stage == "ABORTED" for stage,*rest in self.q.events(job)))
        with self.factory() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM cloudzy_cz07_jobs").fetchone()[0], 1)

    def test_recovery_rejects_worker_and_unverified_dns_and_changed_default(self):
        job = self._stale_route()
        self.q._running.add(job)
        with self.assertRaisesRegex(CZ07Hold, "RECOVERY_WORKER_STILL_ACTIVE"):
            self.q.recovery_preview(job, 7, 8)
        self.q._running.remove(job)
        self.fake.dns.current = self.fake.target
        with self.assertRaisesRegex(CZ07Hold, "RECOVERY_LIVE_DNS_UNVERIFIED"):
            self.q.recovery_preview(job, 7, 8)
        self.fake.dns.current = self.fake.source
        with self.factory() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host=?",
                       (self.fake.source,))
            db.execute("UPDATE host_pool SET is_default=1 WHERE host=?",
                       (self.fake.target,))
        with self.assertRaisesRegex(CZ07Hold, "RECOVERY_DEFAULT_CHANGED"):
            self.q.recovery_preview(job, 7, 8)

    def test_recovery_rejects_route_journal_lock_and_target_accounts(self):
        job = self._stale_route()
        with self.factory() as db:
            db.execute("INSERT INTO cloudzy_cz04b_operations VALUES (?,?,?,?)",
                       (self.fake.source,self.fake.target,"ABORTED",101))
        with self.assertRaisesRegex(CZ07Hold, "RECOVERY_CZ04B_HISTORY_NEEDS_REVIEW"):
            self.q.recovery_preview(job, 7, 8)
        with self.factory() as db:
            db.execute("DELETE FROM cloudzy_cz04b_operations")
            db.execute("INSERT INTO failover_operations VALUES ('RUNNING')")
        with self.assertRaisesRegex(CZ07Hold, "RECOVERY_SHARED_LEASE_BUSY"):
            self.q.recovery_preview(job, 7, 8)
        with self.factory() as db:
            db.execute("DELETE FROM failover_operations")
            db.execute("INSERT INTO ssh_accounts VALUES (?,?,?,?)",
                       ("target-user",self.fake.target,"inactive","ssh"))
        with self.assertRaisesRegex(CZ07Hold, "RECOVERY_TARGET_HAS_ACCOUNTS"):
            self.q.recovery_preview(job, 7, 8)

    def test_recovery_not_immediate_or_after_any_migration(self):
        job = self._stale_route()
        self.q.now = lambda: 110
        with self.assertRaisesRegex(CZ07Hold, "RECOVERY_JOB_NOT_STALE"):
            self.q.recovery_preview(job, 7, 8)
        self.q.now = lambda: 400
        with self.factory() as db:
            self.q._log(db, job, "MIGRATING", "BATCH_CAS_COMMITTED", 1, 472)
        with self.assertRaisesRegex(CZ07Hold, "RECOVERY_MIGRATION_HISTORY_PRESENT"):
            self.q.recovery_preview(job, 7, 8)

    def test_bot_recovery_requires_one_use_confirmation(self):
        from asyncio import run
        job = self._stale_route()
        class Query:
            def __init__(self):
                self.message = self
                self.text = ""
                self.callbacks = []
            async def edit_message_text(self, text, **kw):
                self.text = text
                self.callbacks = [callback for row in kw["reply_markup"]
                                  for _,callback in row]
            async def reply_text(self, text, **kw):
                self.text = text
        query = Query()
        context = type("Ctx", (), {"user_data": {}})()
        async def cb(data, actor=7):
            await self.q.handle_callback(query, context, data, role="admin",
                                         actor=actor,chat=8,markup=lambda x:x,
                                         app=OfflineApp())
        run(cb("apps_cz7_status"))
        callback = "apps_cz7_recover_"+job
        self.assertIn(callback, query.callbacks)
        run(cb(callback))
        confirm = [x for x in query.callbacks if x.startswith("apps_cz7_close_")]
        self.assertEqual(len(confirm), 1)
        run(cb(confirm[0],actor=9))
        self.assertEqual(self.q.get(job)["status"], "ROUTING")
        # Invalid actor consumes confirmation; re-open a fresh preview.
        run(cb(callback))
        renewed = [x for x in query.callbacks if x.startswith("apps_cz7_close_")]
        self.assertEqual(len(renewed), 1)
        self.assertNotEqual(renewed[0], confirm[0])
        run(cb(renewed[0]))
        self.assertEqual(self.q.get(job)["status"], "ABORTED")
        self.assertIn("شروع دوباره از مرحله اول", query.text)



if __name__ == "__main__":
    unittest.main()
