"""UI success notification: DONE-only, exact recipient and at-most-once send.

No actual Cloudflare, SSH, WireGuard, Telegram or customer side effects.
"""
import asyncio
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from manual_quick_switch_ui import ManualQuickSwitchUI, QuickSwitchHold


class RecordingDelivery:
    sent = []
    fail = False

    def __init__(self, bot):
        assert bot.token == "test-token"

    async def send(self, *, chat, text, rows):
        if self.fail:
            raise RuntimeError("TELEGRAM_DELIVERY_UNCERTAIN")
        self.sent.append((chat, text, rows))
        return 888

    async def show(self, *, chat, context, text, rows):
        self.sent.append((chat, text, rows))
        return 888


class FakeEngine:
    def __init__(self):
        self.calls=[]
        self.return_job="job-42"
        self.error=None
        self.current=None

    async def start(self, plan, *, actor, client_witness):
        self.calls.append(("start", actor, client_witness))
        if self.error:
            raise self.error
        return self.return_job

    async def resume(self, job, *, actor, retry_dns=False):
        self.calls.append(("resume",job,actor,retry_dns))
        if self.error:
            raise self.error
        return "DONE"

    def latest(self):
        return self.current


class NoticeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=str(Path(self.tmp.name)/"core.sqlite3")
        with sqlite3.connect(self.path) as db:
            db.executescript("""
              CREATE TABLE host_pool(host TEXT PRIMARY KEY,
                  active INTEGER,is_default INTEGER,is_standby INTEGER,
                  provider TEXT,provider_instance_id TEXT);
              INSERT INTO host_pool VALUES
                  ('1.1.1.1',1,0,0,'manual',NULL),
                  ('8.8.8.8',1,1,0,'manual',NULL);
              CREATE TABLE manual_quick_switch_jobs(
                  id TEXT PRIMARY KEY,kind TEXT,status TEXT,actor TEXT,
                  source TEXT,target TEXT,account_count INTEGER);
              INSERT INTO manual_quick_switch_jobs VALUES
                  ('job-42','QUICK','DONE','7','1.1.1.1','8.8.8.8',446);
              CREATE TABLE manual_edge_operations(ip TEXT,status TEXT);
              CREATE TABLE ssh_accounts(
                  username TEXT,service_type TEXT,status TEXT);
            """)

        @contextmanager
        def db():
            conn=sqlite3.connect(self.path)
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

        self.db=db
        self.engine=FakeEngine()
        self.ui=ManualQuickSwitchUI(
            engine=self.engine,db=db,admin_ids=lambda:[7],
            now=lambda:101,enabled=lambda:True)
        self.bot=SimpleNamespace(token="test-token")
        RecordingDelivery.sent=[]
        RecordingDelivery.fail=False
        self.patch=patch("manual_quick_switch_ui.ManualHtmlDelivery",
                         RecordingDelivery)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def status(self, job="job-42"):
        with self.db() as db:
            r=db.execute(
                "SELECT status FROM manual_quick_success_notices "
                "WHERE job_id=?", (job,)).fetchone()
            return r[0] if r else None

    async def test_done_sends_success_once_with_exact_transfer_details(self):
        await self.ui._execute(
            plan={"target":"8.8.8.8"},actor=7,chat=7,bot=self.bot)
        self.assertEqual(len(RecordingDelivery.sent),1)
        chat,body,rows=RecordingDelivery.sent[0]
        self.assertEqual(chat,7)
        self.assertIn("انتقال با موفقیت انجام شد",body)
        self.assertIn("8.8.8.8",body)
        self.assertIn("446",body)
        self.assertIn("DNS: <b>تأییدشده</b>",body)
        self.assertIn("تکمیل فنی",body)
        self.assertIn("اتصال واقعی مشتری",body)
        actions=[callback for group in rows for _,callback in group]
        self.assertEqual(actions,[
            "apps_edge_quick_status","apps_edge_manual_home"])
        self.assertEqual(self.status(),"SENT")
        self.assertEqual(self.engine.calls[0][0],"start")

        await self.ui._execute(
            job="job-42",actor=7,chat=7,bot=self.bot)
        self.assertEqual(len(RecordingDelivery.sent),1)
        # Restart or duplicate callback cannot regenerate the notice.
        ui2=ManualQuickSwitchUI(
            engine=self.engine,db=self.db,admin_ids=lambda:[7],
            now=lambda:102,enabled=lambda:True)
        self.assertFalse(await ui2._notify_done(
            job="job-42",actor=7,chat=7,bot=self.bot))
        self.assertEqual(len(RecordingDelivery.sent),1)

    async def test_hold_db_committed_and_unrelated_not_success(self):
        for status in ("HOLD","DNS_INTENT","DB_COMMITTED","ABORTED",
                       "EXTERNAL_VERIFIED"):
            with self.subTest(status=status):
                with self.db() as db:
                    db.execute("UPDATE manual_quick_switch_jobs SET status=?",
                               (status,))
                await self.ui._execute(
                    job="job-42",actor=7,chat=7,bot=self.bot)
                self.assertEqual(RecordingDelivery.sent,[])
        with self.db() as db:
            rows=db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='manual_quick_success_notices'").fetchall()
            self.assertEqual(rows,[])

    async def test_failed_or_uncertain_telegram_send_not_replayed(self):
        RecordingDelivery.fail=True
        await self.ui._execute(
            plan={},actor=7,chat=7,bot=self.bot)
        self.assertEqual(RecordingDelivery.sent,[])
        self.assertEqual(self.status(),"UNCERTAIN")
        RecordingDelivery.fail=False
        await self.ui._execute(
            job="job-42",actor=7,chat=7,bot=self.bot)
        self.assertEqual(RecordingDelivery.sent,[])
        self.assertEqual(self.status(),"UNCERTAIN")

    async def test_non_owner_or_stale_default_never_gets_success(self):
        self.assertFalse(await self.ui._notify_done(
            job="job-42",actor=7,chat=8,bot=self.bot))
        self.assertFalse(await self.ui._notify_done(
            job="job-42",actor=8,chat=8,bot=self.bot))
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host='8.8.8.8'")
            db.execute("UPDATE host_pool SET is_default=1 WHERE host='1.1.1.1'")
        self.assertFalse(await self.ui._notify_done(
            job="job-42",actor=7,chat=7,bot=self.bot))
        self.assertEqual(RecordingDelivery.sent,[])
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE name="
                "'manual_quick_success_notices'").fetchone()[0],0)

    async def test_failed_engine_never_sends_success(self):
        self.engine.error=QuickSwitchHold("DNS_WRITE_RESULT_UNCERTAIN")
        await self.ui._execute(plan={},actor=7,chat=7,bot=self.bot)
        self.assertEqual(RecordingDelivery.sent,[])
        self.assertEqual(self.ui.last_errors["7"],
                         "DNS_WRITE_RESULT_UNCERTAIN")

    async def test_status_page_distinguishes_done_and_hold(self):
        self.engine.current={
            "id":"job-42","kind":"QUICK","status":"DONE",
            "actor":"7","source":"1.1.1.1","target":"8.8.8.8",
            "account_count":446,"error_code":None,
        }
        context=SimpleNamespace(application=SimpleNamespace(bot=self.bot),
                                user_data={})
        await self.ui._status(context,7)
        self.assertIn("انتقال با موفقیت انجام شد",
                      RecordingDelivery.sent[-1][1])
        self.engine.current["status"]="HOLD"
        await self.ui._status(context,7)
        self.assertNotIn("انتقال با موفقیت انجام شد",
                         RecordingDelivery.sent[-1][1])
        self.assertIn("نیازمند بررسی",RecordingDelivery.sent[-1][1])


if __name__=="__main__":
    unittest.main()
