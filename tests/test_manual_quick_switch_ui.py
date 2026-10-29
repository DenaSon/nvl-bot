"""Phase 3: Rich UI navigation and live Quick Switch callback acceptance."""
import ast
import asyncio
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from manual_quick_switch_ui import ManualQuickSwitchUI

ROOT=Path(__file__).resolve().parents[1]


class FakeRich:
    cards=[]

    def __init__(self,token):
        assert token=="test-token"

    async def show(self,*,chat,context,text,rows):
        self.cards.append((text,rows))
        return 1


class FakeEngine:
    def __init__(self):
        self.events=[]
        self.rec=None
        self.plan={
            "source":"153.75.87.190","target":"45.59.126.73",
            "count":446,"issued_at":100,"users":[("not-persisted","")],
        }

    async def preview(self,target):
        self.events.append(("preview",target))
        assert target==self.plan["target"]
        return self.plan

    async def start(self,plan,*,actor,client_witness):
        self.events.append(("start",actor,client_witness))
        assert plan is self.plan

    async def resume(self,job,*,actor,retry_dns=False):
        self.events.append(("resume",job,actor,retry_dns))

    def get(self,job):
        return self.rec if self.rec and self.rec["id"]==job else None

    def latest(self):
        return self.rec

    async def record_external_cutover(self,**kwargs):
        self.events.append(("attest",kwargs))
        return "external-receipt-123"


class Phase3UITests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        tmp=TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path=Path(tmp.name)/"ui.db"
        with sqlite3.connect(self.path) as db:
            db.executescript("""
                CREATE TABLE host_pool(
                  host TEXT PRIMARY KEY,active INTEGER,is_default INTEGER,
                  is_standby INTEGER,provider TEXT,provider_instance_id TEXT
                );
                CREATE TABLE manual_edge_operations(
                  ip TEXT,status TEXT
                );
                CREATE TABLE ssh_accounts(
                  username TEXT,service_type TEXT,status TEXT
                );
            """)
            db.executemany("INSERT INTO host_pool VALUES (?,?,?,?,?,?)",[
                ("153.75.87.190",1,1,0,"cloudzy","old"),
                ("45.59.126.73",1,0,1,"manual",None),
            ])
            db.execute("INSERT INTO manual_edge_operations VALUES (?,?)",
                       ("45.59.126.73","STANDBY"))
            db.execute("INSERT INTO ssh_accounts VALUES (?,?,?)",
                       ("alice","ssh","🟢 فعال"))
        @contextmanager
        def connect():
            db=sqlite3.connect(self.path)
            try:
                yield db
            finally:
                db.close()
        self.engine=FakeEngine()
        self.ui=ManualQuickSwitchUI(
            engine=self.engine,db=connect,admin_ids=lambda:[7],
            now=lambda:100,enabled=lambda:True)
        self.context=SimpleNamespace(
            application=SimpleNamespace(bot=SimpleNamespace(token="test-token")),
            user_data={})
        self.patch=patch("manual_quick_switch_ui.ManualRichDelivery",FakeRich)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        FakeRich.cards=[]

    async def cb(self,data,role="admin",actor=7,chat=7,private=True):
        return await self.ui.handle(None,self.context,data,
                                    role=role,actor=actor,chat=chat,
                                    is_private=private)

    async def test_home_contains_only_manual_edge_navigation(self):
        await self.cb("apps_edge_quick_home")
        text,rows=FakeRich.cards[-1]
        self.assertIn("مدیریت Edge",text)
        callbacks=[d for row in rows for _,d in row]
        self.assertIn("apps_edge_manual_home",callbacks)
        self.assertIn("apps_edge_quick_select_45.59.126.73",callbacks)
        self.assertFalse(any(d.startswith("apps_cz") for d in callbacks))
        self.assertNotIn("Cloudzy",text)

    async def test_legacy_home_redirect_shows_new_ui(self):
        await self.cb("apps_cz_home")
        self.assertIn("مدیریت Edge",FakeRich.cards[-1][0])
        self.assertNotIn("Cloudzy",FakeRich.cards[-1][0])

    async def test_mutation_is_not_released_by_default(self):
        self.ui.enabled=lambda:False
        await self.cb("apps_edge_quick_select_45.59.126.73")
        confirm=next(d for row in FakeRich.cards[-1][1] for _,d in row
                     if d.startswith("apps_edge_quick_confirm_"))
        await self.cb(confirm)
        self.assertIn("فعال نشده",FakeRich.cards[-1][0])
        self.assertFalse(any(e[0]=="start" for e in self.engine.events))

    async def test_admin_must_be_active_and_private(self):
        for kwargs in ({"role":"member"},{"actor":8,"chat":8},
                       {"actor":7,"chat":8},{"private":False}):
            with self.subTest(kwargs=kwargs):
                await self.cb("apps_edge_quick_select_45.59.126.73",**kwargs)
                self.assertIn("فقط مدیر",FakeRich.cards[-1][0])
        self.assertEqual(self.engine.events,[])

    async def test_disabled_release_blocks_resume_and_dns_retry(self):
        self.ui.enabled=lambda:False
        self.engine.rec={
            "id":"deadbeef","kind":"QUICK","status":"HOLD",
            "actor":"7","source":"old","target":"new","account_count":446,
            "error_code":"DNS_WRITE_RESULT_UNCERTAIN",
        }
        await self.cb("apps_edge_quick_resume_deadbeef")
        self.assertIn("فعال نشده",FakeRich.cards[-1][0])
        await self.cb("apps_edge_quick_retry_review_deadbeef")
        yes=next(d for row in FakeRich.cards[-1][1] for _,d in row
                 if d.startswith("apps_edge_quick_retry_yes_"))
        await self.cb(yes)
        self.assertIn("فعال نشده",FakeRich.cards[-1][0])
        self.assertEqual(self.engine.events,[])

    async def test_preview_and_one_use_confirm_never_persist_roster(self):
        await self.cb("apps_edge_quick_select_45.59.126.73")
        text,rows=FakeRich.cards[-1]
        self.assertIn("446",text)
        confirm=next(d for row in rows for _,d in row
                     if d.startswith("apps_edge_quick_confirm_"))
        self.assertNotIn("manual_quick",self.context.user_data)
        self.assertEqual(self.context.user_data,{})
        await self.cb(confirm)
        for _ in range(30):
            if any(e[0]=="start" for e in self.engine.events):
                break
            await asyncio.sleep(.01)
        self.assertEqual(sum(e[0]=="start" for e in self.engine.events),1)
        await self.cb(confirm)
        self.assertEqual(sum(e[0]=="start" for e in self.engine.events),1)
        self.assertIn("متوقف",FakeRich.cards[-1][0])

    async def test_recovery_preserves_explicit_retry_confirmation(self):
        self.engine.rec={
            "id":"deadbeef","kind":"QUICK","status":"HOLD",
            "actor":"7","source":"old","target":"new","account_count":446,
            "error_code":"DNS_WRITE_RESULT_UNCERTAIN",
        }
        await self.cb("apps_edge_quick_status")
        rows=FakeRich.cards[-1][1]
        self.assertIn("apps_edge_quick_resume_deadbeef",
                      [d for row in rows for _,d in row])
        await self.cb("apps_edge_quick_retry_review_deadbeef")
        confirm=next(d for row in FakeRich.cards[-1][1] for _,d in row
                     if d.startswith("apps_edge_quick_retry_yes_"))
        self.assertEqual(self.engine.events,[])
        await self.cb(confirm)
        for _ in range(30):
            if self.engine.events:
                break
            await asyncio.sleep(.01)
        self.assertEqual(self.engine.events,[("resume","deadbeef",7,True)])


class Phase3StaticIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bot=(ROOT/"bot_final_v49-2.py").read_text(encoding="utf-8")
        cls.manual=(ROOT/"manual_edge_wizard.py").read_text(encoding="utf-8")

    def test_programs_menu_no_cloudzy_entry(self):
        tree=ast.parse(self.bot)
        method=next(n for n in tree.body if isinstance(n,ast.FunctionDef)
                    and n.name=="_build_admin_programs_kb")
        text=ast.get_source_segment(self.bot,method)
        self.assertIn("apps_edge_quick_home",text)
        self.assertNotIn("apps_cz_home",text)
        self.assertNotIn("apps_cz_rich_home",text)
        self.assertNotIn("Cloudzy",text)

    def test_handlers_route_old_manual_and_cloudzy_home_to_new_ui(self):
        self.assertIn('d.startswith("apps_edge_quick_") or d == "apps_cz_home"',
                      self.bot)
        self.assertIn('_manual_quick_ui.handle(',self.bot)
        self.assertIn('d.startswith(("apps_edge_manual_review_","apps_edge_manual_go_"))',
                      self.bot)

    def test_manual_standby_routes_to_quick_switch_not_cz07(self):
        self.assertIn('"apps_edge_quick_select_"+op["ip"]',self.manual)
        stage=self.manual.split('if data.startswith("apps_edge_manual_standby_")')[1]
        stage=stage.split('if data.startswith("apps_edge_manual_review_")')[0]
        self.assertIn('"apps_edge_quick_select_"+op["ip"]',stage)
        self.assertNotIn('"apps_edge_manual_review_"+opid',stage)


if __name__=="__main__":
    unittest.main()
