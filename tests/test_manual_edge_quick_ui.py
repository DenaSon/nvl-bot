"""Phase 3 Rich Quick Switch UI: identity, previews, confirmation, recovery."""
import asyncio
import sqlite3
import unittest

from manual_edge_quick_ui import QuickSwitchUI, QuickSwitchUIHold


class Ctx:
    def __init__(self):
        self.user_data = {}


class Delivery:
    def __init__(self, token):
        self.calls = []

    async def show(self, **kwargs):
        self.calls.append(kwargs)
        return 1


class Engine:
    def __init__(self):
        self.starts = []
        self.previews = []
        self.resumes = []
        self.record = None

    def latest(self, actor=None):
        return self.record

    async def preview(self, target):
        self.previews.append(target)
        return {
            "source":"153.75.87.190","target":target,
            "count":446,"issued_at":100,"hosts":"153.75.87.190",
            "fingerprint":"sample","identity":{"provider":"manual"},
            "dns":[{"name":"n1.nvlsup.com","ip":"153.75.87.190"}],
        }

    async def start(self, plan, *, actor, client_witness):
        self.starts.append((plan,actor,client_witness))
        self.record = {
            "id":"abcdef123456","kind":"QUICK","source":plan["source"],
            "target":plan["target"],"status":"DONE","error_code":"",
        }
        return self.record["id"]

    async def resume(self, job, *, actor, retry_dns=False):
        self.resumes.append((job,actor,retry_dns))
        return "DONE"


class UiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.db=sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE host_pool(
              host TEXT,active INTEGER,is_default INTEGER,
              is_standby INTEGER,provider TEXT,provider_instance_id TEXT
            );
            CREATE TABLE manual_edge_operations(ip TEXT,status TEXT);
            CREATE TABLE ssh_accounts(service_type TEXT,status TEXT);
            INSERT INTO host_pool VALUES
              ('153.75.87.190',1,1,0,'cloudzy','old'),
              ('45.59.126.73',1,0,1,'manual',NULL);
            INSERT INTO manual_edge_operations VALUES
              ('45.59.126.73','STANDBY');
            INSERT INTO ssh_accounts VALUES('ssh','🟢 فعال');
        """)
        class Conn:
            def __init__(self,db):
                self.db=db
            def __enter__(self):
                return self.db
            def __exit__(self,*args):
                return False
        self.engine=Engine()
        self.ctx=Ctx()
        self.ui=QuickSwitchUI(
            engine=self.engine,token="test",db_conn=lambda:Conn(self.db),
            delivery_factory=Delivery,now=lambda:101,
        )

    async def go(self,data,actor=7,chat=7,role="admin",private=True,active=(7,)):
        await self.ui.handle(
            data=data,query=object(),context=self.ctx,role=role,
            actor=actor,chat=chat,is_private=private,
            active_admin_ids=active,
        )
        return self.ui.delivery.calls[-1]

    async def test_home_and_standby_are_provider_free(self):
        home=await self.go("apps_edge_quick_home")
        self.assertIn("مدیریت Edge",home["text"])
        self.assertIn("apps_edge_quick_pick",
            [a for row in home["rows"] for _,a in row])
        pick=await self.go("apps_edge_quick_pick")
        actions=[a for row in pick["rows"] for _,a in row]
        self.assertIn("apps_edge_quick_review_45.59.126.73",actions)
        self.assertFalse(any(a.startswith("apps_cz7") for a in actions))

    async def test_private_admin_identity_blocks_others(self):
        for args in (
            {"role":"member"},{"private":False},{"actor":7,"chat":8},
            {"active":()},
        ):
            with self.subTest(args=args), self.assertRaises(QuickSwitchUIHold):
                await self.go("apps_edge_quick_home",**args)
        self.assertEqual(self.ui.delivery.calls,[])

    async def test_confirmation_is_bound_nonce_and_one_use(self):
        review=await self.go("apps_edge_quick_review_45.59.126.73")
        action=review["rows"][0][0][1]
        self.assertTrue(action.startswith("apps_edge_quick_yes_"))
        denied=await self.go("apps_edge_quick_yes_WRONG")
        self.assertIn("CONFIRMATION_EXPIRED",denied["text"])
        self.assertEqual(self.engine.starts,[])
        finished=await self.go(action)
        self.assertIn("تغییر مسیر ثبت شد",finished["text"])
        self.assertEqual(len(self.engine.starts),1)
        self.assertEqual(self.engine.starts[0][1],"telegram:7")
        retry=await self.go(action)
        self.assertIn("CONFIRMATION_EXPIRED",retry["text"])
        self.assertEqual(len(self.engine.starts),1)

    async def test_dns_retry_requires_separate_one_use_confirmation(self):
        self.engine.record={
            "id":"job1","kind":"QUICK","source":"a","target":"b",
            "status":"HOLD","error_code":"DNS_UNCERTAIN",
        }
        page=await self.go("apps_edge_quick_retry")
        action=page["rows"][0][0][1]
        self.assertTrue(action.startswith("apps_edge_quick_retry_yes_"))
        self.assertEqual(self.engine.resumes,[])
        page=await self.go(action)
        self.assertIn("نتیجه بازیابی",page["text"])
        self.assertEqual(self.engine.resumes,[("job1","telegram:7",True)])
        page=await self.go(action)
        self.assertIn("CONFIRMATION_EXPIRED",page["text"])
        self.assertEqual(len(self.engine.resumes),1)

    async def test_unresolved_recovery_uses_no_blind_dns_retry(self):
        self.engine.record={
            "id":"job1","kind":"QUICK","source":"a","target":"b",
            "status":"HOLD","error_code":"DNS_UNCERTAIN",
        }
        status=await self.go("apps_edge_quick_status")
        self.assertIn("apps_edge_quick_resume",
            [a for row in status["rows"] for _,a in row])
        await self.go("apps_edge_quick_resume")
        self.assertEqual(self.engine.resumes,[("job1","telegram:7",False)])


if __name__=="__main__":
    unittest.main()
