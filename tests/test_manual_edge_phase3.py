"""Phase-3 manual Edge identity, credential and lease regression tests.

No real SSH, Cloudflare, Cloudzy or customer effects.
"""
import hashlib
import hmac
import json
import os
import sqlite3
import tempfile
import time
import unittest
from urllib.parse import urlencode

from manual_edge_secure_form import (
    ManualFormStore, IntakeHold, public_ip, ssh_port, validate_init_data,
)
from manual_edge_journal import ManualEdgeJournal, ManualEdgeHold
from manual_edge_identity import resolve, assert_ref, EdgeIdentityHold


class Phase3ManualTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=os.path.join(self.temp.name,"manual.sqlite3")
        def factory():
            return sqlite3.connect(self.path)
        self.db=factory
        with self.db() as conn:
            conn.execute("""CREATE TABLE host_pool(
                host TEXT PRIMARY KEY, active INTEGER DEFAULT 0,
                is_default INTEGER DEFAULT 0,is_standby INTEGER DEFAULT 0,
                provider TEXT,provider_instance_id TEXT,
                service_port INTEGER,admin_ssh_port INTEGER)""")
            conn.execute("""CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT)""")
            conn.executemany("INSERT INTO settings VALUES (?,?)", [
                ("hosts","1.1.1.1"),("dns_current_ip","1.1.1.1"),
                ("auto_failover_mode","0"),
                ("phase6h_auto_failover_enabled","0"),
                ("edge_egress_v1_onboard_enabled","0"),
            ])
            conn.execute("""CREATE TABLE ssh_accounts(
                username TEXT PRIMARY KEY,host TEXT,
                status TEXT,service_type TEXT)""")
            conn.execute("""CREATE TABLE cloudzy_edge_operations(
                id TEXT PRIMARY KEY, public_ipv4 TEXT,status TEXT,
                provider_server_id TEXT,host_key_type TEXT,host_key_base64 TEXT)""")
            conn.execute("""INSERT INTO host_pool
                (host,active,is_default,is_standby,provider,provider_instance_id,
                 service_port,admin_ssh_port)
                 VALUES ('1.1.1.1',1,1,0,'legacy',NULL,2222,22)""")
        self.journal=ManualEdgeJournal(
            self.db,now=lambda:10000,
            install_lock_path=os.path.join(self.temp.name,"wg-install.lock"))

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def fake_key():
        return ("ssh-ed25519","AAAAC3NzaC1lZDI1NTE5AAAAIGV4YW1wbGVleGFtcGxlZmFrZWtleTEyMzQ1Njc4OTA=",
                "SHA256:TEST_INDEPENDENT_FINGERPRINT")

    def prepare(self,ip="8.8.8.8",port=2222):
        op=self.journal.start(77,77)
        self.journal.set_server(op,77,77,ip,port)
        self.journal.pin(op,77,77,*self.fake_key())
        self.journal.begin_install(op,77,77)
        with self.db() as db:
            db.execute("""INSERT INTO host_pool
                (host,active,is_default,is_standby,provider,provider_instance_id,
                 service_port,admin_ssh_port) VALUES (?,?,?,?,?,?,?,?)""",
                (ip,0,0,0,"manual",None,2222,port))
        self.journal.mark_edge_ready(op,77,77,2222)
        return op

    def test_reject_nonpublic_addresses_and_invalid_ssh_port(self):
        for ip in ("127.0.0.1","10.0.0.3","192.168.1.2","169.254.169.254",
                   "0.0.0.0","224.0.0.2","203.0.113.2","::1"):
            with self.subTest(ip=ip),self.assertRaises(IntakeHold):
                public_ip(ip)
        self.assertEqual(public_ip("8.8.8.8"),"8.8.8.8")
        for port in ("0","65536","-1","22x",True):
            with self.subTest(port=port),self.assertRaises(IntakeHold):
                ssh_port(port)
        self.assertEqual(ssh_port("2222"),2222)

    def test_telegram_initdata_signed_and_bound_to_exact_operator(self):
        token="99999:secret-token-for-tests"
        now=1000
        data={"auth_date":str(now),"user":json.dumps({"id":77}),
              "query_id":"AAExample"}
        raw="\n".join(k+"="+v for k,v in sorted(data.items()))
        secret=hmac.new(b"WebAppData",token.encode(),hashlib.sha256).digest()
        data["hash"]=hmac.new(secret,raw.encode(),hashlib.sha256).hexdigest()
        signed=urlencode(data)
        self.assertTrue(validate_init_data(signed,token,77,now=now))
        with self.assertRaises(IntakeHold):
            validate_init_data(signed,token,78,now=now)
        with self.assertRaises(IntakeHold):
            validate_init_data(signed,token,77,now=now+181)
        with self.assertRaises(IntakeHold):
            validate_init_data(signed.replace("id%22%3A+77","id%22%3A+78"),
                               token,77,now=now)

    def test_form_password_one_use_no_disk_and_expiry(self):
        now=[100.]
        store=ManualFormStore(clock=lambda:now[0])
        key=store.issue(actor=77,chat=77,stage="password",op_id="op")
        password="DO_NOT_LOG_SECRET_EXAMPLE"
        self.assertTrue(store.submit(key,actor=77,stage="password",
                                     value={"password":password}))
        with self.assertRaises(IntakeHold):
            store.submit(key,actor=77,stage="password",
                         value={"password":"duplicate"})
        with self.assertRaises(IntakeHold):
            store.consume(key,actor=99,chat=77,stage="password",op_id="op")
        self.assertEqual(store.consume(
            key,actor=77,chat=77,stage="password",op_id="op"),
            {"password":password})
        with self.assertRaises(IntakeHold):
            store.consume(key,actor=77,chat=77,stage="password",op_id="op")
        q=store.issue(actor=77,chat=77,stage="password",op_id="op")
        now[0]+=181
        with self.assertRaises(IntakeHold):
            store.info(q)
        with open(self.path,"rb") as f:
            self.assertNotIn(password.encode(),f.read())

    def test_manual_host_registered_without_cloudzy_receipt(self):
        op=self.prepare()
        r=self.journal.get(op)
        self.assertEqual(r["status"],"EDGE_READY")
        self.journal.mark_standby(op,77,77)
        with self.db() as db:
            info=resolve(db,"8.8.8.8",require_standby=True)
            self.assertEqual(info["provider"],"manual")
            self.assertEqual(info["identity_ref"],"manual:"+op)
            self.assertEqual(info["admin_port"],2222)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM cloudzy_edge_operations").fetchone()[0],0)
            with self.assertRaises(EdgeIdentityHold):
                assert_ref(db,"8.8.8.8","cloudzy-fake",require_standby=True)
        self.assertEqual(self.journal.latest(77,77)["status"],"STANDBY")

    def test_hold_is_persistent_and_does_not_allow_blind_reinstall(self):
        op=self.journal.start(77,77)
        self.journal.set_server(op,77,77,"8.8.4.4",22)
        self.journal.pin(op,77,77,*self.fake_key())
        self.journal.begin_install(op,77,77)
        self.journal.install_hold(op,77,77,"INSTALL_PARTIAL")
        with self.assertRaises(ManualEdgeHold):
            self.journal.begin_install(op,77,77)
        with self.assertRaises(ManualEdgeHold):
            self.journal.cancel_draft(op,77,77)
        self.assertEqual(self.journal.get(op)["status"],"INSTALL_HOLD")

    def test_manual_and_cloudzy_identity_collision_guard(self):
        with self.db() as db:
            db.execute("INSERT INTO cloudzy_edge_operations VALUES "
                       "('old','8.8.8.8','EDGE_READY','vps',NULL,NULL)")
        op=self.journal.start(77,77)
        with self.assertRaisesRegex(ManualEdgeHold,"CLOUDZY"):
            self.journal.set_server(op,77,77,"8.8.8.8",22)
        self.journal.set_server(op,77,77,"8.8.4.4",22)
        with self.assertRaises(ManualEdgeHold):
            self.journal.set_server(op,77,77,"9.9.9.9",22)

    def test_standby_rejects_auto_failover_and_keeps_dns(self):
        op=self.prepare()
        with self.db() as db:
            db.execute("UPDATE settings SET value='1' "
                       "WHERE key='auto_failover_mode'")
        with self.assertRaises(ManualEdgeHold):
            self.journal.mark_standby(op,77,77)
        with self.db() as db:
            db.execute("UPDATE settings SET value='0' "
                       "WHERE key='auto_failover_mode'")
            before=dict(db.execute("SELECT key,value FROM settings"))
        self.journal.mark_standby(op,77,77)
        with self.db() as db:
            after=dict(db.execute("SELECT key,value FROM settings"))
            self.assertEqual(before,after)
            self.assertEqual(db.execute(
                "SELECT active,is_standby,is_default FROM host_pool "
                "WHERE host='8.8.8.8'").fetchone(),(1,1,0))

    def test_wizard_callbacks_use_rich_native_telegram_without_webapp(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock,patch
        from manual_edge_wizard import ManualEdgeWizard

        def no_network(*args):
            raise AssertionError("NO_REMOTE_EFFECTS")
        wizard=ManualEdgeWizard(
            db=self.db,preflight=lambda:(2252,"ssh-pub"),
            provision=no_network,verify=no_network,probe=no_network,
            nat=no_network,queue=SimpleNamespace(),enabled=lambda:False,
            form_url=lambda:"")
        context=SimpleNamespace(user_data={})
        app=SimpleNamespace(bot=SimpleNamespace(token="123:TEST_TOKEN"))
        with patch("manual_edge_wizard.ManualRichDelivery") as factory:
            factory.return_value.show=AsyncMock(return_value=44)
            asyncio.run(wizard.handle(
                SimpleNamespace(),context,"apps_edge_manual_home",
                role="admin",actor=77,chat=77,app=app))
            view=factory.return_value.show.call_args.kwargs
            self.assertIn("افزودن Edge دستی",view["text"])
            self.assertEqual(view["rows"][0][0][1],"apps_edge_manual_new")
            asyncio.run(wizard.handle(
                SimpleNamespace(),context,"apps_edge_manual_new",
                role="admin",actor=77,chat=77,app=app))
            view=factory.return_value.show.call_args.kwargs
            self.assertIn("IP عمومی",view["text"])
            self.assertEqual(context.user_data["state"],"MANUAL_EDGE_IP")
            self.assertNotIn("web_app",str(view["rows"]))
            self.assertNotIn("password",str(context.user_data).lower())

    def test_install_completion_callback_edits_clicked_rich_message(self):
        """A background install receipt is a new Rich message, not the old pointer."""
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import patch
        from cloudzy_rich_transport import RichBotAPI
        from manual_edge_rich import ManualRichDelivery
        from manual_edge_wizard import ManualEdgeWizard

        def no_network(*args):
            raise AssertionError("NO_REMOTE_EFFECTS")

        wizard=ManualEdgeWizard(
            db=self.db,preflight=lambda:(2252,"ssh-pub"),
            provision=no_network,verify=no_network,probe=no_network,
            nat=no_network,queue=SimpleNamespace(),
            enabled=lambda:False,form_url=lambda:"")
        context=SimpleNamespace(user_data={"manual_edge_rich_pointer":101})
        query=SimpleNamespace(message=SimpleNamespace(
            message_id=902,chat=SimpleNamespace(id=77)))
        app=SimpleNamespace(bot=SimpleNamespace(token="123:TEST_TOKEN"))
        calls=[]
        def transport(method,body):
            calls.append((method,body))
            return {"message_id":902}
        def delivery(token):
            return ManualRichDelivery(token,api_factory=lambda t:
                                      RichBotAPI(t,transport=transport))

        with patch("manual_edge_wizard.ManualRichDelivery",side_effect=delivery):
            asyncio.run(wizard.handle(
                query,context,"apps_edge_manual_home",role="admin",
                actor=77,chat=77,app=app))
        self.assertEqual(context.user_data["manual_edge_rich_pointer"],902)
        self.assertEqual([method for method,_ in calls],["editMessageText"])
        self.assertEqual(calls[0][1]["message_id"],902)

    def test_callback_pointer_is_not_rebound_from_another_chat(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock, patch
        from manual_edge_wizard import ManualEdgeWizard

        wizard=ManualEdgeWizard(
            db=self.db,preflight=lambda:(2252,"ssh-pub"),
            provision=lambda *args:None,verify=lambda *args:None,
            probe=lambda *args:None,nat=lambda *args:None,
            queue=SimpleNamespace(),enabled=lambda:False)
        context=SimpleNamespace(user_data={"manual_edge_rich_pointer":101})
        app=SimpleNamespace(bot=SimpleNamespace(token="123:TEST_TOKEN"))
        wrong=SimpleNamespace(message=SimpleNamespace(
            message_id=902,chat=SimpleNamespace(id=88)))
        with patch("manual_edge_wizard.ManualRichDelivery") as delivery:
            delivery.return_value.show=AsyncMock(return_value=101)
            asyncio.run(wizard.handle(
                wrong,context,"apps_edge_manual_home",role="admin",
                actor=77,chat=77,app=app))
            self.assertEqual(context.user_data["manual_edge_rich_pointer"],101)
            denied=SimpleNamespace(message=SimpleNamespace(
                message_id=903,chat=SimpleNamespace(id=77)))
            asyncio.run(wizard.handle(
                denied,context,"apps_edge_manual_home",role="member",
                actor=77,chat=77,app=app))
            self.assertEqual(context.user_data["manual_edge_rich_pointer"],101)

    def test_management_port_collisions_fail_before_any_remote_effect(self):
        from manual_edge_wizard import ManualEdgeWizard, ManualWizardHold
        for unsafe in (2252,2088):
            with self.subTest(port=unsafe), self.assertRaisesRegex(
                    ManualWizardHold, "SSH_MANAGEMENT_PORT_CONFLICT"):
                ManualEdgeWizard._assert_management_port_safe(
                    unsafe,customer_port=2252,tls_port=2088)
        ManualEdgeWizard._assert_management_port_safe(
            22,customer_port=2252,tls_port=2088)
        ManualEdgeWizard._assert_management_port_safe(
            2299,customer_port=2252,tls_port=2088)

    def test_after_activation_a_new_manual_operation_becomes_current(self):
        op=self.prepare("8.8.8.8",port=2299)
        self.journal.mark_standby(op,77,77)
        self.journal.bind_route(op,77,77,"route-1")
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host='1.1.1.1'")
            db.execute("UPDATE host_pool SET is_default=1,is_standby=0 "
                       "WHERE host='8.8.8.8'")
        self.journal.finish(op,77,77,"route-1")
        self.assertEqual(self.journal.get(op)["status"],"ACTIVE")
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock,patch
        from manual_edge_wizard import ManualEdgeWizard
        async def prohibited(*_):
            raise AssertionError("NO_NETWORK_TEST")
        wizard=ManualEdgeWizard(
            db=self.db,preflight=lambda:(2252,"pub"),
            provision=prohibited,verify=prohibited,
            probe=prohibited,nat=prohibited,queue=SimpleNamespace(),
            enabled=lambda:True)
        with patch("manual_edge_wizard.ManualRichDelivery") as rich:
            rich.return_value.show=AsyncMock(return_value=99)
            asyncio.run(wizard.handle(
                SimpleNamespace(),SimpleNamespace(user_data={}),
                "apps_edge_manual_home",role="admin",actor=77,chat=77,
                app=SimpleNamespace(bot=SimpleNamespace(token="123:TEST"))))
            actions=[item[1] for row in rich.return_value.show.call_args.kwargs["rows"]
                     for item in row]
            self.assertIn("apps_edge_manual_new",actions)
        newer=self.journal.start(77,77)
        # Fixed timestamp=10000 in fixture: rowid must win ties, not a
        # lexicographic sort of random operation IDs.
        self.assertEqual(self.journal.latest(77,77)["id"],newer)
        self.assertEqual(self.journal.get(op)["status"],"ACTIVE")

    def test_actor_and_chat_owned_and_draft_cancel_only(self):
        op=self.journal.start(77,77)
        with self.assertRaises(ManualEdgeHold):
            self.journal.set_server(op,78,77,"8.8.8.8",22)
        self.journal.cancel_draft(op,77,77)
        self.assertEqual(self.journal.get(op)["status"],"CANCELLED")
        self.journal.start(77,77)


if __name__=="__main__":
    unittest.main()
