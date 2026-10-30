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

    def test_wizard_callbacks_keep_html_navigation_without_webapp(self):
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
        with patch("manual_edge_wizard.ManualHtmlDelivery") as factory:
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

    def test_html_navigation_uses_new_message_without_old_rich_pointer(self):
        """Old Rich cards remain harmless; ordinary HTML never edits them."""
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import patch
        from manual_edge_html import ManualHtmlDelivery, ManualHtmlBotAPI
        from manual_edge_wizard import ManualEdgeWizard

        def no_network(*args):
            raise AssertionError("NO_REMOTE_EFFECTS")
        wizard=ManualEdgeWizard(
            db=self.db,preflight=lambda:(2252,"ssh-pub"),
            provision=no_network,verify=no_network,probe=no_network,
            nat=no_network,queue=SimpleNamespace())
        calls=[]
        def transport(method,body):
            calls.append((method,body))
            return {"message_id":903}
        def delivery(bot):
            return ManualHtmlDelivery(bot,api_factory=lambda token:
                ManualHtmlBotAPI(token,transport=transport))
        bot=SimpleNamespace(token="123:TEST_TOKEN")
        context=SimpleNamespace(user_data={"manual_edge_rich_pointer":101})
        query=SimpleNamespace(message=SimpleNamespace(
            message_id=902,chat=SimpleNamespace(id=77)))
        with patch("manual_edge_wizard.ManualHtmlDelivery",side_effect=delivery):
            asyncio.run(wizard.handle(
                query,context,"apps_edge_manual_home",role="admin",
                actor=77,chat=77,app=SimpleNamespace(bot=bot)))
        self.assertEqual([method for method,_ in calls],["sendMessage"])
        body=calls[0][1]
        self.assertEqual(body["parse_mode"],"HTML")
        self.assertEqual(body["chat_id"],77)
        self.assertIn("افزودن Edge",body["text"])
        self.assertEqual(context.user_data["manual_edge_rich_pointer"],101)

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
        with patch("manual_edge_wizard.ManualHtmlDelivery") as delivery:
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
        with patch("manual_edge_wizard.ManualHtmlDelivery") as rich:
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


    def test_two_standbys_coexist_and_third_intake_is_allowed(self):
        first=self.prepare("8.8.8.8",port=2299)
        second=self.prepare("8.8.4.4",port=2298)
        self.journal.mark_standby(first,77,77)
        self.journal.mark_standby(second,77,77)
        pending=self.journal.start(77,77)
        self.assertEqual(self.journal.get(pending)["status"],"DRAFT")
        with self.assertRaisesRegex(ManualEdgeHold,"ACTIVE_MANUAL_OPERATION_EXISTS"):
            self.journal.start(77,77)
        rows=self.journal.list_by_owner(77,77)
        self.assertEqual([x["id"] for x in rows[:3]],[pending,second,first])
        self.assertEqual(self.journal.list_by_owner(78,78),[])
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM host_pool WHERE is_standby=1").fetchone()[0],2)
            self.assertEqual(dict(db.execute(
                "SELECT key,value FROM settings WHERE key IN ('hosts','dns_current_ip')")),
                {"hosts":"1.1.1.1","dns_current_ip":"1.1.1.1"})

    def test_upgrades_old_single_owner_unique_index_without_dropping_ip_lock(self):
        first=self.prepare("8.8.8.8",port=2299)
        with self.db() as db:
            db.execute("DROP INDEX manual_edge_live_owner")
            db.execute("""CREATE UNIQUE INDEX manual_edge_live_owner
                ON manual_edge_operations(actor,chat)
                WHERE status IN ('DRAFT','IDENTITY_PENDING','HOSTKEY_PENDING',
                    'READY_INSTALL','INSTALLING','EDGE_READY','STANDBY',
                    'ROUTING','MIGRATING')""")
        second=self.journal.start(77,77)
        with self.db() as db:
            definition=db.execute("SELECT sql FROM sqlite_master "
                "WHERE type='index' AND name='manual_edge_live_owner'").fetchone()[0]
            self.assertNotIn("'EDGE_READY'",definition)
            self.assertIn("'INSTALLING'",definition)
            ip_definition=db.execute("SELECT sql FROM sqlite_master "
                "WHERE type='index' AND name='manual_edge_host_identity'").fetchone()[0]
            self.assertIn("status != 'CANCELLED'",ip_definition)
        self.assertEqual(self.journal.get(first)["status"],"EDGE_READY")
        self.assertEqual(self.journal.get(second)["status"],"DRAFT")

    def test_standby_inventory_mismatch_fails_before_network_effects(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from manual_edge_wizard import ManualEdgeWizard
        op=self.prepare("8.8.8.8",port=2299)
        with self.db() as db:
            db.execute("DELETE FROM host_pool WHERE host='8.8.8.8'")
        with self.assertRaisesRegex(ManualEdgeHold,"MANUAL_HOST_POOL_MISMATCH"):
            self.journal.assert_standby_candidate(op,77,77,2222)
        probe=AsyncMock(return_value=True)
        nat=AsyncMock(return_value=True)
        wizard=ManualEdgeWizard(
            db=self.db,preflight=lambda:(2222,"pub"),
            provision=AsyncMock(),verify=AsyncMock(),probe=probe,nat=nat,
            queue=SimpleNamespace(),enabled=lambda:True)
        wizard._tls_port=lambda:2088
        wizard._view=AsyncMock(return_value=42)
        asyncio.run(wizard.handle(
            SimpleNamespace(),SimpleNamespace(user_data={}),
            "apps_edge_manual_standby_"+op,role="admin",actor=77,chat=77,
            app=SimpleNamespace(bot=SimpleNamespace(token="123:TEST"))))
        self.assertIn("MANUAL_HOST_POOL_MISMATCH",wizard._view.await_args.args[1])
        probe.assert_not_awaited()
        nat.assert_not_awaited()
        self.assertEqual(self.journal.get(op)["status"],"EDGE_READY")

    def test_listing_is_paginated_and_each_detail_is_owner_scoped(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from manual_edge_wizard import ManualEdgeWizard
        from manual_edge_rich import render_manual_card
        for n in range(1,10):
            self.prepare("9.9.9."+str(n),port=2200+n)
        wizard=ManualEdgeWizard(
            db=self.db,preflight=lambda:(2222,"pub"),
            provision=AsyncMock(),verify=AsyncMock(),probe=AsyncMock(),
            nat=AsyncMock(),queue=SimpleNamespace())
        wizard._view=AsyncMock(return_value=42)
        context=SimpleNamespace(user_data={})
        app=SimpleNamespace(bot=SimpleNamespace(token="123:TEST"))
        asyncio.run(wizard.handle(SimpleNamespace(),context,
                "apps_edge_manual_home",role="admin",actor=77,chat=77,app=app))
        text,rows=wizard._view.await_args.args[1:]
        self.assertIn("سرورهای دستی",text)
        actions=[action for row in rows for _,action in row]
        self.assertIn("apps_edge_manual_new",actions)
        self.assertIn("apps_edge_manual_list_1",actions)
        self.assertEqual(sum(x.startswith("apps_edge_manual_detail_")
                             for x in actions),7)
        render_manual_card(text,rows)
        op=self.journal.list_by_owner(77,77)[0]
        asyncio.run(wizard.handle(SimpleNamespace(),context,
                "apps_edge_manual_detail_"+op["id"],
                role="admin",actor=77,chat=77,app=app))
        self.assertIn(op["ip"],wizard._view.await_args.args[1])
        asyncio.run(wizard.handle(SimpleNamespace(),context,
                "apps_edge_manual_detail_"+op["id"],
                role="admin",actor=78,chat=78,app=app))
        self.assertIn("OPERATOR_MISMATCH",wizard._view.await_args.args[1])

    def test_specific_cancel_never_cancels_other_newer_draft(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from manual_edge_wizard import ManualEdgeWizard
        old=self.prepare("8.8.8.8")
        new=self.journal.start(77,77)
        wizard=ManualEdgeWizard(
            db=self.db,preflight=lambda:(2222,"pub"),
            provision=AsyncMock(),verify=AsyncMock(),probe=AsyncMock(),
            nat=AsyncMock(),queue=SimpleNamespace())
        wizard._view=AsyncMock(return_value=42)
        asyncio.run(wizard.handle(
            SimpleNamespace(),SimpleNamespace(user_data={}),
            "apps_edge_manual_cancel_"+old,
            role="admin",actor=77,chat=77,
            app=SimpleNamespace(bot=SimpleNamespace(token="123:TEST"))))
        self.assertIn("عملیات متوقف شد",wizard._view.await_args.args[1])
        self.assertEqual(self.journal.get(new)["status"],"DRAFT")
        self.assertEqual(self.journal.get(old)["status"],"EDGE_READY")

    def test_standby_failure_reports_stage_and_keeps_journal_ready(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from manual_edge_wizard import ManualEdgeWizard
        op=self.prepare("8.8.8.8",port=2299)
        probe=AsyncMock(return_value=False)
        nat=AsyncMock(return_value=True)
        wizard=ManualEdgeWizard(
            db=self.db,preflight=lambda:(2222,"pub"),
            provision=AsyncMock(),verify=AsyncMock(),probe=probe,nat=nat,
            queue=SimpleNamespace())
        wizard._tls_port=lambda:2088
        wizard._view=AsyncMock(return_value=42)
        with self.assertLogs("manual_edge_wizard",level="WARNING") as logged:
            asyncio.run(wizard.handle(
                SimpleNamespace(),SimpleNamespace(user_data={}),
                "apps_edge_manual_standby_"+op,
                role="admin",actor=77,chat=77,
                app=SimpleNamespace(bot=SimpleNamespace(token="123:TEST"))))
        self.assertIn("STANDBY_CORE_PATH_UNVERIFIED",wizard._view.await_args.args[1])
        self.assertIn("STANDBY_CORE_PATH_UNVERIFIED"," ".join(logged.output))
        nat.assert_not_awaited()
        self.assertEqual(self.journal.get(op)["status"],"EDGE_READY")


    def _promote_for_test(self, ip="8.8.8.8"):
        op=self.prepare(ip,port=2299)
        self.journal.mark_standby(op,77,77)
        self.journal.bind_route(op,77,77,"test-job-"+ip)
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host='1.1.1.1'")
            db.execute("UPDATE host_pool SET is_default=1,is_standby=0 WHERE host=?",
                       (ip,))
        self.journal.finish(op,77,77,"test-job-"+ip)
        return op

    def test_current_default_and_historical_active_are_different_labels(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from manual_edge_wizard import ManualEdgeWizard
        former=self._promote_for_test("8.8.8.8")
        current=self._promote_for_test("8.8.4.4")
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host='8.8.8.8'")
            db.execute("UPDATE settings SET value='8.8.4.4' "
                       "WHERE key IN ('hosts','dns_current_ip')")
        missing=self.prepare("9.9.9.9",port=2298)
        with self.db() as db:
            db.execute("DELETE FROM host_pool WHERE host='9.9.9.9'")
        self.assertEqual(self.journal.display_state(current,77,77),"DEFAULT")
        self.assertEqual(self.journal.display_state(former,77,77),"FORMER")
        self.assertEqual(self.journal.display_state(missing,77,77),"POOL_MISSING")
        wiz=ManualEdgeWizard(db=self.db,preflight=lambda:(2222,"pub"),
            provision=AsyncMock(),verify=AsyncMock(),probe=AsyncMock(),
            nat=AsyncMock(),queue=SimpleNamespace())
        wiz._view=AsyncMock(return_value=1)
        asyncio.run(wiz.handle(SimpleNamespace(),SimpleNamespace(user_data={}),
            "apps_edge_manual_home",role="admin",actor=77,chat=77,
            app=SimpleNamespace(bot=SimpleNamespace(token="123:TEST"))))
        rows=wiz._view.await_args.args[2]
        labels=" ".join(label for row in rows for label,_ in row)
        self.assertEqual(labels.count("رله اصلی"),1)
        self.assertIn("8.8.4.4 · 🟢 رله اصلی",labels)
        self.assertIn("8.8.8.8 · ⚪ رله سابق",labels)
        self.assertIn("9.9.9.9 · 🔴 ثبت سرور ناقص",labels)
        with self.db() as db:
            db.execute("UPDATE settings SET value='1.1.1.1' "
                       "WHERE key='dns_current_ip'")
        self.assertEqual(self.journal.display_state(current,77,77),"ROUTE_REVIEW")

    def test_archive_former_preserves_every_live_resource_and_audit(self):
        op=self._promote_for_test()
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host='8.8.8.8'")
            db.execute("UPDATE host_pool SET is_default=1 WHERE host='1.1.1.1'")
            before_pool=db.execute(
                "SELECT * FROM host_pool WHERE host='8.8.8.8'").fetchone()
            before_settings=dict(db.execute("SELECT * FROM settings"))
        self.assertEqual(self.journal.display_state(op,77,77),"FORMER")
        preview=self.journal.archive_preview(op,77,77)
        self.assertEqual(preview["status"],"ACTIVE")
        self.journal.archive_inactive(op,77,77)
        self.assertNotIn(op,[x["id"] for x in self.journal.list_by_owner(77,77)])
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT * FROM host_pool WHERE host='8.8.8.8'").fetchone(),
                before_pool)
            self.assertEqual(dict(db.execute("SELECT * FROM settings")),before_settings)
            self.assertEqual(db.execute(
                "SELECT status FROM manual_edge_operations WHERE id=?",(op,)
                ).fetchone()[0],"ACTIVE")
            self.assertTrue(db.execute(
                "SELECT archived_at FROM manual_edge_operations WHERE id=?",
                (op,)).fetchone()[0])
            self.assertEqual(db.execute(
                "SELECT code FROM manual_edge_events WHERE op_id=? "
                "ORDER BY seq DESC LIMIT 1",(op,)).fetchone()[0],
                "REMOVED_FROM_EDGE_LIST")
        with self.assertRaisesRegex(ManualEdgeHold,"ALREADY_ARCHIVED"):
            self.journal.archive_inactive(op,77,77)
        with self.assertRaises(ManualEdgeHold):
            self.journal.set_server(self.journal.start(77,77),77,77,
                                    "8.8.8.8",22)

    def test_archive_never_hides_default_standby_or_assigned_customers(self):
        current=self._promote_for_test()
        with self.assertRaisesRegex(ManualEdgeHold,"ARCHIVE_HOST_IS_ROUTED"):
            self.journal.archive_preview(current,77,77)
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host='8.8.8.8'")
            db.execute("UPDATE host_pool SET is_default=1 WHERE host='1.1.1.1'")
            db.execute("INSERT INTO ssh_accounts "
                       "(username,host,status,service_type) "
                       "VALUES ('expired-old','8.8.8.8','expired','ssh')")
        with self.assertRaisesRegex(ManualEdgeHold,"ARCHIVE_USERS_STILL_ASSIGNED"):
            self.journal.archive_inactive(current,77,77)
        with self.db() as db:
            db.execute("DELETE FROM ssh_accounts WHERE username='expired-old'")
        standby=self.prepare("9.9.9.9",port=2298)
        self.journal.mark_standby(standby,77,77)
        with self.assertRaisesRegex(ManualEdgeHold,"ARCHIVE_STATUS_UNSAFE"):
            self.journal.archive_inactive(standby,77,77)
        with self.assertRaisesRegex(ManualEdgeHold,"OPERATOR_MISMATCH"):
            self.journal.archive_inactive(current,99,99)
        self.assertIsNone(self.journal.get(current)["archived_at"])

    def test_archive_rechecks_pending_jobs_and_is_atomic(self):
        op=self._promote_for_test()
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host='8.8.8.8'")
            db.execute("UPDATE host_pool SET is_default=1 WHERE host='1.1.1.1'")
            db.execute("""CREATE TABLE manual_quick_switch_jobs (
                source TEXT,target TEXT,kind TEXT,status TEXT)""")
            db.execute("INSERT INTO manual_quick_switch_jobs VALUES "
                       "('8.8.8.8','9.9.9.9','QUICK','HOLD')")
        with self.assertRaisesRegex(ManualEdgeHold,"ARCHIVE_ROUTE_JOB_UNRESOLVED"):
            self.journal.archive_inactive(op,77,77)
        with self.db() as db:
            db.execute("UPDATE manual_quick_switch_jobs SET status='DONE'")
        self.journal.archive_inactive(op,77,77)
        self.assertEqual(self.journal.get(op)["status"],"ACTIVE")

    def test_archive_missing_inventory_edge_ready_does_not_fake_recovery(self):
        op=self.prepare("8.8.8.8",port=2299)
        with self.db() as db:
            db.execute("DELETE FROM host_pool WHERE host='8.8.8.8'")
        self.assertEqual(self.journal.display_state(op,77,77),"POOL_MISSING")
        self.journal.archive_inactive(op,77,77)
        self.assertEqual(self.journal.get(op)["status"],"EDGE_READY")
        with self.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM host_pool "
                "WHERE host='8.8.8.8'").fetchone()[0],0)

    def test_archive_is_two_step_rich_and_requires_exact_owner(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from manual_edge_wizard import ManualEdgeWizard
        from manual_edge_rich import render_manual_card
        op=self._promote_for_test()
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host='8.8.8.8'")
            db.execute("UPDATE host_pool SET is_default=1 WHERE host='1.1.1.1'")
        wiz=ManualEdgeWizard(db=self.db,preflight=lambda:(2222,"pub"),
            provision=AsyncMock(),verify=AsyncMock(),probe=AsyncMock(),
            nat=AsyncMock(),queue=SimpleNamespace())
        wiz._view=AsyncMock(return_value=1)
        context=SimpleNamespace(user_data={})
        app=SimpleNamespace(bot=SimpleNamespace(token="123:TEST"))
        def invoke(action,actor=77,chat=77):
            asyncio.run(wiz.handle(SimpleNamespace(),context,action,role="admin",
                                   actor=actor,chat=chat,app=app))
            txt,rows=wiz._view.await_args.args[1:]
            render_manual_card(txt,rows)
            return txt,rows
        _,rows=invoke("apps_edge_manual_detail_"+op)
        self.assertIn("apps_edge_manual_archive_"+op,
            [a for row in rows for _,a in row])
        _,rows=invoke("apps_edge_manual_archive_"+op)
        self.assertIn("apps_edge_manual_archive_yes_"+op,
            [a for row in rows for _,a in row])
        deny,_=invoke("apps_edge_manual_archive_yes_"+op,actor=78,chat=78)
        self.assertIn("عملیات متوقف شد",deny)
        self.assertIsNone(self.journal.get(op)["archived_at"])
        done,_=invoke("apps_edge_manual_archive_yes_"+op)
        self.assertIn("سابقه از فهرست",done)
        self.assertIsNotNone(self.journal.get(op)["archived_at"])


    def _former_after_verified_transfer(self):
        """Simulates a completed switch away from a previous manual relay."""
        op=self._promote_for_test("8.8.8.8")
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=0 "
                       "WHERE host='8.8.8.8'")
            db.execute("UPDATE host_pool SET is_default=1 "
                       "WHERE host='1.1.1.1'")
            db.execute("INSERT INTO settings(key,value) VALUES "
                       "('core_wg_public_ip','91.107.170.239')")
        self.assertEqual(self.journal.display_state(op,77,77),"FORMER")
        return op

    def test_former_rearm_is_atomic_and_preserves_dns_accounts_and_history(self):
        op=self._former_after_verified_transfer()
        with self.db() as db:
            settings=dict(db.execute("SELECT key,value FROM settings"))
            history=db.execute(
                "SELECT status FROM manual_edge_operations WHERE id=?",
                (op,)).fetchone()[0]
        preview=self.journal.preview_former_standby(op,77,77,2222)
        self.assertEqual(preview["source"],"1.1.1.1")
        self.assertEqual(preview["pin_type"],self.fake_key()[0])
        self.journal.mark_former_standby(op,77,77,2222)
        with self.db() as db:
            self.assertEqual(dict(db.execute("SELECT key,value FROM settings")),
                             settings)
            self.assertEqual(db.execute(
                "SELECT active,is_default,is_standby FROM host_pool "
                "WHERE host='8.8.8.8'").fetchone(),(1,0,1))
            self.assertEqual(db.execute(
                "SELECT active,is_default FROM host_pool "
                "WHERE host='1.1.1.1'").fetchone(),(1,1))
            self.assertEqual(db.execute(
                "SELECT status FROM manual_edge_operations WHERE id=?",
                (op,)).fetchone()[0],"STANDBY")
            self.assertEqual(history,"ACTIVE")
            self.assertEqual(db.execute(
                "SELECT code FROM manual_edge_events WHERE op_id=? "
                "ORDER BY seq DESC LIMIT 1",(op,)).fetchone()[0],
                "FORMER_NETWORK_REVERIFIED")
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM ssh_accounts").fetchone()[0],0)
            self.assertEqual(resolve(db,"8.8.8.8",require_standby=True)["provider"],
                             "manual")
        with self.assertRaisesRegex(ManualEdgeHold,"FORMER_NOT_ELIGIBLE"):
            self.journal.mark_former_standby(op,77,77,2222)

    def test_former_rearm_denies_current_default_accounts_and_unresolved_jobs(self):
        op=self._promote_for_test("8.8.8.8")
        with self.db() as db:
            db.execute("INSERT INTO settings(key,value) VALUES "
                       "('core_wg_public_ip','91.107.170.239')")
            db.execute("UPDATE settings SET value='8.8.8.8' "
                       "WHERE key IN ('hosts','dns_current_ip')")
        with self.assertRaisesRegex(ManualEdgeHold,"FORMER_ROLE_CHANGED"):
            self.journal.mark_former_standby(op,77,77,2222)
        with self.db() as db:
            db.execute("UPDATE host_pool SET is_default=0 WHERE host='8.8.8.8'")
            db.execute("UPDATE host_pool SET is_default=1 WHERE host='1.1.1.1'")
            db.execute("UPDATE settings SET value='1.1.1.1' "
                       "WHERE key IN ('hosts','dns_current_ip')")
            db.execute("INSERT INTO ssh_accounts VALUES "
                       "('expired','8.8.8.8','expired','ssh')")
        with self.assertRaisesRegex(ManualEdgeHold,"FORMER_USERS_STILL_ASSIGNED"):
            self.journal.mark_former_standby(op,77,77,2222)
        with self.db() as db:
            db.execute("DELETE FROM ssh_accounts WHERE username='expired'")
            db.execute("CREATE TABLE manual_quick_switch_jobs "
                       "(source TEXT,target TEXT,kind TEXT,status TEXT)")
            db.execute("INSERT INTO manual_quick_switch_jobs VALUES "
                       "('1.1.1.1','8.8.8.8','QUICK','HOLD')")
        with self.assertRaisesRegex(ManualEdgeHold,"FORMER_TRANSFER_UNRESOLVED"):
            self.journal.mark_former_standby(op,77,77,2222)
        with self.db() as db:
            db.execute("UPDATE manual_quick_switch_jobs SET status='DONE'")
        with self.assertRaisesRegex(ManualEdgeHold,"OPERATOR_MISMATCH"):
            self.journal.mark_former_standby(op,99,99,2222)
        with self.assertRaisesRegex(ManualEdgeHold,"FORMER_ROLE_CHANGED"):
            self.journal.mark_former_standby(op,77,77,2223)
        self.assertEqual(self.journal.get(op)["status"],"ACTIVE")

    def test_former_rearm_ui_verifies_pinned_key_probe_nat_then_quick_cta(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock,Mock
        from manual_edge_wizard import ManualEdgeWizard
        from manual_edge_rich import render_manual_card
        op=self._former_after_verified_transfer()
        probe=AsyncMock(return_value=True)
        nat=AsyncMock(return_value=True)
        key=Mock(return_value=self.fake_key())
        wizard=ManualEdgeWizard(db=self.db,preflight=lambda:(2222,"pub"),
            provision=AsyncMock(),verify=AsyncMock(),probe=probe,nat=nat,
            queue=SimpleNamespace(),key_reader=key)
        wizard._view=AsyncMock(return_value=42)
        context=SimpleNamespace(user_data={})
        app=SimpleNamespace(bot=SimpleNamespace(token="123:TEST"))
        def invoke(callback):
            asyncio.run(wizard.handle(
                SimpleNamespace(),context,callback,
                role="admin",actor=77,chat=77,app=app))
            text,rows=wizard._view.await_args.args[1:]
            render_manual_card(text,rows)
            return text,[action for row in rows for _,action in row]
        _,detail=invoke("apps_edge_manual_detail_"+op)
        self.assertIn("apps_edge_manual_rearm_"+op,detail)
        _,review=invoke("apps_edge_manual_rearm_"+op)
        self.assertIn("apps_edge_manual_rearm_yes_"+op,review)
        self.assertEqual(self.journal.get(op)["status"],"ACTIVE")
        text,actions=invoke("apps_edge_manual_rearm_yes_"+op)
        self.assertIn("دوباره Standby شد",text)
        self.assertIn("apps_edge_quick_select_8.8.8.8",actions)
        self.assertEqual(self.journal.get(op)["status"],"STANDBY")
        key.assert_called_once_with("8.8.8.8",2299)
        probe.assert_awaited_once_with("8.8.8.8",2222,2299)
        nat.assert_awaited_once()
        self.assertEqual(nat.await_args.args[-1],self.fake_key()[:2])
        _,after=invoke("apps_edge_manual_detail_"+op)
        self.assertIn("apps_edge_quick_select_8.8.8.8",after)

    def test_former_rearm_hostkey_changed_blocks_probes_and_changes(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from manual_edge_wizard import ManualEdgeWizard
        op=self._former_after_verified_transfer()
        probe=AsyncMock(return_value=True)
        nat=AsyncMock(return_value=True)
        wizard=ManualEdgeWizard(db=self.db,preflight=lambda:(2222,"pub"),
            provision=AsyncMock(),verify=AsyncMock(),probe=probe,nat=nat,
            queue=SimpleNamespace(),
            key_reader=lambda *_:("ssh-ed25519","DIFFERENT","SHA256:MISMATCH"))
        wizard._view=AsyncMock(return_value=42)
        asyncio.run(wizard.handle(SimpleNamespace(),SimpleNamespace(user_data={}),
            "apps_edge_manual_rearm_yes_"+op,role="admin",actor=77,chat=77,
            app=SimpleNamespace(bot=SimpleNamespace(token="123:TEST"))))
        self.assertIn("FORMER_HOSTKEY_CHANGED",wizard._view.await_args.args[1])
        probe.assert_not_awaited()
        nat.assert_not_awaited()
        self.assertEqual(self.journal.get(op)["status"],"ACTIVE")

    def test_new_edge_standby_to_quick_switch_action_stays_visible(self):
        import asyncio
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from manual_edge_wizard import ManualEdgeWizard
        op=self.prepare("8.8.8.8",port=2299)
        self.journal.mark_standby(op,77,77)
        wizard=ManualEdgeWizard(db=self.db,preflight=lambda:(2222,"pub"),
            provision=AsyncMock(),verify=AsyncMock(),probe=AsyncMock(),
            nat=AsyncMock(),queue=SimpleNamespace())
        wizard._view=AsyncMock(return_value=42)
        asyncio.run(wizard.handle(SimpleNamespace(),SimpleNamespace(user_data={}),
            "apps_edge_manual_detail_"+op,role="admin",actor=77,chat=77,
            app=SimpleNamespace(bot=SimpleNamespace(token="123:TEST"))))
        self.assertIn("apps_edge_quick_select_8.8.8.8",
            [action for row in wizard._view.await_args.args[2]
             for _,action in row])


if __name__=="__main__":
    unittest.main()
