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
        self.journal=ManualEdgeJournal(self.db,now=lambda:10000)

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

    def test_actor_and_chat_owned_and_draft_cancel_only(self):
        op=self.journal.start(77,77)
        with self.assertRaises(ManualEdgeHold):
            self.journal.set_server(op,78,77,"8.8.8.8",22)
        self.journal.cancel_draft(op,77,77)
        self.assertEqual(self.journal.get(op)["status"],"CANCELLED")
        self.journal.start(77,77)


if __name__=="__main__":
    unittest.main()
