"""K2 B3: only operator read-receipts; no executor in the package."""
import sqlite3
import time
import unittest
from dataclasses import replace
from types import SimpleNamespace

from edge_egress_phase2_review import (
    ACTIONS, EXECUTOR_ENABLED, build_review, issue_ticket,
    acknowledge_ticket, review_html,
)
from edge_egress_v1_console import EgressConsoleHold


class ReviewSafety(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
            INSERT INTO settings VALUES('edge_egress_protected_mode','0');
            CREATE TABLE failover_operations(id INTEGER,status TEXT);
            CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY,host TEXT,
                                      service_type TEXT,status TEXT);
            INSERT INTO ssh_accounts VALUES(
                'nvl0557','104.194.144.195','ssh','🟢 فعال');
        """)
        self.clock = 1791844347
        self.conn = lambda: self.db
        self.card = SimpleNamespace(
            edge_id="e7",ip="172.86.105.67",ingress_verified=True,
            pool_active=True,allocation="NOT_STAGED",stage_pin=None,
            f4_state="NO_EVIDENCE",f4_valid=False,evidence_at=None,
            expires_at=None,
        )
        self.stage = SimpleNamespace(
            stage_state="LOCAL_UNATTESTED",
            local_sha256="a"*64,tunnel_state="UP",
        )

    def review(self, action="EDGE_PREPARE", username=""):
        return build_review(
            self.conn, self.card, self.stage, action, username, now=self.clock,
        )

    def test_real_e7_operator_stage_stays_hold(self):
        plan = self.review()
        self.assertFalse(EXECUTOR_ENABLED)
        self.assertEqual(plan.decision,"HOLD")
        self.assertIn("F3_STAGED_ALLOCATION_MISSING", plan.blockers)
        self.assertIn("INDEPENDENT_STAGE_SHA_REQUIRED",plan.blockers)
        self.assertIn("F4_ACCEPTANCE_NOT_VALID",plan.blockers)
        self.assertIn("PROTECTED_MODE_NOT_APPROVED",plan.blockers)
        self.assertIn("F2_PAM_BOOT_RESCUE_NOT_ACCEPTED",plan.blockers)
        self.assertIn("DNS_IPV6_FAIL_CLOSED_NOT_ACCEPTED",plan.blockers)
        self.assertIn("PROTECTED_6G_EXECUTOR_NOT_INSTALLED",plan.blockers)
        self.assertIn("HOLD",review_html(plan))
        self.assertNotIn("PrivateKey",review_html(plan))

    def test_uid_dry_run_tracks_account_state_and_6g_lock_read_only(self):
        trace=[]
        self.db.set_trace_callback(trace.append)
        plan = self.review("UID_ATTACH","nvl0557")
        self.assertEqual(plan.affected_accounts,1)
        self.assertEqual(plan.current_host,"104.194.144.195")
        self.assertIn("nvl0557",review_html(plan))
        self.assertNotIn("ANOTHER_6G_OPERATION_RUNNING",plan.blockers)
        self.assertFalse(any(
            sql.strip().upper().startswith((
                "INSERT","UPDATE","DELETE","DROP","CREATE","ALTER","REPLACE"))
            for sql in trace
        ))
        self.db.execute("INSERT INTO failover_operations VALUES(1,'RUNNING')")
        new=self.review("UID_ATTACH","nvl0557")
        self.assertNotEqual(plan.digest,new.digest)
        self.assertIn("ANOTHER_6G_OPERATION_RUNNING",new.blockers)
        self.assertEqual(self.review("UID_FREEZE","nvl0557").decision,"HOLD")

    def test_unauthorized_or_malformed_action_username_fails_before_sql(self):
        for name,action,user in [
            ("action","UID_REMOVE","nvl0557"),
            ("missing","UID_ATTACH",""),
            ("path","UID_FREEZE","../../etc/shadow"),
            ("multiple","EDGE_PREPARE","nvl0557"),
        ]:
            with self.subTest(name=name),self.assertRaises(EgressConsoleHold):
                build_review(
                    lambda: (_ for _ in ()).throw(
                        AssertionError("Invalid action reached database")
                    ), self.card,self.stage,action,user,now=self.clock,
                )

    def test_green_f4_still_does_not_create_execution_authority(self):
        self.db.execute("UPDATE settings SET value='1'")
        card=replace(self.card) if hasattr(self.card,'__dataclass_fields__') else SimpleNamespace(
            **{**vars(self.card),"allocation":"STAGED",
               "stage_pin":"a"*64,"f4_valid":True,
               "f4_state":"READY"}
        )
        stage=SimpleNamespace(stage_state="PINNED",
                              local_sha256="a"*64,tunnel_state="UP")
        plan=build_review(self.conn,card,stage,"EDGE_PREPARE",now=self.clock)
        self.assertEqual(plan.decision,"HOLD")
        self.assertIn("F2_PAM_BOOT_RESCUE_NOT_ACCEPTED",plan.blockers)
        self.assertIn("DNS_IPV6_FAIL_CLOSED_NOT_ACCEPTED",plan.blockers)
        self.assertIn("PROTECTED_6G_EXECUTOR_NOT_INSTALLED",plan.blockers)

    def test_ack_is_actor_chat_ttl_and_full_snapshot_bound(self):
        original=self.review()
        ticket=issue_ticket(
            original,actor_id=131,chat_id=-45,now=self.clock,
            nonce=lambda:"abcdef0123456789",
        )
        self.assertEqual(acknowledge_ticket(
            ticket,original,token=ticket.token,actor_id=131,chat_id=-45,
            now=self.clock+5,
        ),"REVIEW_ACKNOWLEDGED_NO_EXECUTION")
        cases=[
            {"token":"a"*16},
            {"actor_id":500},
            {"chat_id":200},
            {"now":self.clock+120},
        ]
        for change in cases:
            params={"token":ticket.token,"actor_id":131,
                    "chat_id":-45,"now":self.clock+5,**change}
            with self.subTest(change=change),self.assertRaises(EgressConsoleHold):
                acknowledge_ticket(ticket,original,**params)
        self.db.execute("INSERT INTO failover_operations VALUES(8,'RUNNING')")
        changed=self.review()
        with self.assertRaisesRegex(EgressConsoleHold,"REVIEW_EVIDENCE_CHANGED"):
            acknowledge_ticket(
                ticket,changed,token=ticket.token,actor_id=131,chat_id=-45,
                now=self.clock+5,
            )

    def test_receipt_non_anonymizable_or_injectable(self):
        for actor,chat in ((0,1),(True,1),(1,0),(1,False)):
            with self.subTest(actor=actor,chat=chat),self.assertRaises(EgressConsoleHold):
                issue_ticket(self.review(),actor_id=actor,chat_id=chat,
                             now=self.clock,nonce=lambda:"abcdef0123456789")
        with self.assertRaises(EgressConsoleHold):
            issue_ticket(self.review(),actor_id=1,chat_id=1,
                         nonce=lambda:"../../bad")


if __name__=="__main__":
    unittest.main()
