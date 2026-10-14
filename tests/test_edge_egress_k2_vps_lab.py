"""K2 P3 VPS trial navigation: real temporary SQLite, no mutation."""
from dataclasses import replace
from pathlib import Path
import re
import sqlite3
import unittest

from edge_egress_k2_vps_lab import (
    K2LabReview,LabReviewHold,review_vps_lab,lab_html,lab_buttons,
)
from edge_egress_phase2_console import EdgeCard,Dashboard
from tests.test_edge_egress_k2_source_enrollment import SameEdgeEnrollmentTests
from tests.test_edge_egress_uid_runtime_store import SOURCE,TARGET


class K2VPSTrialTests(unittest.TestCase):
    def setUp(self):
        self.fx=SameEdgeEnrollmentTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.card=EdgeCard(
            "dst1",TARGET,True,False,False,False,
            "STAGED","VERIFIED_LAB",False,"","",None,None,"a"*64,
        )
        self.base=Dashboard((self.card,),1,True,SOURCE,SOURCE,"0",0)

    def review(self,**params):
        def reader(db_conn,*,only_edge):
            self.assertEqual(only_edge,"dst1")
            return params.get("dashboard",self.base)
        return review_vps_lab(self.fx.conn_factory,
                              params.get("edge_id","dst1"),
                              dashboard_reader=reader)

    def test_stage_only_new_edge_eligible_even_if_not_in_host_pool(self):
        before=self.fx.state()
        p=self.review()
        self.assertTrue(p.stage_trial_eligible)
        self.assertEqual((p.legacy_count,p.protected_count,p.active_total),(1,0,1))
        self.assertFalse(p.customer_ready)
        self.assertFalse(p.can_execute)
        self.assertEqual(self.fx.state(),before)
        self.assertIn("hpeg_p1_probe_dst1",[c for row in lab_buttons(p) for _,c in row])
        self.assertIn("قدیمی",lab_html(p))
        self.assertNotIn("SSH آماده",lab_html(p))

    def test_target_f4_not_a_requirement_for_preliminary_namespace_probe(self):
        with self.fx.db() as c:
            c.execute("UPDATE edge_egress_readiness SET expires_at=1 "
                      "WHERE edge_id='dst1'")
        r=self.review()
        self.assertTrue(r.stage_trial_eligible)
        self.assertFalse(r.target_f4)
        self.assertFalse(r.can_execute)
        self.assertIn("تأیید نهایی",lab_html(r))

    def test_all_source_users_protected_still_no_execute_button(self):
        plan,ticket,engine,_=self.fx.engine()
        self.assertTrue(self.fx.execute(plan,ticket,engine).allowed)
        p=self.review()
        self.assertEqual((p.legacy_count,p.protected_count),(0,1))
        self.assertFalse(p.can_execute)
        names=[c for row in lab_buttons(p) for _,c in row]
        self.assertFalse(any("yes" in c or "activate" in c for c in names))
        self.assertIn("hpeg_relay_dst1",names)

    def test_running_6g_removes_stage_ip_probe(self):
        with self.fx.db() as c:
            c.execute("INSERT INTO failover_operations(source_host,target_host,"
                      "status,detail_json) VALUES(?,?,'RUNNING','{}')",
                      (SOURCE,TARGET))
        p=self.review()
        self.assertFalse(p.stage_trial_eligible)
        self.assertIn("SHARED_6G_BUSY",p.blockers)
        self.assertNotIn("hpeg_p1_probe_dst1",[b for row in lab_buttons(p) for _,b in row])

    def test_dns_or_source_change_fences_trial(self):
        with self.fx.db() as c:
            c.execute("UPDATE settings SET value=? WHERE key='dns_current_ip'",
                      (TARGET,))
        bad=replace(self.base,dns_ip=TARGET)
        r=self.review(dashboard=bad)
        self.assertFalse(r.stage_trial_eligible)
        self.assertIn("PUBLIC_DNS_NOT_CURRENT_SOURCE",r.blockers)

    def test_source_staged_allocation_required(self):
        with self.fx.db() as c:
            c.execute("DELETE FROM edge_egress_allocations WHERE edge_id='src1'")
        p=self.review()
        self.assertFalse(p.stage_trial_eligible)
        self.assertIn("SOURCE_F3_IDENTITY_UNVERIFIED",p.blockers)

    def test_missing_pin_or_ingress_does_not_offer_network_probe(self):
        for card in (replace(self.card,stage_pin=None),
                     replace(self.card,ingress_verified=False),
                     replace(self.card,allocation="IDENTITY_CONFLICT")):
            with self.subTest(card=card):
                p=self.review(dashboard=replace(self.base,cards=(card,)))
                self.assertFalse(p.stage_trial_eligible)
                self.assertFalse(p.can_execute)

    def test_other_or_corrupt_users_are_reported_not_transferred(self):
        with self.fx.db() as c:
            c.execute("INSERT INTO ssh_accounts(username,host,service_type,status)"
                      " VALUES('nvlbad',?,'ssh','🟢 فعال')",(TARGET,))
        p=self.review()
        self.assertEqual((p.other_edge_count,p.legacy_count),(1,1))
        self.assertIn("ACCOUNT_INGRESS_OR_PROTECTION_INCONSISTENT",p.blockers)
        self.assertFalse(p.can_execute)

    def test_untrusted_fingerprint_data_does_not_reach_ui(self):
        with self.assertRaises(LabReviewHold):
            self.review(edge_id="../bad")
        with self.fx.db() as c:
            c.execute("DROP TABLE edge_egress_uid_runtime")
        with self.assertRaises(LabReviewHold):
            self.review()

    def test_f4_ready_does_not_equal_customer_ready(self):
        p=self.review()
        self.assertTrue(p.target_f4)
        self.assertFalse(p.customer_ready)
        self.assertFalse(p.can_execute)
        self.assertIn("تست واقعی کاربران",lab_html(p))

    def test_html_escape_and_callback_validation(self):
        p=replace(self.review(),target_ipv4="<img onerror=1>")
        self.assertIn("&lt;img",lab_html(p))
        self.assertNotIn("<img",lab_html(p))
        with self.assertRaises(Exception):
            lab_buttons(replace(p,edge_id="bad;cmd"))

    def test_existing_bot_hpeg_lab_is_admin_only_and_readonly(self):
        src=(Path(__file__).resolve().parents[1] /
             "bot_final_v49-2.py").read_text(encoding="utf-8")
        self.assertIn("review_vps_lab, lab_html as k2_lab_html",src)
        self.assertIn('elif d.startswith("hpeg_lab_"):',src)
        match=re.search(
            r'    elif d.startswith\("hpeg_lab_"\):(.*?)'
            r'    elif d.startswith\("hpeg_relay_"\):',
            src,re.S,
        )
        self.assertIsNotNone(match)
        body=match.group(1)
        self.assertIn("if role != 'admin':",body)
        self.assertIn("edge_id_checked(edge_id)",body)
        self.assertIn("await asyncio.to_thread(",body)
        self.assertIn("review_vps_lab, db_conn, edge_id",body)
        self.assertIn("k2_lab_buttons(snapshot)",body)
        self.assertNotIn("activate_phase1",body)
        self.assertNotIn("execute_relay_switch",body)
        self.assertNotIn("_db_update_failover_operation",body)
        self.assertNotIn("subprocess",body)

    def test_only_safe_readonly_callbacks_registered(self):
        names=[callback for row in lab_buttons(self.review())
               for _,callback in row]
        self.assertTrue(set(names)<={
            "hpeg_p1_probe_dst1","hpeg_user_dst1",
            "hpeg_relay_dst1","hpeg_lab_dst1","hpeg_edge_dst1",
        })


if __name__=="__main__":
    unittest.main()
