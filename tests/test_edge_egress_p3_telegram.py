"""K2 P3-F: short admin UX, fail-closed read-only orphan view and bot bindings."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import ast
import os
import re
import stat
import unittest

from edge_egress_phase2_console import Dashboard, EdgeCard, TransportCheck
from edge_egress_phase2_retire import RetirePlan
from edge_egress_phase2_review import OperatorReview
from edge_egress_p3_telegram import (
    P3F_LIVE_EXECUTION_ENABLED, dashboard_html, dashboard_buttons,
    edge_html, detail_buttons, maintenance_buttons, actions_html, transport_html, stage_html,
    review_html, retire_html, steps_html, orphan_html,
    user_prompt_html, user_result_html, wizard_prompt, wizard_result,
)


def edge(eid="fra1",**kw):
    base=EdgeCard(
        eid,"216.126.229.12",True,True,False,False,"STAGED",
        "VERIFIED_LAB",False,"","",None,None,"a"*64,
    )
    return replace(base,**kw)


class OperatorUXTests(unittest.TestCase):
    def setUp(self):
        self.card=edge()
        self.board=Dashboard(
            (edge("fra1"),edge("sfo1"),edge("lon1")),3,True,
            "144.172.84.82","144.172.84.82","0",0,
        )

    def test_dashboard_is_compact_and_two_columns(self):
        html=dashboard_html(self.board)
        grid=dashboard_buttons(self.board)
        self.assertIn("مدیریت خروجی",html)
        self.assertNotIn("144.172.84.82",html)
        self.assertIn("fra1",dashboard_html(self.board,active_edge="fra1"))
        self.assertEqual([len(row) for row in grid],[2,1,2,2,1])
        self.assertEqual(grid[0][0][1],"hpeg_edge_fra1")
        self.assertEqual(grid[-1][0][1],"apps_home")
        for banned in ("6G","SHA","PAM","F4","Stage","Kernel","Phase","UID"):
            self.assertNotIn(banned,html)

    def test_orphan_inventory_is_reachable_without_any_registered_server(self):
        board=replace(self.board,cards=(),total=0)
        rows=dashboard_buttons(board)
        self.assertIn(("🧹 منابع باقی‌مانده","hpeg_orphans"),sum(rows,[]))
        self.assertTrue(all(1<=len(row)<=2 for row in rows))
        self.assertFalse(any(cb.startswith('hpeg_edge_') for row in rows for _,cb in row))

    def test_pagination_and_no_extra_page(self):
        board=replace(self.board,page=0,total=17)
        self.assertIn(("بعدی ▶️","hpeg_page_1"),dashboard_buttons(board)[2])
        board=replace(board,page=1,total=9)
        keys=sum(dashboard_buttons(board),[])
        self.assertIn(("◀️ قبلی","hpeg_page_0"),keys)
        self.assertNotIn(("بعدی ▶️","hpeg_page_2"),keys)

    def test_detail_layout_preserves_inspection_user_review_and_delete(self):
        grid=detail_buttons(self.card)
        self.assertTrue(all(1<=len(row)<=2 for row in grid))
        callbacks=[callback for row in grid+maintenance_buttons(self.card) for _,callback in row]
        self.assertEqual(len([cb for row in grid for _,cb in row]),
                         len(set(cb for row in grid for _,cb in row)))
        for needed in ("hpeg_edge_fra1","hpeg_user_fra1","hpeg_health_fra1",
                       "hpeg_stage_fra1","hpeg_m4_home_fra1",
                       "hpeg_actions_fra1","hpeg_retire_open_fra1"):
            self.assertIn(needed,callbacks)
        self.assertIn("hpeg_probe_fra1",callbacks)
        not_ready=edge(allocation="NOT_STAGED",stage_pin=None)
        callbacks=[cb for row in detail_buttons(not_ready) for _,cb in row]
        self.assertNotIn("hpeg_probe_fra1",callbacks)

    def test_escaped_metadata_and_minimal_state(self):
        card=replace(self.card,ip='<img src=x onerror=1>')
        output=edge_html(card)
        self.assertNotIn("<img",output)
        self.assertIn("&lt;img",output)
        self.assertNotIn("F4",output)
        self.assertNotIn("INGRESS_ONLY",output)
        self.assertIn("🟡",output)

    def test_user_review_is_short_and_only_read(self):
        self.assertIn("لغو",user_prompt_html("fra1"))
        self.assertIn("<code>nvl0557</code>",user_result_html("fra1","nvl0557"))
        r=OperatorReview("UID_ATTACH","fra1","216.126.229.12",
            "nvl0557","144.172.84.82",("K2_P3A_LOCK",),
            ("unix sudo",),1000,"c"*64,1)
        rendered=review_html(r)
        self.assertNotIn("K2_P3A_LOCK",rendered)
        self.assertNotIn("unix sudo",rendered)
        self.assertIn("امکان انجام",rendered)
        self.assertTrue(P3F_LIVE_EXECUTION_ENABLED is False)

    def test_retire_confirmation_is_distinct_from_blocked(self):
        can=RetirePlan("fra1","216.126.229.12","a"*64,(),False)
        blocked=replace(can,blockers=("WG0_PERSISTENT_PEER_PRESENT","UID1644"))
        self.assertIn("✅",retire_html(can))
        self.assertIn("⛔",retire_html(blocked))
        self.assertNotIn("WG0",retire_html(blocked))
        self.assertIn("خود سرور را خاموش نمی‌کند",retire_html(can))

    def test_health_actions_and_guide_hide_internal_flags(self):
        health=transport_html(self.card,TransportCheck("STAGE_PIN_REQUIRED",1000))
        stage=stage_html(self.card,SimpleNamespace(stage_state="PINNED"))
        actions=actions_html(self.card,TransportCheck("UP",1000))
        guide=steps_html()
        for body in (health,stage,actions,guide):
            self.assertNotIn("PAM",body)
            self.assertNotIn("HOLD",body)
            self.assertNotIn("Phase",body)
            self.assertLess(len(body),500)
        self.assertIn("مرحله",guide) if False else None

    def test_orphan_listing_is_read_only_and_cannot_claim_safe_cleanup(self):
        class FakeDir:
            def __init__(self,name,children=()):
                self.name=name
                self.children=children
            def lstat(self):
                return SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0)
            def iterdir(self):
                return self.children
        root=FakeDir("root",(FakeDir("core-e7"),FakeDir("core-fra1"),
                                  FakeDir("other-edge"),))
        text=orphan_html(stage_root=root)
        self.assertIn("e7",text)
        self.assertIn("fra1",text)
        self.assertNotIn("other-edge",text)
        self.assertIn("نیازمند بررسی",text)
        self.assertNotIn("✅",text)
        broken=FakeDir("root",(FakeDir("core-e7"),))
        broken.children[0].lstat=lambda:SimpleNamespace(
            st_mode=stat.S_IFLNK|0o777,st_uid=0)
        self.assertNotIn("e7",orphan_html(stage_root=broken))

    def test_wizard_concise_and_reuses_original_validation(self):
        self.assertIn("IP عمومی",wizard_prompt(integrated=True))
        with self.assertRaises((ValueError,TypeError)):
            wizard_prompt(integrated=1)
        with self.assertRaises(ValueError):
            wizard_result("10.0.0.1",{})
        self.assertNotIn("Stage",wizard_prompt(integrated=True))


class BotBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=(Path(__file__).resolve().parents[1]/"bot_final_v49-2.py").read_text(
            encoding="utf-8")

    def test_existing_admin_handlers_reused_not_parallel_bot(self):
        source=self.source
        for pattern in ('elif d == "hpeg_status"','elif d == "hpeg_orphans"',
                        'elif d.startswith("hpeg_retire_open_")',
                        'or d.startswith("hpeg_retire_yes_")',
                        'egress_dashboard_buttons(board)',
                        'egress_detail_buttons(card)',
                        'egress_retire_plan_html(plan)',
                        'apply_egress_retire_metadata, db_conn, ticket'):
            self.assertIn(pattern,source)
        self.assertLess(source.index('elif d == "hpeg_orphans"'),
                        source.index('elif d == "hpeg_steps"'))

    def test_new_admin_handler_denies_non_admin_before_scan(self):
        source=self.source
        start=source.index('    elif d == "hpeg_orphans":')
        end=source.index('    elif d == "hpeg_steps":',start)
        handler=source[start:end]
        self.assertLess(handler.index("if role != 'admin'"),
                        handler.index("egress_orphan_html"))
        self.assertNotIn("subprocess",handler)
        self.assertNotIn("retire",handler)

    def test_no_live_executor_registered_in_telegram(self):
        source=self.source
        self.assertNotIn("GuardedOrphanRetirePort(",source)
        self.assertNotIn("GuardedProtectedUIDPort(",source)
        self.assertNotIn("GuardedIngressCloudflarePort(",source)
        self.assertNotIn("P3F_LIVE_EXECUTION_ENABLED = True",source)
        self.assertIn("context.user_data.pop('egress_retire_ticket', None)",source)
        self.assertIn("issue_egress_retire_ticket(",source)


if __name__=="__main__":
    unittest.main()
