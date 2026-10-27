"""K2 traffic-only scope: Legacy relay semantics and read-only Telegram review."""
from dataclasses import replace
from pathlib import Path
import unittest

from edge_egress_k2_relay_switch import (
    RelayTrafficReview, review_relay_traffic,
    relay_traffic_html, relay_traffic_buttons,
)
from edge_egress_phase2_console import Dashboard, EdgeCard
from edge_egress_k2_final_integration import TransferPreview

ROOT = Path(__file__).resolve().parents[1]
BOT = ROOT / "bot_final_v49-2.py"
LEGACY_EDGE = ROOT / "setup_edge_relay.sh"


def edge(**kw):
    sample = EdgeCard(
        "fra1","216.126.229.12",True,True,False,False,
        "STAGED","READY",True,"","",None,None,"a"*64,
    )
    return replace(sample,**kw)


class LegacyRelayContractTests(unittest.TestCase):
    def test_legacy_edge_has_no_ssh_account_provision(self):
        src=LEGACY_EDGE.read_text(encoding="utf-8")
        self.assertIn('iptables -t nat -A PREROUTING -p tcp',src)
        self.assertIn('10.77.0.1:',src)
        self.assertIn('iptables -t nat -A POSTROUTING ! -o lo -j MASQUERADE',src)
        self.assertNotIn('iptables -t nat -A POSTROUTING -j MASQUERADE',src)
        for mutator in ('useradd ', 'adduser ', 'passwd ', 'CREATE TABLE ', 'ssh_accounts'):
            self.assertNotIn(mutator,src)

    def test_legacy_default_and_manual_confirmed_migration_are_preserved(self):
        src=BOT.read_text(encoding="utf-8")
        self.assertIn('callback_data=f"hpdef_{edge_ip}"',src)
        start=src.index('    elif d.startswith("hpdef_")')
        end=src.index('    # 🗑 حذف‌شده: خریدِ خودکارِ VPS',start)
        block=src[start:end]
        # Admin callback requires a live customer SSH service before changing
        # the default, and offers a separate confirmation for moving customers.
        self.assertLess(block.index("_check_ssh_reachable"),
                        block.index("_db_set_default_host"))
        self.assertIn('callback_data=f"hpdef_migrate_{host}"',block)
        confirm_start=src.index('    elif d.startswith("hpdefmig_yes_")')
        confirm_end=src.index('    elif d.startswith("hpdef_")',confirm_start)
        confirmed=src[confirm_start:confirm_end]
        self.assertLess(confirmed.index("_check_ssh_reachable"),
                        confirmed.index("_db_set_all_accounts_host"))
        self.assertIn("_update_cloudflare_dns(host)",confirmed)
        # Provisioning still uses the same installer + optional Egress stage.
        self.assertIn("_provision_new_edge_sync, edge_ip",src)
        self.assertIn("_db_add_host_pool, edge_ip",src)
        self.assertIn('callback_data=f"hpdef_{edge_ip}"',src)
        self.assertNotIn('useradd ',confirmed)

    def test_failover_rebuild_is_distinct_emergency_flow(self):
        src=BOT.read_text(encoding="utf-8")
        start=src.index('async def _safe_manual_failover(')
        end=src.index('        # Step 2: rebuild exactly',start)
        flow=src[start:end]
        self.assertIn('_db_acquire_failover_lock',flow)
        self.assertIn('_cf_switch_public_domain(core_public_ip',flow)


class K2RelayPreviewTests(unittest.TestCase):
    def setUp(self):
        self.card=edge()
        self.board=Dashboard(
            (self.card,),1,True,"104.194.144.195",
            "104.194.144.195","0",0,
        )
        self.preview=TransferPreview(
            "fra1","216.126.229.12",2,("آماده‌سازی خروجی ثبت و تأیید نشده",),True,
        )

    def test_traffic_only_keeps_core_accounts(self):
        result=review_relay_traffic(self.board,self.card,self.preview)
        self.assertEqual(result.active_ssh_accounts,2)
        self.assertFalse(result.execution_available)
        self.assertFalse(result.destination_is_default)
        output=relay_traffic_html(result)
        self.assertIn("همه حساب‌ها روی Core باقی می‌مانند",output)
        self.assertIn("IP خروجی",output)
        self.assertIn("سوییچ ترافیک فعلاً انجام نمی‌شود",output)
        self.assertIn("216.126.229.12",output)
        actions=sum(relay_traffic_buttons(result),[])
        self.assertIn(("👥 بررسی ترافیک کاربران","hpeg_transfer_fra1"),actions)
        self.assertFalse(any(x.startswith("hpdef") or "confirm" in x or "yes" in x
                             for _,x in actions))

    def test_inconsistent_default_dns_does_not_offer_switch(self):
        altered=replace(self.board,dns_ip="198.51.100.4")
        result=review_relay_traffic(altered,self.card,self.preview)
        self.assertIn("رله پیش‌فرض و DNS فعلی همخوان نیستند",result.blockers)
        self.assertFalse(result.execution_available)

    def test_wrong_identity_or_private_ip_fails_closed(self):
        with self.assertRaises(ValueError):
            review_relay_traffic(self.board,edge(ip="10.0.0.3"),self.preview)
        with self.assertRaises(ValueError):
            review_relay_traffic(self.board,self.card,
                                 replace(self.preview,edge_id="other"))

    def test_no_unreviewed_release_claim(self):
        fake=RelayTrafficReview(
            "fra1","216.126.229.12","104.194.144.195",
            "104.194.144.195",2,False,(),True,
        )
        with self.assertRaisesRegex(ValueError,"MUST_NOT_BE_RENDERED"):
            relay_traffic_html(fake)


class TelegramRouteWiringTests(unittest.TestCase):
    def test_new_wizard_and_detail_offer_existing_relay_intent(self):
        text=BOT.read_text(encoding="utf-8")
        view=(ROOT/"edge_egress_p3_telegram.py").read_text(encoding="utf-8")
        self.assertIn('callback_data=f"hpeg_relay_{edge_id}"',text)
        self.assertIn('f"hpeg_relay_{eid}"',view)

    def test_relay_manual_branch_is_admin_with_existing_6g_worker_only(self):
        src=BOT.read_text(encoding="utf-8")
        start=src.index('    elif d.startswith("hpeg_relay_"):')
        end=src.index('    elif d.startswith("hpeg_transfer_"):',start)
        callback=src[start:end]
        self.assertLess(callback.index("if role != 'admin':"),
                        callback.index("review_relay_cohort"))
        self.assertIn("render_cohort_review(review)",callback)
        self.assertIn("hpeg_p2_open_",callback)
        self.assertIn("hpeg_p2_yes_",callback)
        self.assertIn("execute_relay_switch(",callback)
        self.assertIn("_db_acquire_failover_lock",callback)
        for mutation in (
            "_db_set_default_host", "_db_set_all_accounts_host",
            "_db_rebuild_hosts_from_pool","_update_cloudflare_dns",
            "set_account_host", "set_hosts_bulk","systemctl",
            "_safe_manual_failover",
        ):
            self.assertNotIn(mutation,callback)


if __name__ == "__main__":
    unittest.main()
