"""K2 Phase 2: real SQLite cohort, explicit manual gate, no Legacy bypass."""
import asyncio
from pathlib import Path
import sqlite3
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from edge_egress_f3_readiness import install_readiness_schema
from edge_egress_uid_runtime_store import install_runtime_schema
from edge_egress_protected_mapping import install_protected_mapping_schema
from edge_egress_k2_phase2_operator import (
    review_relay_cohort, RelaySwitchTicket, Phase2Hold,
    execute_relay_switch, render_cohort_review, relay_cohort_buttons,
)

SOURCE="144.172.84.76"
TARGET="144.172.84.82"
CORE="209.200.246.198"
USERS=(("nvl0557",1644),("nvl0558",1645))


class Phase2CohortTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(":memory:",check_same_thread=False,isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT);
            INSERT INTO settings VALUES('edge_egress_protected_mode','1');
            INSERT INTO settings VALUES('dns_current_ip','144.172.84.76');
            INSERT INTO settings VALUES('hosts','144.172.84.76');
            CREATE TABLE failover_operations(id INT,status TEXT);
            CREATE TABLE host_pool(host TEXT PRIMARY KEY,active INT,
                is_default INT,is_standby INT,service_port INT);
            INSERT INTO host_pool VALUES('144.172.84.76',1,1,0,2252);
            CREATE TABLE ssh_accounts(username TEXT PRIMARY KEY,host TEXT,
                service_type TEXT,status TEXT);
            CREATE TABLE edge_egress_allocations(edge_id TEXT PRIMARY KEY,
                edge_public_ipv4 TEXT,core_public_ipv4 TEXT,
                route_table INT,status TEXT);
            INSERT INTO edge_egress_allocations VALUES
                ('e8','144.172.84.76','209.200.246.198',20008,'STAGED'),
                ('e9','144.172.84.82','209.200.246.198',20009,'STAGED');
        """)
        install_runtime_schema(self.db)
        install_protected_mapping_schema(self.db)
        install_readiness_schema(self.db)
        now=int(time.time())
        self.db.execute(
            "INSERT INTO edge_egress_readiness "
            "(edge_id,edge_ipv4,state,observed_ipv4,witness,probed_at,"
            "expires_at,last_operation_id) VALUES('e9',?,'READY',?,"
            "'F4_PRODUCTION_ACCEPTANCE',?,?,1)",
            (TARGET,TARGET,now-5,now+180),
        )
        for index,(name,uid) in enumerate(USERS):
            self.db.execute("INSERT INTO ssh_accounts VALUES(?,?,?,?)",
                            (name,SOURCE,"ssh","🟢 فعال"))
            self.db.execute(
                "INSERT INTO edge_egress_uid_runtime "
                "(username,uid,edge_id,edge_ipv4,route_table,priority,"
                "dns_port,state,last_operation_id) "
                "VALUES(?,?,'e8',?,20008,?,?, 'PROTECTED',1)",
                (name,uid,SOURCE,20010+index,10553+index),
            )
            self.db.execute(
                "INSERT INTO edge_egress_uid_bindings "
                "(username,uid,edge_id,edge_ipv4,status) "
                "VALUES(?,?,'e8',?,'PROTECTED')",
                (name,uid,SOURCE),
            )
        self.pin=SimpleNamespace(
            edge_id="e9",edge_ipv4=TARGET,core_ipv4=CORE,
            core_sha="a"*64,edge_sha="b"*64,
            ssh_host_key="pinned-test-key",ssh_port=22,
            customer_port=2252,ingress_ipv4="10.77.0.9",
        )
        self.known=dict(USERS)

    def review(self):
        with patch("edge_egress_k2_phase2_operator.load_registry",
                   return_value=[SimpleNamespace(
                       edge_id="e9",edge_ipv4=TARGET,ingress_ipv4="10.77.0.9")]):
            return review_relay_cohort(
                lambda:self.db,"e9",os_uid=lambda name:self.known[name],
                pin_loader=lambda _:self.pin,
            )

    def test_release_gate_and_precisely_two_protected_users(self):
        off=self.review()
        self.assertIn("OPERATOR_RELEASE_DISABLED",off.blockers)
        self.assertEqual(off.active_accounts,2)
        self.assertEqual(off.legacy_accounts,0)
        self.db.execute(
            "INSERT INTO settings VALUES('k2_p2_relay_switch_enabled','1')")
        ready=self.review()
        self.assertTrue(ready.ready,ready.blockers)
        self.assertIn("✅ بررسی اولیه موفق بود",render_cohort_review(ready))
        buttons=sum(relay_cohort_buttons(ready),[])
        self.assertIn(("✅ بررسی نهایی انتقال","hpeg_p2_open_e9"),buttons)

    def test_mixed_existing_legacy_user_blocks_whole_cohort_without_db_write(self):
        self.db.execute(
            "INSERT INTO settings VALUES('k2_p2_relay_switch_enabled','1')")
        self.db.execute(
            "INSERT INTO ssh_accounts VALUES('nvl_legacy',?,?,?)",
            (SOURCE,"ssh","🟢 فعال"),
        )
        sql=[]
        self.db.set_trace_callback(sql.append)
        preview=self.review()
        self.assertIn("MIXED_OR_UNPROTECTED_COHORT",preview.blockers)
        self.assertEqual(preview.legacy_accounts,1)
        self.assertNotIn("hpeg_p2_open_e9",
                         [x for _,x in sum(relay_cohort_buttons(preview),[])])
        self.assertFalse(any(q.lstrip().upper().startswith(
            ("UPDATE ","INSERT ","DELETE ","REPLACE ","CREATE ")
        ) for q in sql))

    def test_legacy_enrollment_status_in_existing_telegram_review(self):
        self.db.execute(
            "INSERT INTO ssh_accounts VALUES('legacy2',?,?,?)",
            (SOURCE,"ssh","🟢 فعال"),
        )
        self.known["legacy2"]=1651
        self.db.execute(
            "INSERT INTO edge_egress_readiness "
            "(edge_id,edge_ipv4,state,observed_ipv4,witness,probed_at,"
            "expires_at,last_operation_id) VALUES('e8',?,'READY',?,"
            "'F4_PRODUCTION_ACCEPTANCE',?,?,1)",
            (SOURCE,SOURCE,int(time.time())-5,int(time.time())+120),
        )
        review=self.review()
        self.assertFalse(review.ready)
        self.assertIsNotNone(review.enrollment_audit)
        self.assertEqual(review.enrollment_audit.legacy_users,(("legacy2",1651),))
        self.assertEqual(review.enrollment_audit.invalid_count,0)
        self.assertEqual(review.enrollment_audit.protected_count,2)
        self.assertIn("کاربران قدیمیِ شناسایی‌شده: <b>1</b>",
                      render_cohort_review(review))
        self.assertNotIn(("✅ بررسی نهایی انتقال","hpeg_p2_open_e9"),
                         sum(relay_cohort_buttons(review),[]))

    def test_source_protected_allocation_must_match_existing_users(self):
        self.db.execute(
            "INSERT INTO settings VALUES('k2_p2_relay_switch_enabled','1')")
        self.db.execute(
            "DELETE FROM edge_egress_allocations WHERE edge_id='e8'")
        review=self.review()
        self.assertFalse(review.ready)
        self.assertIn("SOURCE_PROTECTED_EDGE_UNVERIFIED",review.blockers)
        self.assertIn("MIXED_OR_UNPROTECTED_COHORT",review.blockers)
        self.assertNotIn(("✅ بررسی نهایی انتقال","hpeg_p2_open_e9"),
            sum(relay_cohort_buttons(review),[]))

    def test_runtime_and_binding_edge_identity_drift_blocks_all_accounts(self):
        self.db.execute(
            "INSERT INTO settings VALUES('k2_p2_relay_switch_enabled','1')")
        self.db.execute(
            "UPDATE edge_egress_uid_runtime SET edge_id='e7' "
            "WHERE username='nvl0557'")
        view=self.review()
        self.assertIn("MIXED_OR_UNPROTECTED_COHORT",view.blockers)
        self.assertFalse(view.ready)

    def test_matching_but_wrong_source_edge_ids_are_not_proof(self):
        self.db.execute(
            "INSERT INTO settings VALUES('k2_p2_relay_switch_enabled','1')")
        self.db.execute(
            "UPDATE edge_egress_uid_runtime SET edge_id='e7' "
            "WHERE username='nvl0557'")
        self.db.execute(
            "UPDATE edge_egress_uid_bindings SET edge_id='e7' "
            "WHERE username='nvl0557'")
        view=self.review()
        self.assertIn("MIXED_OR_UNPROTECTED_COHORT",view.blockers)
        self.assertFalse(view.ready)

    def test_retired_source_allocation_cannot_be_used_for_relay_switch(self):
        self.db.execute(
            "INSERT INTO settings VALUES('k2_p2_relay_switch_enabled','1')")
        self.db.execute(
            "UPDATE edge_egress_allocations SET status='RETIRED' WHERE edge_id='e8'")
        preview=self.review()
        self.assertIn("SOURCE_PROTECTED_EDGE_UNVERIFIED",preview.blockers)
        self.assertFalse(preview.ready)

    def test_source_allocation_core_drift_is_not_ready(self):
        self.db.execute(
            "INSERT INTO settings VALUES('k2_p2_relay_switch_enabled','1')")
        self.db.execute(
            "UPDATE edge_egress_allocations SET core_public_ipv4='203.0.113.10' "
            "WHERE edge_id='e8'")
        view=self.review()
        self.assertIn("SOURCE_PROTECTED_EDGE_UNVERIFIED",view.blockers)
        self.assertFalse(view.ready)

    def test_stale_f4_witness_blocks_even_with_valid_stage(self):
        self.db.execute(
            "INSERT INTO settings VALUES('k2_p2_relay_switch_enabled','1')")
        self.db.execute(
            "UPDATE edge_egress_readiness SET expires_at=1")
        preview=self.review()
        self.assertIn("F4_LIVE_ACCEPTANCE_REQUIRED",preview.blockers)
        self.assertFalse(preview.ready)

    def test_candidate_listed_but_not_safe_standby_holds(self):
        self.db.execute(
            "INSERT INTO settings VALUES('k2_p2_relay_switch_enabled','1')")
        self.db.execute(
            "INSERT INTO host_pool VALUES(?,1,0,0,2252)",(TARGET,))
        review=self.review()
        self.assertIn("TARGET_POOL_NOT_SAFE_STANDBY",review.blockers)

    def test_missing_original_customer_service_port_blocks_new_edge(self):
        self.db.execute(
            "INSERT INTO settings VALUES('k2_p2_relay_switch_enabled','1')")
        self.pin.customer_port=0
        preview=self.review()
        self.assertIn("NEW_EDGE_SERVICE_PORT_NOT_PINNED",preview.blockers)

    def test_running_6g_hold_disables_operator_action(self):
        self.db.execute(
            "INSERT INTO settings VALUES('k2_p2_relay_switch_enabled','1')")
        self.db.execute("INSERT INTO failover_operations VALUES(1,'RUNNING')")
        review=self.review()
        self.assertIn("SHARED_6G_OPERATION_BUSY",review.blockers)

    def test_expired_or_wrong_actor_ticket_cannot_call_host(self):
        ticket=RelaySwitchTicket(
            "e9",SOURCE,TARGET,"x"*64,"y"*64,
            "1"*32,300,400,int(time.time())+50,
        )
        async def denied(actor, expiry=None):
            with self.assertRaisesRegex(Phase2Hold,"UNAUTHORIZED"):
                await execute_relay_switch(
                    expiry or ticket,db_conn=lambda:self.db,
                    acquire=lambda *a:self.fail("no acquire"),
                    journal=lambda *a,**k:self.fail("no journal"),
                    cf_config_loader=lambda:self.fail("no CF"),
                    actor_id=actor,chat_id=400,getuid=lambda:0,
                )
        asyncio.run(denied(301))
        expired=RelaySwitchTicket(
            "e9",SOURCE,TARGET,"x"*64,"y"*64,
            "1"*32,300,400,int(time.time())-1,
        )
        asyncio.run(denied(300,expiry=expired))

    def test_ticket_binds_pinned_cloudflare_record_identity(self):
        from edge_egress_k2_phase2_operator import make_switch_ticket
        from edge_egress_v1_cloudflare import PinnedDnsCutover, PinnedDnsRecord
        self.db.execute(
            "INSERT INTO settings VALUES('k2_p2_relay_switch_enabled','1')")
        review=self.review()
        plan=PinnedDnsCutover(SOURCE,TARGET,"a"*32,(
            PinnedDnsRecord("vpn.example.com","b"*32,SOURCE,"c"*64),
        ))
        with patch("edge_egress_k2_phase2_operator.ProtectedCloudflareDNS") as cls:
            cls.return_value.preview_edge_to_edge.return_value=plan
            ticket=make_switch_ticket(
                review,actor_id=125,chat_id=678,
                cf_config_loader=lambda:{"zone":"a"*32},
            )
        self.assertEqual(ticket.cohort_fingerprint,review.fingerprint)
        self.assertEqual(ticket.source,SOURCE)
        self.assertEqual(ticket.target,TARGET)
        self.assertEqual(len(ticket.nonce),32)
        self.assertEqual(len(ticket.dns_fingerprint),64)

    def test_worker_calls_existing_6g_saga_only_with_exact_pins(self):
        from edge_egress_k2_phase2_operator import make_switch_ticket
        from edge_egress_v1_cloudflare import PinnedDnsCutover, PinnedDnsRecord
        from unittest.mock import AsyncMock, MagicMock
        self.db.execute(
            "INSERT INTO settings VALUES('k2_p2_relay_switch_enabled','1')")
        review=self.review()
        plan=PinnedDnsCutover(SOURCE,TARGET,"a"*32,(
            PinnedDnsRecord("vpn.example.com","b"*32,SOURCE,"c"*64),
        ))
        dns_loader=lambda:{"zone":"a"*32}
        with patch("edge_egress_k2_phase2_operator.ProtectedCloudflareDNS") as dns:
            dns.return_value.preview_edge_to_edge.return_value=plan
            ticket=make_switch_ticket(
                review,actor_id=125,chat_id=678,
                cf_config_loader=dns_loader,
            )
            adapter=object()
            saga=AsyncMock(return_value=SimpleNamespace(ok=True))
            with patch("edge_egress_k2_phase2_operator.review_relay_cohort",
                       return_value=review), \
                 patch("edge_egress_k2_phase2_operator.load_stage_pin",
                       return_value=self.pin), \
                 patch("edge_egress_k2_phase2_operator._check_stage"), \
                 patch("ops.edge_egress_v1_transport.pinned",
                       return_value=(SimpleNamespace(edge_public_ipv4=TARGET),"peer")), \
                 patch("ops.edge_egress_v1_transport.observe",return_value="UP"), \
                 patch("edge_egress_k2_phase2_operator._remote_transport",
                       return_value="UP"), \
                 patch("edge_egress_k2_phase2_operator.make_live_adapter",
                       return_value=adapter) as factory, \
                 patch("edge_egress_k2_phase2_operator.execute_protected_switch",
                       saga):
                outcome=asyncio.run(execute_relay_switch(
                    ticket,db_conn=lambda:self.db,acquire=lambda *a:None,
                    journal=lambda *a:None,cf_config_loader=dns_loader,
                    actor_id=125,chat_id=678,getuid=lambda:0,
                ))
                self.assertTrue(outcome.ok)
                config=factory.call_args.kwargs["config"]
                self.assertIs(config.dns_plan,plan)
                self.assertTrue(config.acceptance_enabled)
                self.assertEqual(config.edge.ipv4,TARGET)
                saga.assert_awaited_once_with(adapter,SOURCE,TARGET)

    def test_bot_has_explicit_two_step_admin_only_6g_path(self):
        source=Path("bot_final_v49-2.py").read_text(encoding="utf-8")
        a=source.index('    elif d.startswith("hpeg_p2_open_"):')
        b=source.index('    elif d.startswith("hpeg_transfer_"):',a)
        snippet=source[a:b]
        self.assertLess(snippet.index("if role != 'admin':"),
                        snippet.index("make_switch_ticket"))
        self.assertIn('context.user_data.pop("k2_p2_switch_ticket",None)',snippet)
        self.assertIn("execute_relay_switch(",snippet)
        self.assertIn("journal=_db_update_failover_operation",snippet)
        for forbidden in ("_db_set_all_accounts_host",
                          "_update_cloudflare_dns",
                          "_safe_manual_failover"):
            self.assertNotIn(forbidden,snippet)


if __name__=="__main__":
    unittest.main()
