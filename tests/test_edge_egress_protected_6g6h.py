"""D1-D1: protected 6G/6H uses same handoff/lock, no legacy migrations.

Pure mock/SQLite-shape regression. NO real Edge, SSH, DNS or VM activity.
"""
import asyncio
from dataclasses import replace
from datetime import timedelta
import json
import unittest

from edge_egress_failover_guard import (
    UIDGuardProof, ProtectedFailoverProof, GuardProofError,
    assert_protected_failover_proof,
)
from edge_egress_protected_6g6h import run_guarded_6g6h_handoff
from edge_egress_handoff import is_egress_recovery_hold
from test_edge_egress_handoff import Fake6GPorts, snapshot, NOW


SOURCE="172.86.94.174"
TARGET="216.126.229.12"
CORE="209.200.246.198"


def evidence(record, selected, *, op=42, trigger="manual_6g", boot=True,
             missing=None, wrong_public=False, stale=False, one_leak=None):
    proofs=[]
    for account in record.active_accounts:
        if account.username == missing:
            continue
        kwargs=dict(
            username=account.username, uid=account.uid,
            selected_edge_ip=selected,
            observed_public_ip=CORE if wrong_public else selected,
            observed_at=NOW - timedelta(minutes=3) if stale else NOW,
            boot_guard_installed=True, full_ipv4_uid_rule=True,
            terminal_blackhole=True, ipv6_packet_blocked=True,
            dns_exits_only_via_edge=True, ssh_identity_on_core=True,
            no_core_fallback=True,
        )
        if account.username == "nvl0557" and one_leak is not None:
            kwargs[one_leak]=False
        proofs.append(UIDGuardProof(**kwargs))
    return ProtectedFailoverProof(
        operation_id=op, trigger=trigger,
        source_edge_ip=record.source_host,
        target_edge_ip=record.target_host,
        core_public_ipv4=record.core_public_ipv4,
        users=tuple(proofs), boot_gate_verified_on_disposable_vps=boot,
        existing_6g_lock_running=True, observed_at=NOW,
    )


class FakeGuarded6GPorts(Fake6GPorts):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.guard_boot=True
        self.bad_target=None
        self.current_protected_mode="1"
        self.automatic_incident_ok=True
        self.real_source_mapping=SOURCE
        self.proof_edges=[]
        self.legacy_methods_called=[]

    async def assert_protected_mode_under_6g_lock(self, operation_id):
        self.actions.append("mode_under_lock")
        if operation_id != 42 or not self.locked or self.current_protected_mode != "1":
            raise RuntimeError("PROTECTED_MODE_UNAVAILABLE")

    async def confirm_automatic_incident_under_6g_lock(self, operation_id, incident_ref):
        self.actions.append("auto_incident")
        if operation_id != 42 or not self.locked or not self.automatic_incident_ok:
            raise RuntimeError("6H_INCIDENT_NOT_CONFIRMED")

    async def measure_all_uid_guards(self, record, *, operation_id, trigger,
                                     selected_edge_ip):
        self.actions.append("proof:"+selected_edge_ip)
        self.proof_edges.append(selected_edge_ip)
        return evidence(
            record, selected_edge_ip, op=operation_id, trigger=trigger,
            boot=self.guard_boot,
            one_leak=self.bad_target if selected_edge_ip==TARGET else None,
        )

    async def commit_protected_mapping_cas_only(self, record):
        self.actions.append("protected_mapping_cas_only")
        self.real_source_mapping=record.target_host
        # Intentionally keep DB ssh_accounts.host and Unix identity on Core.

    async def assert_public_ingress_dns_unchanged(self, record):
        self.actions.append("assert_dns_unchanged")
        if self.dns != SOURCE:
            raise RuntimeError("PUBLIC_INGRESS_DNS_CHANGED")

    async def commit_source_accounts_cas(self, record):
        self.legacy_methods_called.append("legacy_rebuild_accounts")
        raise AssertionError("Protected execution called legacy accounts CAS")

    async def switch_dns_direct_to_target(self, record):
        self.legacy_methods_called.append("legacy_dns_change")
        raise AssertionError("Protected execution called legacy DNS mutation")


def go(ports, trigger="manual_6g", incident=None, approved=True):
    return asyncio.run(run_guarded_6g6h_handoff(
        ports, source_host=SOURCE, target_host=TARGET,
        trigger=trigger, incident_ref=incident,
        explicitly_approved_for_isolated_lab=approved,
        now=NOW,
    ))


class GuardedProofTests(unittest.TestCase):
    def test_exact_all_user_coverage_and_edge_source(self):
        record=snapshot()
        assert_protected_failover_proof(
            record,evidence(record,SOURCE),operation_id=42,
            trigger="manual_6g",selected_edge_ip=SOURCE,now=NOW)

    def test_missing_account_stale_identity_boot_and_bypass_are_rejected(self):
        rec=snapshot()
        cases=[
            (evidence(rec,SOURCE,missing="nvl0558"),"COVERAGE"),
            (evidence(rec,SOURCE,boot=False),"BOOT_GUARD"),
            (evidence(rec,SOURCE,op=20),"LOCK"),
            (evidence(rec,SOURCE,wrong_public=True),"PUBLIC_IP"),
            (evidence(rec,SOURCE,stale=True),"STALE"),
            (evidence(rec,SOURCE,one_leak="dns_exits_only_via_edge"),"DNS"),
            (evidence(rec,SOURCE,one_leak="terminal_blackhole"),"BLACKHOLE"),
            (evidence(rec,SOURCE,one_leak="no_core_fallback"),"FALLBACK"),
            (evidence(rec,SOURCE,one_leak="ipv6_packet_blocked"),"IPV6"),
            (evidence(rec,SOURCE,one_leak="ssh_identity_on_core"),"SSH"),
        ]
        for item,reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(GuardProofError,reason):
                    assert_protected_failover_proof(
                        rec,item,operation_id=42,trigger="manual_6g",
                        selected_edge_ip=SOURCE,now=NOW)

    def test_selected_target_must_match_public_ip(self):
        record=snapshot()
        with self.assertRaisesRegex(GuardProofError,"PUBLIC_IP"):
            assert_protected_failover_proof(
                record,evidence(record,SOURCE),operation_id=42,
                trigger="manual_6g",selected_edge_ip=TARGET,now=NOW)


class GuardedWorkflowTests(unittest.TestCase):
    def test_default_deny_no_lock_or_host_actions(self):
        p=FakeGuarded6GPorts()
        r=go(p,approved=False)
        self.assertEqual(r.reason,"PROTECTED_HANDOFF_RELEASE_NOT_APPROVED")
        self.assertEqual(p.actions,[])

    def test_missing_6h_incident_denied_before_any_lock(self):
        for incident in (None,"", "incident", "INC-"+"X"*70):
            p=FakeGuarded6GPorts()
            r=go(p,trigger="automatic_6h",incident=incident)
            self.assertFalse(r.ok)
            self.assertEqual(r.reason,"6H_INCIDENT_EVIDENCE_REQUIRED")
            self.assertEqual(p.actions,[])

    def test_manual_6g_safe_success_never_calls_legacy_account_or_dns(self):
        p=FakeGuarded6GPorts()
        r=go(p)
        self.assertTrue(r.ok,r.reason)
        self.assertEqual(p.legacy_methods_called,[])
        self.assertEqual(p.current_db_host,SOURCE)
        self.assertEqual(p.dns,SOURCE)
        self.assertEqual(p.real_source_mapping,TARGET)
        self.assertEqual(p.proof_edges,[SOURCE,SOURCE,TARGET,TARGET])
        self.assertEqual(p.actions.count("acquire_6g_lock"),1)
        self.assertLess(p.actions.index("proof:"+TARGET),
                        p.actions.index("protected_mapping_cas_only"))
        self.assertTrue(all(j[2]["kind"]=="PROTECTED_EGRESS_SWITCH"
                            for j in p.journal))
        self.assertTrue(all(j[2]["trigger"]=="manual_6g"
                            for j in p.journal))
        self.assertEqual(p.journal[-1][0],"SUCCEEDED")

    def test_automatic_6h_requires_incident_and_reuses_same_6g_lock(self):
        p=FakeGuarded6GPorts()
        r=go(p,trigger="automatic_6h",incident="INC-20261011-000001")
        self.assertTrue(r.ok,r.reason)
        self.assertIn("auto_incident",p.actions)
        self.assertEqual(p.actions.count("acquire_6g_lock"),1)
        self.assertEqual(p.journal[-1][2]["incident_ref"],"INC-20261011-000001")
        self.assertEqual(p.legacy_methods_called,[])

    def test_unverified_vm_boot_cannot_stage_or_mutate(self):
        p=FakeGuarded6GPorts()
        p.guard_boot=False
        r=go(p)
        self.assertFalse(r.ok)
        self.assertFalse(r.needs_manual_recovery)
        self.assertFalse(p.locked)
        self.assertNotIn("stage_target_shadow",p.actions)
        self.assertNotIn("arm_fail_closed",p.actions)
        self.assertEqual(p.journal[-1][0],"FAILED")

    def test_protected_setting_off_refuses_before_stage(self):
        p=FakeGuarded6GPorts()
        p.current_protected_mode="0"
        r=go(p)
        self.assertFalse(r.ok)
        self.assertNotIn("stage_target_shadow",p.actions)
        self.assertNotIn("arm_fail_closed",p.actions)

    def test_6h_incident_failed_refuses_before_stage(self):
        p=FakeGuarded6GPorts()
        p.automatic_incident_ok=False
        r=go(p,trigger="automatic_6h",incident="INC-20261011-000001")
        self.assertFalse(r.ok)
        self.assertNotIn("stage_target_shadow",p.actions)

    def test_missing_target_dns_proof_freezes_and_holds_shared_lock(self):
        p=FakeGuarded6GPorts()
        p.bad_target="dns_exits_only_via_edge"
        r=go(p)
        self.assertFalse(r.ok)
        self.assertTrue(r.needs_manual_recovery)
        self.assertTrue(p.frozen)
        self.assertTrue(p.locked)
        self.assertNotIn("protected_mapping_cas_only",p.actions)
        self.assertEqual(p.journal[-1][0],"RUNNING")
        self.assertTrue(is_egress_recovery_hold(json.dumps({
            "phase":p.journal[-1][1]
        })))
        self.assertEqual(p.legacy_methods_called,[])

    def test_crash_during_candidate_stage_holds_shared_6g_and_6h_lock(self):
        for trigger,incident in [("manual_6g",None),
                                 ("automatic_6h","INC-20261011-000001")]:
            with self.subTest(trigger=trigger):
                p=FakeGuarded6GPorts(fail_at="stage_target_shadow")
                r=go(p,trigger=trigger,incident=incident)
                self.assertFalse(r.ok)
                self.assertTrue(r.needs_manual_recovery)
                self.assertTrue(p.locked)
                self.assertFalse(p.frozen)  # Old source route was never switched.
                self.assertNotIn("arm_fail_closed",p.actions)
                self.assertEqual(p.journal[-1][1],"EGRESS_RECOVERY_REQUIRED")
                self.assertTrue(is_egress_recovery_hold(json.dumps({
                    "phase":p.journal[-1][1]
                })))

    def test_guarded_staging_phase_itself_is_stale_lock_protected(self):
        for phase in ("EGRESS_GUARDED_CANDIDATE_STAGE",
                      "EGRESS_GUARDED_DEDICATED_PEER_REKEY",
                      "EGRESS_GUARDED_EXTERNAL_EGRESS_PROOF",
                      "EGRESS_GUARDED_REVALIDATE_OWNERSHIP_AND_ALLOCATION"):
            with self.subTest(phase=phase):
                self.assertTrue(is_egress_recovery_hold(
                    json.dumps({"phase":phase,"kind":"PROTECTED_EGRESS_SWITCH"})
                ))

    def test_shared_lock_busy_denies_both_6g_and_6h(self):
        for trigger,incident in [("manual_6g",None),
                                 ("automatic_6h","INC-20261011-000001")]:
            p=FakeGuarded6GPorts(busy=True)
            r=go(p,trigger=trigger,incident=incident)
            self.assertFalse(r.ok)
            self.assertEqual(r.reason,"SHARED_FAILOVER_BUSY")
            self.assertEqual(p.journal,[])
            self.assertNotIn("stage_target_shadow",p.actions)


if __name__=="__main__":
    unittest.main()
