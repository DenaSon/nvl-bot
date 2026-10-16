"""Pre-attach is not customer success; post proof owns exact original 6G.

Real SQLite/nonce/signature-consumer contract, synthetic external reports.
No physical traffic, server changes or deployment occurs in these tests.
"""
from dataclasses import replace
from hashlib import sha256
import json
import sqlite3
import unittest
from unittest.mock import patch

import edge_egress_k2_m42_evidence as ev
from edge_egress_p3_executor import ExecutionScope, ExecutionTicket, _scope_digest, INTENT_PHASE
from tests.test_edge_egress_k2_m42_evidence import NOW, TARGET, report

SOURCE = "172.86.111.69"


class StagedProofTests(unittest.TestCase):
    def setUp(self):
        self.scope = ExecutionScope("UID_ATTACH", "e9", SOURCE, TARGET,
                                    username="nvl0555", uid=1636)
        self.ticket = ExecutionTicket(11, 11, "b"*32, NOW+90,
                                      _scope_digest(self.scope), "c"*64)
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.execute("CREATE TABLE failover_operations("
                        "id INTEGER,status TEXT,source_host TEXT,target_host TEXT,detail_json TEXT)")
        self.db.execute("INSERT INTO failover_operations VALUES(1,'RUNNING',?,?,?)", (
            SOURCE, TARGET, json.dumps({"phase": INTENT_PHASE, "kind": "K2_P3A",
                "scope_digest": _scope_digest(self.scope),
                "nonce_hash": sha256(self.ticket.nonce.encode()).hexdigest()}),
        ))
        self.db.commit()
        self.db.execute("CREATE TABLE edge_egress_uid_runtime("
                        "username TEXT,uid INTEGER,edge_id TEXT,edge_ipv4 TEXT,"
                        "state TEXT,last_operation_id INTEGER)")
        self.db.execute("INSERT INTO edge_egress_uid_runtime VALUES(?,?,?,?,?,?)",
                        ("nvl0555", 1636, "e9", TARGET, "PROTECTED", 1))
        self.db.commit()

    def raw(self, phase_kind, **changes):
        phase = phase_kind
        data = json.loads(report())
        data.update(version=2, phase=phase, scope_digest="", nonce_hash="",
                    operation_id=None, observed_public_ipv4="")
        data["accounts"][0].update(source_edge="s8", source_ipv4=SOURCE)
        checks = (ev.PRE_ATTACH_CHECKS if phase == "PRE_ATTACH" else
                  ev.UID_ROUTE_CHECKS if phase == "UID_ROUTE" else ev.POST_ATTACH_CHECKS)
        data["checks"] = {key: True for key in checks}
        if phase in ("UID_ROUTE", "POST_ATTACH"):
            data.update(scope_digest=_scope_digest(self.scope),
                        nonce_hash=sha256(self.ticket.nonce.encode()).hexdigest(),
                        operation_id=1, observed_public_ipv4=TARGET)
        data.update(changes)
        return json.dumps(data).encode()

    def test_pre_attach_accepts_edge_readiness_without_impossible_client_proof(self):
        proof = ev.decode_evidence(self.raw("PRE_ATTACH"), now=NOW)
        proof.verify_pre_attach()
        self.assertNotIn("ssh_socks_ipv4", proof.checks)
        self.assertNotIn("no_core_leak", proof.checks)
        with self.assertRaisesRegex(ev.M42EvidenceHold, "POST_ATTACH"):
            proof.verify_post_attach(self.scope, self.ticket, operation_id=1, now=NOW)

    def test_post_attach_requires_the_same_scope_nonce_operation_and_ip(self):
        proof = ev.decode_evidence(self.raw("POST_ATTACH"), now=NOW)
        proof.verify_post_attach(self.scope, self.ticket, operation_id=1, now=NOW)
        with self.assertRaisesRegex(ev.M42EvidenceHold, "PRE_ATTACH"):
            proof.verify_pre_attach()
        for altered in (
            replace(proof, nonce_hash="f"*64), replace(proof, operation_id=2),
            replace(proof, observed_public_ipv4="209.200.246.198"),
            replace(proof, scope_digest="e"*64), replace(proof, expires_at=NOW),
            replace(proof, accounts=(replace(proof.accounts[0], uid=1644),)),
        ):
            with self.subTest(altered=altered), self.assertRaises(ev.M42EvidenceHold):
                altered.verify_post_attach(self.scope, self.ticket, operation_id=1, now=NOW)

    def test_pre_cannot_claim_a_transfer_or_weaken_the_required_host_checks(self):
        for changes in (
            {"operation_id": 1}, {"nonce_hash": "c"*64},
            {"checks": {"f4_accepted": True}}, {"phase": "READY"},
            {"observed_public_ipv4": TARGET},
        ):
            with self.subTest(changes=changes), self.assertRaises(ev.M42EvidenceHold):
                ev.decode_evidence(self.raw("PRE_ATTACH", **changes), now=NOW)

    def test_post_loader_uses_real_original_6g_and_exact_signed_bytes(self):
        raw = self.raw("POST_ATTACH")
        with patch.object(ev, "M42_EVIDENCE_ENABLED", True), patch.object(
            ev, "verify_external_signature", return_value=raw,
        ) as verify:
            proof = ev.load_post_attach_evidence(
                scope=self.scope, ticket=self.ticket, db_conn=lambda: self.db,
                now=NOW, geteuid=lambda: 0,
            )
            self.assertEqual(proof.operation_id, 1)
            self.assertEqual(verify.call_args.kwargs["paths"], (
                ev.POST_WITNESS_JSON, ev.POST_WITNESS_SIG, ev.WITNESS_PUB,
            ))
            self.db.execute("UPDATE failover_operations SET status='SUCCEEDED'")
            self.db.commit()
            with self.assertRaises(ValueError):
                ev.load_post_attach_evidence(
                    scope=self.scope, ticket=self.ticket, db_conn=lambda: self.db,
                    now=NOW, geteuid=lambda: 0,
                )
        self.assertEqual(self.db.execute(
            "SELECT status FROM failover_operations").fetchone(), ("SUCCEEDED",))

    def test_nonce_changed_during_signature_verification_holds(self):
        def change(**kwargs):
            self.db.execute("UPDATE failover_operations SET detail_json='{}'")
            self.db.commit()
            return self.raw("POST_ATTACH")
        with patch.object(ev, "M42_EVIDENCE_ENABLED", True), patch.object(
            ev, "verify_external_signature", side_effect=change,
        ), self.assertRaises(ValueError):
            ev.load_post_attach_evidence(scope=self.scope, ticket=self.ticket,
                                        db_conn=lambda: self.db, now=NOW,
                                        geteuid=lambda: 0)

    def test_old_complete_report_remains_readable_but_cannot_verify_new_transfer(self):
        old = ev.decode_evidence(report(), now=NOW)
        old.verify_pre_attach()
        with self.assertRaises(ev.M42EvidenceHold):
            old.verify_post_attach(self.scope, self.ticket, operation_id=1, now=NOW)

    def test_routed_uid_proof_cannot_be_reused_as_the_real_ssh_proof(self):
        raw = self.raw("UID_ROUTE")
        self.db.execute("UPDATE edge_egress_uid_runtime SET state='ROUTED_UNVERIFIED'")
        self.db.commit()
        with patch.object(ev, "M42_EVIDENCE_ENABLED", True), patch.object(
            ev, "verify_external_signature", return_value=raw,
        ):
            proof = ev.load_post_attach_evidence(scope=self.scope, ticket=self.ticket,
                db_conn=lambda: self.db, now=NOW, geteuid=lambda: 0, phase="UID_ROUTE")
            self.assertNotIn("ssh_socks_ipv4", proof.checks)
            with self.assertRaisesRegex(ev.M42EvidenceHold, "NOT_ROUTED"):
                ev.load_post_attach_evidence(scope=self.scope, ticket=self.ticket,
                    db_conn=lambda: self.db, now=NOW, geteuid=lambda: 0)

    def test_pre_attach_signed_schema_can_be_produced_without_fabricating_client_results(self):
        from edge_egress_k2_a4_observer import build_observation_report
        from tests.test_edge_egress_k2_a4_observer import receipts, sessions
        from tests.test_edge_egress_k2_a4_observer import NOW as A4_NOW
        raw = build_observation_report(
            probes=tuple(p for p in receipts() if p.check in ev.PRE_ATTACH_CHECKS),
            sessions=sessions(), target_edge="e9", target_ipv4=TARGET,
            now=A4_NOW, phase="PRE_ATTACH",
        )
        proof = ev.decode_evidence(raw, now=A4_NOW)
        proof.verify_pre_attach()
        self.assertEqual(proof.checks, ev.PRE_ATTACH_CHECKS)


if __name__ == "__main__":
    unittest.main()
