"""K2 cross-Edge F2 CAS, original 6G and Legacy isolation.

Hermetic SQLite + real typed PAM/WG journal parsing. No host mutation.
"""
import base64
from hashlib import sha256
import json
import unittest
from unittest.mock import patch

from tests import test_edge_egress_p3_uid as original_fixture
from edge_egress_k2_m2_ingress_journal import (
    IngressRecord, RootReadOnlyIngressEvidence, encode_records,
)
from edge_egress_p3_executor import INTENT_PHASE, _scope_digest
from edge_egress_uid_runtime_store import (
    K2CrossEdgeUIDRuntimeStore, RuntimeStoreUnsafe, read_binding,
)
from edge_egress_v1_ingress import IngressPeer
from tests.test_edge_egress_uid_runtime_store import SOURCE, TARGET


class CrossEdgeStoreTests(unittest.TestCase):
    def setUp(self):
        # Reuse exact P3/F2 schemas, readiness and users; do not fork a second
        # fake 6G implementation or override existing runtime transitions.
        self.fx = original_fixture.P3CUIDTests(
            methodName="test_source_never_defaults_to_live_release"
        )
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.plan, _, _, self.ticket = self.fx.setup_action()
        self.scope = self.plan.scope
        self.key = base64.b64encode(bytes(range(32))).decode()
        self.peer = IngressPeer("s8", SOURCE, "10.77.0.8", self.key)
        self.evidence = self._fresh()
        with self.fx.db() as db:
            db.execute(
                "UPDATE settings SET value='0' WHERE key='edge_egress_protected_mode'"
            )
            db.execute(
                "UPDATE settings SET value='8.8.8.8' WHERE key='dns_current_ip'"
            )
            db.execute(
                "UPDATE host_pool SET is_default=0 WHERE host=?", (SOURCE,)
            )
        self.op, busy = self.fx.acquire(SOURCE, TARGET)
        self.assertIsNone(busy)
        self._journal()

    def _fresh(self, peer=None, allowed=None):
        peer = self.peer if peer is None else peer
        record = IngressRecord(
            "nvl0557", 1644, "s8", SOURCE, "10.77.0.8",
            self.key, 1000,
        )
        return RootReadOnlyIngressEvidence(
            encode_records({"nvl0557": record}), (peer,),
            self.key+" 10.77.0.8/32\n" if allowed is None else allowed,
            1000, self.fx.unix_lookup,
        )

    def _journal(self, *, nonce=None):
        nonce = self.ticket.nonce if nonce is None else nonce
        with self.fx.db() as db:
            db.execute(
                "UPDATE failover_operations SET detail_json=? WHERE id=?",
                (json.dumps({
                    "kind": "K2_P3A",
                    "phase": INTENT_PHASE,
                    "action": "UID_ATTACH",
                    "edge_id": self.scope.edge_id,
                    "scope_digest": _scope_digest(self.scope),
                    "nonce_hash": sha256(nonce.encode()).hexdigest(),
                }), self.op),
            )

    def store(self, **changes):
        args = dict(
            scope=self.scope, ticket=self.ticket, ingress_edge_id="s8",
            source_evidence=lambda: self.evidence,
            geteuid=lambda: 0, reviewed_release=True,
        )
        args.update(changes)
        return K2CrossEdgeUIDRuntimeStore(
            self.fx.conn_factory, self.fx.unix_lookup, **args,
        )

    def test_default_off_blocks_before_any_uid_mutation(self):
        store = self.store()
        with self.assertRaisesRegex(RuntimeStoreUnsafe, "NOT_RELEASED"):
            store.reserve_blocked(
                self.op, self.fx.uid_req, source=SOURCE, dns_port=10553,
            )
        self.assertIsNone(self.fx.binding())

    def test_real_f2_cas_accepts_attested_source_with_unchanged_global_mode(self):
        with patch(
            "edge_egress_uid_runtime_store.K2_CROSS_EDGE_RUNTIME_STORE_ENABLED",
            True,
        ):
            store = self.store()
            blocked = store.reserve_blocked(
                self.op, self.fx.uid_req, source=SOURCE, dns_port=10553,
            )
            self.assertEqual((blocked.state, blocked.generation), ("BLOCKED", 1))
            routed = store.transition(
                self.op, self.fx.uid_req, source=SOURCE,
                expected="BLOCKED", target="ROUTED_UNVERIFIED",
            )
            self.assertEqual((routed.state, routed.generation),
                             ("ROUTED_UNVERIFIED", 2))
            protected = store.commit_protected(
                self.op, self.fx.uid_req, source=SOURCE,
            )
            self.assertEqual((protected.state, protected.generation),
                             ("PROTECTED", 3))
            self.assertEqual(self.fx.mapping(),
                             (1644, "fra1", TARGET, "PROTECTED"))
        with self.fx.db() as db:
            self.assertEqual(db.execute(
                "SELECT value FROM settings WHERE key='edge_egress_protected_mode'"
            ).fetchone(), ("0",))
            self.assertEqual(db.execute(
                "SELECT value FROM settings WHERE key='dns_current_ip'"
            ).fetchone(), ("8.8.8.8",))
            self.assertEqual(db.execute(
                "SELECT host FROM ssh_accounts WHERE username='nvl0557'"
            ).fetchone(), (SOURCE,))
            self.assertIsNone(read_binding(db, "nvl0558"))

    def test_no_untrusted_source_or_nonce_can_reserve(self):
        scenarios = (
            {"source_evidence": lambda: object()},
            {"source_evidence": lambda: self._fresh(
                allowed=self.key+" 10.77.0.9/32\n")},
            {"ingress_edge_id": "s7"},
            {"geteuid": lambda: 1000},
            {"reviewed_release": False},
        )
        with patch(
            "edge_egress_uid_runtime_store.K2_CROSS_EDGE_RUNTIME_STORE_ENABLED",
            True,
        ):
            for changes in scenarios:
                with self.subTest(changes=str(changes)):
                    with self.assertRaises(RuntimeStoreUnsafe):
                        self.store(**changes).reserve_blocked(
                            self.op, self.fx.uid_req, source=SOURCE,
                            dns_port=10553,
                        )
                    self.assertIsNone(self.fx.binding())
            self._journal(nonce="0"*32)
            with self.assertRaisesRegex(RuntimeStoreUnsafe, "INTENT_NOT_PINNED"):
                self.store().reserve_blocked(
                    self.op, self.fx.uid_req, source=SOURCE,
                    dns_port=10553,
                )
            self.assertIsNone(self.fx.binding())

    def test_wrong_global_mode_and_stale_lease_hold(self):
        with patch(
            "edge_egress_uid_runtime_store.K2_CROSS_EDGE_RUNTIME_STORE_ENABLED",
            True,
        ):
            with self.fx.db() as db:
                db.execute("UPDATE settings SET value='1' "
                           "WHERE key='edge_egress_protected_mode'")
            with self.assertRaisesRegex(RuntimeStoreUnsafe, "GLOBAL_MODE_CHANGED"):
                self.store().reserve_blocked(
                    self.op, self.fx.uid_req, source=SOURCE,
                    dns_port=10553,
                )
            with self.fx.db() as db:
                db.execute("UPDATE settings SET value='0' "
                           "WHERE key='edge_egress_protected_mode'")
                db.execute("UPDATE failover_operations SET status='SUCCEEDED'")
            with self.assertRaises(RuntimeStoreUnsafe):
                self.store().reserve_blocked(
                    self.op, self.fx.uid_req, source=SOURCE,
                    dns_port=10553,
                )
            self.assertIsNone(self.fx.binding())


if __name__ == "__main__":
    unittest.main()
