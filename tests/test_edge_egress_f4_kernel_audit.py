"""F4 live UID audit never mutates or confuses a local rule with E2E."""
import unittest
from types import SimpleNamespace

from edge_egress_f4_kernel_audit import inspect_uid_kernel
from edge_egress_uid_boot import BootGuardError, BootGuardManifest
from edge_egress_uid_policy import UIDPolicyRequest
from ops.edge_egress_provision import EgressSpec


def manifest():
    spec=EgressSpec(
        edge_id="fra1",edge_public_ipv4="216.126.229.12",
        core_public_ipv4="209.200.246.198",
        tunnel_network="10.78.100.0/30",
        veth_network="10.78.101.0/30",
        route_table=1780,edge_uplink="eth0",edge_listen_port=51832,
    )
    return BootGuardManifest(
        UIDPolicyRequest(spec,"nvl0557",1644,1780),
        "PROTECTED_BOOT_GUARD",10553,
    )


class GoodGuard:
    def verify(self, _manifest):
        return None


class BadGuard:
    def verify(self, _manifest):
        raise BootGuardError("UID_RULE_NOT_ARMED")


class KernelAuditTests(unittest.TestCase):
    def run_audit(self, state="PROTECTED", *, attached=True, wrong=False,
                  dns_active=True, guard_factory=GoodGuard):
        called=[]
        req=manifest().request
        routes=(
            ("default via "+req.spec.ns_veth_ip+
             " dev "+req.spec.veth_root+" src "+
             req.spec.root_veth_ip+" metric 100\n")
            if attached else ""
        )+"blackhole default metric 4096\n"
        if wrong:
            routes="default via 209.200.246.198 dev eth0\n"+routes
        def run(args,**_kwargs):
            called.append(tuple(args))
            if args[:4]==["ip","-4","route","show"]:
                return SimpleNamespace(returncode=0,stdout=routes)
            if args[0]=="systemctl":
                return SimpleNamespace(returncode=0 if dns_active else 3,
                                       stdout="")
            return SimpleNamespace(returncode=0,stdout="")
        outcome=inspect_uid_kernel(
            manifest(),expected_state=state,
            guard_factory=guard_factory,run=run,
        )
        self.assertFalse(outcome.customer_ready)
        self.assertFalse(any("add" in args or "replace" in args or
                             "del" in args or "flush" in args for args in called))
        return outcome

    def test_verified_local_route_does_not_claim_customer_ready(self):
        outcome=self.run_audit()
        self.assertTrue(outcome.locally_consistent)
        self.assertEqual(outcome.code,"LOCAL_EDGE_ROUTE_CONSISTENT")

    def test_frozen_and_hold_are_accepted_only_with_blackhole_only(self):
        for state in ("FROZEN","HOLD"):
            self.assertTrue(self.run_audit(state,attached=False).locally_consistent)
            self.assertFalse(self.run_audit(state,attached=True).locally_consistent)

    def test_missing_edge_foreign_route_or_dns_unit_denied(self):
        for kwargs in ({"attached":False},{"wrong":True},
                       {"dns_active":False},
                       {"guard_factory":BadGuard}):
            with self.subTest(kwargs=kwargs):
                self.assertFalse(self.run_audit(**kwargs).locally_consistent)

    def test_invalid_state_denied_before_any_command(self):
        result=inspect_uid_kernel(
            manifest(),expected_state="ACTIVE",
            guard_factory=lambda:self.fail("unexpected read"),
            run=lambda *args,**kwargs:self.fail("unexpected subprocess"),
        )
        self.assertFalse(result.locally_consistent)


if __name__=="__main__":
    unittest.main()
