"""F2: stateful runtime orchestration never silently falls back to Core."""
import asyncio
import unittest

from edge_egress_uid_runtime import attach_protected, freeze_protected, HOLD_PHASE
from edge_egress_uid_policy import UIDPolicyRequest
from ops.edge_egress_provision import EgressSpec


SOURCE="172.86.94.174"
TARGET="216.126.229.12"


def request():
    return UIDPolicyRequest(EgressSpec(
        edge_id="fra1",edge_public_ipv4=TARGET,core_public_ipv4="209.200.246.198",
        tunnel_network="10.78.100.0/30",veth_network="10.78.101.0/30",
        edge_uplink="eth0",route_table=1780,edge_listen_port=51832),
        "nvl0557",1644,1780)


class Ports:
    def __init__(self, fail_at=None, ip=TARGET):
        self.calls=[]
        self.state=None
        self.fail_at=fail_at
        self.ip=ip
        self.busy=False

    def step(self, name):
        self.calls.append(name)
        if self.fail_at==name:
            raise RuntimeError("injected failure")

    async def acquire_6g(self, source, target):
        self.step("acquire")
        return (None, 99) if self.busy else (42, None)

    async def journal(self, op,status,phase,details):
        self.calls.append("journal:"+phase+":"+status)
        if self.fail_at=="journal:"+phase:
            raise RuntimeError("persist failed")

    async def check_session_gate(self,req): self.step("session_gate")
    async def reserve_blocked(self,op,req,source,dns_port):
        self.step("reserve")
        assert source==SOURCE and dns_port==10553
        self.state="BLOCKED"
    async def check_no_existing_sessions(self,req): self.step("idle")
    async def arm_boot_guard(self,req,dns_port):
        assert self.state=="BLOCKED"
        self.step("arm")
    async def start_edge(self,req): self.step("start")
    async def attach_edge(self,req): self.step("attach")
    async def transition(self,op,req,source,before,after):
        self.step("transition:"+before+":"+after)
        if self.state!=before:
            raise RuntimeError("stale")
        self.state=after
    async def prove_ipv4(self,req):
        self.step("ipv4")
        return self.ip
    async def prove_dns_ipv6(self,req): self.step("dns6")
    async def commit_protected(self,op,req,source):
        self.step("commit")
        assert self.state=="ROUTED_UNVERIFIED"
        self.state="PROTECTED"
    async def freeze_edge(self,req): self.step("freeze")
    async def prove_frozen(self,req): self.step("frozen")


class RuntimeTests(unittest.TestCase):
    def run_attach(self,port,authorized=True):
        return asyncio.run(attach_protected(port,request(),source=SOURCE,
                                           dns_port=10553,authorized=authorized))

    def test_explicit_gate_no_lock_or_mutation_when_off(self):
        p=Ports()
        result=self.run_attach(p,False)
        self.assertFalse(result.ok)
        self.assertEqual(p.calls,[])

    def test_shared_6g_busy_never_mutates(self):
        p=Ports()
        p.busy=True
        result=self.run_attach(p)
        self.assertEqual(result.reason,"SHARED_6G_BUSY")
        self.assertEqual(p.calls,["acquire"])

    def test_ordered_proof_then_mapping_commit_and_journal_success(self):
        p=Ports()
        result=self.run_attach(p)
        self.assertTrue(result.ok)
        self.assertFalse(result.customer_ready)
        self.assertEqual(p.state,"PROTECTED")
        for first,second in (
            ("session_gate","reserve"),
            ("reserve","idle"),
            ("idle","arm"),
            ("arm","start"),
            ("start","attach"),
            ("attach","ipv4"),
            ("ipv4","dns6"),
            ("dns6","commit"),
        ):
            self.assertLess(p.calls.index(first),p.calls.index(second))
        self.assertIn("journal:EGRESS_UID_RUNTIME_PROTECTED:SUCCEEDED",p.calls)

    def test_bad_public_ip_freezes_and_holds_shared_6g(self):
        p=Ports(ip="209.200.246.198")
        result=self.run_attach(p)
        self.assertFalse(result.ok)
        self.assertTrue(result.recovery_required)
        self.assertEqual(p.state,"HOLD")
        self.assertLess(p.calls.index("freeze"),p.calls.index("frozen"))
        self.assertIn("journal:"+HOLD_PHASE+":RUNNING",p.calls)
        self.assertFalse(any(":FAILED" in x or ":SUCCEEDED" in x for x in p.calls))

    def test_new_login_gate_failure_does_not_reserve_user(self):
        p=Ports(fail_at="session_gate")
        result=self.run_attach(p)
        self.assertEqual(result.reason,"PRE_RESERVATION_FAILED")
        self.assertNotIn("reserve",p.calls)
        self.assertEqual(p.state,None)

    def test_existing_session_detected_after_block_intent_holds_user(self):
        p=Ports(fail_at="idle")
        result=self.run_attach(p)
        self.assertTrue(result.recovery_required)
        self.assertEqual(p.state,"HOLD")
        self.assertLess(p.calls.index("reserve"),p.calls.index("idle"))

    def test_failed_freeze_cannot_release_shared_lease(self):
        p=Ports(fail_at="freeze", ip="209.200.246.198")
        result=self.run_attach(p)
        self.assertTrue(result.recovery_required)
        self.assertIn("journal:"+HOLD_PHASE+":RUNNING",p.calls)

    def test_freeze_does_not_remove_protected_intent(self):
        p=Ports()
        p.state="PROTECTED"
        out=asyncio.run(freeze_protected(p,request(),source=SOURCE,
                                         authorized=True))
        self.assertTrue(out.ok)
        self.assertEqual(p.state,"FROZEN")
        self.assertIn("journal:EGRESS_UID_RUNTIME_FROZEN:SUCCEEDED",p.calls)
        self.assertNotIn("restore_disposable_canary",p.calls)

    def test_freeze_uncertain_holds_6g(self):
        p=Ports(fail_at="frozen")
        p.state="PROTECTED"
        out=asyncio.run(freeze_protected(p,request(),source=SOURCE,
                                         authorized=True))
        self.assertTrue(out.recovery_required)
        self.assertEqual(p.state,"HOLD")
        self.assertIn("journal:"+HOLD_PHASE+":RUNNING",p.calls)


if __name__=="__main__":
    unittest.main()
