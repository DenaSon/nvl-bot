"""D1-C2B2 stage-only coordinator: fake Core/Edge hosts and existing 6G lock."""
import asyncio
import base64
import unittest

from edge_egress_prepare import prepare_edge_stage_only, PREPARE_RECOVERY_PHASE
from edge_egress_inventory import EdgeReservation
from ops.edge_egress_provision import EgressSpec


def pub(n):
    return base64.b64encode(bytes([(v+n) % 256 for v in range(32)])).decode("ascii")


def spec():
    return EgressSpec.from_json(dict(edge_id="fra1", edge_public_ipv4="216.126.229.12",
        core_public_ipv4="209.200.246.198", tunnel_network="10.78.100.0/30",
        veth_network="10.78.101.0/30", edge_uplink="eth0",
        edge_listen_port=51832, route_table=1780, mode="relay"))


class FakeHost:
    def __init__(self, role, recorder, *, error_at=None, cleanup_error=False):
        self.role=role
        self.events=recorder
        self.error_at=error_at
        self.cleanup_error=cleanup_error
        self.public_key=pub(1 if role=="core" else 2)
        self.peer=None

    async def read_only_preflight(self, config):
        self.events.append(self.role+":preflight")
        return (False, ("PORT_BUSY",)) if self.error_at=="preflight" else (True, ())

    async def ensure_local_keypair(self, edge_id):
        self.events.append(self.role+":key")
        if self.error_at=="key":
            raise RuntimeError("key error")
        return self.public_key

    async def stage_config_only(self, config, *, peer_public_key):
        self.events.append(self.role+":stage")
        self.peer=peer_public_key
        if self.error_at=="stage":
            raise RuntimeError("fake staging interrupted")

    async def discard_staged_config_only(self, edge_id):
        self.events.append(self.role+":discard")
        if self.cleanup_error:
            raise RuntimeError("delete failed")


class FakePorts:
    def __init__(self, *, busy=False, error_at=None, role_error=None, cleanup_error=False):
        self.events=[]
        self.journal=[]
        self.busy=busy
        self.error_at=error_at
        self.source="172.86.94.174"
        self.target="216.126.229.12"
        self.core_host=FakeHost("core",self.events,error_at=error_at if role_error=="core" else None,
                                cleanup_error=cleanup_error)
        self.edge_host=FakeHost("edge",self.events,error_at=error_at if role_error=="edge" else None,
                                cleanup_error=cleanup_error)
        self.locked=False
        self.status=None
        self.reservation=None

    async def acquire_existing_6g_lock(self, source, target):
        self.events.append("6g:lock")
        if self.busy:
            return None,57
        self.locked=True
        self.source,self.target=source,target
        return 42,None

    async def journal_existing_6g(self, op,status,phase,details):
        self.events.append("6g:journal:"+phase)
        self.journal.append((status,phase,dict(details)))
        self.status=status
        if status!="RUNNING":
            self.locked=False

    async def assert_current_ownership_unchanged(self,source,target):
        self.events.append("6g:revalidate")
        if self.error_at=="ownership":
            raise RuntimeError("stale DB")

    async def core(self,core_ip):
        self.events.append("host:core")
        return self.core_host

    async def edge(self,edge_ip):
        self.events.append("host:edge")
        return self.edge_host

    async def reserve_under_6g_lock(self,conf,*,core_public_key,edge_public_key):
        self.events.append("6g:reserve")
        if self.error_at=="reserve":
            raise RuntimeError("allocation conflict")
        self.reservation=(core_public_key,edge_public_key)
        return EdgeReservation(conf.edge_id,conf.edge_public_ipv4,conf.tunnel_network,
                               conf.veth_network,conf.route_table,"RESERVED",True)

    async def stage_reservation_under_6g_lock(self,edge_id):
        self.events.append("6g:mark_staged")
        if self.error_at=="mark":
            raise RuntimeError("DB mark failed")


class PrepareCoordinatorTests(unittest.TestCase):
    def run_prepare(self,ports,config=None,source="172.86.94.174"):
        return asyncio.run(prepare_edge_stage_only(ports,spec=config or spec(),source_host=source))

    def test_stage_only_does_not_route_or_assign_accounts(self):
        ports=FakePorts()
        result=self.run_prepare(ports)
        self.assertTrue(result.ok)
        self.assertEqual(result.reason,"STAGED_ONLY")
        self.assertEqual(result.state,"STAGED")
        self.assertFalse(ports.locked)
        self.assertEqual(ports.core_host.peer,pub(2))
        self.assertEqual(ports.edge_host.peer,pub(1))
        self.assertEqual(ports.reservation,(pub(1),pub(2)))
        self.assertEqual(ports.journal[-1][1],"STAGED_ONLY")
        self.assertEqual(ports.journal[-1][2]["customers_moved"],0)
        self.assertLess(ports.events.index("edge:stage"),ports.events.index("core:stage"))
        for forbidden in ("activate","dns","user_route","host_pool","wg0"):
            self.assertNotIn(forbidden," ".join(ports.events).lower())

    def test_busy_shared_lock_has_no_side_effect(self):
        ports=FakePorts(busy=True)
        result=self.run_prepare(ports)
        self.assertFalse(result.ok)
        self.assertEqual(result.operation_id,57)
        self.assertEqual(ports.events,["6g:lock"])

    def test_invalid_spec_aborts_even_before_lock(self):
        ports=FakePorts()
        result=self.run_prepare(ports,source="209.200.246.198")
        self.assertFalse(result.ok)
        self.assertEqual(ports.events,[])

    def test_preflight_failure_no_staging_or_keys(self):
        ports=FakePorts(error_at="preflight",role_error="edge")
        result=self.run_prepare(ports)
        self.assertFalse(result.ok)
        self.assertNotIn("edge:key",ports.events)
        self.assertNotIn("core:stage",ports.events)
        self.assertFalse(ports.locked)
        self.assertEqual(ports.status,"FAILED")

    def test_key_creation_failure_does_not_touch_routes(self):
        ports=FakePorts(error_at="key",role_error="core")
        result=self.run_prepare(ports)
        self.assertFalse(result.ok)
        self.assertNotIn("edge:stage",ports.events)
        self.assertFalse(ports.locked)

    def test_duplicate_public_keys_refused(self):
        ports=FakePorts()
        ports.edge_host.public_key=ports.core_host.public_key
        result=self.run_prepare(ports)
        self.assertFalse(result.ok)
        self.assertNotIn("6g:reserve",ports.events)
        self.assertFalse(ports.locked)

    def test_partial_staging_failure_cleans_only_stage_files(self):
        ports=FakePorts(error_at="stage",role_error="core")
        result=self.run_prepare(ports)
        self.assertFalse(result.ok)
        self.assertEqual(result.state,"NOT_STAGED")
        self.assertIn("core:discard",ports.events)
        self.assertIn("edge:discard",ports.events)
        self.assertEqual(ports.status,"FAILED")
        self.assertFalse(ports.locked)

    def test_cleanup_failure_holds_shared_lock_for_reconciliation(self):
        ports=FakePorts(error_at="stage",role_error="core",cleanup_error=True)
        result=self.run_prepare(ports)
        self.assertFalse(result.ok)
        self.assertTrue(result.requires_recovery)
        self.assertTrue(ports.locked)
        self.assertEqual(ports.journal[-1][1],PREPARE_RECOVERY_PHASE)
        self.assertEqual(ports.journal[-1][0],"RUNNING")

    def test_mark_staged_failure_cleans_but_not_marked_ready(self):
        ports=FakePorts(error_at="mark")
        result=self.run_prepare(ports)
        self.assertFalse(result.ok)
        self.assertIn("edge:discard",ports.events)
        self.assertEqual(ports.status,"FAILED")


if __name__=="__main__":
    unittest.main()
