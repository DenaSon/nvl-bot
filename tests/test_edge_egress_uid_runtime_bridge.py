"""F2: bridge reuses only the existing 6G lock, no implicit live ports."""
import asyncio
from unittest.mock import Mock
import unittest

from edge_egress_uid_runtime_bridge import Existing6GUIDRuntimeBridge
from edge_egress_uid_runtime import RuntimeUnsafe


class RuntimeBridgeTests(unittest.TestCase):
    def bridge(self, **overrides):
        calls=[]
        def update(op, *, status, detail, finished, require_running):
            calls.append((op,status,detail,finished,require_running))
        base=dict(
            db_conn=lambda: None,
            acquire_fn=lambda source,target:(42,None),
            update_fn=update, os_uid_for_username=lambda _:1644,
            kernel=object(), shadow=object(),
            session_gate_probe=lambda req:True,
            existing_sessions_probe=lambda req:True,
        )
        base.update(overrides)
        return Existing6GUIDRuntimeBridge(**base), calls

    def test_default_missing_ports_never_acquires_shared_lease(self):
        count=[]
        bridge,_=self.bridge(
            kernel=None,
            acquire_fn=lambda *args:count.append(args) or (42,None),
        )
        with self.assertRaisesRegex(RuntimeUnsafe, "EXPLICIT_VERIFIED"):
            asyncio.run(bridge.acquire_6g("172.86.94.174","216.126.229.12"))
        self.assertEqual(count,[])

    def test_shared_lock_is_single_use(self):
        bridge,_=self.bridge()
        self.assertEqual(asyncio.run(bridge.acquire_6g(
            "172.86.94.174","216.126.229.12")), (42,None))
        with self.assertRaisesRegex(RuntimeUnsafe,"SINGLE_USE"):
            asyncio.run(bridge.acquire_6g(
                "172.86.94.174","216.126.229.12"))

    def test_runtime_journals_only_scrubbed_payloads(self):
        bridge,calls=self.bridge()
        asyncio.run(bridge.acquire_6g("172.86.94.174","216.126.229.12"))
        asyncio.run(bridge.journal(
            42,"RUNNING","EGRESS_UID_RUNTIME_ARM_GUARD",{"uid":1644}))
        self.assertEqual(calls[0][0],42)
        self.assertEqual(calls[0][2]["kind"],"EGRESS_UID_RUNTIME")
        self.assertTrue(calls[0][4])
        with self.assertRaisesRegex(RuntimeUnsafe,"UNSAFE_JOURNAL"):
            asyncio.run(bridge.journal(
                42,"RUNNING","EGRESS_UID_RUNTIME_PROVE",{"private_key":"secret"}))
        with self.assertRaisesRegex(RuntimeUnsafe,"PHASE_OR_LEASE"):
            asyncio.run(bridge.journal(
                42,"RUNNING","UNSAFE_OTHER_PHASE",{}))
        self.assertEqual(len(calls),1)


if __name__=="__main__":
    unittest.main()
