"""M4 IPC: exact framed protocol, peer UID, no callback-supplied root witness."""
from __future__ import annotations

import json
import os
import socket
import unittest
from unittest.mock import patch

from edge_egress_k2_m4_ipc import (
    M4IPCReject,RootOperatorIPC,handle_accepted_socket,
)
from tests.test_edge_egress_k2_m4_root_portal import M4RootPortalTests
from tests.test_edge_egress_k2_migration_inventory import NOW


class M4UnixOperatorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fx=M4RootPortalTests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        self.fx=fx
        self.ipc=RootOperatorIPC(
            portal=fx.portal,bot_uid=50101,
            geteuid=lambda:0,released=True,
        )
        self.patches=[
            patch("edge_egress_k2_m4_ipc.M4_UNIX_IPC_ENABLED",True),
            patch("edge_egress_k2_m4_root_portal.M4_ROOT_PORTAL_ENABLED",True),
            patch("edge_egress_k2_m4_checkpoint.M4_CHECKPOINT_RELEASE_ENABLED",True),
            patch("edge_egress_k2_m3_waves.M3_WAVE_EXECUTION_ENABLED",True),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    async def call(self,d,uid=50101):
        return json.loads(await self.ipc.dispatch(
            json.dumps(d).encode(),peer_uid=uid))

    def prepare_message(self):
        return dict(action="PREPARE",mode="SINGLE",
                    usernames=["nvl0555"],edge_id="e9",
                    actor_id=11,chat_id=-222)

    async def test_preview_confirm_one_shot_original_p3_only(self):
        prepared=await self.call(self.prepare_message())
        self.assertEqual(prepared["state"],"PREPARED")
        self.assertEqual(prepared["user_count"],1)
        self.assertNotIn("signature",prepared)
        self.assertNotIn("ticket",prepared)
        confirm=dict(action="CONFIRM",request_id=prepared["request_id"],
                     actor_id=11,chat_id=-222)
        result=await self.call(confirm)
        self.assertEqual(result["state"],"COMPLETED")
        self.assertEqual(result["completed"],1)
        self.assertEqual(self.fx.actions,["ticket","mutation"])
        with self.assertRaisesRegex(M4IPCReject,"MISSING"):
            await self.call(confirm)

    async def test_no_wrong_uid_or_chat_prepare_even_with_credentials(self):
        with self.assertRaisesRegex(M4IPCReject,"PEER"):
            await self.call(self.prepare_message(),uid=0)
        with self.assertRaisesRegex(Exception,"SUPERADMIN"):
            await self.call(dict(self.prepare_message(),actor_id=80))
        self.assertEqual(self.fx.actions,[])

    async def test_wrong_actor_cannot_steal_live_confirmation(self):
        prep=await self.call(self.prepare_message())
        token=prep["request_id"]
        with self.assertRaisesRegex(M4IPCReject,"WRONG_ACTOR"):
            await self.call(dict(action="CONFIRM",request_id=token,
                                 actor_id=11,chat_id=-20))
        result=await self.call(dict(action="CONFIRM",request_id=token,
                                    actor_id=11,chat_id=-222))
        self.assertEqual(result["completed"],1)

    async def test_invalid_json_duplicate_fields_injection_and_bulk(self):
        frames=[
            b'{"action":"PREPARE","action":"CONFIRM"}',
            b'{"action":"SHELL","cmd":"ip rule"}',
            b'{"action":"PREPARE","actor_id":11,"chat_id":-222,'
            b'"edge_id":"e9","mode":"SINGLE",'
            b'"usernames":["nvl0555"],"f4":true}',
            b"{" + b" "*4100 + b"}",
            b'{"action":"PREPARE","usernames":["@root"]}',
            b'{"action":"CONFIRM","request_id":"../../root"}',
        ]
        for frame in frames:
            with self.subTest(frame=frame[:25]),self.assertRaises(Exception):
                await self.ipc.dispatch(frame,peer_uid=50101)
        self.assertEqual(self.fx.actions,[])

    async def test_cancellation_and_process_restart_never_replays_ticket(self):
        prep=await self.call(self.prepare_message())
        restart=RootOperatorIPC(
            portal=self.fx.portal,bot_uid=50101,
            geteuid=lambda:0,released=True,
        )
        msg=dict(action="CONFIRM",request_id=prep["request_id"],
                 actor_id=11,chat_id=-222)
        with self.assertRaises(M4IPCReject):
            await restart.dispatch(json.dumps(msg).encode(),peer_uid=50101)
        cancelled=await self.call(
            dict(action="CANCEL",request_id=prep["request_id"],
                 actor_id=11,chat_id=-222))
        self.assertEqual(cancelled["state"],"CANCELLED")
        with self.assertRaises(M4IPCReject):
            await self.call(msg)
        self.assertEqual(self.fx.actions,[])

    async def test_real_kernel_peer_credentials_on_unix_socket_pair(self):
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        trusted=RootOperatorIPC(
            portal=self.fx.portal,bot_uid=os.getuid(),
            geteuid=lambda:0,released=True,
        )
        right.sendall(json.dumps(self.prepare_message()).encode()+b"\n")
        await handle_accepted_socket(trusted,left)
        reply=json.loads(right.recv(4096))
        self.assertEqual(reply["state"],"PREPARED")

    async def test_stream_without_delimiter_holds_and_no_executor(self):
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        trusted=RootOperatorIPC(
            portal=self.fx.portal,bot_uid=os.getuid(),
            geteuid=lambda:0,released=True,
        )
        right.sendall(json.dumps(self.prepare_message()).encode())
        right.shutdown(socket.SHUT_WR)
        with self.assertRaisesRegex(M4IPCReject,"HELD"):
            await handle_accepted_socket(trusted,left)
        self.assertEqual(json.loads(right.recv(4096))["state"],"HOLD")
        self.assertEqual(self.fx.actions,[])

    async def test_multiple_stream_frames_never_execute(self):
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        trusted=RootOperatorIPC(
            portal=self.fx.portal,bot_uid=os.getuid(),
            geteuid=lambda:0,released=True,
        )
        payload=json.dumps(self.prepare_message()).encode()
        right.sendall(payload+b"\n"+payload+b"\n")
        with self.assertRaisesRegex(M4IPCReject,"HELD"):
            await handle_accepted_socket(trusted,left)
        self.assertEqual(json.loads(right.recv(4096))["state"],"HOLD")
        self.assertEqual(self.fx.actions,[])

    async def test_unreleased_root_service_rejects_before_portal(self):
        with patch("edge_egress_k2_m4_ipc.M4_UNIX_IPC_ENABLED",False):
            with self.assertRaisesRegex(M4IPCReject,"RELEASE"):
                await self.call(self.prepare_message())
        self.assertEqual(self.fx.actions,[])


if __name__=="__main__":
    unittest.main()
