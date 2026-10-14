"""M4.3 isolated non-root bot client: strict framing and no privileged params."""
from __future__ import annotations
import json
import os
import unittest
from unittest.mock import patch

import edge_egress_k2_m43_client as client
from edge_egress_k2_migration_inventory import select_migration


class M43BotClientTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.frames=[]
        self.selection=select_migration("SINGLE",("nvl0555",),"e9")
        def exchange(frame):
            self.frames.append(json.loads(frame))
            action=self.frames[-1]["action"]
            if action=="PREPARE":
                return json.dumps({
                    "state":"PREPARED","request_id":"a"*32,
                    "edge_id":"e9","user_count":1,"expires_at":1792010190,
                }).encode()
            if action=="CANCEL":
                return b'{"state":"CANCELLED"}'
            return json.dumps({
                "state":"COMPLETED","completed":1,"halted":False,
                "accounts":[{"username":"nvl0555","state":"VERIFIED"}],
            }).encode()
        self.bot=client.NonRootOperatorClient(
            released=True,geteuid=lambda:10001,exchange=exchange,
        )
        flag=patch.object(client,"M43_TELEGRAM_EXECUTION_ENABLED",True)
        flag.start()
        self.addCleanup(flag.stop)

    async def test_exact_prepare_confirm_cancel_frames_never_include_secrets(self):
        result=await self.bot.request(
            "PREPARE",actor_id=11,chat_id=-222,selection=self.selection)
        self.assertEqual(result["state"],"PREPARED")
        out=await self.bot.request(
            "CONFIRM",actor_id=11,chat_id=-222,request_id="a"*32)
        self.assertEqual(out["state"],"COMPLETED")
        out=await self.bot.request(
            "CANCEL",actor_id=11,chat_id=-222,request_id="a"*32)
        self.assertEqual(out["state"],"CANCELLED")
        self.assertEqual(len(self.frames),3)
        self.assertEqual(set(self.frames[0]),
            {"action","mode","usernames","edge_id","actor_id","chat_id"})
        self.assertEqual(set(self.frames[1]),
            {"action","request_id","actor_id","chat_id"})
        combined=json.dumps(self.frames).lower()
        for secret in ("nonce","ticket","signature","root_secret","f4", "shell"):
            self.assertNotIn(secret,combined)

    async def test_not_released_or_bot_running_as_root_never_opens_socket(self):
        with patch.object(client,"M43_TELEGRAM_EXECUTION_ENABLED",False):
            with self.assertRaisesRegex(client.M43ClientHold,"NONROOT"):
                await self.bot.request("PREPARE",actor_id=11,chat_id=-222,
                                       selection=self.selection)
        root=client.NonRootOperatorClient(
            released=True,geteuid=lambda:0,
            exchange=lambda _:self.fail("Root bot must never use IPC"),
        )
        with self.assertRaisesRegex(client.M43ClientHold,"NONROOT"):
            await root.request("PREPARE",actor_id=11,chat_id=-222,
                               selection=self.selection)
        self.assertEqual(self.frames,[])

    async def test_batch_remains_off_before_m7(self):
        batch=select_migration("BATCH",("nvl0555","nvl0557"),"e9")
        with self.assertRaisesRegex(client.M43ClientHold,"BATCH"):
            await self.bot.request("PREPARE",actor_id=11,chat_id=-222,
                                   selection=batch)
        self.assertEqual(self.frames,[])

    async def test_role_chat_and_request_id_strict(self):
        for actor,chat in ((True,-222),(11,False),(0,-222),(11,0)):
            with self.assertRaises(client.M43ClientHold):
                await self.bot.request("CANCEL",actor_id=actor,chat_id=chat,
                                       request_id="a"*32)
        for rid in ("../../etc", "a"*31, "A"*32):
            with self.assertRaises(client.M43ClientHold):
                await self.bot.request("CONFIRM",actor_id=11,chat_id=-222,
                                       request_id=rid)
        self.assertEqual(self.frames,[])

    def test_invalid_or_duplicate_json_response_never_success(self):
        for raw in (
            b'{"state":"COMPLETED","state":"HOLD"}',
            b'{"state":"HOLD"}',
            b'{"state":"COMPLETED","completed":1,"halted":false,"accounts":[]}',
            b'{"state":"COMPLETED","completed":0,"halted":false,'
            b'"accounts":[{"username":"nvl0555","state":"VERIFIED"}]}',
            b'{"state":"COMPLETED","completed":1,"halted":true,'
            b'"accounts":[{"username":"nvl0555","state":"VERIFIED"}]}',
        ):
            with self.subTest(raw=raw[:55]),self.assertRaises(client.M43ClientHold):
                client._response(raw,"CONFIRM")
        hold=client._response(
            b'{"state":"HOLD","completed":0,"halted":true,'
            b'"accounts":[{"username":"nvl0555","state":"DEFERRED"}]}',"CONFIRM")
        self.assertEqual(hold["state"],"HOLD")

    async def test_no_generic_command_and_scoped_reply(self):
        with self.assertRaisesRegex(client.M43ClientHold,"DENIED"):
            await self.bot.request("SHELL",actor_id=11,chat_id=-222)
        bot=client.NonRootOperatorClient(
            released=True,geteuid=lambda:10001,
            exchange=lambda frame:b'{"state":"PREPARED","request_id":"'+
            b'a'*32+b'","edge_id":"e7","user_count":1,"expires_at":1792010190}',
        )
        with self.assertRaisesRegex(client.M43ClientHold,"SCOPE_DRIFT"):
            await bot.request("PREPARE",actor_id=11,chat_id=-222,
                              selection=self.selection)


if __name__=="__main__":
    unittest.main()
