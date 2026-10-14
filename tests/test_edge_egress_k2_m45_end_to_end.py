"""M4.5 hermetic end-to-end: Telegram intent -> real AF_UNIX frames/peercred ->
root IPC -> M3 wave -> ORIGINAL P3/6G SQLite CAS -> M4 checkpoint -> status.

The only substituted part is the physically installed Linux host and off-host
F4/PAM/WG observer. Those remain M5 field acceptance and NEVER run in CI.
No GitHub runner root privilege, VPS access, bot token or network request.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import json
import os
from pathlib import Path
import socket
import sqlite3
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from edge_egress_k2_migration_inventory import (
    LiveIngressWitness,preview_migration,select_migration,
)
from edge_egress_k2_m3_journal import confirm_original_6g_commit
from edge_egress_k2_m4_checkpoint import (
    DurableWaveCheckpoint,install_checkpoint_schema,
)
from edge_egress_k2_m4_root_portal import RootMigrationPortal
from edge_egress_k2_m4_ipc import RootOperatorIPC,handle_accepted_socket
from edge_egress_k2_m43_client import NonRootOperatorClient,M43ClientHold
from edge_egress_k2_m43_workflow import (
    EphemeralApprovalStore,PendingTelegramApproval,result_html,
)
from edge_egress_p3_executor import (
    BASE_GATES,ATTACH_GATES,SOURCE_ENROLL_GATES,
    ExecutionScope,Existing6GGuardedExecutor,FreshEvidence,
    issue_execution_ticket,INTENT_PHASE,RECOVERY_PHASE,
)
from tests.test_edge_egress_k2_migration_inventory import (
    K2M1InventoryTests,NOW,TARGET,
)

ADMIN, CHAT, MESSAGE = 11,-222,77
TEST_BOT_UID = os.getuid()
TEST_SECRET = b"TEST-ONLY-NOT-DEPLOYED-M45-" + b"x"*32
ALLOWED = BASE_GATES|ATTACH_GATES|SOURCE_ENROLL_GATES


class SimulatedHostPort:
    """Synthetic Linux mutation only; asserts P3 original 6G intent first."""
    def __init__(self, suite):
        self.suite = suite
        self.applied = False

    async def apply(self, scope):
        with self.suite.db() as conn:
            row=conn.execute(
                "SELECT status,detail_json FROM failover_operations "
                "WHERE status='RUNNING'"
            ).fetchone()
        self.suite.assertIsNotNone(row)
        self.suite.assertEqual(json.loads(row[1])["phase"],INTENT_PHASE)
        self.suite.effects.append("synthetic-host-apply")
        self.applied=True
        if self.suite.fail_after_apply:
            raise RuntimeError("SIMULATED_PARTIAL_HOST_FAILURE: private-data")

    async def verify(self, scope):
        self.suite.effects.append("synthetic-host-verify")
        return True

    async def freeze_or_hold(self, scope):
        self.suite.effects.append("synthetic-host-freeze")


class M45FullIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fixture=K2M1InventoryTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.original_fixture=fixture
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path=Path(temp.name)/"original-core.sqlite"
        copy=sqlite3.connect(str(self.path))
        fixture.c.backup(copy)
        copy.close()
        with self.db() as conn:
            # The original M1 fixture uses an id-only preview table.
            # Rebuild its EMPTY table with the actual original 6G PK so
            # INSERT.lastrowid is the same id read by P3 _locked().
            conn.execute("DROP TABLE failover_operations")
            conn.execute("CREATE TABLE failover_operations ("
                         "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                         "status TEXT,source_host TEXT,target_host TEXT,"
                         "detail_json TEXT)")
            conn.execute("CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT)")
            conn.execute(
                "INSERT INTO settings VALUES('edge_egress_protected_mode','0')"
            )
            install_checkpoint_schema(conn)
        self.now=NOW
        self.fail_after_apply=False
        self.effects=[]
        self.review_changes=False
        self.f4=True
        self.m1uid={"nvl0555":1636,"nvl0557":1644,"pool_user":1666}
        self.selection=select_migration("SINGLE",("nvl0555",),"e9")
        self.fresh=FreshEvidence(
            sha256(b"fixture-independent-f4-not-production").hexdigest(),
            NOW,ALLOWED,
        )
        self.checkpoint=DurableWaveCheckpoint(
            db_conn=self.db,geteuid=lambda:0,clock=lambda:self.now,
            release_enabled=True,
        )
        self.portal=RootMigrationPortal(
            root_secret=TEST_SECRET,review=self.review,
            admin_authorized=lambda actor,chat:(
                actor,chat)==(ADMIN,CHAT),
            independent_physical_f4=lambda plan:self.f4,
            current_protected_mode=lambda:"0",
            issue_single_ticket=self.issue,
            execute_single=self.execute,
            committed_6g=lambda s,t,op:confirm_original_6g_commit(
                self.db,s,t,op),
            checkpoint=self.checkpoint,
            clock=lambda:self.now,geteuid=lambda:0,release_enabled=True,
        )
        self.ipc=RootOperatorIPC(
            portal=self.portal,bot_uid=TEST_BOT_UID,
            geteuid=lambda:0,released=True,
        )
        self.ui=EphemeralApprovalStore()
        self.bot=NonRootOperatorClient(
            geteuid=lambda:10001,released=True,exchange=self.socket_exchange,
        )
        for name in (
            "edge_egress_k2_m4_ipc.M4_UNIX_IPC_ENABLED",
            "edge_egress_k2_m4_root_portal.M4_ROOT_PORTAL_ENABLED",
            "edge_egress_k2_m4_checkpoint.M4_CHECKPOINT_RELEASE_ENABLED",
            "edge_egress_k2_m3_waves.M3_WAVE_EXECUTION_ENABLED",
            "edge_egress_k2_m43_client.M43_TELEGRAM_EXECUTION_ENABLED",
            "edge_egress_k2_m43_client.M44_TELEGRAM_STATUS_ENABLED",
            "edge_egress_k2_m44_recovery.M44_ROOT_STATUS_ENABLED",
        ):
            setting=patch(name,True)
            setting.start()
            self.addCleanup(setting.stop)
        resolve=patch(
            "edge_egress_k2_m44_recovery.pwd.getpwnam",
            side_effect=lambda name:SimpleNamespace(pw_uid=self.m1uid[name]),
        )
        resolve.start()
        self.addCleanup(resolve.stop)

    async def asyncSetUp(self):
        self.loop=asyncio.get_running_loop()

    @contextmanager
    def db(self):
        conn=sqlite3.connect(str(self.path),timeout=3)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def review(self,selection):
        inventory=preview_migration(
            self.db,selection,
            os_uid=lambda name:self.m1uid[name],
            ingress_witness=lambda name:LiveIngressWitness(
                name,"e9",TARGET,
                self.now-1 if not self.review_changes else self.now-350,
                "INDEPENDENT_LIVE",
            ),
            session_count=lambda name,uid:0,
            now=self.now,
        )
        return inventory

    def issue(self,scope,actor,chat):
        self.effects.append("p3-ticket")
        return issue_execution_ticket(
            scope,self.fresh,actor_id=actor,chat_id=chat,now=self.now,
        )

    def acquire(self,source,target):
        with self.db() as conn:
            busy=conn.execute(
                "SELECT id FROM failover_operations "
                "WHERE status='RUNNING' LIMIT 1"
            ).fetchone()
            if busy:
                return None,busy[0]
            cursor=conn.execute(
                "INSERT INTO failover_operations "
                "(status,source_host,target_host,detail_json) VALUES(?,?,?,?)",
                ("RUNNING",source,target,json.dumps({"phase":"LOCKED"})),
            )
            self.effects.append("original-6g-acquired")
            return cursor.lastrowid,None

    def journal(self,op,*,status,detail,finished,require_running):
        if not require_running or finished != (status=="SUCCEEDED"):
            raise AssertionError("ORIGINAL_6G_INVALID_JOURNAL_ARGS")
        with self.db() as conn:
            updated=conn.execute(
                "UPDATE failover_operations SET status=?,detail_json=? "
                "WHERE id=? AND status='RUNNING'",
                (status,json.dumps(detail),op),
            )
            if updated.rowcount!=1:
                raise AssertionError("ORIGINAL_6G_CAS_LOST")
        self.effects.append("journal:"+detail["phase"])

    async def execute(self,scope,ticket,actor,chat):
        executor=Existing6GGuardedExecutor(
            db_conn=self.db,acquire_fn=self.acquire,
            journal_fn=self.journal,
            review_fn=lambda s:self.fresh,
            host_port=SimulatedHostPort(self),
            release_enabled=True,geteuid=lambda:0,
            clock=lambda:self.now,
        )
        return await executor.execute(scope,ticket,
                                      actor_id=actor,chat_id=chat)

    def socket_exchange(self,payload):
        """REAL SOCK_STREAM frames; kernel SO_PEERCRED in server handler.

        Python's synthetic root control is explicitly TEST ONLY. Client
        exchange runs in a thread, server asyncio on original test loop
        (all SQLite mutation stays outside this thread).
        """
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            right.settimeout(7)
            future=asyncio.run_coroutine_threadsafe(
                handle_accepted_socket(self.ipc,left),self.loop,
            )
            right.sendall(payload+b"\n")
            frame=bytearray()
            while b"\n" not in frame and len(frame)<=4096:
                chunk=right.recv(1024)
                if not chunk:
                    raise RuntimeError("BROKEN_SOCKET")
                frame.extend(chunk)
            try:
                future.result(timeout=7)
            except Exception:
                # IPC correctly emits a generic HOLD before server reject.
                pass
            if not frame.endswith(b"\n") or frame.count(b"\n")!=1:
                raise RuntimeError("MALFORMED_ROOT_STREAM")
            return bytes(frame[:-1])
        finally:
            left.close()
            right.close()

    async def prepare(self):
        epoch=self.ui.begin(ADMIN,CHAT)
        try:
            response=await self.bot.request(
                "PREPARE",actor_id=ADMIN,chat_id=CHAT,
                selection=self.selection,
            )
            pending=PendingTelegramApproval.create(
                selection=self.selection,
                actor_id=ADMIN,chat_id=CHAT,message_id=MESSAGE,
                result=response,now=self.now,
            )
            self.ui.finish(pending,epoch)
            return pending
        finally:
            self.ui.release(ADMIN,CHAT)

    async def confirm(self):
        pending=self.ui.consume(
            actor_id=ADMIN,chat_id=CHAT,message_id=MESSAGE,
            edge_id="e9",now=self.now,
        )
        result=await self.bot.request(
            "CONFIRM",actor_id=ADMIN,chat_id=CHAT,
            request_id=pending.request_id,
        )
        return result

    async def status(self):
        return await self.bot.request(
            "STATUS",actor_id=ADMIN,chat_id=CHAT,
            selection=self.selection,
        )

    def original_rows(self):
        with self.db() as conn:
            return conn.execute(
                "SELECT id,status,detail_json FROM failover_operations"
            ).fetchall()

    async def test_real_socket_full_green_p3_6g_checkpoint_and_root_readback(self):
        self.assertEqual((await self.status())["wave_state"],"NO_CHECKPOINT")
        before=self.original_rows()
        prepared=await self.prepare()
        self.assertEqual(prepared.selection,self.selection)
        self.assertEqual(self.original_rows(),before)
        self.assertNotIn("ticket",repr(prepared))
        response=await self.confirm()
        self.assertEqual(response["state"],"COMPLETED")
        self.assertEqual(response["completed"],1)
        self.assertIn("تکمیل",result_html(response,selection=self.selection))
        self.assertEqual(self.effects,[
            "p3-ticket","original-6g-acquired",
            "journal:EGRESS_P3_EXECUTE_INTENT",
            "synthetic-host-apply","synthetic-host-verify",
            "journal:EGRESS_P3_VERIFIED",
        ])
        rows=self.original_rows()
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0][1],"SUCCEEDED")
        recovered=await self.status()
        self.assertEqual(recovered["wave_state"],"RECEIPTS_RECORDED")
        self.assertFalse(recovered["busy"])
        self.assertEqual(recovered["users"][0]["state"],"RECEIPT_SCOPED")
        self.assertEqual(recovered["note"],
                         "REQUIRES_INDEPENDENT_PACKET_PROOF")
        # Local root-approved request ids are gone and source 6G is terminal.
        with self.assertRaises(M43ClientHold):
            await self.confirm()

    async def test_partial_original_6g_failure_survives_process_restart(self):
        await self.prepare()
        self.fail_after_apply=True
        result=await self.confirm()
        self.assertEqual(result["state"],"HOLD")
        self.assertEqual(self.original_rows()[0][1],"RUNNING")
        self.assertIn("journal:"+RECOVERY_PHASE,self.effects)
        self.assertIn("synthetic-host-freeze",self.effects)
        recovered=await self.status()
        self.assertTrue(recovered["busy"])
        self.assertEqual(recovered["wave_state"],"HOLD")
        self.assertTrue(recovered["unresolved"])
        # Simulate both Telegram and RootOperatorIPC memory lost at restart.
        self.ui=EphemeralApprovalStore()
        self.ipc=RootOperatorIPC(
            portal=self.portal,bot_uid=TEST_BOT_UID,
            geteuid=lambda:0,released=True,
        )
        self.assertEqual((await self.status())["wave_state"],"HOLD")
        with self.assertRaises(M43ClientHold):
            await self.prepare() # Root emits sanitized HOLD.
        self.assertEqual(len(self.original_rows()),1)
        self.assertEqual(self.effects.count("synthetic-host-apply"),1)

    async def test_crash_after_original_uid_receipt_before_checkpoint_terminal(self):
        await self.prepare()
        # Root dies after original 6G receipt is persisted but before
        # M4 checkpoint finish. Never infer SUCCEEDED from partial projection.
        def crash(*args):
            raise RuntimeError("SIMULATED_ROOT_CRASH_AFTER_6G_COMMIT")
        self.portal.checkpoint.finish=crash
        with self.assertRaises(M43ClientHold):
            await self.confirm()
        self.assertEqual(self.original_rows()[0][1],"SUCCEEDED")
        view=await self.status()
        self.assertEqual(view["wave_state"],"HOLD")
        self.assertTrue(view["unresolved"])
        self.ipc=RootOperatorIPC(
            portal=self.portal,bot_uid=TEST_BOT_UID,
            geteuid=lambda:0,released=True,
        )
        with self.assertRaises(M43ClientHold):
            await self.prepare()
        self.assertEqual(self.effects.count("synthetic-host-apply"),1)

    async def test_root_restart_after_prepare_loses_opaque_request(self):
        pending=await self.prepare()
        self.ipc=RootOperatorIPC(
            portal=self.portal,bot_uid=TEST_BOT_UID,
            geteuid=lambda:0,released=True,
        )
        with self.assertRaises(M43ClientHold):
            await self.confirm()
        self.assertEqual(self.original_rows(),[])
        view=await self.status()
        self.assertIn(view["wave_state"],("PREPARED","EXPIRED"))
        self.assertFalse(view["unresolved"])
        self.assertNotIn(pending.request_id,json.dumps(view))

    async def test_wrong_actor_chat_and_message_cannot_mutate(self):
        await self.prepare()
        with self.assertRaises(M43ClientHold):
            self.ui.consume(
                actor_id=ADMIN,chat_id=CHAT,message_id=999,
                edge_id="e9",now=self.now,
            )
        with self.assertRaises(M43ClientHold):
            self.ui.consume(
                actor_id=ADMIN+1,chat_id=CHAT,message_id=MESSAGE,
                edge_id="e9",now=self.now,
            )
        with self.assertRaises(M43ClientHold):
            await self.bot.request(
                "CONFIRM",actor_id=ADMIN,chat_id=CHAT+1,
                request_id="0"*32,
            )
        self.assertEqual(self.original_rows(),[])
        completed=await self.confirm()
        self.assertEqual(completed["state"],"COMPLETED")

    async def test_stale_f4_denies_prepare_before_original_6g(self):
        self.f4=False
        with self.assertRaises(M43ClientHold):
            await self.prepare()
        self.assertEqual(self.original_rows(),[])
        self.assertEqual(self.effects,[])

    async def test_snapshot_drift_after_prepare_denies_without_p3(self):
        await self.prepare()
        self.review_changes=True
        with self.assertRaises(M43ClientHold):
            await self.confirm()
        self.assertEqual(self.original_rows(),[])
        self.assertEqual(self.effects,[])

    async def test_cancel_consumes_approval_without_original_6g_write(self):
        prepared=await self.prepare()
        self.ui.consume(
            actor_id=ADMIN,chat_id=CHAT,message_id=MESSAGE,
            edge_id="e9",now=self.now,
        )
        reply=await self.bot.request(
            "CANCEL",actor_id=ADMIN,chat_id=CHAT,
            request_id=prepared.request_id,
        )
        self.assertEqual(reply,{"state":"CANCELLED"})
        with self.assertRaises(M43ClientHold):
            await self.confirm()
        self.assertEqual(self.original_rows(),[])

    async def test_root_ipc_peercred_rejects_wrong_bot_uid(self):
        self.ipc=RootOperatorIPC(
            portal=self.portal,bot_uid=os.getuid()+123,
            geteuid=lambda:0,released=True,
        )
        with self.assertRaises(M43ClientHold):
            await self.prepare()
        self.assertEqual(self.original_rows(),[])

    async def test_batch_requires_M7_release_even_if_telegram_client_is_modified(self):
        selection=select_migration("BATCH",("nvl0555","nvl0557"),"e9")
        with patch("edge_egress_k2_m43_client.M43_BATCH_EXECUTION_ENABLED",True):
            with self.assertRaises(M43ClientHold):
                await self.bot.request(
                    "PREPARE",actor_id=ADMIN,chat_id=CHAT,
                    selection=selection,
                )
        self.assertEqual(self.original_rows(),[])

    async def test_root_mode_off_makes_status_independent_of_write_release(self):
        with patch("edge_egress_k2_m4_ipc.M4_UNIX_IPC_ENABLED",False):
            status=await self.status()
            self.assertEqual(status["wave_state"],"NO_CHECKPOINT")
            with self.assertRaises(M43ClientHold):
                await self.prepare()
        self.assertEqual(self.original_rows(),[])


if __name__=="__main__":
    unittest.main()
