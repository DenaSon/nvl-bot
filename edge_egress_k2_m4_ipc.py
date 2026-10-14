"""M4 root Unix-socket IPC protocol (transport port only; NOT a daemon).

This module NEVER binds a socket, spawns a shell, starts a unit or enables
M3. A separately reviewed root daemon must own the AF_UNIX socket (0600/0660,
trusted group, peer UIDs) and call handle_accepted_socket for accepted peers.
The Telegram client must send only selected users + actor/chat, never P3
tickets, HMAC secrets, F4 booleans or privileged object factories.

PREPARE creates an ephemeral server-side request id from an independently
approved root plan, CONFIRM consumes it before executing existing 6G.
After root restart pending requests disappear; no automatically restored
approval or execution. Original DB checkpoint preserves consumed approvals.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import os
import re
import secrets
import socket
import struct
import time
from typing import Callable

from edge_egress_k2_migration_inventory import select_migration
from edge_egress_k2_m4_root_portal import PreparedWave, RootMigrationPortal
from edge_egress_k2_m4_telegram import select_input
from edge_egress_k2_m44_recovery import inspect_root_recovery

M4_UNIX_IPC_ENABLED = False
M4_BATCH_RELEASE_ENABLED = False
MAX_REQUEST_BYTES = 4096
MAX_RESPONSE_BYTES = 4096
_REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")


class M4IPCReject(ValueError):
    pass


def _unique_object(pairs):
    result={}
    for k,v in pairs:
        if k in result:
            raise M4IPCReject("DUPLICATE_JSON_FIELD")
        result[k]=v
    return result


def _decode_request(raw: bytes) -> dict:
    if (not isinstance(raw,bytes) or not raw or len(raw)>MAX_REQUEST_BYTES
        or b"\n" in raw or b"\r" in raw):
        raise M4IPCReject("INVALID_REQUEST_FRAMING")
    try:
        request=json.loads(raw.decode("utf-8"),object_pairs_hook=_unique_object)
    except (UnicodeDecodeError,ValueError) as exc:
        raise M4IPCReject("INVALID_REQUEST_JSON") from exc
    if not isinstance(request,dict):
        raise M4IPCReject("REQUEST_NOT_OBJECT")
    return request


def _field_keys(data: dict,expected: frozenset[str]):
    if data.keys()!=expected:
        raise M4IPCReject("REQUEST_FIELDS_UNEXPECTED")


def _actor(data: dict)->tuple[int,int]:
    actor,chat=data["actor_id"],data["chat_id"]
    if type(actor) is not int or actor<=0 or type(chat) is not int or chat==0:
        raise M4IPCReject("ACTOR_CHAT_INVALID")
    return actor,chat


@dataclass(frozen=True)
class PendingRequest:
    prepared: PreparedWave
    actor_id: int
    chat_id: int


class RootOperatorIPC:
    """Typed root-side dispatcher; no generic function/command API."""

    def __init__(self, *, portal: RootMigrationPortal,
                 bot_uid: int, geteuid: Callable[[],int] = os.geteuid,
                 released: bool = False):
        if (not isinstance(portal,RootMigrationPortal)
            or type(bot_uid) is not int or bot_uid<0
            or not callable(geteuid)):
            raise M4IPCReject("IPC_ROOT_FACTORY_INVALID")
        self.portal=portal
        self.bot_uid=bot_uid
        self.geteuid=geteuid
        self.released=released
        self._pending: dict[str,PendingRequest]={}

    def _gate(self,peer_uid:int, *, peer_only:bool=False,
              action:str|None=None) -> None:
        if (self.released is not True or self.geteuid()!=0
            or type(peer_uid) is not int or peer_uid!=self.bot_uid):
            raise M4IPCReject("IPC_UNTRUSTED_PEER_OR_RELEASE")
        if peer_only:
            return  # kernel SO_PEERCRED identity only, before reading frame.
        from edge_egress_k2_m44_recovery import M44_ROOT_STATUS_ENABLED
        if not (M44_ROOT_STATUS_ENABLED if action=="STATUS"
                else M4_UNIX_IPC_ENABLED):
            raise M4IPCReject("IPC_ACTION_RELEASE_DISABLED")

    async def dispatch(self,raw:bytes,*,peer_uid:int) -> bytes:
        self._gate(peer_uid, peer_only=True)
        request=_decode_request(raw)
        action=request.get("action")
        self._gate(peer_uid, action=action)
        if action=="STATUS":
            _field_keys(request,frozenset((
                "action","mode","usernames","edge_id","actor_id","chat_id",
            )))
            actor,chat=_actor(request)
            names=request["usernames"]
            if not isinstance(names,list) or any(
                type(name) is not str for name in names
            ):
                raise M4IPCReject("IPC_STATUS_USERS_INVALID")
            selection=select_input(request["mode"],",".join(names),
                                   request["edge_id"])
            from edge_egress_k2_m4_checkpoint import DurableWaveCheckpoint
            cp=self.portal.checkpoint
            if (not isinstance(cp,DurableWaveCheckpoint)
                or not callable(self.portal.admin_authorized)):
                raise M4IPCReject("IPC_ROOT_CHECKPOINT_MISSING")
            view=inspect_root_recovery(
                cp.db_conn,selection,actor_id=actor,chat_id=chat,
                admin_authorized=self.portal.admin_authorized,
                geteuid=self.geteuid,release_enabled=True,
            )
            result={
                "state":"STATUS","edge_id":view.edge_id,
                "wave_state":view.wave_state,
                "busy":view.original_6g_busy,
                "unresolved":view.unresolved,
                "users":[{"username":u.username,"state":u.state}
                         for u in view.users],
                "note":view.note,
            }
        elif action=="PREPARE":
            _field_keys(request,frozenset((
                "action","mode","usernames","edge_id","actor_id","chat_id",
            )))
            actor,chat=_actor(request)
            names=request["usernames"]
            if not isinstance(names,list) or any(
                not isinstance(n,str) for n in names):
                raise M4IPCReject("IPC_USERNAME_LIST_UNTRUSTED")
            # Reuse exactly the existing Telegram normalization, not a
            # second separate parser for the root service.
            selection=select_input(request["mode"],",".join(names),
                                   request["edge_id"])
            # M7 independent batch approval is not inherited from M4.
            if selection.mode != "SINGLE" and not M4_BATCH_RELEASE_ENABLED:
                raise M4IPCReject("IPC_BATCH_NOT_RELEASED")
            if len(self._pending)>=20:
                raise M4IPCReject("IPC_PENDING_QUEUE_FULL")
            prepared=self.portal.prepare(
                selection,actor_id=actor,chat_id=chat)
            request_id=secrets.token_hex(16)
            while request_id in self._pending:
                request_id=secrets.token_hex(16)
            self._pending[request_id]=PendingRequest(prepared,actor,chat)
            result={
                "state":"PREPARED",
                "request_id":request_id,
                "edge_id":selection.target_edge_id,
                "user_count":len(selection.usernames),
                "expires_at":prepared.approval.expires_at,
            }
        elif action=="CONFIRM":
            _field_keys(request,frozenset((
                "action","request_id","actor_id","chat_id",
            )))
            actor,chat=_actor(request)
            request_id=request["request_id"]
            if not isinstance(request_id,str) or not _REQUEST_ID.fullmatch(request_id):
                raise M4IPCReject("IPC_REQUEST_ID_INVALID")
            pending=self._pending.get(request_id)
            if (pending is None or pending.actor_id!=actor
                or pending.chat_id!=chat):
                raise M4IPCReject("IPC_REQUEST_MISSING_OR_WRONG_ACTOR")
            # A request is irreversibly one-shot even on exception, losing
            # the socket, cancelling the coroutine or root crash.
            del self._pending[request_id]
            report=await self.portal.execute(
                pending.prepared,actor_id=actor,chat_id=chat)
            result={
                "state":"COMPLETED" if report.all_verified else "HOLD",
                "completed":report.completed,
                "halted":report.halted,
                "accounts":[
                    {"username":p.username,"state":p.status}
                    for p in report.progress
                ],
            }
        elif action=="CANCEL":
            _field_keys(request,frozenset((
                "action","request_id","actor_id","chat_id",
            )))
            actor,chat=_actor(request)
            request_id=request["request_id"]
            if not isinstance(request_id,str) or not _REQUEST_ID.fullmatch(request_id):
                raise M4IPCReject("IPC_REQUEST_ID_INVALID")
            p=self._pending.get(request_id)
            if p is None or (p.actor_id,p.chat_id)!=(actor,chat):
                raise M4IPCReject("IPC_REQUEST_MISSING_OR_WRONG_ACTOR")
            del self._pending[request_id]
            result={"state":"CANCELLED"}  # original PREPARED DB entry remains
        else:
            raise M4IPCReject("IPC_ACTION_NOT_WHITELISTED")
        wire=json.dumps(result,ensure_ascii=True,separators=(",",":")).encode()
        if len(wire)>MAX_RESPONSE_BYTES:
            raise M4IPCReject("IPC_RESPONSE_TOO_LARGE")
        return wire


def _read_one_frame(conn: socket.socket) -> bytes:
    """One newline-terminated request, bounded in size AND total wall time.

    SOCK_STREAM has no record boundary. A single recv can read half a JSON
    request, so never treat recv() as an authenticated complete message.
    """
    deadline = time.monotonic() + 5.0
    frame = bytearray()
    while len(frame) <= MAX_REQUEST_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise M4IPCReject("IPC_FRAME_DEADLINE_EXPIRED")
        conn.settimeout(remaining)
        try:
            chunk = conn.recv(min(1024, MAX_REQUEST_BYTES + 2 - len(frame)))
        except socket.timeout as exc:
            raise M4IPCReject("IPC_FRAME_DEADLINE_EXPIRED") from exc
        if not chunk:
            raise M4IPCReject("IPC_INCOMPLETE_FRAME")
        frame.extend(chunk)
        if b"\n" in chunk:
            if frame.count(b"\n") != 1 or not frame.endswith(b"\n"):
                raise M4IPCReject("IPC_MULTIPLE_OR_TRAILING_FRAMES")
            payload = bytes(frame[:-1])
            if not payload or len(payload) > MAX_REQUEST_BYTES:
                raise M4IPCReject("IPC_FRAME_LENGTH_INVALID")
            return payload
    raise M4IPCReject("IPC_FRAME_LENGTH_INVALID")


async def handle_accepted_socket(transport: RootOperatorIPC,
                                 conn: socket.socket) -> None:
    """For already accepted AF_UNIX stream, trusted kernel SO_PEERCRED.

    No user-supplied UID is accepted as peer identity; bad peer has no
    access to the privileged dispatcher. This handles a single request.
    Caller owns socket lifecycle and the reviewed service unit.
    """
    if not isinstance(transport,RootOperatorIPC) or (
        not isinstance(conn,socket.socket) or conn.family!=socket.AF_UNIX
    ):
        raise M4IPCReject("IPC_SOCKET_UNTRUSTED")
    try:
        peer=conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)
        if len(peer)!=12:
            raise M4IPCReject("IPC_PEER_CREDENTIALS_ABSENT")
        _pid,uid,_gid=struct.unpack("3i",peer)
        transport._gate(uid,peer_only=True)   # kernel peer before any payload
        raw=await asyncio.to_thread(_read_one_frame,conn)
        response=await transport.dispatch(raw,peer_uid=uid)
        await asyncio.to_thread(conn.sendall,response+b"\n")
    except (OSError,ValueError,TypeError) as exc:
        # Never leak SQL/secret/nonce or raw server errors across the socket.
        try:
            conn.sendall(b'{"state":"HOLD"}\n')
        except OSError:
            pass
        raise M4IPCReject("IPC_REQUEST_HELD") from exc
