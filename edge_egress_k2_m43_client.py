"""M4.3 non-root Telegram IPC client: exact one-shot framed requests only.

No generic command API, root credentials, ticket, signing key, dynamic socket
path, or production release. Bot never imports a root executor.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct

M43_TELEGRAM_EXECUTION_ENABLED = False
M43_BATCH_EXECUTION_ENABLED = False
ROOT_SOCKET = Path("/run/nvl-k2-m4/operator.sock")
MAX_BYTES = 4096
_REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")


class M43ClientHold(ValueError):
    pass


def _pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise M43ClientHold("M43_DUPLICATE_RESPONSE_FIELD")
        d[k] = v
    return d


def _exchange(payload: bytes, *, path: Path = ROOT_SOCKET) -> bytes:
    """Blocking bounded AF_UNIX exchange: only invoked inside asyncio.to_thread."""
    if path != ROOT_SOCKET or len(payload) > MAX_BYTES or not payload:
        raise M43ClientHold("M43_UNTRUSTED_SOCKET_OR_FRAME")
    try:
        info = path.lstat()
        parent = path.parent.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o660
            or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
            or stat.S_IMODE(parent.st_mode) != 0o750):
            raise M43ClientHold("M43_ROOT_SOCKET_NOT_ATTESTED")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(5)
            conn.connect(str(path))
            peer = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            if len(peer) != 12 or struct.unpack("3i", peer)[1] != 0:
                raise M43ClientHold("M43_REMOTE_ROOT_IDENTITY_FAILED")
            conn.sendall(payload + b"\n")
            out = bytearray()
            while len(out) <= MAX_BYTES:
                chunk = conn.recv(min(1024, MAX_BYTES + 2 - len(out)))
                if not chunk:
                    raise M43ClientHold("M43_INCOMPLETE_RESPONSE")
                out.extend(chunk)
                if b"\n" in chunk:
                    if out.count(b"\n") != 1 or not out.endswith(b"\n"):
                        raise M43ClientHold("M43_MULTI_RESPONSE")
                    if not 0 < len(out) - 1 <= MAX_BYTES:
                        raise M43ClientHold("M43_OVERSIZED_RESPONSE")
                    return bytes(out[:-1])
            raise M43ClientHold("M43_OVERSIZED_RESPONSE")
    except (OSError, TimeoutError) as exc:
        raise M43ClientHold("M43_ROOT_SOCKET_UNAVAILABLE") from exc


def _response(raw: bytes, action: str) -> dict:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_BYTES:
        raise M43ClientHold("M43_RESPONSE_SIZE_INVALID")
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise M43ClientHold("M43_RESPONSE_INVALID") from exc
    if not isinstance(result, dict) or (\n        result.get("state") == "HOLD" and action != "CONFIRM"\n    ):
        raise M43ClientHold("M43_ROOT_HOLD_OR_RESPONSE_INVALID")
    if action == "PREPARE":
        if (set(result) != {"state", "request_id", "edge_id",
                            "user_count", "expires_at"}
            or result["state"] != "PREPARED"
            or type(result["request_id"]) is not str
            or not _REQUEST_ID.fullmatch(result["request_id"])
            or type(result["user_count"]) is not int
            or not 1 <= result["user_count"] <= 10
            or type(result["expires_at"]) is not int):
            raise M43ClientHold("M43_PREPARE_RESPONSE_UNTRUSTED")
    elif action == "CANCEL":
        if result != {"state": "CANCELLED"}:
            raise M43ClientHold("M43_CANCEL_UNVERIFIED")
    elif action == "CONFIRM":
        if (set(result) != {"state", "completed", "halted", "accounts"}
            or result["state"] not in ("COMPLETED", "HOLD")
            or type(result["completed"]) is not int
            or not 0 <= result["completed"] <= 10
            or type(result["halted"]) is not bool
            or not isinstance(result["accounts"], list)
            or len(result["accounts"]) > 10
            or result["completed"] != sum(
                isinstance(x, dict) and x.get("state") == "VERIFIED"
                for x in result["accounts"])
            or (result["state"] == "COMPLETED"
                and (result["halted"]
                     or result["completed"] != len(result["accounts"])))
            or any(not isinstance(x, dict) or set(x) != {"username","state"}
                   or type(x["username"]) is not str
                   or type(x["state"]) is not str
                   or x["state"] not in ("VERIFIED","HOLD","DEFERRED")
                   for x in result["accounts"])):
            raise M43ClientHold("M43_EXECUTION_RESPONSE_UNTRUSTED")
    else:
        raise M43ClientHold("M43_UNKNOWN_ACTION")
    return result


class NonRootOperatorClient:
    def __init__(self, *, geteuid=os.geteuid, released: bool = False,
                 exchange=_exchange):
        self.geteuid, self.released, self.exchange = geteuid, released, exchange

    async def request(self, action: str, *, actor_id: int, chat_id: int,
                      selection=None, request_id=None) -> dict:
        # Runtime gate before constructing JSON, opening a socket or side effect.
        if (not M43_TELEGRAM_EXECUTION_ENABLED or self.released is not True
            or not callable(self.geteuid) or type(self.geteuid()) is not int
            or self.geteuid() <= 0
            or not callable(self.exchange)
            or type(actor_id) is not int or actor_id <= 0
            or type(chat_id) is not int or chat_id == 0):
            raise M43ClientHold("M43_NONROOT_RELEASE_REQUIRED")
        if action == "PREPARE":
            from edge_egress_k2_migration_inventory import MigrationSelection,select_migration
            if not isinstance(selection, MigrationSelection):
                raise M43ClientHold("M43_SELECTION_REQUIRED")
            if select_migration(selection.mode,selection.usernames,
                                selection.target_edge_id) != selection:
                raise M43ClientHold("M43_SELECTION_CHANGED")
            if (selection.mode != "SINGLE"
                and not M43_BATCH_EXECUTION_ENABLED):
                raise M43ClientHold("M43_BATCH_NOT_RELEASED")
            data = {"action":action,"mode":selection.mode,
                    "usernames":list(selection.usernames),
                    "edge_id":selection.target_edge_id,
                    "actor_id":actor_id,"chat_id":chat_id}
        elif action in ("CONFIRM","CANCEL"):
            if (type(request_id) is not str
                or not _REQUEST_ID.fullmatch(request_id)):
                raise M43ClientHold("M43_REQUEST_ID_NOT_PINNED")
            data = {"action":action,"request_id":request_id,
                    "actor_id":actor_id,"chat_id":chat_id}
        else:
            raise M43ClientHold("M43_ACTION_DENIED")
        frame = json.dumps(data,separators=(",",":"),ensure_ascii=True).encode()
        if len(frame) > MAX_BYTES:
            raise M43ClientHold("M43_REQUEST_TOO_LONG")
        raw = await asyncio.to_thread(self.exchange,frame)
        result = _response(raw,action)
        if action == "PREPARE" and (
            result["edge_id"] != selection.target_edge_id
            or result["user_count"] != len(selection.usernames)
        ):
            raise M43ClientHold("M43_PREPARE_SCOPE_DRIFT")
        return result
