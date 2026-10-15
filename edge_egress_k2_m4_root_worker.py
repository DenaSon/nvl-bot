"""K2 M4.1: sealed, default-OFF root-side Unix operator worker.

This is the transport host, NOT an enabled production executor. The only
privileged operations come from an explicitly supplied RootOperatorIPC using
the original M3/P3/6G ports. M4.2 must supply real independently reviewed
factories, source/session/F4 evidence, a non-root bot UID and authorization.
No arbitrary commands, shell, dynamic factory imports or route mutations.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import socket
import stat
from typing import Callable

from edge_egress_k2_m4_ipc import RootOperatorIPC, handle_accepted_socket, M4IPCReject

M4_ROOT_WORKER_ENABLED = False
SOCKET_NAME = "operator.sock"
MAX_SECRET_BYTES = 4096
MAX_MANIFEST_BYTES = 8192
MAX_SOURCE_BYTES = 2_000_000
PINNED_SOURCE_FILES = frozenset((
    "edge_egress_k2_a_6g_shared.py",
    "edge_egress_k2_a3_host_plans.py",
    "edge_egress_k2_a_host_factory.py",
    "edge_egress_k2_a_root_assembly.py",
    "edge_egress_k2_m4_root_worker.py",
    "edge_egress_k2_m4_ipc.py",
    "edge_egress_k2_m44_recovery.py",
    "edge_egress_k2_m4_status.py",
    "edge_egress_k2_m43_client.py",
    "edge_egress_k2_m43_workflow.py",
    "edge_egress_k2_m4_telegram.py",
    "bot_final_v49-2.py",
    "edge_egress_k2_m42_evidence.py",
    "edge_egress_k2_m42_bindings.py",
    "edge_egress_k2_m4_bootstrap.py",
    "edge_egress_k2_m2_ingress_journal.py",
    "edge_egress_k2_m2_ingress_observer.py",
    "edge_egress_k2_m3_ingress_port.py",
    "edge_egress_p3_uid.py",
    "edge_egress_k2_m4_root_portal.py",
    "edge_egress_k2_m4_checkpoint.py",
    "edge_egress_k2_m3_waves.py",
    "edge_egress_k2_m3_journal.py",
    "edge_egress_k2_migration_inventory.py",
    "edge_egress_p3_executor.py",
    "ops/k2_m4_root_daemon.py",
    "ops/k2_m2_first_uid.py",
    "ops/k2_m2_guard_append.py",
    "ops/k2_m2_guard_recovery.py",
    "ops/k2_p3_uid_worker.py",
))
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_COMMIT = re.compile(r"[a-f0-9]{40}\Z")


class RootWorkerHold(ValueError):
    """Fail closed without including file contents or secrets in messages."""


@dataclass(frozen=True)
class WorkerPaths:
    source_root: Path
    manifest_file: Path
    secret_file: Path
    runtime_dir: Path
    bot_uid: int
    ipc_gid: int

    def validate(self) -> None:
        if (not all(isinstance(p, Path) and p.is_absolute() for p in (
            self.source_root, self.manifest_file, self.secret_file,
            self.runtime_dir))
            or self.runtime_dir != Path("/run/nvl-k2-m4")
            or self.manifest_file != Path("/etc/nvl-egress/k2-m4/release.json")
            or self.secret_file != Path("/etc/nvl-egress/k2-m4/root-hmac.key")
            or type(self.bot_uid) is not int or self.bot_uid <= 0
            or type(self.ipc_gid) is not int or self.ipc_gid <= 0):
            raise RootWorkerHold("M4_WORKER_PATH_OR_NONROOT_PEER_UNTRUSTED")


def _read_checked(path: Path, *, maximum: int, owner_uid: int = 0,
                  strict: bool = False) -> bytes:
    """Open no-follow and check *the opened inode*; never follow symlinks."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            mode = stat.S_IMODE(info.st_mode)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
                or info.st_nlink != 1 or mode & 0o022
                or (strict and (mode & 0o077)) or info.st_size > maximum):
                raise RootWorkerHold("M4_UNTRUSTED_ROOT_FILE")
            data = os.read(fd, maximum + 1)
            if not data or len(data) > maximum:
                raise RootWorkerHold("M4_ROOT_FILE_EMPTY_OR_OVERSIZED")
            return data
        finally:
            os.close(fd)
    except (OSError, ValueError) as exc:
        raise RootWorkerHold("M4_ROOT_FILE_UNAVAILABLE") from exc


def _verify_root_directory(path: Path, *, group: int | None,
                           owner_uid: int = 0, private: bool = False) -> None:
    try:
        s = path.lstat()
    except OSError as exc:
        raise RootWorkerHold("M4_ROOT_DIRECTORY_UNAVAILABLE") from exc
    if (not stat.S_ISDIR(s.st_mode) or s.st_uid != owner_uid
        or (group is not None and s.st_gid != group)
        or stat.S_IMODE(s.st_mode) & 0o022
        or (private and stat.S_IMODE(s.st_mode) & 0o007)):
        raise RootWorkerHold("M4_ROOT_DIRECTORY_NOT_PINNED")


def verify_reviewed_release(paths: WorkerPaths, *,
                            owner_uid: int = 0) -> str:
    """Root-owned 0600 manifest with exact critical SHA256 set; no partial pins."""
    _verify_root_directory(paths.source_root, group=None, owner_uid=owner_uid)
    _verify_root_directory(paths.manifest_file.parent, group=None, owner_uid=owner_uid, private=True)
    raw = _read_checked(paths.manifest_file, maximum=MAX_MANIFEST_BYTES,
                        owner_uid=owner_uid, strict=True)
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise RootWorkerHold("M4_RELEASE_MANIFEST_MALFORMED") from exc
    if (not isinstance(manifest, dict)
        or set(manifest) != {"git_sha", "files"}
        or not isinstance(manifest["git_sha"], str)
        or not _COMMIT.fullmatch(manifest["git_sha"])
        or not isinstance(manifest["files"], dict)
        or set(manifest["files"]) != PINNED_SOURCE_FILES):
        raise RootWorkerHold("M4_RELEASE_MANIFEST_SCOPE_INVALID")
    for name in sorted(PINNED_SOURCE_FILES):
        expected = manifest["files"][name]
        if not isinstance(expected, str) or not _SHA256.fullmatch(expected):
            raise RootWorkerHold("M4_RELEASE_HASH_INVALID")
        path = paths.source_root / name
        if name.startswith("ops/"):
            _verify_root_directory(path.parent, group=None, owner_uid=owner_uid)
        actual = hashlib.sha256(_read_checked(
            path, maximum=MAX_SOURCE_BYTES, owner_uid=owner_uid,
        )).hexdigest()
        if not hmac.compare_digest(expected, actual):
            raise RootWorkerHold("M4_RELEASE_HASH_MISMATCH")
    return manifest["git_sha"]


def load_root_secret(paths: WorkerPaths, *, owner_uid: int = 0) -> bytes:
    _verify_root_directory(paths.secret_file.parent, group=None, owner_uid=owner_uid, private=True)
    secret = _read_checked(paths.secret_file, maximum=MAX_SECRET_BYTES,
                           owner_uid=owner_uid, strict=True)
    if len(secret) < 32:
        raise RootWorkerHold("M4_ROOT_SECRET_TOO_SHORT")
    return secret


def _check_socket_directory(paths: WorkerPaths, *, owner_uid: int = 0) -> None:
    _verify_root_directory(paths.runtime_dir, group=paths.ipc_gid, owner_uid=owner_uid)
    if stat.S_IMODE(paths.runtime_dir.stat().st_mode) != 0o750:
        raise RootWorkerHold("M4_SOCKET_PARENT_MODE_UNTRUSTED")


def _bind_socket(path: Path, *, gid: int) -> socket.socket:
    """Requires an already checked private parent. Never delete an old socket."""
    if path.name != SOCKET_NAME or path.exists() or path.is_symlink():
        raise RootWorkerHold("M4_SOCKET_PATH_OCCUPIED")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_mask = os.umask(0o177)
    try:
        sock.bind(str(path))
    except OSError as exc:
        sock.close()
        raise RootWorkerHold("M4_SOCKET_BIND_FAILED") from exc
    finally:
        os.umask(old_mask)
    try:
        os.chown(path, 0, gid)
        os.chmod(path, 0o660)
        sock.listen(4)
        sock.settimeout(2)
        return sock
    except OSError as exc:
        sock.close()
        path.unlink(missing_ok=True)
        raise RootWorkerHold("M4_SOCKET_PERMISSIONS_FAILED") from exc


class RootWorkerService:
    """Single-flight socket host. Original 6G and durable checkpoint own progress."""

    def __init__(self, *, paths: WorkerPaths, transport: RootOperatorIPC,
                 release_enabled: bool = False,
                 geteuid: Callable[[], int] = os.geteuid):
        self.paths = paths
        self.transport = transport
        self.release_enabled = release_enabled
        self.geteuid = geteuid

    def open_listener(self) -> socket.socket:
        if (not M4_ROOT_WORKER_ENABLED or self.release_enabled is not True
            or self.geteuid() != 0 or not isinstance(self.transport, RootOperatorIPC)
            or self.transport.bot_uid != self.paths.bot_uid
            or self.transport.released is not True
            or self.transport.geteuid() != 0):
            raise RootWorkerHold("M4_ROOT_WORKER_RELEASE_DISABLED")
        self.paths.validate()
        verify_reviewed_release(self.paths)
        secret = load_root_secret(self.paths)
        # Portal must derive its signing key from the same reviewed root-only file.
        if not isinstance(self.transport.portal.secret, bytes) or not hmac.compare_digest(
            secret, self.transport.portal.secret,
        ):
            raise RootWorkerHold("M4_ROOT_SECRET_NOT_BOUND_TO_PORTAL")
        _check_socket_directory(self.paths)
        return _bind_socket(self.paths.runtime_dir / SOCKET_NAME, gid=self.paths.ipc_gid)

    async def serve(self, *, max_connections: int | None = None) -> int:
        if max_connections is not None and (
            type(max_connections) is not int or max_connections < 1
        ):
            raise RootWorkerHold("M4_REQUEST_BOUND_INVALID")
        listener = self.open_listener()
        served = 0
        socket_path = self.paths.runtime_dir / SOCKET_NAME
        inode = socket_path.lstat().st_ino
        try:
            while max_connections is None or served < max_connections:
                try:
                    conn, _ = await asyncio.to_thread(listener.accept)
                except socket.timeout:
                    continue
                except OSError as exc:
                    raise RootWorkerHold("M4_SOCKET_ACCEPT_FAILED") from exc
                with conn:
                    try:
                        await handle_accepted_socket(self.transport, conn)
                    except (M4IPCReject, OSError, ValueError):
                        # Protocol returns sanitized HOLD; no raw root data.
                        pass
                served += 1
            return served
        finally:
            listener.close()
            try:
                if socket_path.lstat().st_ino == inode:
                    socket_path.unlink()
            except FileNotFoundError:
                pass
