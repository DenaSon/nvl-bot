"""Cross-process Core WireGuard installer mutex shared by ALL Legacy Edge callers.

A single live file lock covers IP selection (_next_edge_wg_ip), remote setup
and the Core peer write. It is owned by the worker thread, not the asyncio
timeout wrapper, so a timed-out coroutine cannot release a running worker's
lease. The existing Manual/Cloudzy journals still record effect uncertainty.
"""
from __future__ import annotations

import functools
import os
import stat
import fcntl

LOCK_PATH = "/run/lock/nvl-edge-wg-provision.lock"


class LegacyWGLeaseHold(RuntimeError):
    pass


def exclusive_legacy_edge_install(fn=None, *, lock_path=LOCK_PATH):
    """Nonblocking OS-enforced lease around the shared sync installer.

    For tests only, inject an owner-controlled private lock_path. Never use
    a user-provided Telegram value as the path.
    """
    if fn is None:
        return lambda func: exclusive_legacy_edge_install(func, lock_path=lock_path)

    @functools.wraps(fn)
    def locked(*args, **kwargs):
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(lock_path, flags, 0o600)
        except OSError as exc:
            raise LegacyWGLeaseHold("CORE_WG_INSTALL_LOCK_UNAVAILABLE") from None
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or (stat.S_IMODE(info.st_mode) & 0o077)):
                raise LegacyWGLeaseHold("CORE_WG_INSTALL_LOCK_UNTRUSTED")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                # Preserve the sync installer's tuple contract, and avoid
                # blocking a daemon worker behind another uncertain install.
                return False, "CORE_WG_INSTALL_BUSY", None
            try:
                return fn(*args, **kwargs)
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
    return locked
