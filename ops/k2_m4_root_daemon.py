"""K2 M4 root daemon entrypoint: sealed explicit assembly, default-OFF.

There is intentionally no runtime environment toggle and NO direct import
of the historical root bot. A reviewed in-process integrator must supply
the exact RootAssembly with genuinely physical ports and separate UID
before the worker can serve one AF_UNIX client. The installed entrypoint
remains fail-closed until that host composition is independently accepted.
"""
from __future__ import annotations

from edge_egress_k2_a_root_assembly import RootAssembly
from edge_egress_k2_m4_root_worker import (
    M4_ROOT_WORKER_ENABLED, RootWorkerHold, verify_reviewed_release,
)

M4A_ROOT_DAEMON_RELEASED = False


async def serve_reviewed_assembly(
    assembly: RootAssembly, *, max_connections: int | None = None,
) -> int:
    """Start ONLY a reviewed worker. Never synthesize root host factories.

    One worker owns socket lifetime. Its own open_listener rechecks source
    pins, root secret, bot UID and runtime group before any listen().
    """
    if (not M4A_ROOT_DAEMON_RELEASED or not M4_ROOT_WORKER_ENABLED
        or not isinstance(assembly, RootAssembly)
        or type(assembly.bot_uid) is not int or assembly.bot_uid <= 0
        or assembly.worker.paths.bot_uid != assembly.bot_uid
        or assembly.worker.transport.bot_uid != assembly.bot_uid
        or assembly.worker.release_enabled is not True
        or assembly.worker.transport.released is not True
        or assembly.worker.geteuid() != 0
        or not isinstance(assembly.release_sha, str)
        or len(assembly.release_sha) != 40):
        raise RootWorkerHold("M4A_ROOT_DAEMON_NOT_ACCEPTED")
    fresh=verify_reviewed_release(assembly.worker.paths)
    if fresh != assembly.release_sha:
        raise RootWorkerHold("M4A_ROOT_DAEMON_SOURCE_CHANGED")
    return await assembly.worker.serve(max_connections=max_connections)


def main() -> int:
    # Deliberately non-operational even when the new function exists.
    # No unreviewed HostReviewedPorts or bot UID factory is created here;
    # installing a service unit must not auto-activate customer migrations.
    return 78


if __name__ == "__main__":
    raise SystemExit(main())
