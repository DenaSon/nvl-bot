"""Inert entry point for a future reviewed M4.2 root-service integration.

Intentionally no dynamic provider loading, mock F4, or implicit privileged
executor. The service example cannot start a live worker in M4.1.
"""
from edge_egress_k2_m4_root_worker import M4_ROOT_WORKER_ENABLED


def main() -> int:
    # Do not change this into an environment-variable / --enable escape hatch.
    # M4.2 must bind audited fixed factories and physical witnesses in source.
    if not M4_ROOT_WORKER_ENABLED:
        return 78
    return 78  # no trusted live providers or bot UID cutover yet


if __name__ == "__main__":
    raise SystemExit(main())
