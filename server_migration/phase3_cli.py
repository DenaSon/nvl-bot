from __future__ import annotations

import argparse
import getpass
import json
import sys

from .models import ServerCredentials
from .phase3 import run_phase3
from .phase3_models import (
    PHASE3_MODE_INSPECT,
    PHASE3_MODE_RESTORE,
    Phase3Error,
    Phase3Policy,
)


def _password() -> str:
    return getpass.getpass("Destination SSH password: ")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NVL Change Server Phase 3 restore + dry-run validation"
    )
    parser.add_argument(
        "--destination",
        required=True,
        help="destination server IP/hostname",
    )
    parser.add_argument("--destination-port", type=int, default=22)
    parser.add_argument("--destination-user", default="root")
    parser.add_argument("--job-id", required=True)

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--inspect-only",
        action="store_true",
        help=(
            "verify/extract only under the migration job directory; "
            "never touch runtime paths"
        ),
    )
    mode.add_argument(
        "--restore",
        action="store_true",
        help="restore into runtime paths after all safety checks pass",
    )

    parser.add_argument(
        "--no-install-docker",
        action="store_true",
        help="fail instead of installing Docker/Compose when missing",
    )
    parser.add_argument(
        "--start-runtime-dry-run",
        action="store_true",
        help=(
            "after a successful restore, start Marzban and run local "
            "listener/API health checks; never changes DNS"
        ),
    )
    parser.add_argument(
        "--remote-root",
        default="/root/nvl-migrations",
    )
    args = parser.parse_args()

    selected_mode = PHASE3_MODE_RESTORE if args.restore else PHASE3_MODE_INSPECT
    if args.start_runtime_dry_run and selected_mode != PHASE3_MODE_RESTORE:
        parser.error("--start-runtime-dry-run requires --restore")

    credentials = ServerCredentials(
        host=args.destination,
        port=args.destination_port,
        username=args.destination_user,
        password=_password(),
    )
    policy = Phase3Policy(
        remote_root=args.remote_root,
        mode=selected_mode,
        install_docker_if_missing=not args.no_install_docker,
        start_runtime=bool(args.start_runtime_dry_run),
    )

    try:
        result = run_phase3(
            credentials,
            job_id=args.job_id,
            policy=policy,
        )
    except Phase3Error as exc:
        print(
            json.dumps(
                {
                    "phase": 3,
                    "status": "failed",
                    "mode": selected_mode,
                    "job_id": args.job_id,
                    "error": str(exc),
                },
                ensure_ascii=False,
                indent=2,
            ),
            file=sys.stderr,
        )
        return 3

    print(
        json.dumps(
            {
                "phase": 3,
                "status": "completed",
                "result": result.to_dict(),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
