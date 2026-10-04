from __future__ import annotations

import argparse
import getpass
import json
import sys

from .models import ServerCredentials
from .phase2 import run_phase2
from .phase2_models import Phase2Error, Phase2Policy
from .preflight import run_preflight


def _password(label: str) -> str:
    return getpass.getpass(f"{label} SSH password: ")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NVL Change Server Phase 2 backup + transfer"
    )
    parser.add_argument("--source", required=True, help="source server IP/hostname")
    parser.add_argument(
        "--destination",
        required=True,
        help="destination server IP/hostname",
    )
    parser.add_argument("--source-port", type=int, default=22)
    parser.add_argument("--destination-port", type=int, default=22)
    parser.add_argument("--source-user", default="root")
    parser.add_argument("--destination-user", default="root")
    parser.add_argument("--job-id", default=None)
    parser.add_argument(
        "--local-root",
        default="/var/lib/nvl/migrations",
        help="NVL-local staging root",
    )
    parser.add_argument(
        "--allow-existing-destination-staging",
        action="store_true",
        help=(
            "allow transfer-only staging when the only preflight blockers are "
            "DEST_CLEAN/DEST_PORTS; runtime paths remain untouched"
        ),
    )
    args = parser.parse_args()

    source = ServerCredentials(
        host=args.source,
        port=args.source_port,
        username=args.source_user,
        password=_password("Source"),
    )
    destination = ServerCredentials(
        host=args.destination,
        port=args.destination_port,
        username=args.destination_user,
        password=_password("Destination"),
    )

    preflight = run_preflight(source, destination)
    if not preflight.ready and not args.allow_existing_destination_staging:
        print(
            json.dumps(
                {
                    "phase": 2,
                    "status": "blocked",
                    "preflight": preflight.to_dict(),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 2

    policy = Phase2Policy(
        local_root=args.local_root,
        require_preflight_ready=not args.allow_existing_destination_staging,
    )

    try:
        result = run_phase2(
            preflight,
            source,
            destination,
            job_id=args.job_id,
            policy=policy,
        )
    except Phase2Error as exc:
        print(
            json.dumps(
                {
                    "phase": 2,
                    "status": "failed",
                    "error": str(exc),
                    "preflight_ready": preflight.ready,
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
                "phase": 2,
                "status": "completed",
                "preflight_ready": preflight.ready,
                "staging_override": bool(
                    args.allow_existing_destination_staging
                    and not preflight.ready
                ),
                "result": result.to_dict(),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
