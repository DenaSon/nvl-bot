from __future__ import annotations

import argparse
import getpass
import json
import sys

from .models import ServerCredentials
from .phase4 import run_phase4
from .phase4_models import (
    PHASE4_MODE_FINALIZE,
    PHASE4_MODE_PLAN,
    Phase4Error,
    Phase4Policy,
)


def _password(label: str) -> str:
    return getpass.getpass(f"{label} SSH password: ")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NVL Change Server Phase 4 final sync + IP rewrite"
    )
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--source-port", type=int, default=22)
    parser.add_argument("--destination-port", type=int, default=22)
    parser.add_argument("--source-user", default="root")
    parser.add_argument("--destination-user", default="root")
    parser.add_argument(
        "--remote-root",
        default="/root/nvl-migrations",
    )
    parser.add_argument(
        "--local-root",
        default="/var/lib/nvl/migrations",
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--plan-only",
        action="store_true",
        help="non-disruptive readiness inspection; this is the default",
    )
    mode.add_argument(
        "--finalize",
        action="store_true",
        help="perform downtime final sync; requires --confirm FINAL-SYNC",
    )

    parser.add_argument(
        "--confirm",
        default="",
        help="required exact confirmation phrase for --finalize",
    )
    parser.add_argument(
        "--allow-residual-old-ip",
        action="store_true",
        help=(
            "do not fail if the old IP is still referenced after the targeted "
            "hosts.address rewrite; intended only for controlled debugging"
        ),
    )
    parser.add_argument(
        "--no-source-recovery",
        action="store_true",
        help="do not restart an initially-running source when finalization fails",
    )
    parser.add_argument(
        "--no-start-destination",
        action="store_true",
        help="leave destination stopped after final DB sync",
    )
    args = parser.parse_args()

    selected_mode = PHASE4_MODE_FINALIZE if args.finalize else PHASE4_MODE_PLAN

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

    policy = Phase4Policy(
        remote_root=args.remote_root,
        local_root=args.local_root,
        mode=selected_mode,
        fail_on_residual_old_ip=not args.allow_residual_old_ip,
        recover_source_on_failure=not args.no_source_recovery,
        start_destination=not args.no_start_destination,
    )

    try:
        result = run_phase4(
            source,
            destination,
            job_id=args.job_id,
            confirmation=args.confirm,
            policy=policy,
        )
    except Phase4Error as exc:
        print(
            json.dumps(
                {
                    "phase": 4,
                    "status": "failed",
                    "mode": selected_mode,
                    "job_id": args.job_id,
                    "error": str(exc),
                    "dns_cutover_performed": False,
                },
                ensure_ascii=False,
                indent=2,
            ),
            file=sys.stderr,
        )
        return 4

    payload = result.to_dict()
    print(
        json.dumps(
            {
                "phase": 4,
                "status": "completed",
                "mode": selected_mode,
                "dns_cutover_performed": False,
                "result": payload,
            },
            ensure_ascii=False,
            indent=2,
        )
    )

    if selected_mode == PHASE4_MODE_PLAN and not payload["finalization_ready"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
