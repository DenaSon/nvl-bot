from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from .models import ServerCredentials
from .phase5 import run_phase5
from .phase5_models import (
    PHASE5_MODE_CUTOVER,
    PHASE5_MODE_PLAN,
    Phase5Error,
    Phase5Policy,
)
from .ssh import SSHConnectionError


def _secret(label: str) -> str:
    return getpass.getpass(f"{label}: ")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NVL Change Server Phase 5 Cloudflare cutover + rollback"
    )
    parser.add_argument("--source", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--zone", required=True)
    parser.add_argument("--source-port", type=int, default=22)
    parser.add_argument("--destination-port", type=int, default=22)
    parser.add_argument("--source-user", default="root")
    parser.add_argument("--destination-user", default="root")
    parser.add_argument(
        "--remote-root",
        default="/root/nvl-migrations",
    )
    parser.add_argument(
        "--cloudflare-token-env",
        default="",
        help=(
            "optional environment variable containing the scoped Cloudflare API "
            "token; if omitted the token is requested with a hidden prompt"
        ),
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--plan-only",
        action="store_true",
        help="read-only cutover readiness inspection; default",
    )
    mode.add_argument(
        "--cutover",
        action="store_true",
        help="update the Cloudflare A record; requires --confirm CUTOVER",
    )
    parser.add_argument("--confirm", default="")
    parser.add_argument(
        "--allow-unproxied",
        action="store_true",
        help="allow a non-proxied Cloudflare A record",
    )
    parser.add_argument(
        "--no-auto-rollback",
        action="store_true",
        help="do not automatically restore Cloudflare/source on post-cutover failure",
    )
    args = parser.parse_args()

    selected_mode = PHASE5_MODE_CUTOVER if args.cutover else PHASE5_MODE_PLAN

    source = ServerCredentials(
        host=args.source,
        port=args.source_port,
        username=args.source_user,
        password=_secret("Source SSH password"),
    )
    destination = ServerCredentials(
        host=args.destination,
        port=args.destination_port,
        username=args.destination_user,
        password=_secret("Destination SSH password"),
    )

    token = ""
    if args.cloudflare_token_env:
        token = str(os.environ.get(args.cloudflare_token_env) or "").strip()
        if not token:
            print(
                json.dumps(
                    {
                        "phase": 5,
                        "status": "failed",
                        "mode": selected_mode,
                        "job_id": args.job_id,
                        "error": (
                            f"environment variable {args.cloudflare_token_env!r} "
                            "is empty or missing"
                        ),
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 5
    else:
        token = _secret("Cloudflare API token")

    policy = Phase5Policy(
        remote_root=args.remote_root,
        mode=selected_mode,
        rollback_on_failure=not args.no_auto_rollback,
        require_proxied_record=not args.allow_unproxied,
    )

    try:
        result = run_phase5(
            source,
            destination,
            job_id=args.job_id,
            hostname=args.hostname,
            zone_name=args.zone,
            cloudflare_api_token=token,
            confirmation=args.confirm,
            policy=policy,
        )
    except (Phase5Error, SSHConnectionError) as exc:
        print(
            json.dumps(
                {
                    "phase": 5,
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
        return 5

    payload = result.to_dict()
    print(
        json.dumps(
            {
                "phase": 5,
                "status": "completed",
                "mode": selected_mode,
                "result": payload,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    if selected_mode == PHASE5_MODE_PLAN and not payload["cutover_ready"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
