from __future__ import annotations

import argparse
import getpass
import json

from .models import ServerCredentials
from .preflight import run_preflight


def _password(label: str) -> str:
    return getpass.getpass(f"{label} SSH password: ")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NVL Change Server Phase 1 read-only preflight"
    )
    parser.add_argument("--source", required=True, help="source server IP/hostname")
    parser.add_argument("--destination", required=True, help="destination server IP/hostname")
    parser.add_argument("--source-port", type=int, default=22)
    parser.add_argument("--destination-port", type=int, default=22)
    parser.add_argument("--source-user", default="root")
    parser.add_argument("--destination-user", default="root")
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

    report = run_preflight(source, destination)
    print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    return 0 if report.ready else 2


if __name__ == "__main__":
    raise SystemExit(main())
