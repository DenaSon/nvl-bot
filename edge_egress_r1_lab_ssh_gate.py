"""Restricted authorized_keys forced-command for read-only R1 LAB SSH.

Unlike executing the requested shell directly, this parses SSH_ORIGINAL_COMMAND
as data and permits only the reviewed agent with probe/inspect. A START request
must not pass: it needs a separate live 6G-authorized, replay-resistant channel.
Never install this on Production or replace an existing admin SSH key.
"""
from __future__ import annotations

import json
import os
import shlex

from edge_egress_r1_lab_agent import _request, execute

AGENT = "/root/nvl-egress-lab1-source/edge_egress_r1_lab_agent.py"
COORDINATOR_IP = "107.189.16.36"


def execute_ssh_readonly(original: str, ssh_connection: str) -> dict:
    # SSH_CONNECTION is operational context; the *from=Core_IP,restrict*
    # public-key option and host-key-pinned client remain security boundaries.
    fields = ssh_connection.split()
    if len(fields) != 4 or fields[0] != COORDINATOR_IP:
        raise ValueError("UNTRUSTED_SOURCE")
    if not original or len(original) > 8192:
        raise ValueError("INVALID_ORIGINAL_COMMAND")
    argv = shlex.split(original, posix=True)
    if (len(argv) != 4
            or argv[0] != "/usr/bin/python3"
            or argv[1] != AGENT
            or argv[2] not in ("probe", "inspect")):
        raise ValueError("READ_ONLY_ACTION_REQUIRED")
    contract, commit = _request(argv[3])
    if commit != "06d10e9cceae38c8519834e69ac3a2717ef8c18b":
        raise ValueError("UNPINNED_LAB_COMMIT")
    return execute(argv[2], argv[3])


def main() -> int:
    try:
        result = execute_ssh_readonly(
            os.environ.get("SSH_ORIGINAL_COMMAND", ""),
            os.environ.get("SSH_CONNECTION", ""),
        )
    except Exception:
        print('{"ok":false,"role":null,"state":"HOLD"}')
        return 2
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
