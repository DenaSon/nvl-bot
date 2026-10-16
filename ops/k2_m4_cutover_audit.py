"""K2 root-worker cutover compatibility audit -- READ ONLY, always HOLD.

Inspect the reviewed source SHA and live systemd/proc UID proof before
an operator considers changing the legacy single Telegram poller.
Not an installer, chmod helper, privilege-dropper or alternate root executor.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from hashlib import sha256

from edge_egress_k2_m4_root_worker import (
    WorkerPaths, RootWorkerHold, _read_checked, verify_reviewed_release,
)
from edge_egress_k2_a_root_assembly import (
    M4AAssemblyHold, assert_nonroot_bot_identity,
)

BOT_SOURCE = "bot_final_v49-2.py"
MAX_BOT_BYTES = 2_000_000
# Deliberately narrow categories: they are evidence of dependencies to
# review, NOT proof that all other function calls are unprivileged.
PRIVILEGED_CALLS = frozenset((
    "run_cmd", "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "subprocess.run", "subprocess.Popen", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output",
    "os.system", "os.chown", "os.chmod", "os.setuid",
    "os.seteuid", "os.setgid", "os.setegid",
    "paramiko.SSHClient",
))
PRIVILEGED_COMMAND_TERMS = (
    "sudo", "systemctl", "iptables", "ip6tables", "useradd",
    "usermod", "userdel", "chpasswd", "wg-quick", "ip route",
    "nft", "service ssh", "sshd",
)


class CutoverAuditHold(ValueError):
    pass


@dataclass(frozen=True)
class LegacyPrivilegeUse:
    expression: str
    line: int


@dataclass(frozen=True)
class CutoverAudit:
    reviewed_git_sha: str | None
    bot_sha256: str | None
    privileged_uses: tuple[LegacyPrivilegeUse, ...]
    blockers: tuple[str, ...]
    safe_for_cutover: bool = False

    def __post_init__(self) -> None:
        # No source-only/mocked proof can authorize a live bot UID change.
        if self.safe_for_cutover is not False:
            raise CutoverAuditHold("LIVE_CUTOVER_REQUIRES_FIELD_ACCEPTANCE")


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name(node.value)
        return prefix + "." + node.attr if prefix else node.attr
    return ""


def inspect_legacy_source(raw: bytes) -> tuple[str, tuple[LegacyPrivilegeUse, ...]]:
    """Conservative source dependency inventory, not privilege certification."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BOT_BYTES:
        raise CutoverAuditHold("LEGACY_BOT_SOURCE_MISSING_OR_OVERSIZED")
    try:
        source = raw.decode("utf-8", errors="strict")
        root = ast.parse(source, filename=BOT_SOURCE)
    except (UnicodeError, SyntaxError, ValueError) as exc:
        raise CutoverAuditHold("LEGACY_BOT_SOURCE_UNPARSABLE") from exc
    uses: set[tuple[str, int]] = set()
    for node in ast.walk(root):
        if not isinstance(node, ast.Call):
            continue
        expression = _name(node.func)
        if expression in PRIVILEGED_CALLS or (
            expression.endswith(".exec_command")
        ):
            uses.add((expression, node.lineno))
        # Callsite command content is inspected only for constant strings:
        # dynamically built commands are not assumed safe.
        for arg in node.args:
            if not isinstance(arg, ast.Constant) or not isinstance(arg.value, str):
                continue
            value = arg.value.lower()
            if any(term in value for term in PRIVILEGED_COMMAND_TERMS):
                uses.add(("system-command-literal", node.lineno))
                break
    found = tuple(LegacyPrivilegeUse(expression, line) for expression, line
                  in sorted(uses, key=lambda x: (x[1], x[0])))
    return sha256(raw).hexdigest(), found


def inspect_cutover(paths: WorkerPaths) -> CutoverAudit:
    """Pin reviewed source and report reasons; never start, stop or edit bot.

    Checking a nonroot unit does NOT mean its old root-only functions work.
    The read-only audit intentionally returns safe_for_cutover=False even
    if all checks happen to pass: per-function review and field test remain.
    """
    if not isinstance(paths, WorkerPaths):
        raise CutoverAuditHold("REVIEWED_WORKER_PATHS_REQUIRED")
    paths.validate()
    issues = []
    git_sha = digest = None
    uses = ()
    try:
        git_sha = verify_reviewed_release(paths)
        raw = _read_checked(paths.source_root / BOT_SOURCE, maximum=MAX_BOT_BYTES)
        digest, uses = inspect_legacy_source(raw)
    except (RootWorkerHold, CutoverAuditHold, OSError):
        issues.append("REVIEWED_ROOT_SOURCE_NOT_ATTESTED")
    try:
        assert_nonroot_bot_identity(paths)
    except (M4AAssemblyHold, RootWorkerHold, OSError):
        issues.append("NONROOT_BOT_PROCESS_IDENTITY_NOT_ATTESTED")
    if uses:
        issues.append("LEGACY_PRIVILEGED_CALLS_NEED_COMPATIBILITY_REVIEW")
    elif digest is None:
        issues.append("LEGACY_SOURCE_DEPENDENCY_AUDIT_UNAVAILABLE")
    # This is intentionally a diagnostics-only readiness check, not a
    # way to turn unreviewed test fixtures into production permissions.
    issues.append("INDEPENDENT_LEGACY_FUNCTIONAL_AND_VPS_PROOF_PENDING")
    return CutoverAudit(git_sha, digest, uses, tuple(issues))


def main(argv: list[str] | None = None) -> int:
    """Explicit standalone READ-ONLY cutover diagnostics for a lab Core.

    Returns 78/HOLD even with a valid release manifest. Does not run an M4
    worker, modify systemd/permissions, create a socket or issue a ticket.
    """
    import argparse
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(
        description="Read-only NVL K2 root-bot cutover audit (never releases)"
    )
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--bot-uid", type=int, required=True)
    parser.add_argument("--ipc-gid", type=int, required=True)
    parser.add_argument(
        "--details", action="store_true",
        help="Show at most 64 source callsites without command arguments",
    )
    args = parser.parse_args(argv)
    try:
        result = inspect_cutover(WorkerPaths(
            source_root=args.source_root,
            manifest_file=Path("/etc/nvl-egress/k2-m4/release.json"),
            secret_file=Path("/etc/nvl-egress/k2-m4/root-hmac.key"),
            runtime_dir=Path("/run/nvl-k2-m4"),
            bot_uid=args.bot_uid,
            ipc_gid=args.ipc_gid,
        ))
        output = {
            "status": "HOLD",
            "reviewed_git_sha": result.reviewed_git_sha,
            "bot_sha256": result.bot_sha256,
            "legacy_privileged_call_sites": len(result.privileged_uses),
            "blockers": list(result.blockers),
            "can_deploy": False,
            "can_release": False,
        }
        if args.details:
            output["call_sites"] = [
                {"kind": item.expression, "line": item.line}
                for item in result.privileged_uses[:64]
            ]
            output["call_sites_truncated"] = len(result.privileged_uses) > 64
    except (RootWorkerHold, CutoverAuditHold, ValueError, OSError):
        output = {
            "status": "HOLD",
            "blockers": ["CUTOVER_AUDIT_NOT_ATTESTED"],
            "can_deploy": False,
            "can_release": False,
        }
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 78


if __name__ == "__main__":
    raise SystemExit(main())
