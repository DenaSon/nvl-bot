"""Pure Phase 6G safe-failover helpers.

No network, database, Telegram, DNS, or process side effects live here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable, Mapping, Optional


FAILOVER_STATUS_RUNNING = "RUNNING"
FAILOVER_STATUS_SUCCEEDED = "SUCCEEDED"
FAILOVER_STATUS_FAILED = "FAILED"
FAILOVER_STATUS_ROLLED_BACK = "ROLLED_BACK"
FAILOVER_STATUS_ABORTED_STALE = "ABORTED_STALE"

FAILOVER_MODE_MANUAL = "MANUAL"
FAILOVER_MODE_AUTO = "AUTO"


class FailoverValidationError(ValueError):
    pass


@dataclass(frozen=True)
class RebuildSummary:
    source_host: str
    target_host: str
    requested: int
    rebuilt: int
    failed: int
    rebuilt_usernames: tuple[str, ...]
    failed_usernames: tuple[str, ...]
    db_committed: bool
    ok: bool

    @classmethod
    def from_mapping(cls, raw: Mapping) -> "RebuildSummary":
        try:
            return cls(
                source_host=str(raw.get("source_host") or ""),
                target_host=str(raw.get("target_host") or ""),
                requested=int(raw.get("requested") or 0),
                rebuilt=int(raw.get("rebuilt") or 0),
                failed=int(raw.get("failed") or 0),
                rebuilt_usernames=tuple(str(x) for x in (raw.get("rebuilt_usernames") or ())),
                failed_usernames=tuple(str(x) for x in (raw.get("failed_usernames") or ())),
                db_committed=bool(raw.get("db_committed", False)),
                ok=bool(raw.get("ok", False)),
            )
        except (TypeError, ValueError) as exc:
            raise FailoverValidationError(f"invalid helper summary types: {exc}") from exc


def parse_helper_summary(stdout: bytes | str) -> RebuildSummary:
    """Parse the final JSON object emitted by the rebuild helper."""
    if isinstance(stdout, bytes):
        text = stdout.decode(errors="replace")
    else:
        text = str(stdout or "")

    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(raw, dict):
            return RebuildSummary.from_mapping(raw)

    raise FailoverValidationError("helper did not emit a valid JSON summary")


def validate_complete_rebuild(
    summary: RebuildSummary,
    *,
    source_host: str,
    target_host: str,
    expected_usernames: Iterable[str],
) -> RebuildSummary:
    """Require exact all-or-nothing rebuild evidence before DB/routing mutation."""
    expected = tuple(str(x) for x in expected_usernames)
    expected_set = set(expected)
    rebuilt_set = set(summary.rebuilt_usernames)

    if summary.source_host != str(source_host):
        raise FailoverValidationError(
            f"helper source mismatch: {summary.source_host!r} != {source_host!r}"
        )
    if summary.target_host != str(target_host):
        raise FailoverValidationError(
            f"helper target mismatch: {summary.target_host!r} != {target_host!r}"
        )
    if summary.db_committed:
        raise FailoverValidationError(
            "helper mutated DB; Phase 6G requires rebuild-only helper execution"
        )
    if not summary.ok:
        raise FailoverValidationError("helper reported unsuccessful rebuild")
    if summary.failed != 0 or summary.failed_usernames:
        raise FailoverValidationError("helper reported failed accounts")
    if summary.requested != len(expected):
        raise FailoverValidationError(
            f"requested count mismatch: {summary.requested} != {len(expected)}"
        )
    if summary.rebuilt != len(expected):
        raise FailoverValidationError(
            f"rebuilt count mismatch: {summary.rebuilt} != {len(expected)}"
        )
    if len(summary.rebuilt_usernames) != len(rebuilt_set):
        raise FailoverValidationError("helper returned duplicate rebuilt usernames")
    if rebuilt_set != expected_set:
        missing = sorted(expected_set - rebuilt_set)
        extra = sorted(rebuilt_set - expected_set)
        raise FailoverValidationError(
            f"rebuilt username set mismatch; missing={missing}, extra={extra}"
        )

    return summary


def is_transparent_dns_handoff_safe(
    *,
    cloudflare_configured: bool,
    dns_current_ip: Optional[str],
    source_host: str,
    source_service_port: int,
    target_service_port: int,
    core_fallback_ip: Optional[str] = None,
) -> tuple[bool, str]:
    """Static preflight constraints for transparent DNS-only handoff."""
    if not cloudflare_configured:
        return False, "CLOUDFLARE_NOT_CONFIGURED"
    if not dns_current_ip:
        return False, "DNS_CURRENT_IP_UNKNOWN"
    allowed_dns_ips = {str(source_host)}
    if core_fallback_ip:
        allowed_dns_ips.add(str(core_fallback_ip))
    if str(dns_current_ip) not in allowed_dns_ips:
        return False, "DNS_NOT_POINTING_TO_SOURCE_OR_CORE"
    if int(source_service_port) != int(target_service_port):
        return False, "SERVICE_PORT_MISMATCH"
    return True, "OK"
