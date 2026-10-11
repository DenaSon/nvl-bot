"""F4 release evidence contract. Does not mint a customer-ready Edge.

A completed checklist is a *candidate* for independent approval only. Actual
production acceptance must be bound to a live host and signed/recorded by the
operator after an isolated VM reboot, real SSH client proxy/forward checks,
DNS/IPv6 packet capture, induced Edge failure and out-of-band recovery.

Never accept a successful F1/F3 lab witness as F4 production evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import re
import time

EVIDENCE_VERSION = 1
MAX_EVIDENCE_BYTES = 16384
MAX_EVIDENCE_AGE_SECONDS = 3600
ACCEPTANCE_PROBES = (
    "independent_root_console",
    "non_root_admin_ssh_recovery",
    "pam_account_gate_live",
    "pam_direct_tcpip_forwarding",
    "ssh_socks_external_edge_ipv4",
    "uid_local_curl_external_edge_ipv4",
    "edge_down_ssh_fail_closed",
    "edge_down_uid_fail_closed",
    "dns_udp_tcp_no_core_leak",
    "dns_nss_helper_no_core_leak",
    "ipv6_no_core_leak",
    "boot_deny_before_ssh",
    "reboot_recovery_with_edge",
    "badudp_behavior_explicit",
    "shared_edge_multi_uid_safety",
    "offline_encrypted_backup_restore",
    "no_operational_wg0_changes",
    "no_customer_ssh_downtime",
)


class ReleaseEvidenceUnsafe(ValueError):
    pass


@dataclass(frozen=True)
class ReleaseGate:
    accepted: bool
    code: str
    failures: tuple[str, ...]
    observed_edge_ip: str | None = None
    customer_ready: bool = False

    def __post_init__(self):
        if self.customer_ready:
            raise ReleaseEvidenceUnsafe("AUTOMATIC_CUSTOMER_READINESS_FORBIDDEN")


def _canonical_public_ip(value: object) -> str:
    try:
        addr = ipaddress.IPv4Address(value)
        if str(addr) != value or not addr.is_global:
            raise ValueError()
        return str(addr)
    except (ValueError, TypeError, ipaddress.AddressValueError) as exc:
        raise ReleaseEvidenceUnsafe("INVALID_PUBLIC_IPV4") from exc


def check_release_evidence(payload: object, *, now: int | None = None,
                           expected_edge_id: str | None = None,
                           expected_uid: int | None = None,
                           expected_username: str | None = None,
                           expected_core_ipv4: str | None = None,
                           expected_edge_ipv4: str | None = None,
                           expected_environment: str = "disposable-vps",
                           ) -> ReleaseGate:
    """Strict evidence shape. Pass never directly authorizes a production cutover.

    Per-probe booleans are operator-reported data, NOT cryptographic proof of
    their execution. This function rejects stale, wrong-host and lab-only
    artifacts. Independent operator review and a real deployment gate remain
    necessary before any F4 READY state.
    """
    if not isinstance(payload, dict):
        return ReleaseGate(False, "EVIDENCE_INVALID", ("ROOT_NOT_OBJECT",))
    keys={"version","edge_id","username","uid","core_ipv4","edge_ipv4",
          "environment","observed_edge_ipv4","observed_at",
          "probe_results","run_id"}
    if set(payload)!=keys:
        return ReleaseGate(False,"EVIDENCE_INVALID",("UNKNOWN_OR_MISSING_FIELDS",))
    if type(payload["version"]) is not int or payload["version"] != EVIDENCE_VERSION:
        return ReleaseGate(False,"EVIDENCE_INVALID",("VERSION_MISMATCH",))
    if not isinstance(payload["run_id"],str) or not re.fullmatch(
        r"[A-Za-z0-9._-]{12,96}",payload["run_id"]
    ):
        return ReleaseGate(False,"EVIDENCE_INVALID",("INVALID_RUN_ID",))
    if payload["environment"] != expected_environment:
        return ReleaseGate(False,"ENVIRONMENT_NOT_ATTESTED",
                           ("ENVIRONMENT_MISMATCH",))
    if not isinstance(payload["edge_id"],str) or not re.fullmatch(
        r"[a-z][a-z0-9]{0,6}",payload["edge_id"]
    ) or (expected_edge_id is not None and payload["edge_id"]!=expected_edge_id):
        return ReleaseGate(False,"IDENTITY_MISMATCH",("EDGE_ID",))
    if not isinstance(payload["username"],str) or not re.fullmatch(
        r"[a-z_][a-z0-9_-]{0,31}",payload["username"]
    ) or (expected_username is not None and payload["username"]!=expected_username):
        return ReleaseGate(False,"IDENTITY_MISMATCH",("USERNAME",))
    if type(payload["uid"]) is not int or not 1000 <= payload["uid"] < 60000 or (
        expected_uid is not None and payload["uid"] != expected_uid
    ):
        return ReleaseGate(False,"IDENTITY_MISMATCH",("UID",))
    try:
        core=_canonical_public_ip(payload["core_ipv4"])
        edge=_canonical_public_ip(payload["edge_ipv4"])
        observed=_canonical_public_ip(payload["observed_edge_ipv4"])
    except ReleaseEvidenceUnsafe:
        return ReleaseGate(False,"EVIDENCE_INVALID",("INVALID_OR_NONPUBLIC_IP",))
    if core==edge or core==observed or observed!=edge:
        return ReleaseGate(False,"PUBLIC_EGRESS_MISMATCH",("OBSERVED_EXIT_NOT_EDGE",),
                           observed_edge_ip=observed)
    if (expected_core_ipv4 is not None and core!=expected_core_ipv4) or (
        expected_edge_ipv4 is not None and edge!=expected_edge_ipv4
    ):
        return ReleaseGate(False,"IDENTITY_MISMATCH",("PINNED_IP_MISMATCH",))
    stamp=payload["observed_at"]
    current=int(time.time()) if now is None else now
    if type(stamp) is not int or type(current) is not int or stamp > current or (
        current-stamp > MAX_EVIDENCE_AGE_SECONDS
    ):
        return ReleaseGate(False,"EVIDENCE_STALE",("TIMESTAMP_INVALID_OR_EXPIRED",))
    probes=payload["probe_results"]
    if not isinstance(probes,dict) or set(probes)!=set(ACCEPTANCE_PROBES):
        return ReleaseGate(False,"EVIDENCE_INVALID",("PROBE_COVERAGE_INCOMPLETE",))
    failed=tuple(name for name in ACCEPTANCE_PROBES if probes[name] is not True)
    if failed:
        return ReleaseGate(False,"RELEASE_BLOCKED",failed,observed_edge_ip=observed)
    return ReleaseGate(
        True,"CANDIDATE_FOR_INDEPENDENT_REVIEW",(),
        observed_edge_ip=observed,customer_ready=False,
    )


def parse_evidence_json(raw: bytes) -> dict:
    if not isinstance(raw,bytes) or len(raw)>MAX_EVIDENCE_BYTES:
        raise ReleaseEvidenceUnsafe("EVIDENCE_SIZE_INVALID")
    try:
        document=json.loads(raw.decode("utf-8"))
    except (UnicodeError,ValueError) as exc:
        raise ReleaseEvidenceUnsafe("EVIDENCE_JSON_INVALID") from exc
    if not isinstance(document,dict):
        raise ReleaseEvidenceUnsafe("EVIDENCE_ROOT_INVALID")
    return document

def main(argv=None) -> int:
    """Validate operator-collected evidence; NEVER mutate or attest Ready."""
    import argparse
    from pathlib import Path
    p=argparse.ArgumentParser(description="F4 E2E evidence review — no deployment")
    p.add_argument("--evidence",required=True,type=Path)
    p.add_argument("--edge-id",required=True)
    p.add_argument("--username",required=True)
    p.add_argument("--uid",required=True,type=int)
    p.add_argument("--core-ip",required=True)
    p.add_argument("--edge-ip",required=True)
    args=p.parse_args(argv)
    try:
        if not args.evidence.is_file() or args.evidence.is_symlink():
            raise ReleaseEvidenceUnsafe("UNSAFE_EVIDENCE_PATH")
        payload=parse_evidence_json(args.evidence.read_bytes())
        verdict=check_release_evidence(
            payload,expected_edge_id=args.edge_id,
            expected_username=args.username,expected_uid=args.uid,
            expected_core_ipv4=args.core_ip,expected_edge_ipv4=args.edge_ip,
        )
    except (OSError,ReleaseEvidenceUnsafe):
        print("BLOCKED EVIDENCE_UNAVAILABLE")
        return 2
    if not verdict.accepted:
        print("BLOCKED",verdict.code,",".join(verdict.failures))
        return 1
    print("CANDIDATE_FOR_INDEPENDENT_REVIEW — NOT READY / NO HOST CHANGES")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
