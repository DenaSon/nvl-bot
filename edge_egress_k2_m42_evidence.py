"""M4.2 independently signed, short-lived external SSH/F4 witness.

An external observer (NOT the bot or Core root worker) signs a canonical JSON
report after observing actual SSH session accounting, packet paths, DNS/NSS,
IPv6 and boot/WG-loss recovery. The private signing key must stay OFF Core.
This verifies provenance/integrity only; M5 must validate physical methodology.

No bool from Telegram, historical host, namespace curl or DB PROTECTED counts.
Missing/expired evidence is HOLD. No mutation and no dynamic commands.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import time
from typing import Callable

from edge_egress_k2_m4_root_worker import _read_checked, _verify_root_directory

M42_EVIDENCE_ENABLED = False
WITNESS_DIR = Path("/etc/nvl-egress/k2-m4/witness")
WITNESS_JSON = WITNESS_DIR / "report.json"
WITNESS_SIG = WITNESS_DIR / "report.sig"
WITNESS_PUB = WITNESS_DIR / "observer-public.pem"
POST_WITNESS_JSON = WITNESS_DIR / "post-attach.json"
POST_WITNESS_SIG = WITNESS_DIR / "post-attach.sig"
UID_WITNESS_JSON = WITNESS_DIR / "uid-route.json"
UID_WITNESS_SIG = WITNESS_DIR / "uid-route.sig"
MAX_EVIDENCE_BYTES = 16384
MAX_AGE_SECONDS = 30
REQUIRED_CHECKS = frozenset((
    "f4_accepted", "ssh_sessions", "ssh_socks_ipv4", "dns_udp",
    "dns_tcp", "nss", "ipv6", "no_core_leak", "boot_guard",
    "wg_loss_fenced", "operator_rescue", "neighbour_isolation",
))
# Edge/host acceptance precedes attaching a UID. Customer packet results
# belong to the later, nonce-bound observation, never to PREPARE.
PRE_ATTACH_CHECKS = REQUIRED_CHECKS - frozenset((
    "ssh_socks_ipv4", "dns_udp", "dns_tcp", "nss", "ipv6", "no_core_leak",
))
POST_ATTACH_CHECKS = frozenset((
    "ssh_socks_ipv4", "dns_udp", "dns_tcp", "nss", "ipv6",
    "no_core_leak", "neighbour_isolation",
))
UID_ROUTE_CHECKS = (POST_ATTACH_CHECKS - {"ssh_socks_ipv4"}) | {"uid_public_ipv4"}
_EDGE = re.compile(r"[a-z][a-z0-9_-]{1,23}\Z")
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class M42EvidenceHold(ValueError):
    pass


@dataclass(frozen=True)
class WitnessAccount:
    username: str
    uid: int
    source_edge: str
    source_ipv4: str
    active_sessions: int


@dataclass(frozen=True)
class SignedExternalEvidence:
    generation: str
    observed_at: int
    expires_at: int
    target_edge: str
    target_ipv4: str
    checks: frozenset[str]
    accounts: tuple[WitnessAccount, ...]
    phase: str = "LEGACY"
    scope_digest: str = ""
    nonce_hash: str = ""
    operation_id: int | None = None
    observed_public_ipv4: str = ""

    def verify_account(self, name: str, uid: int, *,
                       source_edge: str | None = None,
                       source_ipv4: str | None = None) -> int:
        matches = [a for a in self.accounts if a.username == name and a.uid == uid]
        if (len(matches) != 1 or matches[0].active_sessions != 0
            or (source_edge is not None and source_edge != matches[0].source_edge)
            or (source_ipv4 is not None and source_ipv4 != matches[0].source_ipv4)):
            raise M42EvidenceHold("M42_INDEPENDENT_SESSION_SCOPE_HOLD")
        return 0

    def verify_target(self, edge: str, ipv4: str,
                      names: tuple[str, ...]) -> None:
        if (self.target_edge != edge or self.target_ipv4 != ipv4
            or not names or len(names) > 10
            or any(sum(a.username == name for a in self.accounts) != 1
                   for name in names)):
            raise M42EvidenceHold("M42_EXTERNAL_TARGET_OR_WAVE_DRIFT")

    def verify_pre_attach(self) -> None:
        if not (
            self.phase == "PRE_ATTACH" and self.checks == PRE_ATTACH_CHECKS
            or self.phase == "LEGACY" and self.checks == REQUIRED_CHECKS
        ):
            raise M42EvidenceHold("M42_PRE_ATTACH_EVIDENCE_REQUIRED")

    def verify_post_attach(self, scope, ticket, *, operation_id: int,
                           now: int, phase: str = "POST_ATTACH") -> None:
        from edge_egress_p3_executor import (
            ExecutionScope, ExecutionTicket, _scope_digest,
        )
        if (type(scope) is not ExecutionScope
            or type(ticket) is not ExecutionTicket
            or type(ticket.nonce) is not str
            or re.fullmatch(r"[a-f0-9]{32}", ticket.nonce) is None
            or type(operation_id) is not int or operation_id <= 0
            or type(now) is not int
            or not self.observed_at <= now < self.expires_at
            or now - self.observed_at > MAX_AGE_SECONDS
            or phase not in ("POST_ATTACH", "UID_ROUTE")
            or self.phase != phase
            or self.checks != (POST_ATTACH_CHECKS if phase == "POST_ATTACH" else UID_ROUTE_CHECKS)
            or self.scope_digest != _scope_digest(scope)
            or ticket.scope_digest != self.scope_digest
            or not hmac.compare_digest(
                self.nonce_hash, sha256(ticket.nonce.encode("ascii")).hexdigest()
            )
            or self.operation_id != operation_id
            or self.observed_public_ipv4 != scope.target_host
            or len(self.accounts) != 1):
            raise M42EvidenceHold("M42_POST_ATTACH_SCOPE_OR_PACKET_HOLD")
        self.verify_target(scope.edge_id, scope.target_host, (scope.username,))
        self.verify_account(scope.username, scope.uid,
                            source_ipv4=scope.source_host)


def _unique_pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise M42EvidenceHold("M42_DUPLICATE_WITNESS_FIELD")
        out[key] = value
    return out


def _public_ip(value: object) -> bool:
    try:
        return type(value) is str and str(ipaddress.IPv4Address(value)) == value and (
            ipaddress.IPv4Address(value).is_global
        )
    except (TypeError, ValueError):
        return False


def decode_evidence(raw: bytes, *, now: int) -> SignedExternalEvidence:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_EVIDENCE_BYTES:
        raise M42EvidenceHold("M42_WITNESS_FORMAT_HOLD")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        keys = {"version", "generation", "observed_at", "expires_at",
                "target_edge", "target_ipv4", "checks", "accounts"}
        if not isinstance(obj, dict) or type(obj.get("version")) is not int:
            raise ValueError()
        version = obj["version"]
        phase = "LEGACY"
        if version == 2:
            keys |= {"phase", "scope_digest", "nonce_hash", "operation_id",
                     "observed_public_ipv4"}
            phase = obj.get("phase")
            if phase not in ("PRE_ATTACH", "UID_ROUTE", "POST_ATTACH"):
                raise ValueError()
            if phase == "PRE_ATTACH":
                if (obj.get("scope_digest") != "" or obj.get("nonce_hash") != ""
                    or obj.get("operation_id") is not None
                    or obj.get("observed_public_ipv4") != ""):
                    raise ValueError()
            elif (type(obj.get("scope_digest")) is not str
                  or not _DIGEST.fullmatch(obj["scope_digest"])
                  or type(obj.get("nonce_hash")) is not str
                  or not _DIGEST.fullmatch(obj["nonce_hash"])
                  or type(obj.get("operation_id")) is not int
                  or obj["operation_id"] <= 0
                  or obj.get("observed_public_ipv4") != obj.get("target_ipv4")):
                raise ValueError()
        elif version != 1:
            raise ValueError()
        if set(obj) != keys:
            raise ValueError()
        timestamp, expires = obj["observed_at"], obj["expires_at"]
        if (type(now) is not int or type(timestamp) is not int
            or type(expires) is not int or now < timestamp
            or now >= expires or now - timestamp > MAX_AGE_SECONDS
            or expires - timestamp > MAX_AGE_SECONDS):
            raise ValueError()
        if (not isinstance(obj["generation"], str)
            or not _DIGEST.fullmatch(obj["generation"])
            or not isinstance(obj["target_edge"], str)
            or not _EDGE.fullmatch(obj["target_edge"])
            or not _public_ip(obj["target_ipv4"])):
            raise ValueError()
        checkmap = obj["checks"]
        expected_checks = (PRE_ATTACH_CHECKS if phase == "PRE_ATTACH" else
                           POST_ATTACH_CHECKS if phase == "POST_ATTACH" else
                           UID_ROUTE_CHECKS if phase == "UID_ROUTE" else
                           REQUIRED_CHECKS)
        if (not isinstance(checkmap, dict)
            or set(checkmap) != expected_checks
            or any(v is not True for v in checkmap.values())):
            raise ValueError()
        rows = obj["accounts"]
        if not isinstance(rows, list) or not 1 <= len(rows) <= 10:
            raise ValueError()
        accounts = []
        for item in rows:
            if not isinstance(item, dict) or set(item) != {
                "username", "uid", "source_edge", "source_ipv4",
                "active_sessions",
            }:
                raise ValueError()
            if (not isinstance(item["username"], str)
                or not _USER.fullmatch(item["username"])
                or type(item["uid"]) is not int
                or not 1000 <= item["uid"] < 60000
                or not isinstance(item["source_edge"], str)
                or not _EDGE.fullmatch(item["source_edge"])
                or not _public_ip(item["source_ipv4"])
                or type(item["active_sessions"]) is not int
                or item["active_sessions"] < 0):
                raise ValueError()
            accounts.append(WitnessAccount(**item))
        if len({a.username for a in accounts}) != len(accounts) or (
            len({a.uid for a in accounts}) != len(accounts)
        ):
            raise ValueError()
        if phase in ("UID_ROUTE", "POST_ATTACH") and len(accounts) != 1:
            raise ValueError()
        return SignedExternalEvidence(
            obj["generation"], timestamp, expires,
            obj["target_edge"], obj["target_ipv4"],
            frozenset(checkmap), tuple(accounts), phase,
            obj.get("scope_digest", ""), obj.get("nonce_hash", ""),
            obj.get("operation_id"), obj.get("observed_public_ipv4", ""),
        )
    except (ValueError, TypeError, KeyError, UnicodeDecodeError) as exc:
        raise M42EvidenceHold("M42_WITNESS_INVALID_OR_EXPIRED") from exc


def verify_external_signature(*, paths: tuple[Path, Path, Path],
                              run: Callable = subprocess.run) -> bytes:
    """OpenSSL verifies an off-host private-key signature using root-pinned pubkey.

    All three paths are fixed, root-owned, mode 0600 files under root-only
    directory. No shell, arbitrary command or bot-selected arguments.
    """
    if paths not in ((WITNESS_JSON, WITNESS_SIG, WITNESS_PUB),
                     (POST_WITNESS_JSON, POST_WITNESS_SIG, WITNESS_PUB),
                     (UID_WITNESS_JSON, UID_WITNESS_SIG, WITNESS_PUB)):
        raise M42EvidenceHold("M42_WITNESS_PATH_UNTRUSTED")
    _verify_root_directory(WITNESS_DIR, group=None, private=True)
    # Capture exactly ONE report byte sequence before signature checking.
    # Feeding those bytes to OpenSSL on stdin prevents a different in-place
    # report read from being decoded as an authorized packet witness.
    report_path, signature_path, public_path = paths
    raw = _read_checked(report_path, maximum=MAX_EVIDENCE_BYTES, strict=True)
    sig = _read_checked(signature_path, maximum=4096, strict=True)
    pub = _read_checked(public_path, maximum=8192, strict=True)
    try:
        proc = run(
            ["openssl", "dgst", "-sha256", "-verify", str(public_path),
             "-signature", str(signature_path), "-"],
            input=raw, capture_output=True, text=False, check=False, timeout=4,
        )
    except (OSError, subprocess.TimeoutExpired, TypeError, ValueError) as exc:
        raise M42EvidenceHold("M42_EXTERNAL_SIGNATURE_UNAVAILABLE") from exc
    if proc.returncode != 0 or proc.stdout.strip() != b"Verified OK":
        raise M42EvidenceHold("M42_EXTERNAL_SIGNATURE_INVALID")
    # Signature and public key may only be changed by the trusted root
    # administrator; fail closed if their bytes changed during verification.
    if (_read_checked(signature_path, maximum=4096, strict=True) != sig
        or _read_checked(public_path, maximum=8192, strict=True) != pub):
        raise M42EvidenceHold("M42_EXTERNAL_SIGNER_MATERIAL_CHANGED")
    return raw


def load_external_evidence(*, now: int | None = None,
                           geteuid: Callable[[], int] = __import__("os").geteuid,
                           run: Callable = subprocess.run) -> SignedExternalEvidence:
    if not M42_EVIDENCE_ENABLED or geteuid() != 0:
        raise M42EvidenceHold("M42_EXTERNAL_WITNESS_NOT_RELEASED")
    raw = verify_external_signature(
        paths=(WITNESS_JSON, WITNESS_SIG, WITNESS_PUB), run=run,
    )
    return decode_evidence(raw, now=int(time.time()) if now is None else now)


def load_post_attach_evidence(*, scope, ticket, db_conn: Callable,
                              now: int | None = None,
                              geteuid: Callable[[], int] = __import__("os").geteuid,
                              run: Callable = subprocess.run,
                              phase: str = "POST_ATTACH",
                              ) -> SignedExternalEvidence:
    """Fresh signed client evidence for the exact currently RUNNING 6G UID.

    Read only after routing. A report from PREPARE, a previous attempt, a
    different UID or a completed operation can never verify this transfer.
    """
    from edge_egress_p3_executor import assert_guarded_6g_intent
    if not M42_EVIDENCE_ENABLED or geteuid() != 0:
        raise M42EvidenceHold("M42_EXTERNAL_WITNESS_NOT_RELEASED")
    if phase not in ("UID_ROUTE", "POST_ATTACH"):
        raise M42EvidenceHold("M42_POST_ATTACH_PHASE_INVALID")
    op = assert_guarded_6g_intent(db_conn, scope, ticket)
    def routed_state():
        import sqlite3
        try:
            with db_conn() as db:
                row = db.execute(
                    "SELECT uid,edge_id,edge_ipv4,state,last_operation_id "
                    "FROM edge_egress_uid_runtime WHERE username=?",
                    (scope.username,),
                ).fetchone()
            expected_state = "ROUTED_UNVERIFIED" if phase == "UID_ROUTE" else "PROTECTED"
            if row != (scope.uid, scope.edge_id, scope.target_host, expected_state, op):
                raise M42EvidenceHold("M42_POST_ATTACH_UID_NOT_ROUTED")
        except sqlite3.Error as exc:
            raise M42EvidenceHold("M42_POST_ATTACH_RUNTIME_UNAVAILABLE") from exc
        return row
    before = routed_state()
    paths = ((UID_WITNESS_JSON, UID_WITNESS_SIG, WITNESS_PUB)
             if phase == "UID_ROUTE" else
             (POST_WITNESS_JSON, POST_WITNESS_SIG, WITNESS_PUB))
    raw = verify_external_signature(
        paths=paths, run=run,
    )
    stamp = int(time.time()) if now is None else now
    result = decode_evidence(raw, now=stamp)
    result.verify_post_attach(scope, ticket, operation_id=op, now=stamp, phase=phase)
    assert_guarded_6g_intent(db_conn, scope, ticket)
    if routed_state() != before:
        raise M42EvidenceHold("M42_POST_ATTACH_UID_CHANGED")
    return result
