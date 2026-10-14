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
MAX_EVIDENCE_BYTES = 16384
MAX_AGE_SECONDS = 30
REQUIRED_CHECKS = frozenset((
    "f4_accepted", "ssh_sessions", "ssh_socks_ipv4", "dns_udp",
    "dns_tcp", "nss", "ipv6", "no_core_leak", "boot_guard",
    "wg_loss_fenced", "operator_rescue", "neighbour_isolation",
))
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
        if not isinstance(obj, dict) or set(obj) != keys or type(obj["version"]) is not int
            or obj["version"] != 1:
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
        if (not isinstance(checkmap, dict)
            or set(checkmap) != REQUIRED_CHECKS
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
        return SignedExternalEvidence(
            obj["generation"], timestamp, expires,
            obj["target_edge"], obj["target_ipv4"],
            frozenset(checkmap), tuple(accounts),
        )
    except (ValueError, TypeError, KeyError, UnicodeDecodeError) as exc:
        raise M42EvidenceHold("M42_WITNESS_INVALID_OR_EXPIRED") from exc


def verify_external_signature(*, paths: tuple[Path, Path, Path],
                              run: Callable = subprocess.run) -> None:
    """OpenSSL verifies an off-host private-key signature using root-pinned pubkey.

    All three paths are fixed, root-owned, mode 0600 files under root-only
    directory. No shell, arbitrary command or bot-selected arguments.
    """
    if paths != (WITNESS_JSON, WITNESS_SIG, WITNESS_PUB):
        raise M42EvidenceHold("M42_WITNESS_PATH_UNTRUSTED")
    _verify_root_directory(WITNESS_DIR, group=None, private=True)
    for path, limit in ((WITNESS_JSON, MAX_EVIDENCE_BYTES),
                        (WITNESS_SIG, 4096), (WITNESS_PUB, 8192)):
        _read_checked(path, maximum=limit, strict=True)
    try:
        proc = run(
            ["openssl", "dgst", "-sha256", "-verify", str(WITNESS_PUB),
             "-signature", str(WITNESS_SIG), str(WITNESS_JSON)],
            capture_output=True, text=True, check=False, timeout=4,
        )
    except (OSError, subprocess.TimeoutExpired, TypeError, ValueError) as exc:
        raise M42EvidenceHold("M42_EXTERNAL_SIGNATURE_UNAVAILABLE") from exc
    if proc.returncode != 0 or proc.stdout.strip() != "Verified OK":
        raise M42EvidenceHold("M42_EXTERNAL_SIGNATURE_INVALID")


def load_external_evidence(*, now: int | None = None,
                           geteuid: Callable[[], int] = __import__("os").geteuid,
                           run: Callable = subprocess.run) -> SignedExternalEvidence:
    if not M42_EVIDENCE_ENABLED or geteuid() != 0:
        raise M42EvidenceHold("M42_EXTERNAL_WITNESS_NOT_RELEASED")
    verify_external_signature(paths=(WITNESS_JSON, WITNESS_SIG, WITNESS_PUB), run=run)
    raw = _read_checked(WITNESS_JSON, maximum=MAX_EVIDENCE_BYTES, strict=True)
    return decode_evidence(raw, now=int(time.time()) if now is None else now)
