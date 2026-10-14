"""K2 A4 off-Core observer envelope.

This module DOES NOT execute customer probes or sign fabricated booleans.
An independently operated witness host must supply source-bound, dated
measurement receipts from real client/Core/console/fault probes. Private-key
signing is intentionally separated from the Core reader. ALL release gates
default OFF; passing this schema does not prove physical measurement honesty.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from typing import Callable

from edge_egress_k2_m42_evidence import (
    MAX_AGE_SECONDS, REQUIRED_CHECKS, WitnessAccount, decode_evidence,
)

A4_OFFCORE_SIGNING_ENABLED = False
PRIVATE_KEY = Path("/etc/nvl-observer/keys/observer-private.pem")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_-]{3,63}\Z")
_DOMAINS = {
    "f4_accepted": "client",
    "ssh_sessions": "core-session",
    "ssh_socks_ipv4": "client",
    "dns_udp": "client",
    "dns_tcp": "client",
    "nss": "client",
    "ipv6": "client",
    "no_core_leak": "core-capture",
    "boot_guard": "core-boot",
    "wg_loss_fenced": "fault-lab",
    "operator_rescue": "console",
    "neighbour_isolation": "core-capture",
}
_CLIENT_IP_CHECKS = frozenset(("ssh_socks_ipv4",))


class A4ObserverHold(ValueError):
    pass


@dataclass(frozen=True)
class IndependentProbeReceipt:
    check: str
    domain: str
    probe_id: str
    run_id: str
    observed_at: int
    target_edge: str
    target_ipv4: str
    # A content hash of separately retained raw results, not an "ok" boolean.
    raw_result_sha256: str
    outcome: str
    observed_public_ipv4: str | None = None


@dataclass(frozen=True)
class IndependentSessionReceipt:
    username: str
    uid: int
    source_edge: str
    source_ipv4: str
    active_sessions: int
    observed_at: int
    raw_result_sha256: str
    run_id: str


def _public_ipv4(ip: object) -> bool:
    try:
        return (type(ip) is str and str(ipaddress.IPv4Address(ip)) == ip
                and ipaddress.IPv4Address(ip).is_global)
    except (ValueError,TypeError):
        return False


def build_observation_report(
    *, probes: tuple[IndependentProbeReceipt, ...],
    sessions: tuple[IndependentSessionReceipt, ...],
    target_edge: str, target_ipv4: str, now: int,
) -> bytes:
    """Convert complete independent artifacts to the EXISTING signed M42 wire format.

    There are deliberately no defaults for check outcomes or session counts.
    Every required probe must have a distinct measurement receipt and matching
    target/run identity; missing, failed or outdated => HOLD (no signed READY).
    """
    if (type(now) is not int or now <= 0
        or not isinstance(probes, tuple)
        or len(probes) != len(REQUIRED_CHECKS)
        or not isinstance(sessions, tuple) or not 1 <= len(sessions) <= 10
        or not isinstance(target_edge,str)
        or not re.fullmatch(r"[a-z][a-z0-9_-]{1,23}",target_edge)
        or not _public_ipv4(target_ipv4)):
        raise A4ObserverHold("A4_UNVERIFIED_OBSERVATION_INPUT")
    by_check={}
    ids=set()
    run_ids=set()
    measurements=[]
    for item in probes:
        if not isinstance(item,IndependentProbeReceipt):
            raise A4ObserverHold("A4_UNTRUSTED_PROBE_RECEIPT")
        if (item.check not in REQUIRED_CHECKS
            or item.check in by_check
            or item.domain != _DOMAINS[item.check]
            or item.target_edge != target_edge
            or item.target_ipv4 != target_ipv4
            or not isinstance(item.probe_id,str)
            or not _IDENTIFIER.fullmatch(item.probe_id)
            or item.probe_id in ids
            or not isinstance(item.run_id,str)
            or not _IDENTIFIER.fullmatch(item.run_id)
            or type(item.observed_at) is not int
            or not 0 <= now-item.observed_at <= MAX_AGE_SECONDS-2
            or item.outcome != "PASS"
            or not isinstance(item.raw_result_sha256,str)
            or not _DIGEST.fullmatch(item.raw_result_sha256)
            or (item.check in _CLIENT_IP_CHECKS
                and item.observed_public_ipv4 != target_ipv4)
            or (item.check not in _CLIENT_IP_CHECKS
                and item.observed_public_ipv4 is not None)):
            raise A4ObserverHold("A4_PROBE_FAILED_MISSING_OR_STALE")
        by_check[item.check]=item
        ids.add(item.probe_id)
        run_ids.add(item.run_id)
        measurements.append((item.check,item.domain,item.probe_id,
                             item.raw_result_sha256,item.observed_at))
    if set(by_check)!=REQUIRED_CHECKS or len(run_ids)!=1:
        raise A4ObserverHold("A4_INDEPENDENT_PROBE_COHORT_INCOMPLETE")

    accounts=[]
    seen_names=set()
    seen_uids=set()
    for item in sessions:
        if (not isinstance(item, IndependentSessionReceipt)
            or not isinstance(item.username,str)
            or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}",item.username)
            or type(item.uid) is not int or not 1000 <= item.uid < 60000
            or not isinstance(item.source_edge,str)
            or not re.fullmatch(r"[a-z][a-z0-9_-]{1,23}",item.source_edge)
            or not _public_ipv4(item.source_ipv4)
            or type(item.active_sessions) is not int
            or item.active_sessions != 0
            or type(item.observed_at) is not int
            or not 0 <= now-item.observed_at <= MAX_AGE_SECONDS-2
            or not isinstance(item.raw_result_sha256,str)
            or not _DIGEST.fullmatch(item.raw_result_sha256)
            or item.run_id not in run_ids
            or item.username in seen_names or item.uid in seen_uids):
            raise A4ObserverHold("A4_INDEPENDENT_SESSION_UNVERIFIED")
        seen_names.add(item.username)
        seen_uids.add(item.uid)
        measurements.append((item.username,item.uid,item.source_edge,
                             item.source_ipv4,item.raw_result_sha256,
                             item.observed_at))
        accounts.append({
            "username":item.username,"uid":item.uid,
            "source_edge":item.source_edge,"source_ipv4":item.source_ipv4,
            "active_sessions":item.active_sessions,
        })
    # Root's existing M42 verifier accepts a signed snapshot only for <=30 s.
    # Reserve 2 s for transfer, signature verification and root policy checks.
    first = min(x.observed_at for x in probes + sessions)
    generation=sha256(json.dumps({
        "run_id":next(iter(run_ids)),"target_edge":target_edge,
        "target_ipv4":target_ipv4,"measurements":sorted(
            measurements,key=lambda x:json.dumps(x,separators=(",",":"))
        ),
    },sort_keys=True,separators=(",",":")).encode()).hexdigest()
    body={
        "version":1,"generation":generation,"observed_at":first,
        "expires_at":first+MAX_AGE_SECONDS,
        "target_edge":target_edge,"target_ipv4":target_ipv4,
        "checks":{check:True for check in sorted(REQUIRED_CHECKS)},
        "accounts":sorted(accounts,key=lambda x:x["username"]),
    }
    if now >= body["expires_at"]:
        raise A4ObserverHold("A4_OBSERVATION_EXPIRED")
    raw=json.dumps(body,sort_keys=True,separators=(",",":")).encode()
    decode_evidence(raw,now=now)  # canonical recipient schema, no shortcuts
    return raw


def sign_offcore_observation(
    *, probes: tuple[IndependentProbeReceipt, ...],
    sessions: tuple[IndependentSessionReceipt, ...],
    target_edge: str, target_ipv4: str,
    key_path: Path = PRIVATE_KEY,
    geteuid: Callable[[],int] = os.geteuid,
    clock: Callable[[],int] = lambda: int(time.time()),
    run: Callable = subprocess.run,
) -> tuple[bytes,bytes]:
    """Sign ONLY a fresh A4 report assembled in this call, never on Core.

    Source flag is not a deploy switch. The signer must be installed on a
    different physical host and its private key must never be distributed
    with Git, the bot or the Core public verification material.
    """
    if (not A4_OFFCORE_SIGNING_ENABLED or key_path != PRIVATE_KEY
        or not callable(geteuid) or geteuid() <= 0
        or not callable(run)):
        raise A4ObserverHold("A4_OFFCORE_SIGNER_NOT_RELEASED")
    now=clock()
    raw=build_observation_report(
        probes=probes,sessions=sessions,target_edge=target_edge,
        target_ipv4=target_ipv4,now=now,
    )
    try:
        info=key_path.lstat()
        parent=key_path.parent.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid not in (0,geteuid())
            or stat.S_IMODE(parent.st_mode) & 0o022):
            raise A4ObserverHold("A4_SIGNER_KEY_OWNERSHIP_INVALID")
        result=run(
            ["openssl","dgst","-sha256","-sign",str(key_path),"-"],
            input=raw,capture_output=True,check=False,timeout=4,
        )
        if result.returncode != 0 or not isinstance(result.stdout,bytes):
            raise A4ObserverHold("A4_SIGNING_FAILED")
        if not 1 <= len(result.stdout) <= 4096:
            raise A4ObserverHold("A4_INVALID_SIGNATURE_SIZE")
        return raw,result.stdout
    except A4ObserverHold:
        raise
    except (OSError,ValueError,TypeError,AttributeError,subprocess.TimeoutExpired) as exc:
        raise A4ObserverHold("A4_SIGNER_OR_REPORT_UNAVAILABLE") from exc
