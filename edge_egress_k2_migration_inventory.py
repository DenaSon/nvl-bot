"""K2 M1: shared SINGLE/BATCH read-only SSH UID and ingress inventory.

This is an evidence *preview*, never a customer executor, F4 witness, trusted
OS inventory or replacement for the existing P3-A / 6G guarded flow.  DB
host metadata is never accepted as proof of the customer's actual ingress.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from ipaddress import IPv4Address
import json
import pwd
import re
import sqlite3
import time
from typing import Callable

from edge_egress_f3_readiness import admission_eligible, read_readiness

M1_EXECUTION_ENABLED = False
_MAX_ACTIVE = 10000
_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_EDGE = re.compile(r"[a-z][a-z0-9_-]{1,23}\Z")
_SOURCE_TTL_SECONDS = 300


class MigrationInventoryHold(ValueError):
    """Invalid or unavailable inventory; never interpret as permission to move."""


@dataclass(frozen=True)
class MigrationSelection:
    mode: str  # SINGLE or BATCH; batch_size=1 is allowed for parity tests
    usernames: tuple[str, ...]
    target_edge_id: str


@dataclass(frozen=True)
class LiveIngressWitness:
    """A value returned by a separately trusted LIVE session/peer observer.

    It is deliberately *not* derivable from ssh_accounts.host, host_pool or
    the user's requested target. M1 only bounds and records this evidence;
    M2/M3 must independently establish its authenticity and bind it to 6G.
    """
    username: str
    edge_id: str
    edge_ipv4: str
    observed_at: int
    proof_kind: str  # INDEPENDENT_LIVE only


@dataclass(frozen=True)
class UserInventory:
    username: str
    historical_host: str
    host_class: str
    uid: int | None
    source_edge_id: str
    source_ipv4: str
    source_proven: bool
    protected_edge_id: str
    active_sessions: int | None
    issues: tuple[str, ...]
    selected: bool

    @property
    def needs_review(self) -> bool:
        return not self.source_proven or bool(self.issues)


@dataclass(frozen=True)
class MigrationInventory:
    selection: MigrationSelection
    target_ipv4: str
    active_total: int
    selected_total: int
    host_counts: tuple[tuple[str, int], ...]
    accounts: tuple[UserInventory, ...]
    global_issues: tuple[str, ...]
    fingerprint: str
    target_f4_accepted: bool

    @property
    def needs_review_count(self) -> int:
        return sum(a.needs_review for a in self.accounts)

    @property
    def selected_issues(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(
            issue for account in self.accounts if account.selected
            for issue in account.issues
        ))

    @property
    def inventory_clear(self) -> bool:
        """Metadata/evidence preview only, NOT a live change authorization."""
        return (not self.global_issues and not self.selected_issues
                and self.selected_total == len(self.selection.usernames))

    @property
    def can_execute(self) -> bool:
        # M1 has no ticket, no privileged worker and no root attestation.
        return False


def select_migration(mode: str, usernames: tuple[str, ...] | list[str],
                     target_edge_id: str) -> MigrationSelection:
    if mode not in ("SINGLE", "BATCH") or type(mode) is not str:
        raise MigrationInventoryHold("INVALID_SELECTION_MODE")
    if not isinstance(usernames, (list, tuple)):
        raise MigrationInventoryHold("INVALID_USER_SELECTION")
    if not usernames or len(usernames) > _MAX_ACTIVE:
        raise MigrationInventoryHold("INVALID_USER_COUNT")
    if any(not isinstance(n, str) or not _NAME.fullmatch(n) for n in usernames):
        raise MigrationInventoryHold("INVALID_USERNAME")
    if len(set(usernames)) != len(usernames):
        raise MigrationInventoryHold("DUPLICATE_SELECTED_USERNAME")
    if mode == "SINGLE" and len(usernames) != 1:
        raise MigrationInventoryHold("SINGLE_REQUIRES_ONE_USERNAME")
    if not isinstance(target_edge_id, str) or not _EDGE.fullmatch(target_edge_id):
        raise MigrationInventoryHold("INVALID_TARGET_EDGE_ID")
    return MigrationSelection(mode, tuple(usernames), target_edge_id)


def _ipv4(value: object) -> bool:
    try:
        return (type(value) is str and str(IPv4Address(value)) == value
                and IPv4Address(value).is_global)
    except (ValueError, TypeError):
        return False


def _tables(conn) -> set[str]:
    return {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}


def _reason(account_issues: list[str], code: str) -> None:
    if code not in account_issues:
        account_issues.append(code)


def _observation(witness: object, name: str, known_edges: dict[str, str],
                 now: int, issues: list[str]) -> tuple[str, str, bool]:
    if witness is None:
        _reason(issues, "SOURCE_INGRESS_NOT_ATTESTED")
        return "", "", False
    if (not isinstance(witness, LiveIngressWitness)
            or witness.username != name or witness.proof_kind != "INDEPENDENT_LIVE"
            or type(witness.observed_at) is not int
            or not 0 <= now - witness.observed_at <= _SOURCE_TTL_SECONDS
            or not _ipv4(witness.edge_ipv4)
            or known_edges.get(witness.edge_id) != witness.edge_ipv4):
        _reason(issues, "SOURCE_WITNESS_INVALID_OR_STALE")
        return "", "", False
    return witness.edge_id, witness.edge_ipv4, True


def preview_migration(
    db_conn: Callable, selection: MigrationSelection, *,
    os_uid: Callable[[str], int] = lambda name: pwd.getpwnam(name).pw_uid,
    ingress_witness: Callable[[str], LiveIngressWitness | None] | None = None,
    session_count: Callable[[str, int], int | None] | None = None,
    now: int | None = None,
) -> MigrationInventory:
    """Inventory all active SSH rows, and assess only explicitly selected UIDs.

    Missing active user/target/schema and internal duplicate UID mappings
    fail closed. A lack of historical host_pool membership is *classified*,
    never silently used as an ingress identity or mass-cohort blocker.

    The trusted external ingress/session providers are injectable to keep M1
    fully read-only and testable; a callback is NOT independently accepted as
    F4/PAM/root/packet safety or proof that later live state cannot drift.
    """
    if not isinstance(selection, MigrationSelection):
        raise MigrationInventoryHold("SELECTION_REQUIRED")
    # Defensive re-validation even if callers bypass select_migration.
    if select_migration(selection.mode, selection.usernames,
                        selection.target_edge_id) != selection:
        raise MigrationInventoryHold("SELECTION_MUTATED")
    stamp = int(time.time()) if now is None else now
    if type(stamp) is not int or stamp <= 0:
        raise MigrationInventoryHold("INVALID_REVIEW_TIME")
    if not callable(db_conn) or not callable(os_uid):
        raise MigrationInventoryHold("UNTRUSTED_INVENTORY_PROVIDERS")
    if ingress_witness is not None and not callable(ingress_witness):
        raise MigrationInventoryHold("UNTRUSTED_INGRESS_PROVIDER")
    if session_count is not None and not callable(session_count):
        raise MigrationInventoryHold("UNTRUSTED_SESSION_PROVIDER")

    global_issues: list[str] = []
    accounts: list[UserInventory] = []
    selected_names = set(selection.usernames)
    target_ip = ""
    target_f4 = False
    readiness_identity = None
    counts: dict[str, int] = {}
    os_uids: dict[int, str] = {}
    frozen_source: list[tuple[object, ...]] = []
    try:
        with db_conn() as conn:
            required = {
                "ssh_accounts", "host_pool", "edge_egress_allocations",
                "edge_egress_readiness", "edge_egress_uid_runtime",
                "edge_egress_uid_bindings", "failover_operations",
            }
            if not required.issubset(_tables(conn)):
                raise MigrationInventoryHold("M1_CONTROL_SCHEMA_UNAVAILABLE")

            hosts = conn.execute(
                "SELECT host,active,is_default FROM host_pool ORDER BY host"
            ).fetchall()
            active_pool = {h for h,active,_ in hosts if active == 1 and _ipv4(h)}
            known_pool = {h for h,_,_ in hosts if _ipv4(h)}
            defaults = [h for h,active,default in hosts if active == 1 and default == 1]
            if len(defaults) != 1 or not _ipv4(defaults[0]):
                global_issues.append("DEFAULT_RELAY_UNVERIFIED")

            allocations = conn.execute(
                "SELECT edge_id,edge_public_ipv4,status,route_table "
                "FROM edge_egress_allocations ORDER BY edge_id"
            ).fetchall()
            by_edge = {eid: ip for eid,ip,status,table in allocations
                       if _ipv4(ip) and status == "STAGED"}
            targets = [r for r in allocations if r[0] == selection.target_edge_id]
            if len(targets) != 1 or targets[0][2] != "STAGED" or not _ipv4(targets[0][1]):
                global_issues.append("TARGET_F3_NOT_STAGED")
            else:
                target_ip = targets[0][1]
                if (type(targets[0][3]) is not int or
                        not 1 <= targets[0][3] <= 2**31-1):
                    global_issues.append("TARGET_ROUTE_TABLE_INVALID")
                if sum(r[1] == target_ip for r in allocations) != 1:
                    global_issues.append("TARGET_EGRESS_IDENTITY_COLLISION")
                readiness = read_readiness(conn, selection.target_edge_id)
                if readiness is not None:
                    readiness_identity = (
                        readiness.edge_id,readiness.edge_ipv4,readiness.state,
                        readiness.observed_ipv4,readiness.witness,
                        readiness.probed_at,readiness.expires_at,
                        readiness.generation,readiness.last_operation_id,
                    )
                target_f4 = bool(readiness and readiness.edge_ipv4 == target_ip
                                 and admission_eligible(readiness, now=stamp))
                if not target_f4:
                    global_issues.append("TARGET_F4_NOT_ACCEPTED")

            if conn.execute(
                "SELECT 1 FROM failover_operations WHERE status='RUNNING' LIMIT 1"
            ).fetchone():
                global_issues.append("SHARED_6G_BUSY")

            runtime = conn.execute(
                "SELECT username,uid,edge_id,edge_ipv4,state "
                "FROM edge_egress_uid_runtime ORDER BY username"
            ).fetchall()
            bindings = conn.execute(
                "SELECT username,uid,edge_id,edge_ipv4,status "
                "FROM edge_egress_uid_bindings ORDER BY username"
            ).fetchall()
            by_runtime = {r[0]: r for r in runtime}
            by_binding = {r[0]: r for r in bindings}
            if (len(by_runtime) != len(runtime) or len(by_binding) != len(bindings)):
                global_issues.append("DUPLICATE_PROTECTED_IDENTITY")

            rows = conn.execute(
                "SELECT username,host FROM ssh_accounts "
                "WHERE service_type='ssh' AND status LIKE '%فعال%' "
                "AND status NOT LIKE '%غیر%' ORDER BY username,host"
            ).fetchall()
            if len(rows) > _MAX_ACTIVE:
                raise MigrationInventoryHold("ACTIVE_COHORT_TOO_LARGE")
            names = set()
            for name,host in rows:
                frozen_source.append((name,host))
                issues: list[str] = []
                selected = name in selected_names
                if (not isinstance(name,str) or not _NAME.fullmatch(name)
                        or name in names):
                    _reason(issues,"DUPLICATE_OR_INVALID_ACTIVE_ACCOUNT")
                if isinstance(name,str):
                    names.add(name)
                historical = host if isinstance(host,str) else ""
                if target_ip and historical == target_ip:
                    category = "TARGET_METADATA"
                elif historical in active_pool:
                    category = "ACTIVE_POOL_METADATA"
                elif historical in known_pool:
                    category = "INACTIVE_POOL_METADATA"
                elif _ipv4(historical):
                    category = "UNPOOLED_HISTORICAL_METADATA"
                else:
                    category = "UNRESOLVED_HISTORICAL_METADATA"
                counts[category] = counts.get(category,0)+1

                uid = None
                if isinstance(name,str) and _NAME.fullmatch(name):
                    try:
                        result = os_uid(name)
                        if type(result) is int and 1000 <= result < 60000:
                            uid = result
                    except (KeyError, OSError, ValueError, TypeError):
                        pass
                if uid is None:
                    _reason(issues,"ACCOUNT_UID_NOT_ATTESTED")
                elif uid in os_uids and os_uids[uid] != name:
                    _reason(issues,"DUPLICATE_LINUX_UID")
                else:
                    os_uids[uid] = name

                rr,bb = by_runtime.get(name),by_binding.get(name)
                protected_edge = ""
                if (rr is None) != (bb is None):
                    _reason(issues,"PARTIAL_PROTECTED_IDENTITY")
                elif rr is not None and bb is not None:
                    if (uid is None or rr[:2] != (name,uid)
                            or bb[:2] != (name,uid)
                            or rr[2:] != bb[2:]
                            or rr[4] != "PROTECTED"
                            or by_edge.get(rr[2]) != rr[3]):
                        _reason(issues,"PROTECTED_IDENTITY_CONFLICT")
                    else:
                        protected_edge = rr[2]

                source_edge = source_ip = ""
                source_proven = False
                sessions = None
                if not selected:
                    # Nonselected accounts are inventoried, not silently
                    # given a trusted ingress solely from DB host metadata.
                    _reason(issues,"SOURCE_INGRESS_NOT_ATTESTED")
                if selected:
                    if ingress_witness is None:
                        _reason(issues,"SOURCE_INGRESS_NOT_ATTESTED")
                    else:
                        try:
                            observation = ingress_witness(name)
                            source_edge,source_ip,source_proven = _observation(
                                observation,name,by_edge,stamp,issues)
                        except (KeyError,OSError,ValueError,TypeError):
                            _reason(issues,"SOURCE_INGRESS_NOT_ATTESTED")
                    # Same-edge Legacy→Protected is a valid customer
                    # enrollment route. Being already PROTECTED on the
                    # target is a different (idempotent/no-op) condition.
                    if source_proven and protected_edge == selection.target_edge_id:
                        _reason(issues,"TARGET_ALREADY_PROTECTED")
                    if protected_edge and source_proven and protected_edge != source_edge:
                        _reason(issues,"PROTECTED_SOURCE_DRIFT")
                    if uid is not None:
                        if session_count is None:
                            _reason(issues,"SESSION_STATE_NOT_ATTESTED")
                        else:
                            try:
                                count = session_count(name,uid)
                                if type(count) is not int or count < 0:
                                    _reason(issues,"SESSION_STATE_NOT_ATTESTED")
                                else:
                                    sessions = count
                                    if count:
                                        _reason(issues,"ACTIVE_SESSIONS_PRESENT")
                            except (KeyError,OSError,ValueError,TypeError):
                                _reason(issues,"SESSION_STATE_NOT_ATTESTED")
                accounts.append(UserInventory(
                    name,historical,category,uid,
                    source_edge,source_ip,source_proven,
                    protected_edge,sessions,tuple(issues),selected,
                ))

            if not rows:
                global_issues.append("ACTIVE_COHORT_EMPTY")
            if any(name not in names for name in selection.usernames):
                global_issues.append("SELECTED_ACCOUNT_NOT_ACTIVE")
            if any("DUPLICATE_LINUX_UID" in a.issues or
                   "DUPLICATE_OR_INVALID_ACTIVE_ACCOUNT" in a.issues
                   for a in accounts):
                global_issues.append("UNSAFE_ACCOUNT_OWNERSHIP")
            if any(r[0] not in names for r in runtime + bindings):
                global_issues.append("ORPHAN_PROTECTED_IDENTITY")
            if any(r[0] not in names and r[0] in selected_names
                   for r in runtime + bindings):
                global_issues.append("SELECTED_ORPHAN_IDENTITY")

            # M1 records full inventory drift; does not bind a running 6G
            # transaction or assert the synthetic witness is real F4.
            snap = (
                selection.mode,selection.usernames,selection.target_edge_id,
                target_ip,tuple(hosts),tuple(allocations),
                readiness_identity,tuple(runtime),tuple(bindings),
                tuple(frozen_source),
                tuple((a.username,a.uid,a.source_edge_id,a.source_ipv4,
                       a.source_proven,a.protected_edge_id,a.active_sessions,
                       a.issues,a.host_class,a.selected) for a in accounts),
                tuple(global_issues),target_f4,
            )
    except MigrationInventoryHold:
        raise
    except (sqlite3.Error, OSError, TypeError, ValueError) as exc:
        raise MigrationInventoryHold("M1_READONLY_EVIDENCE_UNAVAILABLE") from exc

    fingerprint=sha256(json.dumps(snap,sort_keys=True,separators=(",",":"),
                                  ensure_ascii=False).encode("utf-8")).hexdigest()
    return MigrationInventory(
        selection,target_ip,len(accounts),len(selected_names),
        tuple(sorted(counts.items())),tuple(accounts),
        tuple(dict.fromkeys(global_issues)),fingerprint,target_f4,
    )
