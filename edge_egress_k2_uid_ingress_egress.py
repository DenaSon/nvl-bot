"""K2 M4 read-only per-UID SSH ingress -> protected egress binding.

This root-owned artifact supplements (never replaces) the existing protected
UID runtime, v1 PAM admission and live wg0 AllowedIPs ownership. It cannot
install PAM, change a route, issue P3 tickets or switch the global mode.

No production reader is enabled by importing this module. Enrollment must
first persist the source identity under the original 6G lease and fail-closed
per-UID protection; this module is only the admission-side primitive.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
import re

from edge_egress_uid_runtime_store import RuntimeBinding
from edge_egress_v1_admission import _trusted_bytes, _trusted_directory

ROOT_BINDINGS = Path("/etc/nvl-egress/k2-m4/uid-ingress-egress.json")
MAX_BINDING_BYTES = 262144

# Original-6G P3 precommit-only policy stage. Inert until root host acceptance.
K2_M4_POLICY_STAGE_ENABLED = False
_EDGE = re.compile(r"[a-z][a-z0-9_-]{1,23}\Z")
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
FIELDS = frozenset(("username", "uid", "ingress_edge", "ingress_ipv4",
                    "egress_edge", "egress_ipv4", "ingress_wg_public_key", "runtime_generation",
                    "operation_id", "guard_sha256"))


class IngressEgressHold(ValueError):
    pass


@dataclass(frozen=True)
class UIDIngressEgressBinding:
    username: str
    uid: int
    ingress_edge: str
    ingress_ipv4: str
    egress_edge: str
    egress_ipv4: str
    ingress_wg_public_key: str
    runtime_generation: int
    operation_id: int
    guard_sha256: str

    def matches_runtime(self, row: RuntimeBinding, *,
                        installed_guard_sha256: str | None = None) -> bool:
        return (
            type(row) is RuntimeBinding
            and row.username == self.username and row.uid == self.uid
            and row.edge_id == self.egress_edge
            and row.edge_ipv4 == self.egress_ipv4
            and row.state == "PROTECTED"
            and row.generation == self.runtime_generation
            and row.last_operation_id == self.operation_id
            and type(installed_guard_sha256) is str
            and installed_guard_sha256 == self.guard_sha256
        )


def _public_ipv4(value: object) -> bool:
    if type(value) is not str:
        return False
    try:
        parsed = ipaddress.IPv4Address(value)
        return str(parsed) == value and parsed.is_global
    except (ValueError, ipaddress.AddressValueError):
        return False


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IngressEgressHold("DUPLICATE_BINDING_JSON_FIELD")
        result[key] = value
    return result


def parse_uid_ingress_egress_bindings(raw: bytes) -> dict[str, UIDIngressEgressBinding]:
    """Strict operator-generated snapshot; absence/duplicates are not approval."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_BINDING_BYTES:
        raise IngressEgressHold("INGRESS_EGRESS_BINDINGS_SIZE")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        if (type(obj) is not dict or set(obj) != {"version", "bindings"}
            or type(obj["version"]) is not int or obj["version"] != 2
            or type(obj["bindings"]) is not list
            or len(obj["bindings"]) > 2000):
            raise IngressEgressHold("INGRESS_EGRESS_BINDINGS_SCHEMA")
        from edge_egress_v1_ingress import _key
        result = {}
        seen_uids = set()
        for item in obj["bindings"]:
            if type(item) is not dict or set(item) != FIELDS:
                raise IngressEgressHold("INGRESS_EGRESS_RECORD_SCHEMA")
            b = UIDIngressEgressBinding(**item)
            if (type(b.username) is not str or not _USER.fullmatch(b.username)
                or b.username in {"root", "nobody"}
                or type(b.uid) is not int or not 1000 <= b.uid < 60000
                or type(b.ingress_edge) is not str
                or not _EDGE.fullmatch(b.ingress_edge)
                or type(b.egress_edge) is not str
                or not _EDGE.fullmatch(b.egress_edge)
                or b.ingress_edge == b.egress_edge
                or not _public_ipv4(b.ingress_ipv4)
                or not _public_ipv4(b.egress_ipv4)
                or b.ingress_ipv4 == b.egress_ipv4
                or type(b.ingress_wg_public_key) is not str
                or type(b.runtime_generation) is not int
                or b.runtime_generation < 1
                or type(b.operation_id) is not int or b.operation_id <= 0
                or type(b.guard_sha256) is not str
                or not re.fullmatch(r"[a-f0-9]{64}", b.guard_sha256)
                or b.username in result or b.uid in seen_uids):
                raise IngressEgressHold("INGRESS_EGRESS_IDENTITY_INVALID")
            try:
                _key(b.ingress_wg_public_key)
            except ValueError as exc:
                raise IngressEgressHold("INGRESS_WG_KEY_INVALID") from exc
            seen_uids.add(b.uid)
            result[b.username] = b
        return result
    except (UnicodeError, ValueError, TypeError, KeyError) as exc:
        raise IngressEgressHold("INGRESS_EGRESS_BINDINGS_INVALID") from exc


def verify_readonly_cross_edge_ingress(
    *, policy: UIDIngressEgressBinding, runtime: RuntimeBinding,
    installed_guard_sha256: str, pam_rhost: str,
    peers: tuple, wg_allowed_ips: str,
) -> bool:
    """Pure source/WG + independent protected egress comparison.

    The source is *PAM_RHOST*, not the DB historical host or DNS/default.
    The root policy must pin the exact WG key, committed 6G op+generation
    and installed boot guard. A separate live kernel/DNS/6G/PAM gate still
    has to authorize login; THIS IS NOT INSTALLED IN THE PAM PATH.
    """
    try:
        from edge_egress_v1_ingress import (
            IngressPeer, NET, _ip, _networks, parse_registry, render_registry,
        )
        from ipaddress import ip_network
        if (type(policy) is not UIDIngressEgressBinding
            or not policy.matches_runtime(
                runtime,installed_guard_sha256=installed_guard_sha256)
            or type(peers) is not tuple or not peers
            or any(type(p) is not IngressPeer for p in peers)
            or type(wg_allowed_ips) is not str):
            return False
        # Reparse the original validated root WireGuard registry schema;
        # never allow an ambiguous peer/key/source within a single snapshot.
        trusted=parse_registry(render_registry(list(peers)).encode("utf-8"))
        rhost=_ip(pam_rhost)
        if rhost not in NET:
            return False
        matching=[p for p in trusted if p.ingress_ipv4==str(rhost)]
        if len(matching)!=1:
            return False
        peer=matching[0]
        if (peer.edge_id!=policy.ingress_edge
            or peer.edge_ipv4!=policy.ingress_ipv4
            or peer.wg_public_key!=policy.ingress_wg_public_key):
            return False
        live=_networks(wg_allowed_ips)
        network=ip_network(str(rhost)+"/32")
        if network not in live.get(peer.wg_public_key,()):
            return False
        if any(rhost in n for key,nets in live.items()
               if key!=peer.wg_public_key for n in nets):
            return False
        return True
    except (OSError,ValueError,TypeError,KeyError):
        return False



def probe_root_cross_edge_ingress(
    row: RuntimeBinding, pam_rhost: str, installed_guard_sha256: str,
) -> bool:
    """Read-only PAM-side proof for a committed cross-Edge PROTECTED UID.

    This is not a migration writer or release flag. The exact installed
    guard digest is supplied by the already-verified V1 roster/manifest.
    No historical host, default Edge, DNS or Telegram input can authorize
    an alternate ingress.
    """
    if (type(row) is not RuntimeBinding or row.state != "PROTECTED"
        or type(installed_guard_sha256) is not str):
        return False
    try:
        import subprocess
        from edge_egress_v1_ingress import load_registry
        binding = load_root_uid_ingress_egress_bindings().get(row.username)
        if binding is None:
            return False
        peers = load_registry()
        result = subprocess.run(
            ["wg", "show", "wg0", "allowed-ips"],
            text=True, capture_output=True, timeout=3, check=False,
        )
        return (result.returncode == 0
                and verify_readonly_cross_edge_ingress(
                    policy=binding, runtime=row,
                    installed_guard_sha256=installed_guard_sha256,
                    pam_rhost=pam_rhost, peers=peers,
                    wg_allowed_ips=result.stdout,
                ))
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        return False


def load_root_uid_ingress_egress_bindings(
    path: Path = ROOT_BINDINGS,
) -> dict[str, UIDIngressEgressBinding]:
    """Read fixed root-only file; never follow symlink or accept another path."""
    if path != ROOT_BINDINGS or not path.is_absolute():
        raise IngressEgressHold("INGRESS_EGRESS_PATH_NOT_PINNED")
    try:
        _trusted_directory(path.parent)
        return parse_uid_ingress_egress_bindings(
            _trusted_bytes(path, MAX_BINDING_BYTES)
        )
    except (OSError, ValueError) as exc:
        raise IngressEgressHold("INGRESS_EGRESS_ROOT_SOURCE_UNTRUSTED") from exc

def stage_6g_cross_edge_binding(
    *, db_conn, scope, ticket, source_evidence, geteuid,
    release_enabled: bool = False,
) -> UIDIngressEgressBinding:
    """Root-only CAS of future-PROTECTED PAM identity *before* F2 commit.

    Called by the original P3 UID port ONLY after ROUTED_UNVERIFIED and
    independent packet/DNS/IPv6 evidence, while original 6G is RUNNING.
    The staged record carries generation+1 and remains non-admitting until
    original F2 commit_protected succeeds. A failed CAS preserves 6G HOLD.
    Existing policy entries and other UIDs cannot be silently changed.
    """
    import os
    import tempfile
    from dataclasses import asdict
    from edge_egress_p3_executor import (
        ExecutionScope, ExecutionTicket, assert_guarded_6g_intent,
    )
    from edge_egress_uid_runtime_store import read_binding
    from edge_egress_v1_admission import load_roster, checked_guard
    from edge_egress_k2_m2_ingress_journal import (
        RootReadOnlyIngressEvidence, _validated as parse_authenticated_pam_journal,
    )
    from edge_egress_v1_ingress import IngressPeer

    if (not K2_M4_POLICY_STAGE_ENABLED or release_enabled is not True
        or not callable(db_conn) or not callable(source_evidence)
        or not callable(geteuid) or geteuid() != 0
        or not isinstance(scope, ExecutionScope)
        or scope.action != "UID_ATTACH"
        or not isinstance(ticket, ExecutionTicket)):
        raise IngressEgressHold("K2_POLICY_STAGE_NOT_RELEASED")
    op_id = assert_guarded_6g_intent(db_conn, scope, ticket)

    def inspect() -> UIDIngressEgressBinding:
        # Typed fresh root PAM journal already checks real live WG ownership;
        # an unrelated Telegram callback cannot provide root source records.
        observed = source_evidence()
        if type(observed) is not RootReadOnlyIngressEvidence:
            raise IngressEgressHold("K2_ROOT_PAM_WG_SOURCE_REQUIRED")
        witness = observed(scope.username)
        # Pin the exact PAM_RHOST/WG key from authenticated root journal,
        # not an arbitrary peer using the same ingress Edge public IP.
        journal_record = parse_authenticated_pam_journal(observed.raw).get(
            scope.username
        )
        matches = [
            p for p in observed.peers if type(p) is IngressPeer
            and journal_record is not None
            and p.edge_id == journal_record.edge_id
            and p.edge_ipv4 == journal_record.edge_ipv4
            and p.ingress_ipv4 == journal_record.ingress_ipv4
            and p.wg_public_key == journal_record.wg_public_key
        ]
        if (witness.username != scope.username
            or witness.edge_ipv4 != scope.source_host
            or witness.edge_id == scope.edge_id
            or journal_record is None
            or journal_record.uid != scope.uid
            or journal_record.username != scope.username
            or len(matches) != 1):
            raise IngressEgressHold("K2_PAM_INGRESS_SCOPE_CHANGED")
        roster = load_roster()
        member = roster.get(scope.username)
        if (member is None or member.uid != scope.uid):
            raise IngressEgressHold("K2_INSTALLED_GUARD_IDENTITY_MISSING")
        manifest = checked_guard(member)
        if (manifest.request.username != scope.username
            or manifest.request.uid != scope.uid
            or manifest.request.spec.edge_id != scope.edge_id
            or manifest.request.spec.edge_public_ipv4 != scope.target_host):
            raise IngressEgressHold("K2_BOOT_GUARD_NOT_AT_TARGET")
        with db_conn() as db:
            row = read_binding(db, scope.username)
            global_mode = db.execute(
                "SELECT value FROM settings "
                "WHERE key='edge_egress_protected_mode'"
            ).fetchone()
        if (type(row) is not RuntimeBinding
            or row.uid != scope.uid or row.edge_id != scope.edge_id
            or row.edge_ipv4 != scope.target_host
            or row.state != "ROUTED_UNVERIFIED"
            or row.last_operation_id != op_id
            or type(row.generation) is not int
            or row.generation < 1 or global_mode != ("0",)):
            raise IngressEgressHold("K2_UNCOMMITTED_F2_SCOPE_NOT_PINNED")
        record = UIDIngressEgressBinding(
            username=scope.username, uid=scope.uid,
            ingress_edge=witness.edge_id, ingress_ipv4=witness.edge_ipv4,
            egress_edge=scope.edge_id, egress_ipv4=scope.target_host,
            ingress_wg_public_key=matches[0].wg_public_key,
            runtime_generation=row.generation + 1,
            operation_id=op_id, guard_sha256=member.guard_sha256,
        )
        parse_uid_ingress_egress_bindings(
            json.dumps({"version": 2, "bindings": [asdict(record)]}).encode()
        )
        return record

    before_record = inspect()
    try:
        _trusted_directory(ROOT_BINDINGS.parent)
        raw_before = _trusted_bytes(ROOT_BINDINGS, MAX_BINDING_BYTES)
        existing = parse_uid_ingress_egress_bindings(raw_before)
    except (OSError, ValueError) as exc:
        raise IngressEgressHold("K2_ROOT_POLICY_FILE_UNTRUSTED") from exc
    if (scope.username in existing
        or any(record.uid == scope.uid for record in existing.values())
        or len(existing) >= 2000):
        raise IngressEgressHold("K2_POLICY_IDENTITY_ALREADY_PRESENT")
    new_rows = [asdict(record) for record in existing.values()]
    new_rows.append(asdict(before_record))
    encoded = (json.dumps(
        {"version": 2, "bindings": sorted(
            new_rows, key=lambda item: item["username"]
        )}, sort_keys=True, separators=(",", ":")
    ) + "\n").encode("utf-8")
    if len(encoded) > MAX_BINDING_BYTES:
        raise IngressEgressHold("K2_POLICY_FILE_TOO_LARGE")
    parse_uid_ingress_egress_bindings(encoded)
    fd, path = tempfile.mkstemp(
        prefix=".uid-ingress-egress-", dir=ROOT_BINDINGS.parent
    )
    temporary = Path(path)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        if (inspect() != before_record
            or assert_guarded_6g_intent(db_conn, scope, ticket) != op_id):
            raise IngressEgressHold("K2_POLICY_SCOPE_DRIFT_BEFORE_CAS")
        try:
            current = _trusted_bytes(ROOT_BINDINGS, MAX_BINDING_BYTES)
        except (OSError, ValueError) as exc:
            raise IngressEgressHold("K2_POLICY_FILE_CHANGED") from exc
        if current != raw_before:
            raise IngressEgressHold("K2_POLICY_CAS_LOST")
        os.replace(temporary, ROOT_BINDINGS)
        parent_fd = os.open(
            ROOT_BINDINGS.parent, os.O_RDONLY | os.O_DIRECTORY
        )
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
        # A post-commit filesystem error is HOLD, never a synthetic PASS.
        if _trusted_bytes(ROOT_BINDINGS, MAX_BINDING_BYTES) != encoded:
            raise IngressEgressHold("K2_POLICY_DURABILITY_UNVERIFIED")
        return before_record
    finally:
        if temporary.exists():
            temporary.unlink()
