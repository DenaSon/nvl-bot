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
_EDGE = re.compile(r"[a-z][a-z0-9_-]{1,23}\\Z")
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\\Z")
FIELDS = frozenset(("username", "uid", "ingress_edge", "ingress_ipv4",
                    "egress_edge", "egress_ipv4"))


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

    def matches_runtime(self, row: RuntimeBinding) -> bool:
        return (
            type(row) is RuntimeBinding
            and row.username == self.username and row.uid == self.uid
            and row.edge_id == self.egress_edge
            and row.edge_ipv4 == self.egress_ipv4
            and row.state == "PROTECTED"
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
            or type(obj["version"]) is not int or obj["version"] != 1
            or type(obj["bindings"]) is not list
            or len(obj["bindings"]) > 2000):
            raise IngressEgressHold("INGRESS_EGRESS_BINDINGS_SCHEMA")
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
                or b.username in result or b.uid in seen_uids):
                raise IngressEgressHold("INGRESS_EGRESS_IDENTITY_INVALID")
            seen_uids.add(b.uid)
            result[b.username] = b
        return result
    except (UnicodeError, ValueError, TypeError, KeyError) as exc:
        raise IngressEgressHold("INGRESS_EGRESS_BINDINGS_INVALID") from exc


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
