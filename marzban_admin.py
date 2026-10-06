"""Administrative service layer for NVL's Marzban integration.

Phase 1 goals:
- keep Telegram handlers independent from raw Marzban HTTP details;
- provide one place for management operations and future dashboards;
- centralize the ownership rule used by V2Ray management;
- reserve a clean presentation primitive for future per-subscription display names.

This module intentionally keeps the existing ``(ok, payload)`` contract used by
``v2ray_engine`` so it can be introduced without a risky rewrite of the bot.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import v2ray_engine


ApiResult = Tuple[bool, Any]

SUBSCRIPTION_NAME_MIN_LENGTH = 2
SUBSCRIPTION_NAME_MAX_LENGTH = 30
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

MARZBAN_USER_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks"}
MARZBAN_RESET_STRATEGIES = {"no_reset", "day", "week", "month", "year"}
_USER_CREATE_USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,32}$")
_PUBLIC_HOSTNAME_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

NODE_MUTABLE_FIELDS = {"name", "address", "port", "api_port", "status", "usage_coefficient"}
NODE_MUTABLE_STATUSES = {"disabled", "connecting"}

# NVL intentionally exposes only the small, proven subset of Marzban
# inbounds on newly-added Nodes.  Marzban's native add_as_new_host switch is
# all-or-nothing, so the bot creates the Node with it disabled and reconciles
# this profile explicitly afterwards.
NVL_NODE_PUBLIC_HOST_TAGS = (
    "Shadowsocks TCP",
    "VLESS TCP REALITY",
    "VLESS TCP REALITY DIRECT",
    "Trojan WS",
)

HOST_FIELDS = (
    "remark",
    "address",
    "port",
    "sni",
    "host",
    "path",
    "security",
    "alpn",
    "fingerprint",
    "allowinsecure",
    "is_disabled",
    "mux_enable",
    "fragment_setting",
    "noise_setting",
    "random_user_agent",
    "use_sni_as_host",
)
HOST_MUTABLE_FIELDS = set(HOST_FIELDS)
HOST_SECURITY_VALUES = {"inbound_default", "none", "tls"}
HOST_ALPN_VALUES = {"", "h3", "h2", "http/1.1", "h3,h2,http/1.1", "h3,h2", "h2,http/1.1"}
HOST_FINGERPRINT_VALUES = {
    "", "chrome", "firefox", "safari", "ios", "android", "edge",
    "360", "qq", "random", "randomized",
}
HOST_BOOLEAN_FIELDS = {
    "allowinsecure",
    "is_disabled",
    "mux_enable",
    "random_user_agent",
    "use_sni_as_host",
}
_HOST_FRAGMENT_RE = re.compile(
    r"^((\d{1,4}-\d{1,4})|(\d{1,4})),((\d{1,3}-\d{1,3})|(\d{1,3})),(tlshello|\d|\d-\d)$"
)
_HOST_NOISE_RE = re.compile(
    r"^(rand:(\d{1,4}-\d{1,4}|\d{1,4})|str:.+|hex:.+|base64:.+)"
    r"(,(\d{1,4}-\d{1,4}|\d{1,4}))?"
    r"(&(rand:(\d{1,4}-\d{1,4}|\d{1,4})|str:.+|hex:.+|base64:.+)"
    r"(,(\d{1,4}-\d{1,4}|\d{1,4}))?)*$"
)


def normalize_node_id(value: Any) -> int:
    try:
        node_id = int(value)
    except (TypeError, ValueError):
        raise ValueError("node id must be an integer")
    if node_id <= 0:
        raise ValueError("node id must be positive")
    return node_id


def normalize_node_changes(changes: Dict[str, Any], *, allow_status: bool = True) -> Dict[str, Any]:
    """Validate and normalize the small subset of NodeModify exposed by NVL."""
    if not changes:
        raise ValueError("no node changes supplied")

    unsupported = set(changes) - NODE_MUTABLE_FIELDS
    if unsupported:
        raise ValueError("unsupported node fields: " + ", ".join(sorted(unsupported)))

    normalized: Dict[str, Any] = {}
    for key, value in changes.items():
        if key == "name":
            cleaned = _CONTROL_CHARS_RE.sub("", str(value or "")).strip()
            cleaned = " ".join(cleaned.split())
            if not cleaned or len(cleaned) > 80:
                raise ValueError("node name must be between 1 and 80 characters")
            normalized[key] = cleaned
        elif key == "address":
            cleaned = _CONTROL_CHARS_RE.sub("", str(value or "")).strip()
            if not cleaned or len(cleaned) > 255 or any(ch.isspace() for ch in cleaned):
                raise ValueError("node address must be a non-empty hostname or IP without spaces")
            if "://" in cleaned:
                raise ValueError("node address must not include a URL scheme")
            normalized[key] = cleaned
        elif key in {"port", "api_port"}:
            try:
                port = int(value)
            except (TypeError, ValueError):
                raise ValueError(f"{key} must be an integer")
            if not 1 <= port <= 65535:
                raise ValueError(f"{key} must be between 1 and 65535")
            normalized[key] = port
        elif key == "usage_coefficient":
            try:
                ratio = float(value)
            except (TypeError, ValueError):
                raise ValueError("usage coefficient must be a number")
            if not math.isfinite(ratio) or ratio <= 0:
                raise ValueError("usage coefficient must be a positive finite number")
            normalized[key] = ratio
        elif key == "status":
            if not allow_status:
                raise ValueError("node status cannot be changed through settings update")
            status = str(value or "").strip().lower()
            if status not in NODE_MUTABLE_STATUSES:
                raise ValueError("node status mutation must be disabled or connecting")
            normalized[key] = status

    return normalized


def _normalize_node_bool(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)

    raw = str(value or "").strip().lower()
    if raw in {"1", "true", "yes", "on", "enable", "enabled"}:
        return True
    if raw in {"0", "false", "no", "off", "disable", "disabled"}:
        return False
    raise ValueError(f"{field} must be a boolean")


def normalize_node_create(
    name: Any,
    address: Any,
    *,
    port: Any = 62050,
    api_port: Any = 62051,
    usage_coefficient: Any = 1.0,
    add_as_new_host: Any = True,
) -> Dict[str, Any]:
    """Validate and normalize Marzban's NodeCreate contract."""
    payload = normalize_node_changes(
        {
            "name": name,
            "address": address,
            "port": port,
            "api_port": api_port,
            "usage_coefficient": usage_coefficient,
        },
        allow_status=False,
    )
    payload["add_as_new_host"] = _normalize_node_bool(
        add_as_new_host,
        "add_as_new_host",
    )
    return payload


def normalize_public_hostname(value: Any) -> str:
    """Validate a stable user-facing DNS hostname for generated Public Hosts."""
    raw = _CONTROL_CHARS_RE.sub("", str(value or "")).strip().rstrip(".").lower()
    if not raw or len(raw) > 253 or any(ch.isspace() for ch in raw):
        raise ValueError("public hostname must be a non-empty DNS name without spaces")
    if "://" in raw or "/" in raw or ":" in raw or "*" in raw:
        raise ValueError("public hostname must not include scheme, path, port, or wildcard")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise ValueError("public hostname must be a DNS name, not an IP address")

    labels = raw.split(".")
    if len(labels) < 2 or any(not _PUBLIC_HOSTNAME_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("public hostname must be a valid FQDN such as edge.example.com")
    return raw


def _resolve_endpoint_ips(value: str, resolver=None) -> Tuple[str, ...]:
    """Resolve a node address/hostname to canonical IPs for DNS preflight."""
    raw = str(value or "").strip().strip("[]")
    try:
        return (str(ipaddress.ip_address(raw)),)
    except ValueError:
        pass

    if resolver is not None:
        values = resolver(raw)
        canonical = {
            str(ipaddress.ip_address(str(item).strip()))
            for item in values
            if str(item).strip()
        }
        return tuple(sorted(canonical))

    infos = socket.getaddrinfo(raw, None, type=socket.SOCK_STREAM)
    values = {
        str(ipaddress.ip_address(info[4][0]))
        for info in infos
        if info and len(info) > 4 and info[4]
    }
    return tuple(sorted(values))


def preflight_public_endpoint(
    node_address: Any,
    public_hostname: Any,
    *,
    resolver=None,
) -> Dict[str, Any]:
    """Verify the stable hostname currently resolves to the Node address."""
    node = normalize_node_changes(
        {"address": node_address},
        allow_status=False,
    )["address"]
    public = normalize_public_hostname(public_hostname)

    try:
        node_ips = _resolve_endpoint_ips(node, resolver=resolver)
    except Exception as exc:
        return {
            "ok": False,
            "node_address": node,
            "public_address": public,
            "node_ips": (),
            "public_ips": (),
            "matched_ips": (),
            "error": f"Node address resolution failed: {type(exc).__name__}: {exc}",
        }
    try:
        public_ips = _resolve_endpoint_ips(public, resolver=resolver)
    except Exception as exc:
        return {
            "ok": False,
            "node_address": node,
            "public_address": public,
            "node_ips": tuple(node_ips),
            "public_ips": (),
            "matched_ips": (),
            "error": f"Public hostname resolution failed: {type(exc).__name__}: {exc}",
        }

    node_ip_set = set(node_ips)
    public_ip_set = set(public_ips)
    matched = tuple(sorted(node_ip_set.intersection(public_ip_set)))
    if not node_ips:
        error = "Node address did not resolve to any IP"
    elif not public_ips:
        error = "Public hostname did not resolve to any IP"
    elif not public_ip_set.issubset(node_ip_set):
        error = "Public hostname resolves outside the Node address set"
    else:
        error = None
    return {
        "ok": error is None,
        "node_address": node,
        "public_address": public,
        "node_ips": tuple(node_ips),
        "public_ips": tuple(public_ips),
        "matched_ips": matched,
        "error": error,
    }


def find_duplicate_node(nodes: Any, name: Any) -> Optional[Dict[str, Any]]:
    """Return an existing Marzban node whose name matches case-insensitively."""
    expected = normalize_node_changes({"name": name}, allow_status=False)["name"].casefold()
    if not isinstance(nodes, list):
        return None

    for node in nodes:
        if not isinstance(node, dict):
            continue
        current = _CONTROL_CHARS_RE.sub("", str(node.get("name") or "")).strip()
        current = " ".join(current.split()).casefold()
        if current and current == expected:
            return node
    return None


def normalize_inbound_tag(value: Any) -> str:
    """Normalize an exact Marzban inbound tag without changing internal spaces."""
    raw = _CONTROL_CHARS_RE.sub("", str(value or "")).strip()
    if not raw or len(raw) > 255:
        raise ValueError("inbound tag must be between 1 and 255 characters")
    if "," in raw:
        raise ValueError("inbound tag cannot contain commas")
    return raw


def normalize_host_index(value: Any) -> int:
    try:
        index = int(value)
    except (TypeError, ValueError):
        raise ValueError("host index must be an integer")
    if index < 0:
        raise ValueError("host index must be zero or greater")
    return index


def _normalize_host_bool(value: Any, field: str) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raw = str(value).strip().lower()
    if raw in {"", "-", "none", "null"}:
        return None
    if raw in {"1", "true", "yes", "on", "enable", "enabled"}:
        return True
    if raw in {"0", "false", "no", "off", "disable", "disabled"}:
        return False
    raise ValueError(f"{field} must be true, false, or unset")


def normalize_host_changes(changes: Dict[str, Any]) -> Dict[str, Any]:
    """Validate the official Marzban ProxyHost fields exposed by NVL."""
    if not changes:
        raise ValueError("no host changes supplied")

    unsupported = set(changes) - HOST_MUTABLE_FIELDS
    if unsupported:
        raise ValueError("unsupported host fields: " + ", ".join(sorted(unsupported)))

    normalized: Dict[str, Any] = {}
    for key, value in changes.items():
        if key == "remark":
            cleaned = _CONTROL_CHARS_RE.sub("", str(value or "")).strip()
            cleaned = " ".join(cleaned.split())
            if not cleaned or len(cleaned) > 160:
                raise ValueError("host remark must be between 1 and 160 characters")
            normalized[key] = cleaned
        elif key == "address":
            cleaned = _CONTROL_CHARS_RE.sub("", str(value or "")).strip()
            if (
                not cleaned
                or len(cleaned) > 255
                or any(ch.isspace() for ch in cleaned)
                or "://" in cleaned
            ):
                raise ValueError("host address must be a hostname/IP without spaces or URL scheme")
            normalized[key] = cleaned
        elif key == "port":
            if value is None or str(value).strip().lower() in {"", "-", "none", "null"}:
                normalized[key] = None
            else:
                try:
                    port = int(value)
                except (TypeError, ValueError):
                    raise ValueError("host port must be an integer or unset")
                if not 1 <= port <= 65535:
                    raise ValueError("host port must be between 1 and 65535")
                normalized[key] = port
        elif key in {"sni", "host"}:
            if value is None or str(value).strip().lower() in {"", "-", "none", "null"}:
                normalized[key] = None
            else:
                cleaned = _CONTROL_CHARS_RE.sub("", str(value)).strip()
                if (
                    len(cleaned) > 255
                    or any(ch.isspace() for ch in cleaned)
                    or "://" in cleaned
                ):
                    raise ValueError(f"{key} must not contain spaces or a URL scheme")
                normalized[key] = cleaned
        elif key == "path":
            if value is None or str(value).strip().lower() in {"", "-", "none", "null"}:
                normalized[key] = None
            else:
                cleaned = _CONTROL_CHARS_RE.sub("", str(value)).strip()
                if len(cleaned) > 1024:
                    raise ValueError("host path must be at most 1024 characters")
                normalized[key] = cleaned
        elif key == "security":
            cleaned = str(value or "").strip().lower()
            if cleaned not in HOST_SECURITY_VALUES:
                raise ValueError("security must be inbound_default, none, or tls")
            normalized[key] = cleaned
        elif key == "alpn":
            cleaned = str(value or "").strip().lower()
            if cleaned in {"-", "none", "null"}:
                cleaned = ""
            if cleaned not in HOST_ALPN_VALUES:
                raise ValueError("unsupported ALPN value")
            normalized[key] = cleaned
        elif key == "fingerprint":
            cleaned = str(value or "").strip().lower()
            if cleaned in {"-", "none", "null"}:
                cleaned = ""
            if cleaned not in HOST_FINGERPRINT_VALUES:
                raise ValueError("unsupported fingerprint value")
            normalized[key] = cleaned
        elif key in HOST_BOOLEAN_FIELDS:
            normalized[key] = _normalize_host_bool(value, key)
        elif key == "fragment_setting":
            if value is None or str(value).strip().lower() in {"", "-", "none", "null"}:
                normalized[key] = None
            else:
                cleaned = _CONTROL_CHARS_RE.sub("", str(value)).strip()
                if not _HOST_FRAGMENT_RE.fullmatch(cleaned):
                    raise ValueError("invalid Marzban fragment setting")
                normalized[key] = cleaned
        elif key == "noise_setting":
            if value is None or str(value).strip().lower() in {"", "-", "none", "null"}:
                normalized[key] = None
            else:
                cleaned = _CONTROL_CHARS_RE.sub("", str(value)).strip()
                if len(cleaned) > 2000 or not _HOST_NOISE_RE.fullmatch(cleaned):
                    raise ValueError("invalid Marzban noise setting")
                normalized[key] = cleaned

    return normalized


def host_snapshot(host: Dict[str, Any]) -> Dict[str, Any]:
    """Canonical snapshot used to detect stale/replayed host confirmations."""
    if not isinstance(host, dict):
        raise ValueError("invalid Marzban host")
    return {field: host.get(field) for field in HOST_FIELDS}


def _host_payload(host: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only fields accepted by Marzban's ProxyHost model."""
    payload = host_snapshot(host)
    if not payload.get("remark") or not payload.get("address"):
        raise ValueError("Marzban host requires remark and address")
    # These fields are non-optional in Marzban's ProxyHost model. GET /api/hosts
    # normally serializes the defaults, but keeping the defaults here makes the
    # PUT safe even if an older/alternate response omitted them.
    if payload.get("security") is None:
        payload["security"] = "inbound_default"
    if payload.get("alpn") is None:
        payload["alpn"] = ""
    if payload.get("fingerprint") is None:
        payload["fingerprint"] = ""
    return payload


def node_generated_host_remark(node_name: Any) -> str:
    """Return the exact remark Marzban uses for add_as_new_host Node hosts."""
    name = normalize_node_changes(
        {"name": node_name},
        allow_status=False,
    )["name"]
    return f"{name} ({{USERNAME}}) [{{PROTOCOL}} - {{TRANSPORT}}]"


def node_generated_host_payload(
    node: Dict[str, Any],
    *,
    public_address: Any = None,
) -> Dict[str, Any]:
    """Build the canonical Public Host payload for one Marzban Node.

    node.address stays the Marzban-to-Node control address. V123A may pass a
    separate stable DNS public_address for user-facing subscriptions.
    """
    if not isinstance(node, dict):
        raise ValueError("invalid Marzban node")

    name = normalize_node_changes(
        {"name": node.get("name")},
        allow_status=False,
    )["name"]
    if public_address is None:
        address = normalize_node_changes(
            {"address": node.get("address")},
            allow_status=False,
        )["address"]
    else:
        address = normalize_public_hostname(public_address)

    return _host_payload({
        "remark": node_generated_host_remark(name),
        "address": address,
        "port": None,
        "sni": None,
        "host": None,
        "path": None,
        "security": "inbound_default",
        # ProxyHostALPN / ProxyHostFingerprint use an empty string for
        # their disabled value in Marzban's API model.
        "alpn": "",
        "fingerprint": "",
        "allowinsecure": None,
        "is_disabled": False,
        "mux_enable": False,
        "fragment_setting": None,
        "noise_setting": None,
        "random_user_agent": False,
        "use_sni_as_host": False,
    })


def find_node_generated_hosts(
    hosts_payload: Any,
    node: Dict[str, Any],
    *,
    public_address: Any = None,
) -> List[Dict[str, Any]]:
    """Find only Public Hosts that match Marzban's automatic Node-host signature.

    Matching both the exact generated remark and the Node address avoids
    deleting manually-created hosts that merely share an IP/hostname.
    """
    if not isinstance(hosts_payload, dict) or not isinstance(node, dict):
        return []

    try:
        expected_remark = node_generated_host_remark(node.get("name"))
    except ValueError:
        return []

    try:
        expected_address = (
            normalize_public_hostname(public_address)
            if public_address is not None
            else normalize_node_changes(
                {"address": node.get("address")},
                allow_status=False,
            )["address"]
        ).casefold()
    except ValueError:
        return []

    matches: List[Dict[str, Any]] = []
    for raw_tag, hosts in hosts_payload.items():
        if not isinstance(hosts, list):
            continue
        try:
            tag = normalize_inbound_tag(raw_tag)
        except ValueError:
            continue
        for index, host in enumerate(hosts):
            if not isinstance(host, dict):
                continue
            if (
                str(host.get("address") or "").strip().casefold() != expected_address
                or str(host.get("remark") or "") != expected_remark
            ):
                continue
            try:
                snapshot = host_snapshot(host)
            except ValueError:
                continue
            matches.append({
                "tag": tag,
                "index": index,
                "host": snapshot,
            })
    return matches


def find_node_generated_host_remark_matches(
    hosts_payload: Any,
    node: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Find exact generated remarks regardless of address.

    V123A uses this only as a fail-closed lifecycle guard. A generated remark
    found on a different address may be a stable Public Endpoint and must not
    be orphaned by legacy Node deletion logic.
    """
    if not isinstance(hosts_payload, dict) or not isinstance(node, dict):
        return []
    try:
        expected_remark = node_generated_host_remark(node.get("name"))
    except ValueError:
        return []

    matches: List[Dict[str, Any]] = []
    for raw_tag, hosts in hosts_payload.items():
        if not isinstance(hosts, list):
            continue
        try:
            tag = normalize_inbound_tag(raw_tag)
        except ValueError:
            continue
        for index, host in enumerate(hosts):
            if not isinstance(host, dict):
                continue
            if str(host.get("remark") or "") != expected_remark:
                continue
            try:
                snapshot = host_snapshot(host)
            except ValueError:
                continue
            matches.append({
                "tag": tag,
                "index": index,
                "host": snapshot,
            })
    return matches


def inspect_node_public_host_profile(
    hosts_payload: Any,
    node: Dict[str, Any],
    tags: Any = NVL_NODE_PUBLIC_HOST_TAGS,
    *,
    public_address: Any,
) -> Dict[str, Any]:
    """Inspect whether an existing Node can be adopted without remote writes.

    Adoption is intentionally stricter than ordinary discovery: each managed
    inbound must contain exactly one canonical NVL-generated Host using the
    stable public hostname, no generated Host may exist on an unmanaged inbound,
    and the same generated remark must not point at another address.
    """
    if not isinstance(hosts_payload, dict):
        raise ValueError("invalid Marzban hosts response")
    if not isinstance(node, dict):
        raise ValueError("invalid Marzban node")

    public = normalize_public_hostname(public_address)
    generated = node_generated_host_payload(node, public_address=public)

    wanted: List[str] = []
    seen = set()
    for raw_tag in tags or ():
        tag = normalize_inbound_tag(raw_tag)
        if tag not in seen:
            wanted.append(tag)
            seen.add(tag)
    if not wanted:
        raise ValueError("at least one managed Public Host tag is required")

    exact_matches = find_node_generated_hosts(
        hosts_payload,
        node,
        public_address=public,
    )
    remark_matches = find_node_generated_host_remark_matches(hosts_payload, node)

    counts: Dict[str, int] = {}
    for item in exact_matches:
        tag = item["tag"]
        counts[tag] = counts.get(tag, 0) + 1

    missing_tags = [tag for tag in wanted if counts.get(tag, 0) == 0]
    duplicate_tags = {
        tag: counts.get(tag, 0)
        for tag in wanted
        if counts.get(tag, 0) > 1
    }
    unexpected_tags = {
        tag: count
        for tag, count in counts.items()
        if tag not in wanted and count
    }

    expected_address = public.casefold()
    remark_conflicts: List[Dict[str, Any]] = []
    for item in remark_matches:
        host = item.get("host") if isinstance(item, dict) else None
        address = (
            str(host.get("address") or "").strip().rstrip(".").casefold()
            if isinstance(host, dict)
            else ""
        )
        if address != expected_address:
            remark_conflicts.append({
                "tag": item.get("tag"),
                "index": item.get("index"),
                "address": address,
            })

    drifted_tags: List[str] = []
    for item in exact_matches:
        tag = item.get("tag")
        if tag not in wanted:
            continue
        try:
            current = _host_payload(item.get("host"))
        except ValueError:
            if tag not in drifted_tags:
                drifted_tags.append(tag)
            continue
        if current != generated and tag not in drifted_tags:
            drifted_tags.append(tag)

    invalid_host_lists: List[str] = []
    for tag in wanted:
        raw_hosts = hosts_payload.get(tag)
        if raw_hosts is not None and not isinstance(raw_hosts, list):
            invalid_host_lists.append(tag)

    adoptable = not (
        missing_tags
        or duplicate_tags
        or unexpected_tags
        or remark_conflicts
        or drifted_tags
        or invalid_host_lists
    )

    return {
        "adoptable": adoptable,
        "verified": adoptable,
        "public_address": public,
        "managed_remark": generated["remark"],
        "managed_tags": wanted,
        "counts": counts,
        "missing_tags": missing_tags,
        "duplicate_tags": duplicate_tags,
        "unexpected_tags": unexpected_tags,
        "remark_conflicts": remark_conflicts,
        "drifted_tags": drifted_tags,
        "invalid_host_lists": invalid_host_lists,
        "matched_hosts": len(exact_matches),
    }


_LEGACY_GENERATED_REMARK_SUFFIX = " ({USERNAME}) [{PROTOCOL} - {TRANSPORT}]"


def _host_matches_generated_except_remark(
    host: Dict[str, Any],
    generated: Dict[str, Any],
) -> bool:
    """Return whether a Host is canonical except for its generated-style label."""
    try:
        current = _host_payload(host)
    except ValueError:
        return False
    return all(
        current.get(field) == generated.get(field)
        for field in HOST_FIELDS
        if field != "remark"
    )


def _is_legacy_generated_public_host(
    host: Dict[str, Any],
    generated: Dict[str, Any],
) -> bool:
    """Recognize a legacy Marzban-generated Host without claiming arbitrary manual Hosts.

    V123B.2 only claims a Host when it points at the requested stable endpoint,
    every ProxyHost field except remark is already canonical, and the remark
    still has Marzban's generated template shape. A custom/manual remark is
    deliberately not enough.
    """
    if not isinstance(host, dict):
        return False
    remark = str(host.get("remark") or "")
    if not remark or remark == str(generated.get("remark") or ""):
        return False
    if (
        not remark.endswith(_LEGACY_GENERATED_REMARK_SUFFIX)
        or len(remark) <= len(_LEGACY_GENERATED_REMARK_SUFFIX)
    ):
        return False
    expected_address = str(generated.get("address") or "").strip().rstrip(".").casefold()
    current_address = str(host.get("address") or "").strip().rstrip(".").casefold()
    if not expected_address or current_address != expected_address:
        return False
    return _host_matches_generated_except_remark(host, generated)


def plan_node_public_host_repair(
    hosts_payload: Any,
    node: Dict[str, Any],
    tags: Any = NVL_NODE_PUBLIC_HOST_TAGS,
    *,
    public_address: Any,
) -> Dict[str, Any]:
    """Build a deterministic, non-mutating repair plan for one stable Public Endpoint.

    Ownership is intentionally conservative:
    - exact canonical Hosts are managed;
    - Hosts with the exact current Node-generated remark are managed even when
      address/payload drifted;
    - legacy generated-style Hosts are claimable only when their stable address
      and every field except remark already match the canonical payload;
    - arbitrary manual Hosts are preserved, and a manual Host on the requested
      endpoint inside a managed inbound makes the plan ambiguous/fail-closed.
    """
    if not isinstance(hosts_payload, dict):
        raise ValueError("invalid Marzban hosts response")
    if not isinstance(node, dict):
        raise ValueError("invalid Marzban node")

    public = normalize_public_hostname(public_address)
    generated = node_generated_host_payload(node, public_address=public)
    expected_remark = str(generated["remark"])
    expected_address = str(generated["address"]).strip().rstrip(".").casefold()

    wanted: List[str] = []
    seen = set()
    for raw_tag in tags or ():
        tag = normalize_inbound_tag(raw_tag)
        if tag not in seen:
            wanted.append(tag)
            seen.add(tag)
    if not wanted:
        raise ValueError("at least one managed Public Host tag is required")

    normalized_lists: Dict[str, List[Dict[str, Any]]] = {}
    invalid_host_lists: List[str] = []
    for raw_tag, raw_hosts in hosts_payload.items():
        try:
            tag = normalize_inbound_tag(raw_tag)
        except ValueError:
            continue
        if not isinstance(raw_hosts, list):
            if tag in wanted:
                invalid_host_lists.append(tag)
            continue
        try:
            normalized_lists[tag] = [_host_payload(item) for item in raw_hosts]
        except ValueError:
            if tag in wanted:
                invalid_host_lists.append(tag)

    for tag in wanted:
        if tag not in normalized_lists and tag not in invalid_host_lists:
            raw_hosts = hosts_payload.get(tag)
            if raw_hosts is None:
                normalized_lists[tag] = []

    fingerprint_data = {
        "node": {
            "id": node.get("id"),
            "name": node.get("name"),
            "address": node.get("address"),
        },
        "public_address": public,
        "wanted": wanted,
        "hosts": {
            tag: normalized_lists[tag]
            for tag in sorted(normalized_lists)
        },
        "invalid_host_lists": sorted(invalid_host_lists),
    }
    fingerprint = hashlib.sha256(
        json.dumps(
            fingerprint_data,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()

    desired_by_tag: Dict[str, List[Dict[str, Any]]] = {}
    added_tags: List[str] = []
    normalized_tags: List[str] = []
    claimed_legacy_tags: List[str] = []
    deduplicated_tags: Dict[str, int] = {}
    removed_unexpected_tags: Dict[str, int] = {}
    ambiguous_tags: List[str] = []
    issues: List[str] = []

    all_tags = sorted(set(normalized_lists) | set(wanted))
    for tag in all_tags:
        if tag in invalid_host_lists:
            continue
        current = list(normalized_lists.get(tag, []))
        owned: List[Dict[str, Any]] = []
        manual: List[Dict[str, Any]] = []
        legacy_count = 0
        ambiguous_same_endpoint = False

        for host in current:
            remark = str(host.get("remark") or "")
            address = str(host.get("address") or "").strip().rstrip(".").casefold()
            exact = host == generated
            current_remark_owned = remark == expected_remark
            legacy = _is_legacy_generated_public_host(host, generated)
            if exact or current_remark_owned or legacy:
                owned.append(host)
                if legacy:
                    legacy_count += 1
                continue
            manual.append(host)
            if tag in wanted and address == expected_address:
                ambiguous_same_endpoint = True

        if ambiguous_same_endpoint:
            ambiguous_tags.append(tag)
            issues.append(
                f"{tag}: manual Host already uses the requested Public Endpoint"
            )
            continue

        if tag in wanted:
            desired = manual + [dict(generated)]
            if not owned:
                added_tags.append(tag)
            else:
                if legacy_count:
                    claimed_legacy_tags.append(tag)
                if len(owned) > 1:
                    deduplicated_tags[tag] = len(owned) - 1
                if len(owned) != 1 or owned[0] != generated:
                    normalized_tags.append(tag)
            if desired != current:
                desired_by_tag[tag] = desired
        else:
            if owned:
                desired = manual
                removed_unexpected_tags[tag] = len(owned)
                if desired != current:
                    desired_by_tag[tag] = desired

    if invalid_host_lists:
        issues.append(
            "invalid Public Host list: " + ", ".join(sorted(invalid_host_lists))
        )

    repairable = not issues
    return {
        "repairable": repairable,
        "public_address": public,
        "managed_remark": expected_remark,
        "managed_tags": wanted,
        "fingerprint": fingerprint,
        "changed_tags": sorted(desired_by_tag),
        "added_tags": added_tags,
        "normalized_tags": normalized_tags,
        "claimed_legacy_tags": claimed_legacy_tags,
        "deduplicated_tags": deduplicated_tags,
        "removed_unexpected_tags": removed_unexpected_tags,
        "ambiguous_tags": ambiguous_tags,
        "invalid_host_lists": invalid_host_lists,
        "issues": issues,
        "desired_by_tag": desired_by_tag,
    }


def can_manage_v2ray_account(role: Optional[str], actor_agent_id: int, owner_agent_id: int) -> bool:
    """Return whether the current actor may read or mutate a V2Ray account.

    Admins may manage every account. Agents may only manage accounts whose
    authoritative ``agent_id`` in the local database matches their own id.
    No callback/user supplied ownership value is trusted.
    """

    if role == "admin":
        return True
    if role != "agent":
        return False
    try:
        return int(owner_agent_id or 0) == int(actor_agent_id or 0)
    except (TypeError, ValueError):
        return False


def normalize_subscription_name(value: Optional[str]) -> Optional[str]:
    """Normalize a future user-facing subscription display name.

    The value is not wired to subscription rendering in Phase 1; it is the
    storage/validation contract for the later presentation layer.
    """

    if value is None:
        return None

    cleaned = _CONTROL_CHARS_RE.sub("", str(value))
    cleaned = " ".join(cleaned.split())
    if not cleaned:
        return None
    if len(cleaned) < SUBSCRIPTION_NAME_MIN_LENGTH:
        raise ValueError(
            f"subscription name must be at least {SUBSCRIPTION_NAME_MIN_LENGTH} characters"
        )
    if len(cleaned) > SUBSCRIPTION_NAME_MAX_LENGTH:
        raise ValueError(
            f"subscription name must be at most {SUBSCRIPTION_NAME_MAX_LENGTH} characters"
        )
    return cleaned



def normalize_user_create_username(value: Any) -> str:
    """Validate the conservative NVL subset of Marzban usernames."""
    username = _CONTROL_CHARS_RE.sub("", str(value or "")).strip()
    if not _USER_CREATE_USERNAME_RE.fullmatch(username):
        raise ValueError(
            "username must be 3-32 characters using only A-Z, a-z, 0-9, _ or -"
        )
    return username


def normalize_user_data_limit_bytes(value: Any) -> int:
    try:
        amount = int(value)
    except (TypeError, ValueError):
        raise ValueError("data limit must be an integer number of bytes")
    if amount < 0:
        raise ValueError("data limit cannot be negative")
    if amount > 100 * 1024**4:
        raise ValueError("data limit is unreasonably large")
    return amount


def normalize_user_expire_timestamp(value: Any) -> int:
    try:
        expire = int(value)
    except (TypeError, ValueError):
        raise ValueError("expire must be a unix timestamp")
    if expire < 0:
        raise ValueError("expire cannot be negative")
    return expire


def normalize_on_hold_duration(value: Any) -> int:
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        raise ValueError("on-hold duration must be an integer number of seconds")
    if not 1 <= seconds <= 10 * 3650 * 86400:
        raise ValueError("on-hold duration is out of range")
    return seconds


def flatten_marzban_inbounds(payload: Any) -> List[Dict[str, str]]:
    """Return supported inbound tag/protocol pairs from Marzban."""
    rows: List[Dict[str, str]] = []
    if not isinstance(payload, dict):
        return rows

    seen = set()
    for group_protocol, items in payload.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            tag = str(item.get("tag") or "").strip()
            protocol = str(item.get("protocol") or group_protocol or "").strip().lower()
            if not tag or protocol not in MARZBAN_USER_PROTOCOLS:
                continue
            key = (protocol, tag)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"protocol": protocol, "tag": tag})
    return rows


def build_user_inbounds(
    payload: Any,
    selected_tags: Optional[List[str]] = None,
) -> Dict[str, List[str]]:
    """Build UserCreate.inbounds from current authoritative Marzban config."""
    rows = flatten_marzban_inbounds(payload)
    available = {row["tag"]: row["protocol"] for row in rows}
    if not available:
        raise ValueError("Marzban has no supported inbounds")

    if selected_tags is None:
        wanted = [row["tag"] for row in rows]
    else:
        wanted = []
        seen = set()
        for raw in selected_tags:
            tag = str(raw or "").strip()
            if not tag or tag in seen:
                continue
            if tag not in available:
                raise ValueError(f"inbound no longer exists: {tag}")
            seen.add(tag)
            wanted.append(tag)
        if not wanted:
            raise ValueError("at least one inbound must be selected")

    grouped: Dict[str, List[str]] = {}
    for tag in wanted:
        protocol = available[tag]
        grouped.setdefault(protocol, []).append(tag)
    return grouped


class MarzbanAdminService:
    """Small, Telegram-agnostic facade around the Marzban REST API."""

    def __init__(self, url: str, username: str, password: str):
        self.url = (url or "").strip().rstrip("/")
        self.username = (username or "").strip()
        self.password = password or ""

    @property
    def configured(self) -> bool:
        return bool(self.url and self.username and self.password)

    async def request(
        self,
        method: str,
        endpoint: str,
        *,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> ApiResult:
        if not self.configured:
            return False, "Marzban is not configured"

        return await v2ray_engine.api_request(
            method,
            endpoint,
            self.url,
            self.username,
            self.password,
            json_data=json_data,
            params=params,
        )

    async def get_user(self, username: str) -> ApiResult:
        return await self.request("GET", f"/api/user/{username}")

    async def create_user(
        self,
        username: str,
        *,
        data_limit_bytes: int,
        expire: int = 0,
        selected_inbound_tags: Optional[List[str]] = None,
        reset_strategy: str = "no_reset",
        status: str = "active",
        on_hold_expire_duration: Optional[int] = None,
        note: str = "",
    ) -> ApiResult:
        """Create a Marzban user and verify it with an authoritative GET.

        If the POST succeeds but verification fails, the structured failure
        includes created=True so callers must not blindly retry the POST.
        """
        try:
            username = normalize_user_create_username(username)
            data_limit_bytes = normalize_user_data_limit_bytes(data_limit_bytes)
            expire = normalize_user_expire_timestamp(expire)
        except ValueError as exc:
            return False, str(exc)

        reset_strategy = str(reset_strategy or "").strip().lower()
        if reset_strategy not in MARZBAN_RESET_STRATEGIES:
            return False, f"unsupported reset strategy: {reset_strategy}"

        status = str(status or "active").strip().lower()
        if status not in {"active", "on_hold"}:
            return False, f"unsupported create status: {status}"

        if status == "on_hold":
            try:
                hold_seconds = normalize_on_hold_duration(on_hold_expire_duration)
            except ValueError as exc:
                return False, str(exc)
            if expire:
                return False, "on-hold users cannot have an absolute expire timestamp"
        else:
            hold_seconds = None

        note = _CONTROL_CHARS_RE.sub("", str(note or "")).strip()
        if len(note) > 500:
            return False, "note cannot exceed 500 characters"

        ok_inbounds, inbound_payload = await self.get_inbounds()
        if not ok_inbounds:
            return False, inbound_payload
        try:
            inbounds = build_user_inbounds(inbound_payload, selected_inbound_tags)
        except ValueError as exc:
            return False, str(exc)

        proxies = {protocol: {} for protocol in inbounds}
        payload: Dict[str, Any] = {
            "username": username,
            "proxies": proxies,
            "inbounds": inbounds,
            "data_limit": data_limit_bytes,
            "data_limit_reset_strategy": reset_strategy,
            "status": status,
            "expire": 0 if status == "on_hold" else expire,
            "note": note,
        }
        if status == "on_hold":
            payload["on_hold_expire_duration"] = hold_seconds

        ok_create, created = await self.request("POST", "/api/user", json_data=payload)
        if not ok_create:
            return False, created

        ok_verify, verified = await self.get_user(username)
        if not ok_verify or not isinstance(verified, dict):
            return False, {
                "stage": "verify",
                "created": True,
                "username": username,
                "error": verified,
            }
        if str(verified.get("username") or "") != username:
            return False, {
                "stage": "verify",
                "created": True,
                "username": username,
                "error": "Marzban returned a different username",
            }

        return True, verified

    async def list_users(
        self,
        *,
        offset: int = 0,
        limit: int = 50,
        search: Optional[str] = None,
        status: Optional[str] = None,
        sort: Optional[str] = None,
    ) -> ApiResult:
        """List Marzban users using the 0.8.4-compatible query contract."""
        params: Dict[str, Any] = {
            "offset": max(0, int(offset)),
            "limit": max(1, min(int(limit), 100000)),
        }
        if search:
            params["search"] = str(search).strip()
        if status:
            params["status"] = status
        if sort:
            params["sort"] = sort
        return await self.request("GET", "/api/users", params=params)

    async def list_online_users(
        self,
        *,
        window_seconds: int = 300,
        limit: int = 100000,
    ) -> ApiResult:
        """Return active users seen online within the recent time window."""
        ok, payload = await self.list_users(limit=limit)
        if not ok:
            return False, payload

        if isinstance(payload, dict):
            users = payload.get("users", [])
        elif isinstance(payload, list):
            users = payload
        else:
            users = []

        now = datetime.now(timezone.utc)
        result: List[Dict[str, Any]] = []
        for user in users:
            if not isinstance(user, dict) or user.get("status") != "active":
                continue
            raw = user.get("online_at")
            if not raw:
                continue
            try:
                stamp = str(raw).strip().replace("Z", "+00:00")
                dt = datetime.fromisoformat(stamp)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                else:
                    dt = dt.astimezone(timezone.utc)
                age = (now - dt).total_seconds()
                if 0 <= age <= max(1, int(window_seconds)):
                    result.append(user)
            except (TypeError, ValueError):
                continue

        result.sort(key=lambda item: str(item.get("online_at") or ""), reverse=True)
        return True, {"users": result, "total": len(result)}

    async def get_system_stats(self) -> ApiResult:
        return await self.request("GET", "/api/system")

    async def get_nodes(self) -> ApiResult:
        return await self.request("GET", "/api/nodes")

    async def get_node_settings(self) -> ApiResult:
        """Fetch Marzban Node settings and validate the client certificate payload."""
        ok, payload = await self.request("GET", "/api/node/settings")
        if not ok:
            return False, payload
        if not isinstance(payload, dict):
            return False, "Invalid Marzban node settings response"

        certificate = str(payload.get("certificate") or "").strip()
        if not certificate:
            return False, "Marzban node settings did not include a certificate"

        normalized = dict(payload)
        normalized["certificate"] = certificate
        return True, normalized

    async def create_node(
        self,
        name: Any,
        address: Any,
        *,
        port: Any = 62050,
        api_port: Any = 62051,
        usage_coefficient: Any = 1.0,
        add_as_new_host: Any = True,
    ) -> ApiResult:
        """Create a Marzban node and verify it with an authoritative GET.

        A successful POST is never retried here. If verification fails, the
        structured failure includes created=True and the returned node id when
        available so callers can reconcile safely instead of duplicating it.
        """
        try:
            payload = normalize_node_create(
                name,
                address,
                port=port,
                api_port=api_port,
                usage_coefficient=usage_coefficient,
                add_as_new_host=add_as_new_host,
            )
        except ValueError as exc:
            return False, str(exc)

        ok_nodes, nodes = await self.get_nodes()
        if not ok_nodes or not isinstance(nodes, list):
            return False, {
                "stage": "precheck",
                "created": False,
                "duplicate": False,
                "error": (
                    nodes
                    if not ok_nodes
                    else "Marzban returned an invalid node list during duplicate precheck"
                ),
            }

        duplicate = find_duplicate_node(nodes, payload["name"])
        if duplicate is not None:
            try:
                duplicate_id = normalize_node_id(duplicate.get("id"))
            except ValueError:
                duplicate_id = None
            return False, {
                "stage": "precheck",
                "created": False,
                "duplicate": True,
                "node_id": duplicate_id,
                "existing": duplicate,
                "error": f'Node "{payload["name"]}" already exists',
            }

        ok_create, created = await self.request(
            "POST",
            "/api/node",
            json_data=payload,
        )
        if not ok_create:
            return False, created

        if not isinstance(created, dict):
            return False, {
                "stage": "verify",
                "created": True,
                "node_id": None,
                "error": "Marzban returned an invalid create-node response",
            }

        try:
            node_id = normalize_node_id(created.get("id"))
        except ValueError:
            return False, {
                "stage": "verify",
                "created": True,
                "node_id": None,
                "error": "Marzban create-node response did not include a valid node id",
                "response": created,
            }

        ok_verify, verified = await self.get_node(node_id)
        if not ok_verify or not isinstance(verified, dict):
            return False, {
                "stage": "verify",
                "created": True,
                "node_id": node_id,
                "error": verified,
            }

        try:
            verified_node_id = normalize_node_id(verified.get("id"))
        except ValueError:
            return False, {
                "stage": "verify",
                "created": True,
                "node_id": node_id,
                "error": "Marzban returned an invalid node id during verification",
                "verified": verified,
            }

        if verified_node_id != node_id:
            return False, {
                "stage": "verify",
                "created": True,
                "node_id": node_id,
                "error": "Marzban returned a different node id during verification",
                "verified": verified,
            }

        expected = {
            "name": payload["name"],
            "address": payload["address"],
            "port": payload["port"],
            "api_port": payload["api_port"],
        }
        for field, expected_value in expected.items():
            if verified.get(field) != expected_value:
                return False, {
                    "stage": "verify",
                    "created": True,
                    "node_id": node_id,
                    "error": f"Marzban returned a different {field} during verification",
                    "verified": verified,
                }

        try:
            verified_ratio = float(verified.get("usage_coefficient"))
        except (TypeError, ValueError):
            return False, {
                "stage": "verify",
                "created": True,
                "node_id": node_id,
                "error": "Marzban returned an invalid usage_coefficient during verification",
                "verified": verified,
            }

        if not math.isclose(
            verified_ratio,
            float(payload["usage_coefficient"]),
            rel_tol=1e-9,
            abs_tol=1e-9,
        ):
            return False, {
                "stage": "verify",
                "created": True,
                "node_id": node_id,
                "error": "Marzban returned a different usage_coefficient during verification",
                "verified": verified,
            }

        return True, verified

    async def get_node(self, node_id: int) -> ApiResult:
        node_id = normalize_node_id(node_id)
        return await self.request("GET", f"/api/node/{node_id}")

    async def modify_node(self, node_id: int, **changes: Any) -> ApiResult:
        node_id = normalize_node_id(node_id)
        payload = normalize_node_changes(changes)
        return await self.request("PUT", f"/api/node/{node_id}", json_data=payload)

    async def update_node_settings(self, node_id: int, **changes: Any) -> ApiResult:
        """Update settings without accidentally enabling a disabled node."""
        node_id = normalize_node_id(node_id)
        payload = normalize_node_changes(changes, allow_status=False)
        ok, current = await self.get_node(node_id)
        if not ok:
            return False, current
        if not isinstance(current, dict):
            return False, "Invalid Marzban node response"
        # Marzban sets status=connecting for a NodeModify request unless
        # status=disabled is explicitly preserved.
        if str(current.get("status") or "").lower() == "disabled":
            payload["status"] = "disabled"
        return await self.request("PUT", f"/api/node/{node_id}", json_data=payload)

    async def set_node_enabled(self, node_id: int, enabled: bool) -> ApiResult:
        return await self.modify_node(
            node_id,
            status="connecting" if enabled else "disabled",
        )

    async def delete_node(self, node_id: int) -> ApiResult:
        """Delete a Node, then remove only its exact auto-generated Public Hosts."""
        node_id = normalize_node_id(node_id)

        ok_current, current = await self.get_node(node_id)
        if not ok_current or not isinstance(current, dict):
            return False, {
                "stage": "precheck",
                "deleted": False,
                "node_id": node_id,
                "error": current,
            }

        # Fail closed before deleting the Node if host inventory cannot be read:
        # the operator asked for Node deletion to include generated-host cleanup.
        ok_hosts, hosts_payload = await self.get_hosts()
        if not ok_hosts or not isinstance(hosts_payload, dict):
            return False, {
                "stage": "host_precheck",
                "deleted": False,
                "node_id": node_id,
                "node": current,
                "error": (
                    hosts_payload
                    if not ok_hosts
                    else "Invalid Marzban hosts response"
                ),
            }
        host_candidates = find_node_generated_hosts(hosts_payload, current)
        remark_matches = find_node_generated_host_remark_matches(
            hosts_payload,
            current,
        )
        exact_keys = {
            (item["tag"], item["index"])
            for item in host_candidates
        }
        address_mismatch = [
            item
            for item in remark_matches
            if (item["tag"], item["index"]) not in exact_keys
        ]
        if address_mismatch:
            return False, {
                "stage": "host_precheck",
                "deleted": False,
                "node_id": node_id,
                "node": current,
                "host_candidates": host_candidates,
                "ambiguous_public_hosts": address_mismatch,
                "error": (
                    "Generated Public Host remark exists on a different address; "
                    "stable-endpoint lifecycle cleanup is required before Node deletion"
                ),
            }

        ok_delete, response = await self.request("DELETE", f"/api/node/{node_id}")
        if not ok_delete:
            return False, {
                "stage": "delete",
                "deleted": False,
                "node_id": node_id,
                "node": current,
                "host_candidates": host_candidates,
                "error": response,
            }

        ok_nodes, nodes = await self.get_nodes()
        if not ok_nodes or not isinstance(nodes, list):
            return False, {
                "stage": "verify",
                "deleted": True,
                "node_id": node_id,
                "node": current,
                "host_candidates": host_candidates,
                "error": (
                    nodes
                    if not ok_nodes
                    else "Marzban returned an invalid node list after DELETE"
                ),
            }

        for node in nodes:
            if not isinstance(node, dict):
                continue
            try:
                remaining_id = normalize_node_id(node.get("id"))
            except ValueError:
                continue
            if remaining_id == node_id:
                return False, {
                    "stage": "verify",
                    "deleted": True,
                    "node_id": node_id,
                    "node": current,
                    "host_candidates": host_candidates,
                    "error": "Node is still present after DELETE",
                }

        cleanup_result = {
            "stage": "host_cleanup",
            "deleted_count": 0,
            "deleted_hosts": [],
        }
        if host_candidates:
            ok_cleanup, cleanup_result = await self.delete_node_generated_hosts(
                host_candidates
            )
            if not ok_cleanup:
                return False, {
                    "stage": "host_cleanup",
                    "deleted": True,
                    "verified": True,
                    "node_id": node_id,
                    "node": current,
                    "host_candidates": host_candidates,
                    "hosts_deleted": int(cleanup_result.get("deleted_count") or 0),
                    "error": cleanup_result,
                }

        return True, {
            "stage": "verify",
            "deleted": True,
            "verified": True,
            "node_id": node_id,
            "node": current,
            "response": response,
            "host_candidates": host_candidates,
            "hosts_deleted": int(cleanup_result.get("deleted_count") or 0),
        }

    async def reconnect_node(self, node_id: int) -> ApiResult:
        node_id = normalize_node_id(node_id)
        return await self.request("POST", f"/api/node/{node_id}/reconnect")

    async def get_nodes_usage(self, *, start: Optional[str] = None, end: Optional[str] = None) -> ApiResult:
        params: Dict[str, Any] = {}
        if start:
            params["start"] = str(start).strip()
        if end:
            params["end"] = str(end).strip()
        return await self.request("GET", "/api/nodes/usage", params=params or None)
    async def get_inbounds(self) -> ApiResult:
        return await self.request("GET", "/api/inbounds")

    async def get_hosts(self) -> ApiResult:
        return await self.request("GET", "/api/hosts")


    async def inspect_node_public_profile(
        self,
        node_id: int,
        public_address: Any,
        tags: Any = NVL_NODE_PUBLIC_HOST_TAGS,
    ) -> ApiResult:
        """Read-only inspection used before adopting an existing Public Endpoint.

        This method performs GETs only. A non-adoptable topology is still a
        successful inspection and returns a report with adoptable=False.
        """
        try:
            node_id = normalize_node_id(node_id)
            public = normalize_public_hostname(public_address)
            wanted: List[str] = []
            seen = set()
            for raw_tag in tags or ():
                tag = normalize_inbound_tag(raw_tag)
                if tag not in seen:
                    wanted.append(tag)
                    seen.add(tag)
            if not wanted:
                raise ValueError("at least one managed Public Host tag is required")
        except ValueError as exc:
            return False, {
                "stage": "adopt_precheck",
                "read_only": True,
                "error": str(exc),
            }

        ok_node, node = await self.get_node(node_id)
        if not ok_node or not isinstance(node, dict):
            return False, {
                "stage": "adopt_precheck",
                "read_only": True,
                "node_id": node_id,
                "error": node if not ok_node else "Invalid Marzban node response",
            }

        ok_inbounds, inbounds_payload = await self.get_inbounds()
        if not ok_inbounds or not isinstance(inbounds_payload, dict):
            return False, {
                "stage": "adopt_precheck",
                "read_only": True,
                "node_id": node_id,
                "error": (
                    inbounds_payload
                    if not ok_inbounds
                    else "Invalid Marzban inbounds response"
                ),
            }

        available = {row["tag"] for row in flatten_marzban_inbounds(inbounds_payload)}
        missing_inbounds = [tag for tag in wanted if tag not in available]
        if missing_inbounds:
            return True, {
                "stage": "adopt_inspect",
                "read_only": True,
                "node_id": node_id,
                "node": node,
                "public_address": public,
                "managed_remark": node_generated_host_remark(node.get("name")),
                "managed_tags": wanted,
                "adoptable": False,
                "verified": False,
                "counts": {},
                "missing_tags": list(missing_inbounds),
                "missing_inbounds": list(missing_inbounds),
                "duplicate_tags": {},
                "unexpected_tags": {},
                "remark_conflicts": [],
                "drifted_tags": [],
                "invalid_host_lists": [],
                "matched_hosts": 0,
            }

        ok_hosts, hosts_payload = await self.get_hosts()
        if not ok_hosts or not isinstance(hosts_payload, dict):
            return False, {
                "stage": "adopt_precheck",
                "read_only": True,
                "node_id": node_id,
                "error": (
                    hosts_payload
                    if not ok_hosts
                    else "Invalid Marzban hosts response"
                ),
            }

        try:
            report = inspect_node_public_host_profile(
                hosts_payload,
                node,
                wanted,
                public_address=public,
            )
        except ValueError as exc:
            return False, {
                "stage": "adopt_precheck",
                "read_only": True,
                "node_id": node_id,
                "error": str(exc),
            }

        report.update({
            "stage": "adopt_inspect",
            "read_only": True,
            "node_id": node_id,
            "node": node,
            "missing_inbounds": [],
        })
        return True, report

    async def preview_node_public_profile_repair(
        self,
        node_id: int,
        public_address: Any,
        tags: Any = NVL_NODE_PUBLIC_HOST_TAGS,
    ) -> ApiResult:
        """GET-only V123B.2 preview for an existing/pending Public Endpoint."""
        try:
            node_id = normalize_node_id(node_id)
            public = normalize_public_hostname(public_address)
            wanted: List[str] = []
            seen = set()
            for raw_tag in tags or ():
                tag = normalize_inbound_tag(raw_tag)
                if tag not in seen:
                    wanted.append(tag)
                    seen.add(tag)
            if not wanted:
                raise ValueError("at least one managed Public Host tag is required")
        except ValueError as exc:
            return False, {
                "stage": "repair_precheck",
                "read_only": True,
                "error": str(exc),
            }

        ok_node, node = await self.get_node(node_id)
        if not ok_node or not isinstance(node, dict):
            return False, {
                "stage": "repair_precheck",
                "read_only": True,
                "node_id": node_id,
                "error": node if not ok_node else "Invalid Marzban node response",
            }

        ok_inbounds, inbounds_payload = await self.get_inbounds()
        if not ok_inbounds or not isinstance(inbounds_payload, dict):
            return False, {
                "stage": "repair_precheck",
                "read_only": True,
                "node_id": node_id,
                "node": node,
                "error": (
                    inbounds_payload
                    if not ok_inbounds
                    else "Invalid Marzban inbounds response"
                ),
            }

        available = {row["tag"] for row in flatten_marzban_inbounds(inbounds_payload)}
        missing_inbounds = [tag for tag in wanted if tag not in available]
        if missing_inbounds:
            return True, {
                "stage": "repair_preview",
                "read_only": True,
                "node_id": node_id,
                "node": node,
                "public_address": public,
                "managed_remark": node_generated_host_remark(node.get("name")),
                "managed_tags": wanted,
                "repairable": False,
                "missing_inbounds": missing_inbounds,
                "issues": [
                    "Required inbound(s) missing: " + ", ".join(missing_inbounds)
                ],
                "changed_tags": [],
                "added_tags": [],
                "normalized_tags": [],
                "claimed_legacy_tags": [],
                "deduplicated_tags": {},
                "removed_unexpected_tags": {},
                "ambiguous_tags": [],
                "invalid_host_lists": [],
                "fingerprint": None,
                "desired_by_tag": {},
            }

        ok_hosts, hosts_payload = await self.get_hosts()
        if not ok_hosts or not isinstance(hosts_payload, dict):
            return False, {
                "stage": "repair_precheck",
                "read_only": True,
                "node_id": node_id,
                "node": node,
                "error": (
                    hosts_payload
                    if not ok_hosts
                    else "Invalid Marzban hosts response"
                ),
            }

        try:
            plan = plan_node_public_host_repair(
                hosts_payload,
                node,
                wanted,
                public_address=public,
            )
        except ValueError as exc:
            return False, {
                "stage": "repair_precheck",
                "read_only": True,
                "node_id": node_id,
                "node": node,
                "error": str(exc),
            }

        plan.update({
            "stage": "repair_preview",
            "read_only": True,
            "node_id": node_id,
            "node": node,
            "missing_inbounds": [],
        })
        return True, plan

    async def repair_node_public_profile(
        self,
        node_id: int,
        public_address: Any,
        tags: Any = NVL_NODE_PUBLIC_HOST_TAGS,
        *,
        expected_fingerprint: Any,
    ) -> ApiResult:
        """Apply one stale-safe Public Host repair and verify the canonical profile."""
        ok_plan, plan = await self.preview_node_public_profile_repair(
            node_id,
            public_address,
            tags,
        )
        if not ok_plan or not isinstance(plan, dict):
            return False, plan
        if not plan.get("repairable"):
            failed = dict(plan)
            failed.update({"stage": "repair_precheck", "read_only": True})
            return False, failed

        current_fingerprint = str(plan.get("fingerprint") or "")
        expected = str(expected_fingerprint or "")
        if not expected or current_fingerprint != expected:
            return False, {
                "stage": "repair_stale",
                "read_only": True,
                "node_id": plan.get("node_id"),
                "public_address": plan.get("public_address"),
                "expected_fingerprint": expected,
                "current_fingerprint": current_fingerprint,
                "error": "Public Host state changed after preview",
            }

        desired_by_tag = dict(plan.get("desired_by_tag") or {})
        changed: List[str] = []
        for tag in sorted(desired_by_tag):
            ok_put, response = await self.request(
                "PUT",
                "/api/hosts",
                json_data={tag: desired_by_tag[tag]},
            )
            if not ok_put:
                return False, {
                    "stage": "repair_write",
                    "read_only": False,
                    "node_id": plan.get("node_id"),
                    "public_address": plan.get("public_address"),
                    "changed_tags": changed,
                    "failed_tag": tag,
                    "partial_write": bool(changed),
                    "error": response,
                }
            changed.append(tag)

        ok_hosts, hosts_payload = await self.get_hosts()
        if not ok_hosts or not isinstance(hosts_payload, dict):
            return False, {
                "stage": "repair_verify",
                "read_only": False,
                "node_id": plan.get("node_id"),
                "public_address": plan.get("public_address"),
                "changed_tags": changed,
                "applied": bool(changed),
                "error": (
                    hosts_payload
                    if not ok_hosts
                    else "Invalid Marzban hosts response"
                ),
            }

        node = plan.get("node") if isinstance(plan.get("node"), dict) else {}
        try:
            verification = inspect_node_public_host_profile(
                hosts_payload,
                node,
                tags,
                public_address=plan.get("public_address"),
            )
        except ValueError as exc:
            return False, {
                "stage": "repair_verify",
                "read_only": False,
                "node_id": plan.get("node_id"),
                "public_address": plan.get("public_address"),
                "changed_tags": changed,
                "applied": bool(changed),
                "error": str(exc),
            }

        if not verification.get("adoptable"):
            return False, {
                "stage": "repair_verify",
                "read_only": False,
                "node_id": plan.get("node_id"),
                "public_address": plan.get("public_address"),
                "changed_tags": changed,
                "applied": bool(changed),
                "verification": verification,
                "error": "Canonical Public Host verification failed after repair",
            }

        result = dict(plan)
        result.pop("desired_by_tag", None)
        result.update({
            "stage": "repair_verified",
            "read_only": False,
            "verified": True,
            "changed_tags": changed,
            "verification": verification,
        })
        return True, result

    async def preview_node_public_profile_rename(
        self,
        node_id: int,
        new_name: Any,
        public_address: Any,
        tags: Any = NVL_NODE_PUBLIC_HOST_TAGS,
    ) -> ApiResult:
        """GET-only V123B.3.1 preview for renaming a managed Node.

        Rename is allowed only when the current Stable Public Endpoint profile is
        already canonical. This keeps lifecycle changes separate from repair and
        gives confirmation a deterministic fingerprint covering the Node,
        managed Hosts, target name, and stable public endpoint.
        """
        try:
            node_id = normalize_node_id(node_id)
            target_name = normalize_node_changes(
                {"name": new_name},
                allow_status=False,
            )["name"]
            public = normalize_public_hostname(public_address)
        except ValueError as exc:
            return False, {
                "stage": "rename_precheck",
                "read_only": True,
                "error": str(exc),
            }

        ok_plan, repair_plan = await self.preview_node_public_profile_repair(
            node_id,
            public,
            tags,
        )
        if not ok_plan or not isinstance(repair_plan, dict):
            return False, repair_plan

        node = (
            repair_plan.get("node")
            if isinstance(repair_plan.get("node"), dict)
            else {}
        )
        current_name = str(node.get("name") or "")
        current_remark = str(repair_plan.get("managed_remark") or "")

        issues: List[str] = []
        if not repair_plan.get("repairable"):
            issues.extend(map(str, repair_plan.get("issues") or ()))
        if repair_plan.get("changed_tags"):
            issues.append(
                "Managed Public Host profile must be canonical before rename"
            )
        if repair_plan.get("missing_inbounds"):
            issues.append(
                "Required inbound(s) missing: "
                + ", ".join(map(str, repair_plan.get("missing_inbounds") or ()))
            )

        ok_nodes, nodes = await self.get_nodes()
        if not ok_nodes or not isinstance(nodes, list):
            return False, {
                "stage": "rename_precheck",
                "read_only": True,
                "node_id": node_id,
                "node": node,
                "error": (
                    nodes
                    if not ok_nodes
                    else "Invalid Marzban node list during rename duplicate precheck"
                ),
            }

        duplicate = find_duplicate_node(nodes, target_name)
        if isinstance(duplicate, dict):
            try:
                duplicate_id = normalize_node_id(duplicate.get("id"))
            except ValueError:
                duplicate_id = None
            if duplicate_id != node_id:
                issues.append(f'Node "{target_name}" already exists')

        base_fingerprint = str(repair_plan.get("fingerprint") or "")
        fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "base_fingerprint": base_fingerprint,
                    "node_id": node_id,
                    "old_name": current_name,
                    "new_name": target_name,
                    "public_address": public,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

        managed_tags = list(repair_plan.get("managed_tags") or ())
        same_name = current_name == target_name
        return True, {
            "stage": "rename_preview",
            "read_only": True,
            "renameable": not issues,
            "no_change": same_name,
            "node_id": node_id,
            "node": node,
            "old_name": current_name,
            "new_name": target_name,
            "public_address": public,
            "old_managed_remark": current_remark,
            "new_managed_remark": node_generated_host_remark(target_name),
            "managed_tags": managed_tags,
            "changed_tags": [] if same_name else managed_tags,
            "fingerprint": fingerprint,
            "issues": issues,
        }

    async def rename_node_public_profile(
        self,
        node_id: int,
        new_name: Any,
        public_address: Any,
        tags: Any = NVL_NODE_PUBLIC_HOST_TAGS,
        *,
        expected_fingerprint: Any,
    ) -> ApiResult:
        """Rename one managed Node, sync generated Host remarks, and verify.

        The Node rename happens first. If Host reconciliation then fails, the
        caller must keep local ownership pending; V123B.2 Repair can safely
        recover the old generated-style remarks using the new Node name.
        """
        ok_preview, preview = await self.preview_node_public_profile_rename(
            node_id,
            new_name,
            public_address,
            tags,
        )
        if not ok_preview or not isinstance(preview, dict):
            return False, preview
        if not preview.get("renameable"):
            failed = dict(preview)
            failed.update({"stage": "rename_precheck", "read_only": True})
            return False, failed

        expected = str(expected_fingerprint or "")
        current = str(preview.get("fingerprint") or "")
        if not expected or expected != current:
            return False, {
                "stage": "rename_stale",
                "read_only": True,
                "renamed": False,
                "node_id": preview.get("node_id"),
                "public_address": preview.get("public_address"),
                "expected_fingerprint": expected,
                "current_fingerprint": current,
                "error": "Node or Public Host state changed after rename preview",
            }

        if preview.get("no_change"):
            return True, {
                **preview,
                "stage": "rename_verified",
                "read_only": False,
                "renamed": False,
                "verified": True,
                "changed_tags": [],
            }

        node_id = normalize_node_id(preview.get("node_id"))
        target_name = str(preview.get("new_name") or "")
        old_node = preview.get("node") if isinstance(preview.get("node"), dict) else {}
        old_address = str(old_node.get("address") or "")

        ok_rename, rename_response = await self.update_node_settings(
            node_id,
            name=target_name,
        )
        if not ok_rename:
            return False, {
                "stage": "rename_node_write",
                "read_only": False,
                "renamed": False,
                "node_id": node_id,
                "public_address": preview.get("public_address"),
                "error": rename_response,
            }

        ok_node, renamed_node = await self.get_node(node_id)
        if (
            not ok_node
            or not isinstance(renamed_node, dict)
            or str(renamed_node.get("name") or "") != target_name
            or str(renamed_node.get("address") or "") != old_address
        ):
            return False, {
                "stage": "rename_node_verify",
                "read_only": False,
                "renamed": True,
                "node_id": node_id,
                "public_address": preview.get("public_address"),
                "node": renamed_node if isinstance(renamed_node, dict) else None,
                "error": (
                    renamed_node
                    if not ok_node
                    else "Renamed Node identity/address did not verify"
                ),
            }

        ok_repair_preview, repair_preview = await self.preview_node_public_profile_repair(
            node_id,
            preview.get("public_address"),
            tags,
        )
        if (
            not ok_repair_preview
            or not isinstance(repair_preview, dict)
            or not repair_preview.get("repairable")
        ):
            return False, {
                "stage": "rename_host_precheck",
                "read_only": False,
                "renamed": True,
                "node_id": node_id,
                "public_address": preview.get("public_address"),
                "node": renamed_node,
                "error": repair_preview,
            }

        ok_sync, sync = await self.repair_node_public_profile(
            node_id,
            preview.get("public_address"),
            tags,
            expected_fingerprint=repair_preview.get("fingerprint"),
        )
        if not ok_sync or not isinstance(sync, dict) or not sync.get("verified"):
            return False, {
                "stage": "rename_host_sync",
                "read_only": False,
                "renamed": True,
                "node_id": node_id,
                "public_address": preview.get("public_address"),
                "node": renamed_node,
                "error": sync,
            }

        return True, {
            "stage": "rename_verified",
            "read_only": False,
            "renamed": True,
            "verified": True,
            "node_id": node_id,
            "node": renamed_node,
            "old_name": preview.get("old_name"),
            "new_name": target_name,
            "public_address": preview.get("public_address"),
            "old_managed_remark": preview.get("old_managed_remark"),
            "new_managed_remark": preview.get("new_managed_remark"),
            "managed_tags": preview.get("managed_tags"),
            "changed_tags": list(sync.get("changed_tags") or ()),
        }

    async def reconcile_node_public_hosts(
        self,
        node: Dict[str, Any],
        tags: Any = NVL_NODE_PUBLIC_HOST_TAGS,
        *,
        public_address: Any = None,
    ) -> ApiResult:
        """Reconcile one Node to an explicit Public Host allow-list.

        Marzban's NodeCreate.add_as_new_host flag creates a Host for every
        inbound. NVL instead creates Nodes with that flag disabled, then calls
        this idempotent reconciler. It adds the exact generated Host to wanted
        tags, removes only exact auto-generated matches from unwanted tags, and
        preserves all manual Hosts.
        """
        if not isinstance(node, dict):
            return False, {
                "stage": "host_profile_precheck",
                "error": "Invalid Marzban node",
            }

        try:
            generated = node_generated_host_payload(
                node,
                public_address=public_address,
            )
            wanted: List[str] = []
            seen = set()
            for raw_tag in tags or ():
                tag = normalize_inbound_tag(raw_tag)
                if tag not in seen:
                    wanted.append(tag)
                    seen.add(tag)
            if not wanted:
                raise ValueError("at least one managed Public Host tag is required")
        except ValueError as exc:
            return False, {
                "stage": "host_profile_precheck",
                "error": str(exc),
            }

        ok_inbounds, inbounds_payload = await self.get_inbounds()
        if not ok_inbounds or not isinstance(inbounds_payload, dict):
            return False, {
                "stage": "host_profile_precheck",
                "error": (
                    inbounds_payload
                    if not ok_inbounds
                    else "Invalid Marzban inbounds response"
                ),
            }

        available = {row["tag"] for row in flatten_marzban_inbounds(inbounds_payload)}
        missing = [tag for tag in wanted if tag not in available]
        if missing:
            return False, {
                "stage": "host_profile_precheck",
                "error": "Required inbound(s) missing: " + ", ".join(missing),
                "managed_tags": wanted,
            }

        ok_hosts, hosts_payload = await self.get_hosts()
        if not ok_hosts or not isinstance(hosts_payload, dict):
            return False, {
                "stage": "host_profile_precheck",
                "error": (
                    hosts_payload
                    if not ok_hosts
                    else "Invalid Marzban hosts response"
                ),
                "managed_tags": wanted,
            }

        expected_remark = generated["remark"]
        expected_address = str(generated["address"]).strip().casefold()

        def is_generated(item: Any) -> bool:
            return (
                isinstance(item, dict)
                and str(item.get("remark") or "") == expected_remark
                and str(item.get("address") or "").strip().casefold() == expected_address
            )

        desired_by_tag: Dict[str, List[Dict[str, Any]]] = {}
        added: List[str] = []
        removed: List[str] = []

        all_tags = set(hosts_payload) | set(wanted)
        for raw_tag in all_tags:
            try:
                tag = normalize_inbound_tag(raw_tag)
            except ValueError:
                continue

            raw_hosts = hosts_payload.get(raw_tag, [])
            if not isinstance(raw_hosts, list):
                if tag in wanted:
                    return False, {
                        "stage": "host_profile_precheck",
                        "error": f"Invalid Public Host list for inbound: {tag}",
                        "managed_tags": wanted,
                    }
                continue

            try:
                current = [_host_payload(item) for item in raw_hosts]
            except ValueError as exc:
                return False, {
                    "stage": "host_profile_precheck",
                    "error": f"{tag}: {exc}",
                    "managed_tags": wanted,
                }

            matches = [item for item in current if is_generated(item)]
            others = [item for item in current if not is_generated(item)]

            if tag in wanted:
                if matches:
                    desired = others + [matches[0]]
                    if len(matches) > 1:
                        removed.extend([tag] * (len(matches) - 1))
                else:
                    desired = others + [dict(generated)]
                    added.append(tag)
            else:
                desired = others
                if matches:
                    removed.extend([tag] * len(matches))

            if desired != current:
                desired_by_tag[tag] = desired

        changed: List[str] = []
        for tag in sorted(desired_by_tag):
            ok_put, response = await self.request(
                "PUT",
                "/api/hosts",
                json_data={tag: desired_by_tag[tag]},
            )
            if not ok_put:
                return False, {
                    "stage": "host_profile_write",
                    "managed_tags": wanted,
                    "changed_tags": changed,
                    "added_tags": added,
                    "removed_tags": removed,
                    "failed_tag": tag,
                    "error": response,
                }
            changed.append(tag)

        ok_verify, verify_payload = await self.get_hosts()
        if not ok_verify or not isinstance(verify_payload, dict):
            return False, {
                "stage": "host_profile_verify",
                "managed_tags": wanted,
                "changed_tags": changed,
                "error": (
                    verify_payload
                    if not ok_verify
                    else "Invalid Marzban hosts response after reconciliation"
                ),
            }

        matches = find_node_generated_hosts(
            verify_payload,
            node,
            public_address=public_address,
        )
        counts: Dict[str, int] = {}
        for item in matches:
            tag = item["tag"]
            counts[tag] = counts.get(tag, 0) + 1

        bad_counts = {
            tag: count
            for tag, count in counts.items()
            if tag not in wanted or count != 1
        }
        missing_after = [tag for tag in wanted if counts.get(tag) != 1]
        if bad_counts or missing_after:
            return False, {
                "stage": "host_profile_verify",
                "managed_tags": wanted,
                "changed_tags": changed,
                "counts": counts,
                "missing_tags": missing_after,
                "unexpected_tags": bad_counts,
                "error": "Managed Public Host profile did not verify",
            }

        return True, {
            "stage": "host_profile_verify",
            "verified": True,
            "managed_tags": wanted,
            "changed_tags": changed,
            "added_tags": added,
            "removed_tags": removed,
        }

    async def update_host(
        self,
        inbound_tag: str,
        host_index: int,
        *,
        expected_host: Optional[Dict[str, Any]] = None,
        **changes: Any,
    ) -> ApiResult:
        """Safely update one Public Host through Marzban's bulk /api/hosts API.

        Marzban Public Hosts have no stable id; they are stored as ordered lists
        per inbound tag. NVL therefore reloads authoritative state immediately
        before writing and can reject a stale confirmation by comparing the
        expected host snapshot at the same index.
        """
        tag = normalize_inbound_tag(inbound_tag)
        index = normalize_host_index(host_index)
        normalized = normalize_host_changes(changes)

        ok, payload = await self.get_hosts()
        if not ok:
            return False, payload
        if not isinstance(payload, dict):
            return False, "Invalid Marzban hosts response"

        current_hosts = payload.get(tag)
        if not isinstance(current_hosts, list):
            return False, f"Inbound host list not found: {tag}"
        if index >= len(current_hosts):
            return False, "Public Host no longer exists"

        current = current_hosts[index]
        if not isinstance(current, dict):
            return False, "Invalid Marzban host response"

        if expected_host is not None:
            try:
                if host_snapshot(current) != host_snapshot(expected_host):
                    return False, "Public Host changed since confirmation; reload and try again"
            except ValueError as exc:
                return False, str(exc)

        try:
            replacement = _host_payload({**current, **normalized})
            tag_hosts = [_host_payload(item) for item in current_hosts]
        except ValueError as exc:
            return False, str(exc)
        tag_hosts[index] = replacement

        return await self.request(
            "PUT",
            "/api/hosts",
            json_data={tag: tag_hosts},
        )

    async def set_host_disabled(
        self,
        inbound_tag: str,
        host_index: int,
        disabled: bool,
        *,
        expected_host: Optional[Dict[str, Any]] = None,
    ) -> ApiResult:
        return await self.update_host(
            inbound_tag,
            host_index,
            expected_host=expected_host,
            is_disabled=bool(disabled),
        )

    async def delete_host(
        self,
        inbound_tag: str,
        host_index: int,
        *,
        expected_host: Optional[Dict[str, Any]] = None,
    ) -> ApiResult:
        """Delete one Public Host with stale-snapshot and post-write verification."""
        tag = normalize_inbound_tag(inbound_tag)
        index = normalize_host_index(host_index)

        ok, payload = await self.get_hosts()
        if not ok:
            return False, {
                "stage": "precheck",
                "deleted": False,
                "tag": tag,
                "index": index,
                "error": payload,
            }
        if not isinstance(payload, dict):
            return False, {
                "stage": "precheck",
                "deleted": False,
                "tag": tag,
                "index": index,
                "error": "Invalid Marzban hosts response",
            }

        current_hosts = payload.get(tag)
        if not isinstance(current_hosts, list) or index >= len(current_hosts):
            return False, {
                "stage": "precheck",
                "deleted": False,
                "tag": tag,
                "index": index,
                "error": "Public Host no longer exists",
            }

        current = current_hosts[index]
        if not isinstance(current, dict):
            return False, {
                "stage": "precheck",
                "deleted": False,
                "tag": tag,
                "index": index,
                "error": "Invalid Marzban host response",
            }

        if expected_host is not None:
            try:
                if host_snapshot(current) != host_snapshot(expected_host):
                    return False, {
                        "stage": "precheck",
                        "deleted": False,
                        "tag": tag,
                        "index": index,
                        "error": "Public Host changed since confirmation; reload and try again",
                    }
            except ValueError as exc:
                return False, {
                    "stage": "precheck",
                    "deleted": False,
                    "tag": tag,
                    "index": index,
                    "error": str(exc),
                }

        try:
            before = [_host_payload(item) for item in current_hosts]
        except ValueError as exc:
            return False, {
                "stage": "precheck",
                "deleted": False,
                "tag": tag,
                "index": index,
                "error": str(exc),
            }
        after = before[:index] + before[index + 1:]

        ok_put, response = await self.request(
            "PUT",
            "/api/hosts",
            json_data={tag: after},
        )
        if not ok_put:
            return False, {
                "stage": "delete",
                "deleted": False,
                "tag": tag,
                "index": index,
                "host": host_snapshot(current),
                "error": response,
            }

        ok_verify, verify_payload = await self.get_hosts()
        if not ok_verify or not isinstance(verify_payload, dict):
            return False, {
                "stage": "verify",
                "deleted": True,
                "tag": tag,
                "index": index,
                "host": host_snapshot(current),
                "error": (
                    verify_payload
                    if not ok_verify
                    else "Invalid Marzban hosts response after delete"
                ),
            }

        verify_hosts = verify_payload.get(tag)
        if not isinstance(verify_hosts, list):
            return False, {
                "stage": "verify",
                "deleted": True,
                "tag": tag,
                "index": index,
                "host": host_snapshot(current),
                "error": "Inbound host list missing after delete",
            }
        try:
            verified = [_host_payload(item) for item in verify_hosts]
        except ValueError as exc:
            return False, {
                "stage": "verify",
                "deleted": True,
                "tag": tag,
                "index": index,
                "host": host_snapshot(current),
                "error": str(exc),
            }

        if verified != after:
            return False, {
                "stage": "verify",
                "deleted": True,
                "tag": tag,
                "index": index,
                "host": host_snapshot(current),
                "error": "Public Host list does not match expected state after delete",
            }

        return True, {
            "stage": "verify",
            "deleted": True,
            "verified": True,
            "tag": tag,
            "index": index,
            "host": host_snapshot(current),
            "response": response,
        }

    async def delete_node_generated_hosts(
        self,
        candidates: Any,
    ) -> ApiResult:
        """Delete pre-confirmed auto-generated Node hosts, safely per inbound."""
        if not isinstance(candidates, list):
            return False, {
                "stage": "host_cleanup",
                "deleted_count": 0,
                "error": "Invalid Node host cleanup candidates",
            }

        normalized: List[Dict[str, Any]] = []
        try:
            for item in candidates:
                if not isinstance(item, dict):
                    raise ValueError("invalid host cleanup candidate")
                normalized.append({
                    "tag": normalize_inbound_tag(item.get("tag")),
                    "index": normalize_host_index(item.get("index")),
                    "host": host_snapshot(item.get("host")),
                })
        except ValueError as exc:
            return False, {
                "stage": "host_cleanup",
                "deleted_count": 0,
                "error": str(exc),
            }

        # Descending index keeps remaining indices stable even in the unlikely
        # case multiple matching hosts exist under the same inbound.
        normalized.sort(key=lambda item: (item["tag"], -item["index"]))
        deleted: List[Dict[str, Any]] = []
        for item in normalized:
            ok_delete, result = await self.delete_host(
                item["tag"],
                item["index"],
                expected_host=item["host"],
            )
            if not ok_delete:
                return False, {
                    "stage": "host_cleanup",
                    "deleted_count": len(deleted),
                    "deleted_hosts": deleted,
                    "failed_host": item,
                    "error": result,
                }
            deleted.append(item)

        return True, {
            "stage": "host_cleanup",
            "deleted_count": len(deleted),
            "deleted_hosts": deleted,
        }

    async def modify_user(self, username: str, **changes: Any) -> ApiResult:
        if not changes:
            return False, "No changes supplied"
        return await self.request("PUT", f"/api/user/{username}", json_data=changes)

    async def set_user_status(self, username: str, status: str) -> ApiResult:
        if status not in {"active", "disabled"}:
            return False, f"Unsupported user status: {status}"
        return await self.modify_user(username, status=status)

    async def reset_user_usage(self, username: str) -> ApiResult:
        return await self.request("POST", f"/api/user/{username}/reset")

    async def get_subscription_url(self, username: str) -> ApiResult:
        ok, payload = await self.get_user(username)
        if not ok:
            return False, payload
        if not isinstance(payload, dict):
            return False, "Invalid Marzban user response"

        sub_url = str(payload.get("subscription_url") or "").strip()
        if not sub_url:
            return False, "Subscription URL is empty"
        if sub_url.startswith("/"):
            sub_url = f"{self.url}{sub_url}"
        return True, sub_url

    async def delete_user(self, username: str) -> ApiResult:
        return await self.request("DELETE", f"/api/user/{username}")