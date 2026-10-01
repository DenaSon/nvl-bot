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

import math
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import v2ray_engine


ApiResult = Tuple[bool, Any]

SUBSCRIPTION_NAME_MIN_LENGTH = 2
SUBSCRIPTION_NAME_MAX_LENGTH = 30
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

NODE_MUTABLE_FIELDS = {"name", "address", "port", "api_port", "status", "usage_coefficient"}
NODE_MUTABLE_STATUSES = {"disabled", "connecting"}

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
    return payload


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
