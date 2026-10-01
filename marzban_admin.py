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

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import v2ray_engine


ApiResult = Tuple[bool, Any]

SUBSCRIPTION_NAME_MIN_LENGTH = 2
SUBSCRIPTION_NAME_MAX_LENGTH = 30
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


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

    async def get_inbounds(self) -> ApiResult:
        return await self.request("GET", "/api/inbounds")

    async def get_hosts(self) -> ApiResult:
        return await self.request("GET", "/api/hosts")

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
