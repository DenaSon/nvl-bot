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
from typing import Any, Dict, Optional, Tuple

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
        username: Optional[str] = None,
        status: Optional[str] = None,
    ) -> ApiResult:
        params: Dict[str, Any] = {
            "offset": max(0, int(offset)),
            "limit": max(1, min(int(limit), 100000)),
        }
        if username:
            params["username"] = username
        if status:
            params["status"] = status
        return await self.request("GET", "/api/users", params=params)

    async def get_system_stats(self) -> ApiResult:
        return await self.request("GET", "/api/system")

    async def modify_user(self, username: str, **changes: Any) -> ApiResult:
        if not changes:
            return False, "No changes supplied"
        return await self.request("PUT", f"/api/user/{username}", json_data=changes)

    async def set_user_status(self, username: str, status: str) -> ApiResult:
        if status not in {"active", "disabled"}:
            return False, f"Unsupported user status: {status}"
        return await self.modify_user(username, status=status)

    async def delete_user(self, username: str) -> ApiResult:
        return await self.request("DELETE", f"/api/user/{username}")
