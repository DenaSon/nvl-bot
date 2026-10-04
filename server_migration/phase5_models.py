from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


PHASE5_MODE_PLAN = "PLAN_ONLY"
PHASE5_MODE_CUTOVER = "CUTOVER"


@dataclass(frozen=True)
class Phase5Policy:
    remote_root: str = "/root/nvl-migrations"
    mode: str = PHASE5_MODE_PLAN
    confirmation_phrase: str = "CUTOVER"
    verify_attempts: int = 6
    verify_interval_seconds: float = 2.0
    connect_timeout_seconds: float = 5.0
    rollback_on_failure: bool = True
    stop_destination_on_rollback: bool = True
    restart_source_on_rollback: bool = True
    require_proxied_record: bool = True


@dataclass(frozen=True)
class CloudflareRecordSnapshot:
    zone_id: str
    record_id: str
    name: str
    record_type: str
    content: str
    proxied: bool | None
    ttl: int | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Phase5Plan:
    job_id: str
    hostname: str
    zone_name: str
    old_ip: str
    new_ip: str
    phase4_complete: bool
    source_running: bool
    destination_running: bool
    cloudflare_record: CloudflareRecordSnapshot
    destination_api_precheck: bool
    destination_direct_ports: tuple[int, ...]
    cutover_ready: bool
    blockers: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Phase5Result:
    job_id: str
    hostname: str
    zone_name: str
    old_ip: str
    new_ip: str
    record_id: str
    proxied: bool | None
    dns_updated: bool
    cloudflare_record_verified: bool
    hostname_api_healthy: bool
    direct_ports_verified: tuple[int, ...]
    rollback_performed: bool
    rollback_record_verified: bool
    source_restarted: bool
    destination_stopped_on_rollback: bool
    cutover_complete_marker: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Phase5Error(RuntimeError):
    pass
