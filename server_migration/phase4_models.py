from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


PHASE4_MODE_PLAN = "PLAN_ONLY"
PHASE4_MODE_FINALIZE = "FINALIZE"


@dataclass(frozen=True)
class Phase4Policy:
    remote_root: str = "/root/nvl-migrations"
    local_root: str = "/var/lib/nvl/migrations"
    mode: str = PHASE4_MODE_PLAN
    confirmation_phrase: str = "FINAL-SYNC"
    require_phase3_restore_marker: bool = True
    fail_on_residual_old_ip: bool = True
    recover_source_on_failure: bool = True
    start_destination: bool = True
    retry_after_cutover_rollback: bool = False
    expected_bundle_schema_version: int = 1


@dataclass(frozen=True)
class Phase4Plan:
    job_id: str
    source_host: str
    destination_host: str
    old_ip: str
    new_ip: str
    source_running: bool
    destination_running: bool
    phase3_restore_complete: bool
    source_database_integrity: str
    destination_database_integrity: str
    matching_host_rows: int
    finalization_ready: bool
    blockers: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Phase4Result:
    job_id: str
    attempt_id: str
    old_ip: str
    new_ip: str
    source_was_running: bool
    source_stopped: bool
    final_database_sha256: str
    local_database_path: str
    destination_staging_path: str
    destination_backup_path: str
    rewritten_host_rows: int
    residual_database_references: tuple[str, ...]
    residual_config_files: tuple[str, ...]
    destination_database_integrity: str
    destination_started: bool
    api_healthy: bool
    listening_ports: tuple[int, ...]
    source_recovered: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Phase4Error(RuntimeError):
    pass
