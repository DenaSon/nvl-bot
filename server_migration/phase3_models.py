from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping


PHASE3_MODE_INSPECT = "INSPECT_ONLY"
PHASE3_MODE_RESTORE = "RESTORE"


@dataclass(frozen=True)
class Phase3Policy:
    remote_root: str = "/root/nvl-migrations"
    mode: str = PHASE3_MODE_RESTORE
    install_docker_if_missing: bool = True
    start_runtime: bool = False
    minimum_destination_free_mb: int = 2048
    preserve_preview: bool = True
    expected_bundle_schema_version: int = 1


@dataclass(frozen=True)
class Phase3Result:
    job_id: str
    mode: str
    incoming_dir: str
    preview_root: str
    metadata: Mapping[str, Any]
    bundle_verified: bool
    archives_verified: bool
    preview_extracted: bool
    database_integrity: str
    compose_valid: bool
    docker_archive_valid: bool
    image_identity_verified: bool
    runtime_restored: bool
    docker_images_loaded: bool
    runtime_started: bool
    api_healthy: bool
    listening_ports: tuple[int, ...]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["metadata"] = dict(self.metadata)
        return data


class Phase3Error(RuntimeError):
    pass
