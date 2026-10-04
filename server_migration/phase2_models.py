from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Optional


PHASE2_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class BundleArtifact:
    name: str
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SourceBundle:
    job_id: str
    source_host: str
    remote_job_dir: str
    remote_bundle_dir: str
    checksum_file: str
    artifacts: tuple[BundleArtifact, ...]
    metadata: Mapping[str, Any]

    @property
    def total_size_bytes(self) -> int:
        return sum(item.size_bytes for item in self.artifacts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "source_host": self.source_host,
            "remote_job_dir": self.remote_job_dir,
            "remote_bundle_dir": self.remote_bundle_dir,
            "checksum_file": self.checksum_file,
            "artifacts": [item.to_dict() for item in self.artifacts],
            "total_size_bytes": self.total_size_bytes,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class TransferReport:
    job_id: str
    local_bundle_dir: str
    destination_bundle_dir: str
    artifacts: tuple[BundleArtifact, ...]
    source_verified: bool
    local_verified: bool
    destination_verified: bool

    @property
    def total_size_bytes(self) -> int:
        return sum(item.size_bytes for item in self.artifacts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "local_bundle_dir": self.local_bundle_dir,
            "destination_bundle_dir": self.destination_bundle_dir,
            "artifacts": [item.to_dict() for item in self.artifacts],
            "total_size_bytes": self.total_size_bytes,
            "source_verified": self.source_verified,
            "local_verified": self.local_verified,
            "destination_verified": self.destination_verified,
        }


@dataclass(frozen=True)
class Phase2Result:
    job_id: str
    source_bundle: SourceBundle
    transfer: TransferReport

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "source_bundle": self.source_bundle.to_dict(),
            "transfer": self.transfer.to_dict(),
        }


@dataclass(frozen=True)
class Phase2Policy:
    remote_root: str = "/root/nvl-migrations"
    local_root: str = "/var/lib/nvl/migrations"
    minimum_local_reserve_mb: int = 256
    require_preflight_ready: bool = True
    keep_source_snapshot_tree: bool = False
    destination_mode: int = 0o700
    file_mode: int = 0o600


class Phase2Error(RuntimeError):
    pass
