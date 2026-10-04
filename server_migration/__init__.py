"""NVL Change Server migration engine.

Phase 1 provides read-only discovery/preflight.
Phase 2 creates verified live backup bundles and relays them
Source -> NVL control host -> Destination staging.

Restore, runtime mutation, DNS cutover, and rollback are intentionally outside
Phase 2.
"""

from .models import (
    CHECK_FAIL,
    CHECK_PASS,
    CHECK_WARN,
    MigrationPreflightReport,
    PreflightCheck,
    PreflightPolicy,
    ServerCredentials,
    ServerFacts,
)
from .phase2 import run_phase2
from .phase2_models import (
    BundleArtifact,
    Phase2Error,
    Phase2Policy,
    Phase2Result,
    SourceBundle,
    TransferReport,
)
from .preflight import evaluate_preflight, run_preflight

__all__ = [
    "CHECK_FAIL",
    "CHECK_PASS",
    "CHECK_WARN",
    "MigrationPreflightReport",
    "PreflightCheck",
    "PreflightPolicy",
    "ServerCredentials",
    "ServerFacts",
    "BundleArtifact",
    "Phase2Error",
    "Phase2Policy",
    "Phase2Result",
    "SourceBundle",
    "TransferReport",
    "evaluate_preflight",
    "run_preflight",
    "run_phase2",
]
