"""NVL Change Server migration engine.

Phase 1 provides read-only discovery/preflight.
Phase 2 creates verified live backup bundles and relays them
Source -> NVL control host -> Destination staging.
Phase 3 verifies the staged bundle, builds an isolated restore preview, and can
restore it onto a clean destination without changing DNS.
Phase 4 performs the guarded final database synchronization, targeted
hosts.address rewrite, destination start, and local health verification.

Cloudflare/DNS cutover and full rollback policy remain later phases.
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
from .phase3 import run_phase3
from .phase3_models import (
    PHASE3_MODE_INSPECT,
    PHASE3_MODE_RESTORE,
    Phase3Error,
    Phase3Policy,
    Phase3Result,
)
from .phase4 import run_phase4
from .phase4_models import (
    PHASE4_MODE_FINALIZE,
    PHASE4_MODE_PLAN,
    Phase4Error,
    Phase4Plan,
    Phase4Policy,
    Phase4Result,
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
    "PHASE3_MODE_INSPECT",
    "PHASE3_MODE_RESTORE",
    "Phase3Error",
    "Phase3Policy",
    "Phase3Result",
    "PHASE4_MODE_PLAN",
    "PHASE4_MODE_FINALIZE",
    "Phase4Error",
    "Phase4Plan",
    "Phase4Policy",
    "Phase4Result",
    "evaluate_preflight",
    "run_preflight",
    "run_phase2",
    "run_phase3",
    "run_phase4",
]
