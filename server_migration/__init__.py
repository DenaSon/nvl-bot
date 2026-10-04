"""Read-only server migration preflight primitives for NVL.

Phase 1 intentionally performs discovery and validation only. It must not
change services, files, databases, DNS, firewall rules, or Docker state.
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
    "evaluate_preflight",
    "run_preflight",
]
