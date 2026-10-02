"""Phase 6C per-Edge observability primitives.

This module is intentionally pure and provider-neutral. It classifies structured
probe evidence only; it never performs failover, DNS changes, membership changes,
or customer migration.
"""
from dataclasses import dataclass
from typing import Optional


DIAG_ALL_PATHS_HEALTHY = "ALL_PATHS_HEALTHY"
DIAG_ADMIN_ONLY_FAILURE = "ADMIN_ONLY_FAILURE"
DIAG_SERVICE_PATH_FAILURE = "SERVICE_PATH_FAILURE"
DIAG_WIREGUARD_PATH_FAILURE = "WIREGUARD_PATH_FAILURE"
DIAG_CORE_PATH_FAILURE = "CORE_PATH_FAILURE"
DIAG_EDGE_UNREACHABLE = "EDGE_UNREACHABLE"
DIAG_EXTERNAL_REACHABILITY_FAILURE = "EXTERNAL_REACHABILITY_FAILURE"
DIAG_REGIONAL_REACHABILITY_FAILURE = "REGIONAL_REACHABILITY_FAILURE"
DIAG_FILTER_SUSPECTED = "FILTER_SUSPECTED"
DIAG_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

FILTER_CONFIDENCE_NONE = "NONE"
FILTER_CONFIDENCE_LOW = "LOW"
FILTER_CONFIDENCE_MEDIUM = "MEDIUM"
FILTER_CONFIDENCE_HIGH = "HIGH"

FILTER_REASON_NONE = "NONE"
FILTER_REASON_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
FILTER_REASON_REGIONAL_REACHABILITY_FAILURE = "REGIONAL_REACHABILITY_FAILURE"

PROBE_REASON_OK = "OK"
PROBE_REASON_TIMEOUT = "TIMEOUT"
PROBE_REASON_CONNECTION_REFUSED = "CONNECTION_REFUSED"
PROBE_REASON_NETWORK_UNREACHABLE = "NETWORK_UNREACHABLE"
PROBE_REASON_DNS_ERROR = "DNS_ERROR"
PROBE_REASON_TLS_ERROR = "TLS_ERROR"
PROBE_REASON_UNKNOWN_ERROR = "UNKNOWN_ERROR"


@dataclass(frozen=True)
class ObservabilityDecision:
    diagnostic_reason: str
    filter_suspected: Optional[bool]
    filter_confidence: str
    filter_reason: str


def normalize_probe_error(error) -> str:
    """Normalize arbitrary probe errors into stable machine-readable categories."""
    if error is None or error == "":
        return PROBE_REASON_OK
    text = str(error).lower()
    if "timeout" in text or "timed out" in text:
        return PROBE_REASON_TIMEOUT
    if "refused" in text:
        return PROBE_REASON_CONNECTION_REFUSED
    if "network is unreachable" in text or "no route to host" in text:
        return PROBE_REASON_NETWORK_UNREACHABLE
    if (
        "name or service not known" in text
        or "temporary failure in name resolution" in text
        or "nodename nor servname" in text
        or "dns" in text
    ):
        return PROBE_REASON_DNS_ERROR
    if "ssl" in text or "tls" in text or "certificate" in text:
        return PROBE_REASON_TLS_ERROR
    return PROBE_REASON_UNKNOWN_ERROR


def derive_observability(
    service_ok,
    admin_ok,
    wg_peer_ok,
    core_path_ok,
    external_service_ok=None,
    regional_service_ok=None,
    regional_failure_streak: int = 0,
    regional_success_streak: int = 0,
    confirm_threshold: int = 3,
    recovery_threshold: int = 2,
    previous_filter_suspected=None,
) -> ObservabilityDecision:
    """Derive a deterministic Phase 6C diagnostic/filtering decision.

    Regional evidence is optional. Filtering is never confirmed from a single
    failure and is only considered after the local service, WireGuard and tunnel
    path are healthy. A previously confirmed suspicion requires the configured
    recovery-success threshold before it clears.
    """
    confirm_threshold = max(1, int(confirm_threshold))
    recovery_threshold = max(1, int(recovery_threshold))
    regional_failure_streak = max(0, int(regional_failure_streak or 0))
    regional_success_streak = max(0, int(regional_success_streak or 0))

    if service_ok is None or admin_ok is None:
        return ObservabilityDecision(
            DIAG_INSUFFICIENT_EVIDENCE,
            None,
            FILTER_CONFIDENCE_NONE,
            FILTER_REASON_INSUFFICIENT_EVIDENCE,
        )

    if not bool(service_ok) and not bool(admin_ok):
        return ObservabilityDecision(
            DIAG_EDGE_UNREACHABLE,
            False,
            FILTER_CONFIDENCE_NONE,
            FILTER_REASON_NONE,
        )

    if wg_peer_ok is None or core_path_ok is None:
        return ObservabilityDecision(
            DIAG_INSUFFICIENT_EVIDENCE,
            None,
            FILTER_CONFIDENCE_NONE,
            FILTER_REASON_INSUFFICIENT_EVIDENCE,
        )

    if not bool(wg_peer_ok):
        return ObservabilityDecision(
            DIAG_WIREGUARD_PATH_FAILURE,
            False,
            FILTER_CONFIDENCE_NONE,
            FILTER_REASON_NONE,
        )

    if not bool(core_path_ok):
        return ObservabilityDecision(
            DIAG_CORE_PATH_FAILURE,
            False,
            FILTER_CONFIDENCE_NONE,
            FILTER_REASON_NONE,
        )

    if not bool(service_ok):
        return ObservabilityDecision(
            DIAG_SERVICE_PATH_FAILURE,
            False,
            FILTER_CONFIDENCE_NONE,
            FILTER_REASON_NONE,
        )

    base_reason = (
        DIAG_ADMIN_ONLY_FAILURE if not bool(admin_ok) else DIAG_ALL_PATHS_HEALTHY
    )

    # Once filtering is confirmed, transient recovery is deliberately sticky.
    if (
        previous_filter_suspected is True
        and regional_service_ok is True
        and regional_success_streak < recovery_threshold
    ):
        return ObservabilityDecision(
            DIAG_FILTER_SUSPECTED,
            True,
            FILTER_CONFIDENCE_MEDIUM,
            FILTER_REASON_REGIONAL_REACHABILITY_FAILURE,
        )

    if regional_service_ok is False:
        if regional_failure_streak >= confirm_threshold:
            confidence = (
                FILTER_CONFIDENCE_HIGH
                if external_service_ok is True
                else FILTER_CONFIDENCE_MEDIUM
            )
            return ObservabilityDecision(
                DIAG_FILTER_SUSPECTED,
                True,
                confidence,
                FILTER_REASON_REGIONAL_REACHABILITY_FAILURE,
            )
        return ObservabilityDecision(
            DIAG_REGIONAL_REACHABILITY_FAILURE,
            False,
            FILTER_CONFIDENCE_LOW,
            FILTER_REASON_REGIONAL_REACHABILITY_FAILURE,
        )

    if external_service_ok is False:
        return ObservabilityDecision(
            DIAG_EXTERNAL_REACHABILITY_FAILURE,
            False,
            FILTER_CONFIDENCE_LOW,
            FILTER_REASON_NONE,
        )

    if regional_service_ok is True:
        return ObservabilityDecision(
            base_reason,
            False,
            FILTER_CONFIDENCE_NONE,
            FILTER_REASON_NONE,
        )

    # Regional evidence is optional. Local diagnostics remain useful while the
    # filtering dimension stays explicitly unknown.
    return ObservabilityDecision(
        base_reason,
        None,
        FILTER_CONFIDENCE_NONE,
        FILTER_REASON_INSUFFICIENT_EVIDENCE,
    )
