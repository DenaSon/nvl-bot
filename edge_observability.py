"""Phase 6C per-Edge observability primitives.

This module is intentionally pure and provider-neutral. It classifies structured
probe evidence only; it never performs failover, DNS changes, membership changes,
or customer migration.
"""
from dataclasses import dataclass
from typing import Optional

from regional_filtering import (
    REGIONAL_STATE_CLEAR,
    REGIONAL_STATE_LIKELY,
    REGIONAL_STATE_POSSIBLE,
    REGIONAL_STATE_UNKNOWN,
)


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
DIAG_CORE_LOCAL = "CORE_LOCAL"

FILTER_CONFIDENCE_NONE = "NONE"
FILTER_CONFIDENCE_LOW = "LOW"
FILTER_CONFIDENCE_MEDIUM = "MEDIUM"
FILTER_CONFIDENCE_HIGH = "HIGH"

FILTER_REASON_NONE = "NONE"
FILTER_REASON_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
FILTER_REASON_REGIONAL_REACHABILITY_FAILURE = "REGIONAL_REACHABILITY_FAILURE"

FILTER_STATE_UNKNOWN = REGIONAL_STATE_UNKNOWN
FILTER_STATE_CLEAR = REGIONAL_STATE_CLEAR
FILTER_STATE_POSSIBLE = REGIONAL_STATE_POSSIBLE
FILTER_STATE_LIKELY = REGIONAL_STATE_LIKELY

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
    filter_state: str = FILTER_STATE_UNKNOWN


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
    regional_filter_state=None,
) -> ObservabilityDecision:
    """Derive a deterministic Phase 6C diagnostic/filtering decision.

    Filtering is confirmed only from repeated regional failures while the local
    Service/WireGuard/Core path remains healthy. Once confirmed, the filtering
    dimension is sticky until *regional* recovery reaches recovery_threshold;
    unrelated infrastructure failures are diagnostics, not proof of recovery.
    """
    confirm_threshold = max(1, int(confirm_threshold))
    recovery_threshold = max(1, int(recovery_threshold))
    regional_failure_streak = max(0, int(regional_failure_streak or 0))
    regional_success_streak = max(0, int(regional_success_streak or 0))

    regional_state_supplied = regional_filter_state is not None
    if regional_state_supplied:
        normalized_regional_state = str(regional_filter_state or "").upper()
        if normalized_regional_state not in {
            FILTER_STATE_UNKNOWN,
            FILTER_STATE_CLEAR,
            FILTER_STATE_POSSIBLE,
            FILTER_STATE_LIKELY,
        }:
            normalized_regional_state = FILTER_STATE_UNKNOWN

        # Phase 6E state is authoritative for the current regional round. UNKNOWN
        # must never be silently converted into a failure.
        if normalized_regional_state == FILTER_STATE_CLEAR:
            regional_service_ok = True
        elif normalized_regional_state in {FILTER_STATE_POSSIBLE, FILTER_STATE_LIKELY}:
            regional_service_ok = False
        else:
            regional_service_ok = None
    else:
        normalized_regional_state = None

    recovery_confirmed = (
        previous_filter_suspected is True
        and service_ok is True
        and wg_peer_ok is True
        and core_path_ok is True
        and regional_service_ok is True
        and regional_success_streak >= recovery_threshold
    )
    sticky_confirmed_filter = (
        previous_filter_suspected is True and not recovery_confirmed
    )

    def result(diagnostic, suspected, confidence, filter_reason, filter_state=None):
        if filter_state is None:
            if suspected is True:
                filter_state = FILTER_STATE_LIKELY
            elif suspected is False:
                filter_state = FILTER_STATE_CLEAR
            else:
                filter_state = FILTER_STATE_UNKNOWN

        # A previously confirmed filtering condition cannot be cleared by missing
        # evidence, an unrelated WG/Core failure, or a single successful regional
        # check. Only the explicit recovery condition above clears it.
        if sticky_confirmed_filter and suspected is not True:
            sticky_diagnostic = (
                DIAG_FILTER_SUSPECTED
                if diagnostic in {DIAG_ALL_PATHS_HEALTHY, DIAG_ADMIN_ONLY_FAILURE}
                else diagnostic
            )
            return ObservabilityDecision(
                sticky_diagnostic,
                True,
                FILTER_CONFIDENCE_LOW,
                FILTER_REASON_REGIONAL_REACHABILITY_FAILURE,
                FILTER_STATE_LIKELY,
            )
        return ObservabilityDecision(
            diagnostic,
            suspected,
            confidence,
            filter_reason,
            filter_state,
        )

    if service_ok is None or admin_ok is None:
        return result(
            DIAG_INSUFFICIENT_EVIDENCE,
            None,
            FILTER_CONFIDENCE_NONE,
            FILTER_REASON_INSUFFICIENT_EVIDENCE,
        )

    if not bool(service_ok) and not bool(admin_ok):
        return result(
            DIAG_EDGE_UNREACHABLE,
            False,
            FILTER_CONFIDENCE_NONE,
            FILTER_REASON_NONE,
            FILTER_STATE_UNKNOWN,
        )

    if wg_peer_ok is None or core_path_ok is None:
        return result(
            DIAG_INSUFFICIENT_EVIDENCE,
            None,
            FILTER_CONFIDENCE_NONE,
            FILTER_REASON_INSUFFICIENT_EVIDENCE,
        )

    if not bool(wg_peer_ok):
        return result(
            DIAG_WIREGUARD_PATH_FAILURE,
            False,
            FILTER_CONFIDENCE_NONE,
            FILTER_REASON_NONE,
            FILTER_STATE_UNKNOWN,
        )

    if not bool(core_path_ok):
        return result(
            DIAG_CORE_PATH_FAILURE,
            False,
            FILTER_CONFIDENCE_NONE,
            FILTER_REASON_NONE,
            FILTER_STATE_UNKNOWN,
        )

    if not bool(service_ok):
        return result(
            DIAG_SERVICE_PATH_FAILURE,
            False,
            FILTER_CONFIDENCE_NONE,
            FILTER_REASON_NONE,
            FILTER_STATE_UNKNOWN,
        )

    base_reason = (
        DIAG_ADMIN_ONLY_FAILURE if not bool(admin_ok) else DIAG_ALL_PATHS_HEALTHY
    )

    if regional_service_ok is False:
        # If the independent external probe is also down, the evidence no longer
        # isolates a regional path. Never newly confirm filtering from that pattern.
        if external_service_ok is False:
            return result(
                DIAG_EXTERNAL_REACHABILITY_FAILURE,
                False,
                FILTER_CONFIDENCE_LOW,
                FILTER_REASON_NONE,
                FILTER_STATE_UNKNOWN,
            )

        if regional_state_supplied:
            # A weak-but-diverse POSSIBLE round remains POSSIBLE even if it repeats.
            # Temporal repetition cannot manufacture spatial evidence that the
            # current round does not contain.
            if normalized_regional_state == FILTER_STATE_POSSIBLE:
                return result(
                    DIAG_REGIONAL_REACHABILITY_FAILURE,
                    False,
                    FILTER_CONFIDENCE_LOW,
                    FILTER_REASON_REGIONAL_REACHABILITY_FAILURE,
                    FILTER_STATE_POSSIBLE,
                )

            if normalized_regional_state == FILTER_STATE_LIKELY:
                if regional_failure_streak >= confirm_threshold:
                    confidence = (
                        FILTER_CONFIDENCE_HIGH
                        if external_service_ok is True
                        else FILTER_CONFIDENCE_MEDIUM
                    )
                    # Without a successful external control, keep the user-facing
                    # state at POSSIBLE even though legacy filter_suspected remains
                    # true/medium for backwards compatibility.
                    final_state = (
                        FILTER_STATE_LIKELY
                        if external_service_ok is True
                        else FILTER_STATE_POSSIBLE
                    )
                    return ObservabilityDecision(
                        DIAG_FILTER_SUSPECTED,
                        True,
                        confidence,
                        FILTER_REASON_REGIONAL_REACHABILITY_FAILURE,
                        final_state,
                    )
                return result(
                    DIAG_REGIONAL_REACHABILITY_FAILURE,
                    False,
                    FILTER_CONFIDENCE_MEDIUM,
                    FILTER_REASON_REGIONAL_REACHABILITY_FAILURE,
                    FILTER_STATE_POSSIBLE,
                )

            return result(
                DIAG_INSUFFICIENT_EVIDENCE,
                None,
                FILTER_CONFIDENCE_NONE,
                FILTER_REASON_INSUFFICIENT_EVIDENCE,
                FILTER_STATE_UNKNOWN,
            )

        # Backwards-compatible Phase 6C behaviour for callers that do not yet pass
        # the richer Phase 6E regional round state.
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
                (
                    FILTER_STATE_LIKELY
                    if confidence == FILTER_CONFIDENCE_HIGH
                    else FILTER_STATE_POSSIBLE
                ),
            )
        return result(
            DIAG_REGIONAL_REACHABILITY_FAILURE,
            False,
            FILTER_CONFIDENCE_LOW,
            FILTER_REASON_REGIONAL_REACHABILITY_FAILURE,
            FILTER_STATE_POSSIBLE,
        )

    if external_service_ok is False:
        return result(
            DIAG_EXTERNAL_REACHABILITY_FAILURE,
            False,
            FILTER_CONFIDENCE_LOW,
            FILTER_REASON_NONE,
            FILTER_STATE_UNKNOWN,
        )

    if regional_service_ok is True:
        if sticky_confirmed_filter:
            return ObservabilityDecision(
                DIAG_FILTER_SUSPECTED,
                True,
                FILTER_CONFIDENCE_MEDIUM,
                FILTER_REASON_REGIONAL_REACHABILITY_FAILURE,
                FILTER_STATE_LIKELY,
            )
        # Recovery is complete only after the configured regional success threshold.
        return result(
            base_reason,
            False,
            FILTER_CONFIDENCE_NONE,
            FILTER_REASON_NONE,
            FILTER_STATE_CLEAR,
        )

    # Regional evidence is optional. Local diagnostics remain useful while the
    # filtering dimension stays explicitly unknown unless a previous confirmation
    # is still waiting for a qualified recovery.
    return result(
        base_reason,
        None,
        FILTER_CONFIDENCE_NONE,
        FILTER_REASON_INSUFFICIENT_EVIDENCE,
        FILTER_STATE_UNKNOWN,
    )

