"""Phase 6E: provider-neutral regional filtering classification.

This module consumes normalized node evidence (for example Phase 6D Check-Host
TcpNodeEvidence objects) and produces ONE regional round verdict.

It does not call providers, mutate SQLite, change DNS, move accounts, activate
Standby, or perform failover.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Optional


REGIONAL_STATE_UNKNOWN = "UNKNOWN"
REGIONAL_STATE_CLEAR = "CLEAR"
REGIONAL_STATE_POSSIBLE = "POSSIBLE"
REGIONAL_STATE_LIKELY = "LIKELY"

REGIONAL_REASON_INSUFFICIENT_COVERAGE = "INSUFFICIENT_COVERAGE"
REGIONAL_REASON_HEALTHY_QUORUM = "HEALTHY_QUORUM"
REGIONAL_REASON_LIMITED_FAILURE = "LIMITED_FAILURE"
REGIONAL_REASON_DIVERSE_FAILURE = "DIVERSE_FAILURE"
REGIONAL_REASON_MAJORITY_DIVERSE_FAILURE = "MAJORITY_DIVERSE_FAILURE"

DEFAULT_MIN_COMPLETED_NODES = 4
DEFAULT_MIN_COMPLETED_ASNS = 4
DEFAULT_MIN_COMPLETED_CITIES = 2

DEFAULT_POSSIBLE_MIN_FAILED_NODES = 2
DEFAULT_POSSIBLE_MIN_FAILED_ASNS = 2
DEFAULT_POSSIBLE_MIN_FAILURE_RATIO = 0.25

DEFAULT_LIKELY_MIN_FAILED_NODES = 4
DEFAULT_LIKELY_MIN_FAILED_ASNS = 4
DEFAULT_LIKELY_MIN_FAILED_CITIES = 2
DEFAULT_LIKELY_MIN_FAILURE_RATIO = 0.60


@dataclass(frozen=True)
class RegionalEvidenceSummary:
    total_nodes: int
    completed_nodes: int
    successful_nodes: int
    failed_nodes: int
    pending_nodes: int
    completed_asns: tuple[str, ...]
    failed_asns: tuple[str, ...]
    completed_cities: tuple[str, ...]
    failed_cities: tuple[str, ...]

    @property
    def completion_ratio(self) -> Optional[float]:
        if self.total_nodes <= 0:
            return None
        return self.completed_nodes / self.total_nodes

    @property
    def failure_ratio(self) -> Optional[float]:
        if self.completed_nodes <= 0:
            return None
        return self.failed_nodes / self.completed_nodes

    @property
    def success_ratio(self) -> Optional[float]:
        if self.completed_nodes <= 0:
            return None
        return self.successful_nodes / self.completed_nodes


@dataclass(frozen=True)
class RegionalFilteringDecision:
    state: str
    reason: str
    regional_service_ok: Optional[bool]
    summary: RegionalEvidenceSummary

    @property
    def is_actionable_failure(self) -> bool:
        """Whether this round supplies negative regional reachability evidence."""
        return self.state in {REGIONAL_STATE_POSSIBLE, REGIONAL_STATE_LIKELY}

    def to_dict(self) -> dict:
        summary = self.summary
        return {
            "state": self.state,
            "reason": self.reason,
            "regional_service_ok": self.regional_service_ok,
            "total_nodes": summary.total_nodes,
            "completed_nodes": summary.completed_nodes,
            "successful_nodes": summary.successful_nodes,
            "failed_nodes": summary.failed_nodes,
            "pending_nodes": summary.pending_nodes,
            "completion_ratio": summary.completion_ratio,
            "failure_ratio": summary.failure_ratio,
            "success_ratio": summary.success_ratio,
            "completed_asns": list(summary.completed_asns),
            "failed_asns": list(summary.failed_asns),
            "completed_cities": list(summary.completed_cities),
            "failed_cities": list(summary.failed_cities),
        }


def _nonempty_text(value) -> str:
    return str(value or "").strip()


def summarize_node_evidence(evidence: Iterable[object]) -> RegionalEvidenceSummary:
    """Build a provider-neutral aggregate from node-like evidence objects.

    Each object is expected to expose:
      - ok: True / False / None
      - pending: bool
      - asn: str
      - city: str

    Pending/unknown nodes never count as failures.
    """
    items = tuple(evidence or ())
    completed = []
    failed = []
    successful = []

    for item in items:
        pending = bool(getattr(item, "pending", False))
        ok = getattr(item, "ok", None)
        if pending or ok is None:
            continue
        completed.append(item)
        if ok is True:
            successful.append(item)
        elif ok is False:
            failed.append(item)

    def unique_text(rows, attr):
        return tuple(
            sorted(
                {
                    text
                    for row in rows
                    if (text := _nonempty_text(getattr(row, attr, "")))
                }
            )
        )

    return RegionalEvidenceSummary(
        total_nodes=len(items),
        completed_nodes=len(completed),
        successful_nodes=len(successful),
        failed_nodes=len(failed),
        pending_nodes=len(items) - len(completed),
        completed_asns=unique_text(completed, "asn"),
        failed_asns=unique_text(failed, "asn"),
        completed_cities=unique_text(completed, "city"),
        failed_cities=unique_text(failed, "city"),
    )


def classify_regional_summary(
    summary: RegionalEvidenceSummary,
    *,
    min_completed_nodes: int = DEFAULT_MIN_COMPLETED_NODES,
    min_completed_asns: int = DEFAULT_MIN_COMPLETED_ASNS,
    min_completed_cities: int = DEFAULT_MIN_COMPLETED_CITIES,
    possible_min_failed_nodes: int = DEFAULT_POSSIBLE_MIN_FAILED_NODES,
    possible_min_failed_asns: int = DEFAULT_POSSIBLE_MIN_FAILED_ASNS,
    possible_min_failure_ratio: float = DEFAULT_POSSIBLE_MIN_FAILURE_RATIO,
    likely_min_failed_nodes: int = DEFAULT_LIKELY_MIN_FAILED_NODES,
    likely_min_failed_asns: int = DEFAULT_LIKELY_MIN_FAILED_ASNS,
    likely_min_failed_cities: int = DEFAULT_LIKELY_MIN_FAILED_CITIES,
    likely_min_failure_ratio: float = DEFAULT_LIKELY_MIN_FAILURE_RATIO,
) -> RegionalFilteringDecision:
    """Classify one regional probe round without temporal escalation.

    A repeated weak round must not become LIKELY merely because it repeats.
    Spatial/diversity evidence is evaluated here; temporal confirmation belongs to
    the Phase 6C/6E observability layer.

    The thresholds are deterministic alert-policy thresholds, not calibrated
    probabilities.
    """
    min_completed_nodes = max(1, int(min_completed_nodes))
    min_completed_asns = max(1, int(min_completed_asns))
    min_completed_cities = max(1, int(min_completed_cities))
    possible_min_failed_nodes = max(1, int(possible_min_failed_nodes))
    possible_min_failed_asns = max(1, int(possible_min_failed_asns))
    likely_min_failed_nodes = max(1, int(likely_min_failed_nodes))
    likely_min_failed_asns = max(1, int(likely_min_failed_asns))
    likely_min_failed_cities = max(1, int(likely_min_failed_cities))

    possible_min_failure_ratio = min(1.0, max(0.0, float(possible_min_failure_ratio)))
    likely_min_failure_ratio = min(1.0, max(0.0, float(likely_min_failure_ratio)))

    coverage_ok = (
        summary.completed_nodes >= min_completed_nodes
        and len(summary.completed_asns) >= min_completed_asns
        and len(summary.completed_cities) >= min_completed_cities
    )
    if not coverage_ok:
        return RegionalFilteringDecision(
            REGIONAL_STATE_UNKNOWN,
            REGIONAL_REASON_INSUFFICIENT_COVERAGE,
            None,
            summary,
        )

    failure_ratio = summary.failure_ratio or 0.0

    # Strong filtering evidence needs both a strong failed-node majority and
    # independent network/location diversity. The dynamic minimum avoids calling a
    # 3/4 split "LIKELY" even though 75% failed; four failed nodes are still required.
    dynamic_likely_failed_nodes = max(
        likely_min_failed_nodes,
        int(math.ceil(summary.completed_nodes * likely_min_failure_ratio)),
    )
    likely = (
        summary.failed_nodes >= dynamic_likely_failed_nodes
        and failure_ratio >= likely_min_failure_ratio
        and len(summary.failed_asns) >= likely_min_failed_asns
        and len(summary.failed_cities) >= likely_min_failed_cities
    )
    if likely:
        return RegionalFilteringDecision(
            REGIONAL_STATE_LIKELY,
            REGIONAL_REASON_MAJORITY_DIVERSE_FAILURE,
            False,
            summary,
        )

    possible = (
        summary.failed_nodes >= possible_min_failed_nodes
        and failure_ratio >= possible_min_failure_ratio
        and len(summary.failed_asns) >= possible_min_failed_asns
    )
    if possible:
        return RegionalFilteringDecision(
            REGIONAL_STATE_POSSIBLE,
            REGIONAL_REASON_DIVERSE_FAILURE,
            False,
            summary,
        )

    if summary.failed_nodes:
        return RegionalFilteringDecision(
            REGIONAL_STATE_CLEAR,
            REGIONAL_REASON_LIMITED_FAILURE,
            True,
            summary,
        )

    return RegionalFilteringDecision(
        REGIONAL_STATE_CLEAR,
        REGIONAL_REASON_HEALTHY_QUORUM,
        True,
        summary,
    )


def classify_regional_evidence(
    evidence: Iterable[object],
    **threshold_overrides,
) -> RegionalFilteringDecision:
    """Convenience adapter for Phase 6D-style normalized node evidence."""
    return classify_regional_summary(
        summarize_node_evidence(evidence),
        **threshold_overrides,
    )
