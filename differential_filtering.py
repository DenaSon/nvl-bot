"""Pure differential regional filtering policy for NVL Filtering V3.3.

This module compares SAME-NODE Iranian evidence for a suspected source Edge and a
healthy control Edge. It performs no network, SQLite, Telegram, DNS or failover work.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


DIFF_TARGET_SPECIFIC = "TARGET_SPECIFIC_REGIONAL_FAILURE"
DIFF_SHARED_FAILURE = "SHARED_REGIONAL_FAILURE"
DIFF_CONTROL_NOT_CLEAR = "CONTROL_NOT_CLEAR"
DIFF_SOURCE_NOT_LIKELY = "SOURCE_NOT_LIKELY"
DIFF_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_DIFFERENTIAL_EVIDENCE"


@dataclass(frozen=True)
class DifferentialDecision:
    verdict: str
    confirmed: bool
    shared_completed_nodes: int
    target_specific_failed_nodes: tuple[str, ...]
    target_specific_failed_asns: tuple[str, ...]
    shared_failed_nodes: tuple[str, ...]

    @property
    def target_specific_count(self) -> int:
        return len(self.target_specific_failed_nodes)

    @property
    def shared_failure_count(self) -> int:
        return len(self.shared_failed_nodes)


def _index_evidence(evidence: Iterable[object]) -> dict[str, object]:
    rows = {}
    for item in evidence or ():
        node = str(getattr(item, "node", "") or "").strip()
        if node:
            rows[node] = item
    return rows


def evaluate_differential_confirmation(
    source_state: str,
    control_state: str,
    source_evidence: Iterable[object],
    control_evidence: Iterable[object],
    *,
    min_target_specific_nodes: int = 2,
    min_target_specific_asns: int = 2,
) -> DifferentialDecision:
    """Confirm that regional failures are target-specific, not node/provider-wide.

    Strong confirmation requires a LIKELY source round, a CLEAR control target on
    the same requested Iranian nodes, and diverse nodes that fail only the source.
    """
    source_state = str(source_state or "").upper()
    control_state = str(control_state or "").upper()
    min_target_specific_nodes = max(1, int(min_target_specific_nodes))
    min_target_specific_asns = max(1, int(min_target_specific_asns))

    source = _index_evidence(source_evidence)
    control = _index_evidence(control_evidence)

    shared_completed = []
    target_specific = []
    shared_failed = []

    for node in sorted(set(source).intersection(control)):
        src = source[node]
        ctl = control[node]
        src_ok = getattr(src, "ok", None)
        ctl_ok = getattr(ctl, "ok", None)
        src_pending = bool(getattr(src, "pending", False))
        ctl_pending = bool(getattr(ctl, "pending", False))
        if src_pending or ctl_pending or src_ok is None or ctl_ok is None:
            continue

        shared_completed.append(node)
        if src_ok is False and ctl_ok is True:
            target_specific.append(node)
        elif src_ok is False and ctl_ok is False:
            shared_failed.append(node)

    target_specific_asns = tuple(
        sorted(
            {
                str(getattr(source[node], "asn", "") or "").strip()
                for node in target_specific
                if str(getattr(source[node], "asn", "") or "").strip()
            }
        )
    )

    def build(verdict: str, confirmed: bool) -> DifferentialDecision:
        return DifferentialDecision(
            verdict=verdict,
            confirmed=confirmed,
            shared_completed_nodes=len(shared_completed),
            target_specific_failed_nodes=tuple(target_specific),
            target_specific_failed_asns=target_specific_asns,
            shared_failed_nodes=tuple(shared_failed),
        )

    if source_state != "LIKELY":
        return build(DIFF_SOURCE_NOT_LIKELY, False)

    if control_state in {"POSSIBLE", "LIKELY"}:
        return build(DIFF_SHARED_FAILURE, False)

    if control_state != "CLEAR":
        return build(DIFF_CONTROL_NOT_CLEAR, False)

    if (
        len(target_specific) < min_target_specific_nodes
        or len(target_specific_asns) < min_target_specific_asns
    ):
        return build(DIFF_INSUFFICIENT_EVIDENCE, False)

    return build(DIFF_TARGET_SPECIFIC, True)
