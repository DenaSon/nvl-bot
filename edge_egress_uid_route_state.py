"""F1: strict read-only ownership check for a protected UID route table.

The terminal metric-4096 blackhole MUST be present before an Edge route is
accepted. A different next-hop, duplicate route or missing blackhole fails
closed. This is not a live egress/reboot proof.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


class ProtectedRouteError(ValueError):
    pass


@dataclass(frozen=True)
class ProtectedRouteState:
    terminal_blackhole: bool
    edge_attached: bool


def inspect_owned_routes(raw: str, *, next_hop: str, device: str,
                         source: str, allow_empty: bool = False) -> ProtectedRouteState:
    if not isinstance(raw, str) or not all(
        isinstance(x, str) and x for x in (next_hop, device, source)
    ):
        raise ProtectedRouteError("INVALID_ROUTE_OBSERVATION")
    rows = [line.strip() for line in raw.splitlines() if line.strip()]
    if not rows and allow_empty:
        return ProtectedRouteState(False, False)
    blackhole = re.compile(r"blackhole default(?: proto static)? metric 4096")
    edge = re.compile(
        r"default via " + re.escape(next_hop) + r" dev " + re.escape(device) +
        r"(?: proto static)? src " + re.escape(source) +
        r" metric 100(?: onlink)?(?: linkdown)?"
    )
    num_blackhole = sum(bool(blackhole.fullmatch(row)) for row in rows)
    num_edge = sum(bool(edge.fullmatch(row)) for row in rows)
    if num_blackhole != 1 or num_edge > 1 or len(rows) != num_blackhole + num_edge:
        raise ProtectedRouteError("UNOWNED_OR_MISSING_TERMINAL_ROUTE")
    return ProtectedRouteState(True, num_edge == 1)
