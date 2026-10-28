"""Read-only route reconciliation helpers. No external writes."""
from dataclasses import dataclass

class RouteProjectionHold(RuntimeError):
    pass

@dataclass(frozen=True)
class RouteEvidence:
    db_route: str
    dns_route: str
    disposition: str
    next_action: str
