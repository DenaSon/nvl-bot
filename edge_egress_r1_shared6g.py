"""R1 predicate adapter for the already-existing Phase 6G failover journal.

No second lock, no acquire, no INSERT/UPDATE, no SQLite migration. Only the
active, unique existing RUNNING operation can grant a one-shot transport check.
The caller must recheck before and after any host-side mutation.
"""
from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
import sqlite3
from typing import Callable

from edge_egress_uid_runtime_store import Existing6GUIDRuntimeStore
from edge_egress_uid_policy import UIDPolicyRequest


@dataclass(frozen=True)
class Existing6GR1LeaseProbe:
    db_conn: Callable[[], AbstractContextManager[sqlite3.Connection]]
    operation_id: int
    source_host: str
    target_host: str

    def __post_init__(self):
        if (type(self.operation_id) is not int or self.operation_id <= 0
                or not isinstance(self.source_host, str)
                or not isinstance(self.target_host, str)
                or not self.source_host or not self.target_host
                or self.source_host == self.target_host):
            raise ValueError("INVALID_EXISTING_6G_LEASE_IDENTITY")

    def active(self) -> bool:
        """Failure, DB busy, missing tables or multiple RUNNING rows => DENY."""
        try:
            with self.db_conn() as conn:
                Existing6GUIDRuntimeStore._lock(
                    conn, self.operation_id,
                    self.source_host, self.target_host,
                )
            return True
        except (sqlite3.Error, ValueError, TypeError, OSError):
            return False

    def for_request(self, req: UIDPolicyRequest) -> bool:
        req.validate()
        return (req.spec.edge_public_ipv4 == self.target_host
                and self.source_host not in (
                    req.spec.core_public_ipv4, req.spec.edge_public_ipv4)
                and self.active())
