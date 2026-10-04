"""Priority coordinator for NVL regional provider work.

The coordinator serializes provider calls while guaranteeing that queued critical
filtering work is selected before background Standby/Marzban monitoring.

It intentionally does not preempt an already-running network request. Low-priority
callers should therefore hold the slot for one bounded provider operation only.
"""

from __future__ import annotations

import asyncio
import heapq
import itertools
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Optional


PROBE_PRIORITY_CONFIRMATION = 0
PROBE_PRIORITY_DEFAULT = 10
PROBE_PRIORITY_STANDBY = 20
PROBE_PRIORITY_MARZBAN = 30


@dataclass(frozen=True)
class ProbeLease:
    priority: int
    label: str
    waited_seconds: float


class RegionalProbeCoordinator:
    """Small FIFO-within-priority async scheduler for regional provider calls."""

    def __init__(self):
        self._condition = asyncio.Condition()
        self._queue = []
        self._sequence = itertools.count()
        self._active = False
        self._active_priority: Optional[int] = None
        self._active_label: Optional[str] = None

    @property
    def active(self) -> bool:
        return self._active

    @property
    def active_priority(self) -> Optional[int]:
        return self._active_priority

    @property
    def active_label(self) -> Optional[str]:
        return self._active_label

    @property
    def queued(self) -> int:
        return len(self._queue)

    @property
    def highest_waiting_priority(self) -> Optional[int]:
        if not self._queue:
            return None
        return self._queue[0][0]

    def has_waiting_at_or_above(self, priority: int) -> bool:
        highest = self.highest_waiting_priority
        return highest is not None and highest <= int(priority)

    async def acquire(self, priority: int, label: str = "") -> ProbeLease:
        priority = int(priority)
        label = str(label or "regional-probe")
        loop = asyncio.get_running_loop()
        requested_at = loop.time()
        token = object()
        entry = (priority, next(self._sequence), token, label)

        async with self._condition:
            heapq.heappush(self._queue, entry)
            while True:
                first = self._queue[0] if self._queue else None
                if not self._active and first is not None and first[2] is token:
                    heapq.heappop(self._queue)
                    self._active = True
                    self._active_priority = priority
                    self._active_label = label
                    return ProbeLease(
                        priority=priority,
                        label=label,
                        waited_seconds=max(0.0, loop.time() - requested_at),
                    )
                await self._condition.wait()

    async def release(self) -> None:
        async with self._condition:
            self._active = False
            self._active_priority = None
            self._active_label = None
            self._condition.notify_all()

    @asynccontextmanager
    async def slot(self, priority: int, label: str = ""):
        lease = await self.acquire(priority, label)
        try:
            yield lease
        finally:
            await self.release()
