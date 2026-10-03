"""Provider-neutral regional probe interface for NVL V119-A.

Only Check-Host is implemented today. The rest of the filtering/runtime code consumes
normalized provider-neutral nodes/results so a second provider can be added later without
rewriting classification or failover policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from checkhost_probe import (
    CheckHostClient,
    CheckHostError,
    CheckHostLimitExceeded,
    CheckHostNode,
)


class RegionalProbeError(RuntimeError):
    """Provider failed and no trustworthy regional evidence was produced."""


class RegionalProbeLimited(RegionalProbeError):
    """Provider temporarily refused new probes because of a rate/request limit."""


@dataclass(frozen=True)
class RegionalProbeNode:
    name: str
    country_code: str
    country: str
    city: str
    ip: str
    asn: str


@dataclass(frozen=True)
class RegionalProbeEvidence:
    node: str
    country_code: str
    country: str
    city: str
    ip: str
    asn: str
    ok: Optional[bool]
    pending: bool
    latency_ms: Optional[float] = None
    address: Optional[str] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class RegionalProbeResult:
    provider: str
    request_id: str
    permanent_link: Optional[str]
    target_host: str
    target_port: int
    evidence: tuple[RegionalProbeEvidence, ...]

    @property
    def total_nodes(self) -> int:
        return len(self.evidence)

    @property
    def completed_nodes(self) -> int:
        return sum(1 for item in self.evidence if not item.pending)

    @property
    def successful_nodes(self) -> int:
        return sum(1 for item in self.evidence if item.ok is True)

    @property
    def failed_nodes(self) -> int:
        return sum(1 for item in self.evidence if item.ok is False)

    @property
    def pending_nodes(self) -> int:
        return sum(1 for item in self.evidence if item.pending)


class RegionalProbeProvider:
    """Minimal synchronous provider contract.

    Network calls are intentionally synchronous here because the Telegram runtime already
    executes them via asyncio.to_thread(). Implementations must only collect evidence.
    """

    name = "unknown"

    def discover_nodes(self, country_code: str) -> tuple[RegionalProbeNode, ...]:
        raise NotImplementedError

    def probe_tcp(
        self,
        target_host: str,
        target_port: int,
        nodes: Iterable[RegionalProbeNode],
    ) -> RegionalProbeResult:
        raise NotImplementedError


class CheckHostRegionalProbeProvider(RegionalProbeProvider):
    name = "check-host"

    def __init__(
        self,
        *,
        request_timeout: float = 6.0,
        poll_timeout: float = 12.0,
        poll_interval: float = 1.5,
    ):
        self.client = CheckHostClient(
            request_timeout=request_timeout,
            poll_timeout=poll_timeout,
            poll_interval=poll_interval,
        )

    @staticmethod
    def _normalize_node(node: CheckHostNode) -> RegionalProbeNode:
        return RegionalProbeNode(
            name=node.name,
            country_code=node.country_code,
            country=node.country,
            city=node.city,
            ip=node.ip,
            asn=node.asn,
        )

    @staticmethod
    def _to_checkhost_node(node: RegionalProbeNode) -> CheckHostNode:
        return CheckHostNode(
            name=node.name,
            country_code=node.country_code,
            country=node.country,
            city=node.city,
            ip=node.ip,
            asn=node.asn,
        )

    def discover_nodes(self, country_code: str) -> tuple[RegionalProbeNode, ...]:
        try:
            return tuple(
                self._normalize_node(node)
                for node in self.client.discover_nodes(country_code)
            )
        except CheckHostLimitExceeded as exc:
            raise RegionalProbeLimited(str(exc)) from exc
        except CheckHostError as exc:
            raise RegionalProbeError(str(exc)) from exc

    def probe_tcp(
        self,
        target_host: str,
        target_port: int,
        nodes: Iterable[RegionalProbeNode],
    ) -> RegionalProbeResult:
        provider_nodes = tuple(self._to_checkhost_node(node) for node in nodes)
        try:
            request_id, permanent_link, request_nodes = self.client.start_tcp_check(
                target_host,
                target_port,
                provider_nodes,
            )
            raw = self.client.poll_tcp_result(
                request_id,
                request_nodes,
                target_host=target_host,
                target_port=target_port,
                permanent_link=permanent_link,
            )
        except CheckHostLimitExceeded as exc:
            raise RegionalProbeLimited(str(exc)) from exc
        except CheckHostError as exc:
            raise RegionalProbeError(str(exc)) from exc

        evidence = tuple(
            RegionalProbeEvidence(
                node=item.node,
                country_code=item.country_code,
                country=item.country,
                city=item.city,
                ip=item.ip,
                asn=item.asn,
                ok=item.ok,
                pending=item.pending,
                latency_ms=item.latency_ms,
                address=item.address,
                error=item.error,
            )
            for item in raw.evidence
        )
        return RegionalProbeResult(
            provider=self.name,
            request_id=raw.request_id,
            permanent_link=raw.permanent_link,
            target_host=raw.target_host,
            target_port=raw.target_port,
            evidence=evidence,
        )


def build_regional_probe_provider(
    provider_name: str = "check-host",
    *,
    request_timeout: float = 6.0,
    poll_timeout: float = 12.0,
    poll_interval: float = 1.5,
) -> RegionalProbeProvider:
    normalized = str(provider_name or "").strip().lower()
    if normalized in {"check-host", "checkhost"}:
        return CheckHostRegionalProbeProvider(
            request_timeout=request_timeout,
            poll_timeout=poll_timeout,
            poll_interval=poll_interval,
        )
    raise ValueError(f"Unsupported regional probe provider: {provider_name}")
