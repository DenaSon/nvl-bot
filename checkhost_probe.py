"""Phase 6D: Check-Host regional probe provider.

Evidence-only module:
- discovers Check-Host nodes by country;
- performs TCP probes against an Edge service endpoint;
- polls asynchronous results;
- normalizes node-level success/failure/pending evidence;
- aggregates metadata for later Phase 6E classification.

This module MUST NOT perform filtering classification, DNS changes, host membership
changes, account moves, standby activation, or failover.
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Callable, Iterable, Mapping, Optional


CHECK_HOST_BASE_URL = "https://check-host.net"
CHECK_HOST_USER_AGENT = "NVL-Regional-Probe/6D"
DEFAULT_COUNTRY_CODE = "ir"


class CheckHostError(RuntimeError):
    """Raised when the Check-Host API returns an invalid or unusable response."""


@dataclass(frozen=True)
class CheckHostNode:
    name: str
    country_code: str
    country: str
    city: str
    ip: str
    asn: str


@dataclass(frozen=True)
class TcpNodeEvidence:
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
class RegionalTcpProbe:
    request_id: str
    permanent_link: Optional[str]
    target_host: str
    target_port: int
    evidence: tuple[TcpNodeEvidence, ...]

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

    @property
    def completed_success_ratio(self) -> Optional[float]:
        if not self.completed_nodes:
            return None
        return self.successful_nodes / self.completed_nodes

    @property
    def successful_asns(self) -> tuple[str, ...]:
        return tuple(sorted({item.asn for item in self.evidence if item.ok is True and item.asn}))

    @property
    def failed_asns(self) -> tuple[str, ...]:
        return tuple(sorted({item.asn for item in self.evidence if item.ok is False and item.asn}))

    @property
    def successful_cities(self) -> tuple[str, ...]:
        return tuple(sorted({item.city for item in self.evidence if item.ok is True and item.city}))

    @property
    def failed_cities(self) -> tuple[str, ...]:
        return tuple(sorted({item.city for item in self.evidence if item.ok is False and item.city}))

    def to_dict(self) -> dict:
        """Stable JSON-friendly representation for smoke tests and future persistence."""
        return {
            "request_id": self.request_id,
            "permanent_link": self.permanent_link,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "total_nodes": self.total_nodes,
            "completed_nodes": self.completed_nodes,
            "successful_nodes": self.successful_nodes,
            "failed_nodes": self.failed_nodes,
            "pending_nodes": self.pending_nodes,
            "completed_success_ratio": self.completed_success_ratio,
            "successful_asns": list(self.successful_asns),
            "failed_asns": list(self.failed_asns),
            "successful_cities": list(self.successful_cities),
            "failed_cities": list(self.failed_cities),
            "evidence": [asdict(item) for item in self.evidence],
        }


Transport = Callable[[str, float], Mapping]


def _default_transport(url: str, timeout: float) -> Mapping:
    # Do not use urllib's default Python-urllib/* user agent. Public API endpoints
    # can sit behind WAF/bot-protection rules that reject generic scripting UAs even
    # though the API request itself is valid. A stable, descriptive application UA
    # also makes provider-side diagnostics substantially easier.
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": CHECK_HOST_USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(512).decode("utf-8", errors="replace")
            body = " ".join(body.split())[:240]
        except Exception:
            body = ""
        detail = f"Check-Host HTTP {exc.code}: {exc.reason}"
        if body:
            detail += f" [{body}]"
        raise CheckHostError(detail) from exc
    except urllib.error.URLError as exc:
        raise CheckHostError(f"Check-Host network error: {exc.reason}") from exc
    except Exception as exc:
        raise CheckHostError(f"Check-Host request failed: {exc}") from exc

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise CheckHostError("Check-Host returned invalid JSON") from exc

    if not isinstance(data, Mapping):
        raise CheckHostError("Check-Host returned a non-object JSON response")
    return data


def _node_from_discovery(name: str, raw: Mapping) -> CheckHostNode:
    location = raw.get("location") or []
    if not isinstance(location, (list, tuple)):
        location = []
    return CheckHostNode(
        name=str(name),
        country_code=str(location[0] if len(location) > 0 else "").lower(),
        country=str(location[1] if len(location) > 1 else ""),
        city=str(location[2] if len(location) > 2 else ""),
        ip=str(raw.get("ip") or ""),
        asn=str(raw.get("asn") or ""),
    )


def _node_from_start_response(name: str, raw) -> CheckHostNode:
    values = raw if isinstance(raw, (list, tuple)) else []
    return CheckHostNode(
        name=str(name),
        country_code=str(values[0] if len(values) > 0 else "").lower(),
        country=str(values[1] if len(values) > 1 else ""),
        city=str(values[2] if len(values) > 2 else ""),
        ip=str(values[3] if len(values) > 3 else ""),
        asn=str(values[4] if len(values) > 4 else ""),
    )


def normalize_tcp_node_result(node: CheckHostNode, raw_result) -> TcpNodeEvidence:
    """Normalize one Check-Host TCP result.

    Official API semantics:
    - null means the node is still performing the check;
    - [{"time": ..., "address": "..."}] means TCP connect success;
    - [{"error": "..."}] means the node completed with a connection failure.

    The parser is deliberately tolerant of "message" error fields and multiple result
    objects because real-world API responses can contain minor shape variations.
    """
    if raw_result is None:
        return TcpNodeEvidence(
            node=node.name,
            country_code=node.country_code,
            country=node.country,
            city=node.city,
            ip=node.ip,
            asn=node.asn,
            ok=None,
            pending=True,
        )

    items = raw_result if isinstance(raw_result, list) else [raw_result]
    success = None
    error = None

    for item in items:
        if not isinstance(item, Mapping):
            continue
        item_error = item.get("error") or item.get("message")
        if item_error:
            error = str(item_error)
            continue

        address = item.get("address")
        latency = item.get("time")
        if address is not None or latency is not None:
            try:
                latency_ms = None if latency is None else float(latency) * 1000.0
            except (TypeError, ValueError):
                latency_ms = None
            success = TcpNodeEvidence(
                node=node.name,
                country_code=node.country_code,
                country=node.country,
                city=node.city,
                ip=node.ip,
                asn=node.asn,
                ok=True,
                pending=False,
                latency_ms=latency_ms,
                address=None if address is None else str(address),
            )
            break

    if success is not None:
        return success

    return TcpNodeEvidence(
        node=node.name,
        country_code=node.country_code,
        country=node.country,
        city=node.city,
        ip=node.ip,
        asn=node.asn,
        ok=False,
        pending=False,
        error=error or "UNKNOWN_TCP_RESULT",
    )


class CheckHostClient:
    """Small provider-neutral client around the public Check-Host API."""

    def __init__(
        self,
        *,
        base_url: str = CHECK_HOST_BASE_URL,
        request_timeout: float = 6.0,
        poll_timeout: float = 12.0,
        poll_interval: float = 1.5,
        transport: Optional[Transport] = None,
        sleeper: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.base_url = base_url.rstrip("/")
        self.request_timeout = max(0.1, float(request_timeout))
        self.poll_timeout = max(0.1, float(poll_timeout))
        self.poll_interval = max(0.0, float(poll_interval))
        self.transport = transport or _default_transport
        self.sleeper = sleeper
        self.monotonic = monotonic

    def _get(self, path: str, params: Optional[Iterable[tuple[str, str]]] = None) -> Mapping:
        query = urllib.parse.urlencode(list(params or []), doseq=True)
        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{query}"
        return self.transport(url, self.request_timeout)

    def discover_nodes(self, country_code: str = DEFAULT_COUNTRY_CODE) -> tuple[CheckHostNode, ...]:
        payload = self._get("/nodes/hosts")
        raw_nodes = payload.get("nodes")
        if not isinstance(raw_nodes, Mapping):
            raise CheckHostError("Check-Host node discovery response has no nodes object")

        cc = str(country_code or "").lower()
        nodes = [
            _node_from_discovery(name, raw)
            for name, raw in raw_nodes.items()
            if isinstance(raw, Mapping)
        ]
        if cc:
            nodes = [node for node in nodes if node.country_code == cc]

        return tuple(sorted(nodes, key=lambda node: node.name))

    def start_tcp_check(
        self,
        target_host: str,
        target_port: int,
        nodes: Iterable[CheckHostNode],
    ) -> tuple[str, Optional[str], tuple[CheckHostNode, ...]]:
        target_host = str(target_host or "").strip()
        if not target_host:
            raise ValueError("target_host is required")
        try:
            target_port = int(target_port)
        except (TypeError, ValueError) as exc:
            raise ValueError("target_port must be an integer") from exc
        if not 1 <= target_port <= 65535:
            raise ValueError("target_port must be between 1 and 65535")

        selected_nodes = tuple(nodes)
        if not selected_nodes:
            raise CheckHostError("No Check-Host nodes were selected")

        params: list[tuple[str, str]] = [("host", f"{target_host}:{target_port}")]
        params.extend(("node", node.name) for node in selected_nodes)

        payload = self._get("/check-tcp", params)
        if payload.get("ok") != 1 or not payload.get("request_id"):
            raise CheckHostError(f"Check-Host rejected TCP request: {payload}")

        response_nodes = payload.get("nodes")
        if isinstance(response_nodes, Mapping) and response_nodes:
            selected_nodes = tuple(
                _node_from_start_response(name, raw)
                for name, raw in response_nodes.items()
            )

        return (
            str(payload["request_id"]),
            None if not payload.get("permanent_link") else str(payload["permanent_link"]),
            selected_nodes,
        )

    def get_check_result(self, request_id: str) -> Mapping:
        request_id = str(request_id or "").strip()
        if not request_id:
            raise ValueError("request_id is required")
        safe_id = urllib.parse.quote(request_id, safe="")
        return self._get(f"/check-result/{safe_id}")

    def poll_tcp_result(
        self,
        request_id: str,
        nodes: Iterable[CheckHostNode],
        *,
        target_host: str,
        target_port: int,
        permanent_link: Optional[str] = None,
    ) -> RegionalTcpProbe:
        nodes = tuple(nodes)
        if not nodes:
            raise CheckHostError("No nodes supplied for polling")

        deadline = self.monotonic() + self.poll_timeout
        latest: Mapping = {}

        while True:
            latest = self.get_check_result(request_id)
            all_complete = all(
                node.name in latest and latest.get(node.name) is not None
                for node in nodes
            )
            if all_complete or self.monotonic() >= deadline:
                break
            self.sleeper(self.poll_interval)

        evidence = tuple(
            normalize_tcp_node_result(node, latest.get(node.name))
            for node in nodes
        )
        return RegionalTcpProbe(
            request_id=str(request_id),
            permanent_link=permanent_link,
            target_host=str(target_host),
            target_port=int(target_port),
            evidence=evidence,
        )

    def probe_tcp(
        self,
        target_host: str,
        target_port: int,
        *,
        country_code: str = DEFAULT_COUNTRY_CODE,
        max_nodes: Optional[int] = None,
    ) -> RegionalTcpProbe:
        nodes = self.discover_nodes(country_code)
        if max_nodes is not None:
            max_nodes = max(1, int(max_nodes))
            nodes = nodes[:max_nodes]
        if not nodes:
            raise CheckHostError(
                f"No Check-Host nodes found for country code {country_code!r}"
            )

        request_id, permanent_link, request_nodes = self.start_tcp_check(
            target_host,
            target_port,
            nodes,
        )
        return self.poll_tcp_result(
            request_id,
            request_nodes,
            target_host=target_host,
            target_port=target_port,
            permanent_link=permanent_link,
        )


def _main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a read-only Check-Host regional TCP probe."
    )
    parser.add_argument("host", help="Target IP or hostname")
    parser.add_argument("port", type=int, help="Target service TCP port")
    parser.add_argument("--country", default=DEFAULT_COUNTRY_CODE)
    parser.add_argument("--max-nodes", type=int, default=None)
    parser.add_argument("--poll-timeout", type=float, default=12.0)
    args = parser.parse_args()

    client = CheckHostClient(poll_timeout=args.poll_timeout)
    try:
        result = client.probe_tcp(
            args.host,
            args.port,
            country_code=args.country,
            max_nodes=args.max_nodes,
        )
    except (CheckHostError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 2

    print(json.dumps({"ok": True, **result.to_dict()}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
