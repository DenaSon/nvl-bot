"""D1-C3B: explicit pinned-SSH Standby + local-Core shadow adapter.

No bot import or auto-registration. Starts ONLY dedicated staged Egress
interfaces through the reviewed finite-action host worker; never wg0.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from edge_egress_uid_lifecycle import UIDCanaryUnsafe
from edge_egress_uid_policy import UIDPolicyRequest
from edge_egress_ssh_transport import PinnedEgressHostPort
from ops.edge_egress_host_worker import execute as local_execute
from ops.edge_egress_provision import EgressSpec


@dataclass
class PinnedUIDCanaryShadow:
    """Explicit opt-in shadow port using the existing stage-only manifests."""
    spec: EgressSpec
    edge: PinnedEgressHostPort

    def _check(self, request: UIDPolicyRequest):
        request.validate()
        if request.spec != self.spec:
            raise UIDCanaryUnsafe("SHADOW_SPEC_CHANGED")
        if self.edge.identity.role != "edge":
            raise UIDCanaryUnsafe("SHADOW_EDGE_ROLE_REQUIRED")
        if self.edge.identity.expected_public_ip != self.spec.edge_public_ipv4:
            raise UIDCanaryUnsafe("SHADOW_EDGE_IDENTITY_MISMATCH")
        if not self.edge.lab_activation:
            raise UIDCanaryUnsafe("SHADOW_LAB_ACTIVATION_DISABLED")

    def _payload(self, *, lab: bool = False):
        payload = {"role": "core", "spec": asdict(self.spec)}
        if lab:
            payload["lab_activation"] = True
        return payload

    async def preflight(self, request: UIDPolicyRequest):
        self._check(request)
        local = local_execute("preflight", self._payload())
        edge_ok, edge_issues = await self.edge.read_only_preflight(self.spec)
        if not local.get("ok") or not edge_ok or edge_issues:
            raise UIDCanaryUnsafe("SHADOW_PREFLIGHT_FAILED")
        c = local_execute("inspect", self._payload())
        e = await self.edge.inspect_shadow(self.spec)
        if c.get("state") != "STAGED" or e.get("state") != "STAGED":
            raise UIDCanaryUnsafe("SHADOW_STAGE_NOT_OWNED")

    async def start(self, request: UIDPolicyRequest):
        self._check(request)
        # The remote stage must be started before Core's dedicated peer.
        # The outer 6G coordinator marks kernel recovery possible first.
        try:
            await self.edge.start_shadow(self.spec)
            local_execute("start", self._payload(lab=True))
        except Exception:
            # Best-effort scoped cleanup, even if Core partially started.
            try:
                local_execute("stop", self._payload(lab=True))
            except Exception:
                pass
            try:
                await self.edge.stop_shadow(self.spec)
            except Exception:
                pass
            raise UIDCanaryUnsafe("SHADOW_START_FAILED") from None

    async def stop(self, request: UIDPolicyRequest):
        self._check(request)
        failures = []
        try:
            local_execute("stop", self._payload(lab=True))
        except Exception:
            failures.append("CORE")
        try:
            await self.edge.stop_shadow(self.spec)
        except Exception:
            failures.append("EDGE")
        if failures:
            raise UIDCanaryUnsafe("SHADOW_STOP_UNCERTAIN:" + ",".join(failures))
