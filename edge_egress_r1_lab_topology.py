"""Attest the ACTUAL two-host disposable LAB Core as its own SSH ingress.

Never a production topology bypass. This does not create a 6G lease, write
host_pool/settings, mark an Edge READY or authorize a customer login.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import os
from pathlib import Path
import pwd
import stat
import subprocess

from edge_egress_uid_policy import UIDPolicyRequest

# Immutable identity of the independently inventoried disposable pair.
_LAB_CORE = "107.189.16.36"
_LAB_EDGE = "216.126.229.12"
_LAB_MACHINE_ID = "a5138b340f5c41e58aaaa1069a7d463e"
_LAB_MARKER_SHA256 = "95bd7c1aba40493912e81dae570bd517cf8a30cea8e881215d1c0e1bdeec1958"


class LabTopologyUnsafe(ValueError):
    pass


@dataclass(frozen=True)
class TwoHostCoreIngress:
    """Pin the observed LAB machine/marker/IP and a *locked* pilot UID."""

    core_ipv4: str = "107.189.16.36"
    edge_ipv4: str = "216.126.229.12"
    machine_id: str = "a5138b340f5c41e58aaaa1069a7d463e"
    marker_sha256: str = "95bd7c1aba40493912e81dae570bd517cf8a30cea8e881215d1c0e1bdeec1958"
    test_username: str = "nvlr1test"
    test_uid: int = 1555
    marker: Path = Path("/etc/nvl-egress/disposable-r1.marker")

    def for_request(self, request: UIDPolicyRequest, source: str) -> bool:
        """Fail closed on any unknown identity, shell unlock or host failure."""
        try:
            request.validate()
            if ((self.core_ipv4, self.edge_ipv4, self.machine_id,
                 self.marker_sha256) != (_LAB_CORE, _LAB_EDGE,
                 _LAB_MACHINE_ID, _LAB_MARKER_SHA256)):
                return False
            if os.geteuid() != 0 or source != self.core_ipv4:
                return False
            if request.spec.core_public_ipv4 != self.core_ipv4:
                return False
            if request.spec.edge_public_ipv4 != self.edge_ipv4:
                return False
            if request.spec.edge_id != "lab1" or request.spec.route_table != 1791:
                return False
            if request.username != self.test_username or request.uid != self.test_uid:
                return False
            if self.marker.is_symlink() or not self.marker.is_file():
                return False
            st = self.marker.stat()
            if st.st_uid != 0 or (st.st_mode & 0o077):
                return False
            if hashlib.sha256(self.marker.read_bytes()).hexdigest() != self.marker_sha256:
                return False
            mid = Path("/etc/machine-id").read_text().strip()
            if mid != self.machine_id:
                return False
            account = pwd.getpwnam(self.test_username)
            if account.pw_uid != self.test_uid or account.pw_shell != "/usr/sbin/nologin":
                return False
            p = subprocess.run(
                ["ip", "-j", "-4", "addr", "show", "dev", "eth0"],
                capture_output=True, text=True, timeout=6, check=True,
            )
            import json
            addresses = json.loads(p.stdout)
            observed = {
                info.get("local") for link in addresses
                for info in link.get("addr_info", [])
            }
            return self.core_ipv4 in observed and str(ipaddress.IPv4Address(source)) == source
        except (OSError, ValueError, KeyError, IndexError,
                subprocess.SubprocessError, TypeError):
            return False
