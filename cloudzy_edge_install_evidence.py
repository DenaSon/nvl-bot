"""Phase 4: read-only, fail-closed Legacy Edge installation evidence manifest.

Inspection contract for setup_edge_relay.sh (old installer is intentionally NEVER
executed here). All arguments are externally collected READ-ONLY observations;
callers must independently attest SSH host identity, Cloudzy provider server ID,
Core key/port and the collection source. No SSH client or shell is launched.
No WireGuard private keys, passwords or provider tokens are stored or returned.

IMPORTANT: This parser is a diagnostic, not a license to mark a legacy
installation READY. The existing live verify/probe and CZ04A/6G gates remain
mandatory; the installer may not be replayed even if this check fails.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from collections import Counter

CHECKS = (
    ("WG_INTERFACE", "WireGuard wg0 exists and contains a live peer"),
    ("WG_CORE_PEER", "wg0 peer equals independently pinned Core public key"),
    ("IP_FORWARD", "net.ipv4.ip_forward = 1"),
    ("SSH_DNAT", "exactly one SSH port DNAT to 10.77.0.1"),
    ("TLS_DNAT", "exactly one TLS port DNAT to 10.77.0.1"),
    ("MASQUERADE", "exactly one expected POSTROUTING MASQUERADE"),
    ("PERSISTED_NAT", "persistent IPv4 rules match required NAT rules"),
)
STATUS = frozenset(("PASS", "FAIL", "UNVERIFIED"))
_PORT = re.compile(r"[1-9][0-9]{0,4}\Z")
_CORE_KEY = re.compile(r"[A-Za-z0-9+/]{43}=\Z")


class EdgeEvidenceHold(ValueError):
    """No remote effects or auto recovery may be performed."""


@dataclass(frozen=True)
class EvidenceLine:
    code: str
    status: str


@dataclass(frozen=True)
class EdgeEvidenceManifest:
    lines: tuple[EvidenceLine, ...]
    disposition: str  # INSPECT_ONLY / COMPLETE_OBSERVATIONS_NOT_ADOPTION

    @property
    def blockers(self):
        return tuple(line.code for line in self.lines if line.status != "PASS")


def _port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise EdgeEvidenceHold("INVALID_PORT")
    return value


def _lines(value, *, limit=131072):
    if not isinstance(value, str) or len(value) > limit:
        raise EdgeEvidenceHold("EVIDENCE_MISSING_OR_OVERSIZED")
    # Never return raw command output: it may include addresses or comments.
    return tuple(line.strip() for line in value.splitlines())


def _nat_shape(rules, *, ssh_port, tls_port):
    """Count exact iptables-save/-S rules without executing/modifying iptables."""
    lines = _lines(rules)
    checks = {}
    for port, name in ((ssh_port, "SSH_DNAT"), (tls_port, "TLS_DNAT")):
        all_targets = []
        for line in lines:
            if not line.startswith("-A PREROUTING "):
                continue
            if not re.search(r"(?:^| )-p tcp(?: |$)", line):
                continue
            match = re.search(r"(?:^| )--dport ([0-9]+)(?: |$)", line)
            if match and int(match.group(1)) == port:
                all_targets.append(line)
        approved = [
            line for line in all_targets
            if re.search(r"(?:^| )-j DNAT(?: |$)", line)
            and re.search(
                rf"(?:^| )--to-destination 10\.77\.0\.1:{port}(?: |$)",
                line)
        ]
        checks[name] = len(all_targets) == len(approved) == 1
    masquerades = [
        line for line in lines
        if line.startswith("-A POSTROUTING ")
        and re.search(r"(?:^| )-j MASQUERADE(?: |$)", line)
        and re.search(r"(?:^| )! -o lo(?: |$)", line)
    ]
    checks["MASQUERADE"] = len(masquerades) == 1
    return checks


def inspect_edge_evidence(*, wg_peers, core_public_key, ip_forward,
                          active_nat, saved_nat,
                          customer_port: int, tls_port: int) -> EdgeEvidenceManifest:
    """Interpret trusted, separately acquired read-only facts.

    wg_peers: output of 'wg show wg0 peers' (public keys only).
    ip_forward: output of 'sysctl -n net.ipv4.ip_forward'.
    active_nat: output of 'iptables -t nat -S'.
    saved_nat: contents of 'iptables-save -t nat' or rules.v4, acquired
    read-only. Authentication, live tunnel handshake, SSH reachability,
    correct wg0.conf and provider identity must be separately proven.
    """
    port = _port(customer_port)
    tls = _port(tls_port)
    if port == tls:
        raise EdgeEvidenceHold("DUPLICATE_CUSTOMER_AND_TLS_PORT")
    if not isinstance(core_public_key, str) or not _CORE_KEY.fullmatch(core_public_key):
        raise EdgeEvidenceHold("INVALID_PINNED_CORE_PUBLIC_KEY")
    peers = _lines(wg_peers, limit=4096)
    # Exact one expected peer; multiple unknown peers must be investigated.
    wg_up = len(peers) >= 1 and all(not " " in p for p in peers)
    peer_ok = len(peers) == 1 and peers[0] == core_public_key
    forwarding = _lines(ip_forward, limit=64) == ("1",)
    current = _nat_shape(active_nat, ssh_port=port, tls_port=tls)
    persisted = _nat_shape(saved_nat, ssh_port=port, tls_port=tls)
    results = {
        "WG_INTERFACE": wg_up,
        "WG_CORE_PEER": peer_ok,
        "IP_FORWARD": forwarding,
        **current,
        "PERSISTED_NAT": all(persisted.values()),
    }
    lines = tuple(
        EvidenceLine(code, "PASS" if results.get(code) is True else "FAIL")
        for code, _ in CHECKS
    )
    # These facts alone NEVER authorize READY: remote source could be stale,
    # handshake could be down, host pin invalid, provider ID or Core may drift.
    disposition = ("COMPLETE_OBSERVATIONS_NOT_ADOPTION"
                   if all(line.status == "PASS" for line in lines)
                   else "INSPECT_ONLY")
    return EdgeEvidenceManifest(lines, disposition)


def legacy_installer_repeat_hazards(script_source: str):
    """Static read of the real legacy setup script; no shell execution.

    Signals are risk inventory, NOT a simulated installer nor approval for
    automated resume. All unconditional append and config-overwrite hazards
    make a blind second install disallowed.
    """
    if not isinstance(script_source, str) or len(script_source) > 262144:
        raise EdgeEvidenceHold("LEGACY_SCRIPT_UNKNOWN")
    return {
        "APPEND_NAT_PREROUTING": "iptables -t nat -A PREROUTING" in script_source,
        "APPEND_NAT_POSTROUTING": "iptables -t nat -A POSTROUTING" in script_source,
        "REWRITE_WG0_CONFIG": "cat > /etc/wireguard/wg0.conf" in script_source,
        "RESTART_WG0": "systemctl restart wg-quick@wg0" in script_source,
    }
