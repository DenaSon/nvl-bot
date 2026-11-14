"""Read-only exact NAT & forwarding verification for a new AWG Edge."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import shlex


class AWGNATHold(ValueError):
    pass


@dataclass(frozen=True)
class AWGNATEvidence:
    wan: str
    core_tunnel_ip: str
    edge_tunnel_ip: str
    customer_port: int
    tls_port: int
    live_nat: str
    saved_rules: str
    live_forward: str
    forwarding: str
    awg_service: str
    awg_autostart: str
    netfilter_autostart: str


def _rules(raw: str, chain: str):
    if not isinstance(raw, str) or len(raw) > 262144:
        raise AWGNATHold("NAT_EVIDENCE_MISSING_OR_OVERSIZED")
    result = []
    for line in raw.splitlines():
        if not line.startswith("-A " + chain + " "):
            continue
        try:
            item = shlex.split(line)
        except ValueError as exc:
            raise AWGNATHold("NAT_RULE_MALFORMED") from exc
        result.append(item)
    return result


def _opt(rule: list[str], name: str):
    return rule[rule.index(name)+1] if name in rule and (
        rule.index(name)+1 < len(rule)
    ) else None


def _for_port(raw: str, chain: str, option: str, port: int):
    return [r for r in _rules(raw, chain)
            if _opt(r, "-p") == "tcp" and _opt(r, option) == str(port)]


def verify_awg_nat(e: AWGNATEvidence) -> bool:
    """Fail closed on missing, duplicate or mismatched persisted/live rules."""
    try:
        core = str(ipaddress.IPv4Address(e.core_tunnel_ip))
        edge = str(ipaddress.IPv4Address(e.edge_tunnel_ip))
        if core == edge:
            return False
        if not (re.fullmatch(r"[a-zA-Z0-9_.:-]{1,15}", e.wan) is not None
                and e.wan not in ("awg0", "lo")
                and e.forwarding.strip() == "1"
                and e.awg_service.strip() == "active"
                and e.awg_autostart.strip() == "enabled"
                and e.netfilter_autostart.strip() == "enabled"):
            return False
        ports = [e.customer_port, e.tls_port]
        if (len(set(ports)) != 2 or any(
            type(p) is not int or not 1 <= p <= 65535 for p in ports
        )):
            return False
        for raw in (e.live_nat, e.saved_rules):
            for p in ports:
                d = _for_port(raw, "PREROUTING", "--dport", p)
                s = _for_port(raw, "POSTROUTING", "--dport", p)
                if len(d) != 1 or len(s) != 1:
                    return False
                if not (
                    _opt(d[0], "-i") == e.wan and
                    _opt(d[0], "-j") == "DNAT" and
                    _opt(d[0], "--to-destination") == f"{core}:{p}" and
                    _opt(s[0], "-o") == "awg0" and
                    _opt(s[0], "-d") in (core, core+"/32") and
                    _opt(s[0], "-j") == "SNAT" and
                    _opt(s[0], "--to-source") == edge
                ):
                    return False
        for raw in (e.live_forward, e.saved_rules):
            for p in ports:
                inbound = _for_port(raw, "FORWARD", "--dport", p)
                outbound = _for_port(raw, "FORWARD", "--sport", p)
                if len(inbound) != 1 or len(outbound) != 1:
                    return False
                a, b = inbound[0], outbound[0]
                if not (
                    _opt(a, "-i") == e.wan and _opt(a, "-o") == "awg0"
                    and _opt(a, "-d") in (core, core+"/32")
                    and _opt(a, "-j") == "ACCEPT"
                    and _opt(b, "-i") == "awg0" and _opt(b, "-o") == e.wan
                    and _opt(b, "-s") in (core, core+"/32")
                    and _opt(b, "-j") == "ACCEPT"
                    and _opt(b, "--ctstate") in (
                        "ESTABLISHED,RELATED", "RELATED,ESTABLISHED")
                ):
                    return False
        return True
    except (ValueError, TypeError, AttributeError, AWGNATHold):
        return False
