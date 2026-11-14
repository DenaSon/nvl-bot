"""NVL-AWG-02: explicit, non-routing adoption of an already-installed AWG Edge.

No installer, firewall write, AWG reconfiguration, SSHD restart, DNS or user
migration. A *pinned* remote collector is required by the eventual operator
workflow. The registrar commits only EDGE_READY (inactive), not STANDBY.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import ipaddress
import re
import secrets
import shlex
import sqlite3
import time

from manual_edge_journal import ManualEdgeJournal
from nvl_tunnel_backend import SCHEMA as TUNNEL_SCHEMA, TunnelHold, _key


class AWGAdoptionHold(ValueError):
    pass


_PORT_RE = re.compile(r"[1-9][0-9]{0,4}\Z")
_IF_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_.:-]{0,30}\Z")


def _ip(raw: str, *, public: bool = False) -> str:
    try:
        value = ipaddress.IPv4Address(raw)
    except (ValueError, ipaddress.AddressValueError, TypeError) as exc:
        raise AWGAdoptionHold("INVALID_IPV4") from exc
    if public and (not value.is_global or value.is_multicast):
        raise AWGAdoptionHold("EDGE_PUBLIC_IP_REQUIRED")
    return str(value)


def _port(value) -> int:
    if type(value) is not int or not 1 <= value <= 65535:
        raise AWGAdoptionHold("INVALID_PORT")
    return value


def _fingerprint(key_type: str, encoded: str) -> str:
    if key_type != "ssh-ed25519" or not isinstance(encoded, str):
        raise AWGAdoptionHold("UNSUPPORTED_SSH_HOST_KEY")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise AWGAdoptionHold("INVALID_SSH_HOST_KEY") from exc
    if len(raw) < 45 or len(raw) > 1024:
        raise AWGAdoptionHold("INVALID_SSH_HOST_KEY")
    digest = base64.b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()
    return "SHA256:" + digest


@dataclass(frozen=True)
class AWGExistingEdge:
    host: str
    admin_port: int
    customer_port: int
    tls_port: int
    core_public_ip: str
    core_tunnel_ip: str
    edge_tunnel_ip: str
    edge_public_key: str
    core_public_key: str
    ssh_host_key_type: str
    ssh_host_key_base64: str

    def __post_init__(self):
        host = _ip(self.host, public=True)
        core = _ip(self.core_public_ip, public=True)
        a = _ip(self.core_tunnel_ip)
        b = _ip(self.edge_tunnel_ip)
        if host == core or a == b or a == host or b == core:
            raise AWGAdoptionHold("TUNNEL_IP_COLLISION")
        if self.customer_port == self.admin_port or self.tls_port in (
            self.customer_port, self.admin_port,
        ):
            raise AWGAdoptionHold("ADMIN_OR_SERVICE_PORT_COLLISION")
        for p in (self.admin_port, self.customer_port, self.tls_port):
            _port(p)
        _key(self.core_public_key)
        _key(self.edge_public_key)
        if self.core_public_key == self.edge_public_key:
            raise AWGAdoptionHold("TUNNEL_KEY_COLLISION")
        _fingerprint(self.ssh_host_key_type, self.ssh_host_key_base64)


@dataclass(frozen=True)
class AWGNetworkSnapshot:
    """Public/read-only observations from independently pinned SSH and Core."""
    core_peers: str
    core_allowed_ips: str
    core_ping_ok: bool
    edge_peers: str
    edge_awg_address: str
    edge_forwarding: str
    edge_wan: str
    nat_live: str
    nat_saved: str
    forward_live: str
    forward_saved: str
    edge_awg_service: str
    edge_awg_enabled: str
    netfilter_enabled: str


@dataclass(frozen=True)
class AWGAcceptance:
    spec: AWGExistingEdge
    verified_at: int
    ssh_fingerprint: str

    # Instantiation only by verified collector in adopter's trusted process;
    # never accept serialized acceptance from Telegram or clients.


def _text(raw, limit=131072) -> str:
    if not isinstance(raw, str) or len(raw) > limit:
        raise AWGAdoptionHold("EVIDENCE_MISSING_OR_OVERSIZED")
    return raw


def _single_peer(output: str, key: str) -> bool:
    return _text(output, 4096).strip().splitlines() == [key]


def _core_allowed(output: str, key: str, tunnel_ip: str) -> bool:
    rows = _text(output, 16384).splitlines()
    matches = [x.split() for x in rows]
    if any(len(x) != 2 for x in matches):
        return False
    exact = [x for x in matches if x[0] == key]
    return len(exact) == 1 and exact[0][1] == tunnel_ip + "/32" and not any(
        tunnel_ip + "/" in x[1] for x in matches if x[0] != key
    )


def _tokens(output: str, chain: str):
    rules = []
    for line in _text(output).splitlines():
        if not line.startswith("-A " + chain + " "):
            continue
        try:
            rules.append(shlex.split(line))
        except ValueError as exc:
            raise AWGAdoptionHold("INVALID_IPTABLES_EVIDENCE") from exc
    return rules


def _value(rule, option):
    if option not in rule:
        return None
    i = rule.index(option)
    return rule[i+1] if i+1 < len(rule) else None


def _target_rules(output: str, chain: str, port: int):
    return [r for r in _tokens(output, chain)
            if _value(r, "--dport") == str(port) and _value(r, "-p") == "tcp"]


def _nat_ok(snapshot: AWGNetworkSnapshot, spec: AWGExistingEdge) -> bool:
    wan = snapshot.edge_wan.strip()
    if not _IF_RE.fullmatch(wan) or wan == "awg0":
        return False
    for nat in (snapshot.nat_live, snapshot.nat_saved):
        for port in (spec.customer_port, spec.tls_port):
            dnat = _target_rules(nat, "PREROUTING", port)
            if len(dnat) != 1:
                return False
            d = dnat[0]
            if any((
                _value(d, "-i") != wan,
                _value(d, "-j") != "DNAT",
                _value(d, "--to-destination") !=
                    spec.core_tunnel_ip + ":" + str(port),
            )):
                return False
            snat = _target_rules(nat, "POSTROUTING", port)
            if len(snat) != 1:
                return False
            s = snat[0]
            if any((
                _value(s, "-o") != "awg0",
                _value(s, "-d") not in (
                    spec.core_tunnel_ip, spec.core_tunnel_ip + "/32",
                ),
                _value(s, "-j") != "SNAT",
                _value(s, "--to-source") != spec.edge_tunnel_ip,
            )):
                return False
    for rules in (snapshot.forward_live, snapshot.forward_saved):
        parsed = _tokens(rules, "FORWARD")
        for port in (spec.customer_port, spec.tls_port):
            inbound = [r for r in parsed
                       if _value(r, "--dport") == str(port)
                       and _value(r, "-p") == "tcp"]
            outbound = [r for r in parsed
                        if _value(r, "--sport") == str(port)
                        and _value(r, "-p") == "tcp"]
            if len(inbound) != 1 or len(outbound) != 1:
                return False
            a, b = inbound[0], outbound[0]
            if any((
                _value(a, "-i") != wan, _value(a, "-o") != "awg0",
                _value(a, "-d") not in (
                    spec.core_tunnel_ip, spec.core_tunnel_ip + "/32",
                ),
                _value(a, "-j") != "ACCEPT",
                _value(b, "-i") != "awg0", _value(b, "-o") != wan,
                _value(b, "-s") not in (
                    spec.core_tunnel_ip, spec.core_tunnel_ip + "/32",
                ),
                _value(b, "-j") != "ACCEPT",
                _value(b, "--ctstate") not in (
                    "ESTABLISHED,RELATED", "RELATED,ESTABLISHED",
                ),
            )):
                return False
    return True


def validate_snapshot(
    spec: AWGExistingEdge, observation: AWGNetworkSnapshot, *,
    clock=time.time,
) -> AWGAcceptance:
    """Fail closed. This validates only facts from trusted independent collectors.

    A client witness and Core limiter deployment are separately required
    before STANDBY/Cutover; this function deliberately cannot promote.
    """
    if not _single_peer(observation.core_peers, spec.edge_public_key):
        raise AWGAdoptionHold("CORE_AWG_PEER_UNVERIFIED")
    if not _core_allowed(
        observation.core_allowed_ips, spec.edge_public_key,
        spec.edge_tunnel_ip,
    ):
        raise AWGAdoptionHold("CORE_AWG_ALLOWED_IP_UNVERIFIED")
    if observation.core_ping_ok is not True:
        raise AWGAdoptionHold("CORE_EDGE_TUNNEL_PATH_UNVERIFIED")
    if not _single_peer(observation.edge_peers, spec.core_public_key):
        raise AWGAdoptionHold("EDGE_AWG_PEER_UNVERIFIED")
    if spec.edge_tunnel_ip + "/32" not in _text(observation.edge_awg_address, 4096).split():
        raise AWGAdoptionHold("EDGE_AWG_ADDRESS_MISMATCH")
    if observation.edge_forwarding.strip() != "1":
        raise AWGAdoptionHold("EDGE_IP_FORWARD_DISABLED")
    if observation.edge_awg_service.strip() != "active" or (
        observation.edge_awg_enabled.strip() != "enabled"
    ):
        raise AWGAdoptionHold("EDGE_AWG_BOOT_UNVERIFIED")
    if observation.netfilter_enabled.strip() != "enabled":
        raise AWGAdoptionHold("EDGE_NAT_BOOT_UNVERIFIED")
    if not _nat_ok(observation, spec):
        raise AWGAdoptionHold("AWG_NAT_OR_FORWARD_UNVERIFIED")
    return AWGAcceptance(
        spec=spec, verified_at=int(clock()),
        ssh_fingerprint=_fingerprint(
            spec.ssh_host_key_type, spec.ssh_host_key_base64,
        ),
    )


def register_inactive(
    db: sqlite3.Connection, acceptance: AWGAcceptance, *,
    actor: int, chat: int, guard, now=time.time,
) -> str:
    """Atomic, guard-protected, inactive registration only; NEVER cut over.

    Caller must supply AWGAcceptance obtained from current pinned observations,
    not from a user/Telegram payload. No external network mutations occur.
    """
    if type(actor) is not int or type(chat) is not int or actor <= 0 or actor != chat:
        raise AWGAdoptionHold("PRIVATE_ADMIN_REQUIRED")
    if guard is None or not callable(guard):
        raise AWGAdoptionHold("PROTECTED_ROUTE_GUARD_REQUIRED")
    if not isinstance(acceptance, AWGAcceptance):
        raise AWGAdoptionHold("TRUSTED_ACCEPTANCE_REQUIRED")
    spec = acceptance.spec
    if int(now()) - acceptance.verified_at > 90 or acceptance.verified_at > int(now()) + 5:
        raise AWGAdoptionHold("AWG_EVIDENCE_EXPIRED")

    db.execute("BEGIN IMMEDIATE")
    try:
        guard(db)  # Existing 6G/Legacy protected-mode fence.
        ManualEdgeJournal.initialize(db)
        for query in TUNNEL_SCHEMA.split(";"):
            if query.strip():
                db.execute(query)
        current = dict(db.execute(
            "SELECT key,value FROM settings WHERE key IN "
            "('hosts','dns_current_ip','core_wg_public_ip','port','tls_port',"
            "'auto_failover_mode','phase6h_auto_failover_enabled',"
            "'edge_egress_v1_onboard_enabled')"
        ).fetchall())
        if (current.get("core_wg_public_ip") != spec.core_public_ip
            or current.get("port") != str(spec.customer_port)
            or current.get("tls_port") != str(spec.tls_port)):
            raise AWGAdoptionHold("CORE_IDENTITY_OR_SERVICE_PORT_CHANGED")
        if any(current.get(x) == "1" for x in
               ("auto_failover_mode", "phase6h_auto_failover_enabled",
                "edge_egress_v1_onboard_enabled")):
            raise AWGAdoptionHold("AUTO_FAILOVER_OR_K2_BUSY")
        if (spec.host in (current.get("hosts") or "").split(",")
            or current.get("dns_current_ip") == spec.host):
            raise AWGAdoptionHold("EDGE_ALREADY_PUBLICLY_ROUTED")
        if db.execute("SELECT 1 FROM host_pool WHERE host=?",
                      (spec.host,)).fetchone():
            raise AWGAdoptionHold("EDGE_ALREADY_REGISTERED")
        if db.execute("SELECT 1 FROM ssh_accounts WHERE host=? LIMIT 1",
                      (spec.host,)).fetchone():
            raise AWGAdoptionHold("EDGE_ALREADY_OWNS_ACCOUNTS")
        if db.execute(
            "SELECT 1 FROM manual_edge_operations WHERE ip=? "
            "AND status!='CANCELLED' LIMIT 1", (spec.host,),
        ).fetchone():
            raise AWGAdoptionHold("EDGE_HAS_MANUAL_OPERATION")
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='cloudzy_edge_operations'",
        ).fetchone() and db.execute(
            "SELECT 1 FROM cloudzy_edge_operations WHERE public_ipv4=? "
            "AND status NOT IN ('REJECTED','CANCELLED') LIMIT 1",
            (spec.host,),
        ).fetchone():
            raise AWGAdoptionHold("EDGE_HAS_CLOUDZY_RECEIPT")
        if db.execute("SELECT 1 FROM edge_tunnel_bindings WHERE host=?",
                      (spec.host,)).fetchone():
            raise AWGAdoptionHold("TUNNEL_ALREADY_REGISTERED")
        # Core WireGuard and AWG peers have different cryptographic identities.
        # Ensure the same /32 is not reused by an existing registered AWG Edge.
        if db.execute(
            "SELECT 1 FROM edge_tunnel_bindings WHERE backend='amneziawg' "
            "AND edge_tunnel_ip=? LIMIT 1", (spec.edge_tunnel_ip,),
        ).fetchone():
            raise AWGAdoptionHold("TUNNEL_ADDRESS_ALREADY_ASSIGNED")
        stamp = int(now())
        op = secrets.token_hex(16)
        db.execute(
            "INSERT INTO manual_edge_operations "
            "(id,actor,chat,ip,admin_port,pin_type,pin_base64,"
            "pin_fingerprint,status,created_at,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,'EDGE_READY',?,?)",
            (op, actor, chat, spec.host, spec.admin_port,
             spec.ssh_host_key_type, spec.ssh_host_key_base64,
             acceptance.ssh_fingerprint, stamp, stamp),
        )
        db.execute(
            "INSERT INTO host_pool "
            "(host,active,is_default,is_standby,provider,provider_instance_id,"
            "added_at,ssh_port,service_port,admin_ssh_port) "
            "VALUES (?,0,0,0,'manual',NULL,?,?,?,?)",
            (spec.host, time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(stamp)),
             spec.customer_port, spec.customer_port, spec.admin_port),
        )
        db.execute(
            "INSERT INTO edge_tunnel_bindings "
            "(host,backend,interface,core_tunnel_ip,edge_tunnel_ip,"
            "peer_public_key,state,verified_at) "
            "VALUES (?,'amneziawg','awg0',?,?,?,'VERIFIED',?)",
            (spec.host, spec.core_tunnel_ip, spec.edge_tunnel_ip,
             spec.edge_public_key, stamp),
        )
        db.execute(
            "INSERT INTO manual_edge_events "
            "(op_id,actor,status,code,happened) "
            "VALUES (?,?,'EDGE_READY','AWG_EXISTING_VERIFIED_NO_INSTALL',?)",
            (op, actor, stamp),
        )
        db.commit()
    except BaseException:
        db.rollback()
        raise
    return op
