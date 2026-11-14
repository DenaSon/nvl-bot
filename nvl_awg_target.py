"""NVL-AWG-03: read-only pinned AWG target admission, never a route writer.

Run from Core to verify an explicitly registered, VERIFIED AWG Edge.
Does not install, change a peer, iptables, DNS, the limiter or customer records.
Only the existing journal/QuickSwitch performs standby/route transitions.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import subprocess
import time

from nvl_tunnel_backend import TunnelHold, lookup_binding, probe_binding, _key
from nvl_awg_nat_evidence import AWGNATEvidence, verify_awg_nat
from nvl_awg_provision import _remote


class AWGTargetHold(RuntimeError):
    pass


@dataclass(frozen=True)
class Target:
    host: str
    service_port: int
    tls_port: int
    admin_port: int
    ssh_host_key_type: str
    ssh_host_key_base64: str


def target_backend(db, host: str) -> str:
    """Strictly separate absent legacy binding from invalid present binding."""
    binding = lookup_binding(db, host)
    return binding.backend if binding is not None else "wireguard"


def _local_public_key(runner) -> str:
    res = runner(["awg", "show", "awg0", "public-key"],
                 capture_output=True, text=True, timeout=5)
    if res.returncode != 0:
        raise AWGTargetHold("AWG_CORE_KEY_UNAVAILABLE")
    return _key(res.stdout.strip())


def _ssh_connect(target: Target, management_key_path: str):
    import paramiko
    if target.ssh_host_key_type != "ssh-ed25519":
        raise AWGTargetHold("AWG_PIN_TYPE_UNSUPPORTED")
    try:
        key_data = base64.b64decode(target.ssh_host_key_base64, validate=True)
        host_key = paramiko.PKey.from_type_string(target.ssh_host_key_type, key_data)
    except (ValueError, TypeError) as exc:
        raise AWGTargetHold("AWG_PIN_INVALID") from exc
    root_key = Path(management_key_path)
    if (root_key.is_symlink() or not root_key.is_file()
            or root_key.stat().st_uid != 0
            or root_key.stat().st_mode & 0o077):
        raise AWGTargetHold("CORE_MANAGEMENT_KEY_NOT_PRIVATE")
    management = paramiko.Ed25519Key.from_private_key_file(str(root_key))
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
    name = target.host if target.admin_port == 22 else (
        f"[{target.host}]:{target.admin_port}"
    )
    ssh.get_host_keys().add(name, target.ssh_host_key_type, host_key)
    try:
        ssh.connect(
            target.host, port=target.admin_port, username="root",
            pkey=management, look_for_keys=False, allow_agent=False,
            timeout=8, auth_timeout=8, banner_timeout=8,
        )
    except BaseException:
        ssh.close()
        raise
    return ssh


def verify_awg_target(
    db_factory, target: Target, *,
    runner=subprocess.run,
    management_key_path="/root/.ssh/edge_provision_ed25519",
    ssh_connect=None,
) -> bool:
    """Fail-closed Core/Edge peer identity, actual path and both NAT ports.

    The SSH transport is pinned to the journal's independently verified
    host key; callers must never substitute AutoAddPolicy or client evidence.
    """
    try:
        host = str(ipaddress.IPv4Address(target.host))
        if host != target.host:
            return False
        with db_factory() as db:
            binding = lookup_binding(db, host)
            if not binding or binding.backend != "amneziawg" or binding.interface != "awg0":
                return False
            row = db.execute(
                "SELECT m.pin_type,m.pin_base64,m.admin_port,"
                "h.service_port,h.admin_ssh_port FROM manual_edge_operations m "
                "JOIN host_pool h ON h.host=m.ip "
                "WHERE m.ip=? AND m.tunnel_backend='amneziawg' "
                "AND m.status IN ('INSTALLING','EDGE_READY','STANDBY','ROUTING','ACTIVE')",
                (host,),
            ).fetchall()
            if len(row) != 1 or row[0] != (
                target.ssh_host_key_type, target.ssh_host_key_base64,
                target.admin_port, target.service_port, target.admin_port,
            ):
                return False
            core_row = db.execute(
                "SELECT value FROM settings WHERE key='core_wg_public_ip'"
            ).fetchone()
            if not core_row:
                return False
            core_public_ip = str(ipaddress.IPv4Address(core_row[0]))
        proof = probe_binding(binding, runner=runner)
        if proof.get("wg_peer_ok") is not True or proof.get("core_path_ok") is not True:
            return False
        core_key = _local_public_key(runner)
        connector = ssh_connect or _ssh_connect
        ssh = connector(target, management_key_path)
        try:
            # Peer identity and exact AllowedIPs must match Core; an unrelated
            # working tunnel cannot be used to qualify the destination.
            peer = _remote(ssh, "awg show awg0 peers", timeout=8).splitlines()
            allowed = _remote(ssh, "awg show awg0 allowed-ips", timeout=8).splitlines()
            if peer != [core_key] or allowed != [
                core_key + " " + binding.core_tunnel_ip + "/32"
            ]:
                return False
            addrs = _remote(ssh, "ip -4 -o addr show dev awg0", timeout=8)
            if binding.edge_tunnel_ip + "/32" not in addrs.split():
                return False
            wan = _remote(ssh, "ip -4 route get " + core_public_ip +
                          " | awk '{for(i=1;i<=NF;i++)if($i==\"dev\")"
                          "{print $(i+1);exit}}'", timeout=8)
            nat = AWGNATEvidence(
                wan=wan.strip(), core_tunnel_ip=binding.core_tunnel_ip,
                edge_tunnel_ip=binding.edge_tunnel_ip,
                customer_port=target.service_port, tls_port=target.tls_port,
                live_nat=_remote(ssh, "iptables -t nat -S", timeout=8),
                saved_rules=_remote(ssh, "cat /etc/iptables/rules.v4", timeout=8),
                live_forward=_remote(ssh, "iptables -S FORWARD", timeout=8),
                forwarding=_remote(ssh, "sysctl -n net.ipv4.ip_forward", timeout=8),
                awg_service=_remote(ssh, "systemctl is-active awg-quick@awg0", timeout=8),
                awg_autostart=_remote(ssh, "systemctl is-enabled awg-quick@awg0", timeout=8),
                netfilter_autostart=_remote(ssh, "systemctl is-enabled netfilter-persistent", timeout=8),
            )
            return verify_awg_nat(nat)
        finally:
            ssh.close()
    except Exception:
        # Read-only target checks never throw raw SSH errors/key material into
        # Telegram. The caller returns a generic HOLD and logs a safe code.
        return False


def core_limiter_canary_ready(edge_tunnel_ip: str, *,
                             marker_path="/run/nvl-awg-limiter-ready",
                             runner=subprocess.run) -> bool:
    """Opt-in, short-lived runtime gate to fail closed before AWG cutover.

    Marker must be created by a dedicated Core runtime reconciliation check
    (not by the bot callback or a Telegram message). Until a trusted writer
    exists, AWG QuickSwitch is deliberately HOLD-only.
    """
    try:
        marker = Path(marker_path)
        if marker.is_symlink() or not marker.is_file():
            return False
        st = marker.stat()
        if (st.st_uid != 0 or st.st_mode & 0o077
                or st.st_size > 256 or time.time() - st.st_mtime > 300
                or st.st_mtime > time.time() + 5):
            return False
        return marker.read_text().strip() == (
            "NVL_AWG_LIMITER_READY " + str(ipaddress.IPv4Address(edge_tunnel_ip))
        )
    except (ValueError, OSError):
        return False
