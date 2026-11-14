"""AWG-02 trusted, read-only collector for adopting a preinstalled Edge.

Root-only Core workflow. Verifies the SSH Host Key *before* executing static,
read-only remote commands. Never reads/prints AWG private keys or HPK.
No remote installs, restarts, firewall writes, database changes or DNS writes.
"""
from __future__ import annotations

import base64
from pathlib import Path
import re
import stat
import subprocess

from nvl_awg_adoption import (
    AWGAdoptionHold, AWGExistingEdge, AWGNetworkSnapshot,
    _fingerprint, validate_snapshot,
)


def _run_local(args: list[str], *, timeout: int = 7) -> str:
    try:
        result = subprocess.run(
            args, text=True, capture_output=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AWGAdoptionHold("CORE_AWG_READ_FAILED") from exc
    if result.returncode != 0 or len(result.stdout) > 131072:
        raise AWGAdoptionHold("CORE_AWG_READ_FAILED")
    return result.stdout.strip()


def collect_pinned_awg(
    spec: AWGExistingEdge, *, ssh_private_key_path: str,
    approved_ssh_fingerprint: str,
):
    """Collect and verify a live snapshot; require independent SSH key approval.

    This is not directly callable by Telegram/user-supplied serialized inputs.
    Only an authorized, trusted Core operator workflow may call it.
    """
    if not isinstance(spec, AWGExistingEdge):
        raise AWGAdoptionHold("EDGE_SPEC_INVALID")
    observed_fingerprint = _fingerprint(
        spec.ssh_host_key_type, spec.ssh_host_key_base64,
    )
    if approved_ssh_fingerprint != observed_fingerprint:
        raise AWGAdoptionHold("SSH_HOST_FINGERPRINT_NOT_APPROVED")
    key_path = Path(ssh_private_key_path)
    try:
        st = key_path.lstat()
    except OSError as exc:
        raise AWGAdoptionHold("SSH_ADMIN_KEY_UNAVAILABLE") from exc
    if not stat.S_ISREG(st.st_mode) or (st.st_mode & 0o077):
        raise AWGAdoptionHold("SSH_ADMIN_KEY_UNTRUSTED")

    core_public_key = _run_local(["awg", "show", "awg0", "public-key"])
    if core_public_key != spec.core_public_key:
        raise AWGAdoptionHold("CORE_AWG_KEY_CHANGED")
    core_addr = _run_local(["ip", "-4", "-o", "addr", "show", "dev", "awg0"])
    if spec.core_tunnel_ip + "/32" not in core_addr.split():
        raise AWGAdoptionHold("CORE_AWG_ADDRESS_CHANGED")

    core_peers = _run_local(["awg", "show", "awg0", "peers"])
    core_allowed = _run_local(["awg", "show", "awg0", "allowed-ips"])
    try:
        ping = subprocess.run(
            ["ping", "-I", "awg0", "-c", "2", "-W", "2", spec.edge_tunnel_ip],
            text=True, capture_output=True, timeout=7, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        ping_ok = False
    else:
        ping_ok = ping.returncode == 0

    try:
        import paramiko
        raw = base64.b64decode(spec.ssh_host_key_base64, validate=True)
        remote_key = paramiko.PKey.from_type_string(spec.ssh_host_key_type, raw)
        management_key = paramiko.Ed25519Key.from_private_key_file(
            str(key_path),
        )
    except (ImportError, OSError, ValueError, Exception) as exc:
        raise AWGAdoptionHold("SSH_HOST_PIN_OR_ADMIN_KEY_UNVERIFIED") from exc

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
    known_name = (spec.host if spec.admin_port == 22 else
                  f"[{spec.host}]:{spec.admin_port}")
    ssh.get_host_keys().add(known_name, spec.ssh_host_key_type, remote_key)
    try:
        ssh.connect(
            spec.host, port=spec.admin_port, username="root",
            pkey=management_key, look_for_keys=False, allow_agent=False,
            timeout=8, banner_timeout=8, auth_timeout=8,
        )

        def read(command: str) -> str:
            # Never return stderr to UI: remote output might include secrets.
            stdin, stdout, stderr = ssh.exec_command(command, timeout=10)
            _ = stdin
            body = stdout.read(131073)
            code = stdout.channel.recv_exit_status()
            if code != 0 or len(body) > 131072:
                raise AWGAdoptionHold("EDGE_READ_ONLY_CHECK_FAILED")
            try:
                return body.decode("utf-8").strip()
            except UnicodeDecodeError as exc:
                raise AWGAdoptionHold("EDGE_READ_ONLY_ENCODING_INVALID") from exc

        route = read("ip -4 route get " + spec.core_public_ip)
        matched = re.search(r"(?:^|\s)dev\s+([a-zA-Z0-9_.:-]+)", route)
        if not matched:
            raise AWGAdoptionHold("EDGE_WAN_UNVERIFIED")
        wan = matched.group(1)
        # All commands below are literal, read-only and have no user-supplied
        # shell snippets. The sole IP argument above was IPv4Address-validated.
        saved = read("cat /etc/iptables/rules.v4")
        evidence = AWGNetworkSnapshot(
            core_peers=core_peers,
            core_allowed_ips=core_allowed,
            core_ping_ok=ping_ok,
            edge_peers=read("awg show awg0 peers"),
            edge_awg_address=read("ip -4 -o addr show dev awg0"),
            edge_forwarding=read("sysctl -n net.ipv4.ip_forward"),
            edge_wan=wan,
            nat_live=read("iptables -t nat -S"),
            nat_saved=saved,
            forward_live=read("iptables -S FORWARD"),
            forward_saved=saved,
            edge_awg_service=read("systemctl is-active awg-quick@awg0.service"),
            edge_awg_enabled=read("systemctl is-enabled awg-quick@awg0.service"),
            netfilter_enabled=read("systemctl is-enabled netfilter-persistent"),
        )
    except AWGAdoptionHold:
        raise
    except Exception as exc:
        raise AWGAdoptionHold("PINNED_EDGE_INSPECTION_FAILED") from exc
    finally:
        ssh.close()

    return validate_snapshot(spec, evidence)
