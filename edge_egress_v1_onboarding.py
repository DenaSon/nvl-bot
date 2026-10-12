"""I — opt-in stage of dedicated Egress during EXISTING hp_addedge onboarding.

Called only after the existing ingress installer returns a real wg0 source and
public key. No second Edge wizard, controller, route or default-relay switch.

This produces one immutable Core stage, one root-only remote Edge stage, and
an atomic root-only H ingress registry entry. It does NOT start WG Egress,
enroll customers, enable services, install PAM, or mark an Edge READY.
The final J/K integration must explicitly activate/attest before 6H use.
"""
from __future__ import annotations

from dataclasses import asdict
import base64
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from edge_egress_v1_ingress import (
    IngressPeer, IngressHold, REGISTRY, _networks, load_registry,
    render_registry,
)
from ops.edge_egress_provision import (
    EgressSpec, preflight, stage_files, wireguard_config, edge_up_script,
    edge_down_script,
)

STAGE_HOME = Path("/root/nvl-egress-v1")
EDGE_HOME = "/root/nvl-egress-v1"
IPv4 = ipaddress.IPv4Address


class OnboardHold(ValueError):
    """No guessing, no implied Egress readiness and no destructive rollback."""


def spec_for_new_edge(*, edge_ip: str, core_ip: str,
                      ingress_ip: str, uplink: str = "eth0") -> EgressSpec:
    """Deterministic independent /30s and route slot for one wg0 peer.

    Allocations MUST still pass real preflight, live collision checks and
    existing 6G ownership before any Egress activation in J/K.
    """
    try:
        src = IPv4(ingress_ip)
    except (ValueError, ipaddress.AddressValueError) as exc:
        raise OnboardHold("INVALID_INGRESS_IP") from exc
    n = int(src) - int(IPv4("10.77.0.0"))
    if not 2 <= n <= 254:
        raise OnboardHold("INGRESS_ADDRESS_NOT_ALLOCATABLE")
    return EgressSpec.from_json(dict(
        edge_id="e" + str(n),
        edge_public_ipv4=edge_ip,
        core_public_ipv4=core_ip,
        tunnel_network=f"10.79.{n}.0/30",
        veth_network=f"10.80.{n}.0/30",
        edge_uplink=uplink,
        edge_listen_port=52000 + n,
        route_table=20000 + n,
    ))


def assert_live_ingress(peer: IngressPeer, allowed_ips: str) -> None:
    """The actual Core wg0 must own only this peer's precise ingress /32."""
    src = IPv4(peer.ingress_ipv4)
    expected = ipaddress.ip_network(peer.ingress_ipv4 + "/32")
    try:
        peers = _networks(allowed_ips)
    except (ValueError, IngressHold) as exc:
        raise OnboardHold("WG0_PEER_INVENTORY_INVALID") from exc
    if expected not in peers.get(peer.wg_public_key, ()):
        raise OnboardHold("WG0_INGRESS_OWNERSHIP_MISSING")
    if any(src in cidr for key, nets in peers.items()
           if key != peer.wg_public_key for cidr in nets):
        raise OnboardHold("WG0_INGRESS_OVERLAP")


def planned_peer(ingress_ip: str, edge_ip: str, public_key: str) -> IngressPeer:
    # Validate using H's full registry parser, not a second implementation.
    spec = spec_for_new_edge(
        edge_ip=edge_ip, core_ip="209.200.246.198", ingress_ip=ingress_ip
    )
    peer = IngressPeer(spec.edge_id, edge_ip, ingress_ip, public_key)
    render_registry([peer])
    return peer


def _wg_keypair() -> tuple[str, str]:
    try:
        private = subprocess.run(
            ["wg", "genkey"], capture_output=True, text=True,
            check=True, timeout=6,
        ).stdout.strip()
        public = subprocess.run(
            ["wg", "pubkey"], input=private + "\n", capture_output=True,
            text=True, check=True, timeout=6,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise OnboardHold("WIREGUARD_KEYGEN_FAILED") from exc
    # Full private/public validation handled in the shared generator.
    return private, public


def _make_dir(directory: Path) -> None:
    if directory.is_symlink():
        raise OnboardHold("UNTRUSTED_STAGE_HOME")
    if not directory.exists():
        directory.mkdir(mode=0o700)
    st = directory.stat()
    if not directory.is_dir() or st.st_uid != 0 or st.st_mode & 0o077:
        raise OnboardHold("UNTRUSTED_STAGE_HOME")


def _checked_ingress_registry(peer: IngressPeer) -> list[IngressPeer]:
    if REGISTRY.exists() or REGISTRY.is_symlink():
        existing = list(load_registry())
    else:
        existing = []
    if any(p.edge_id == peer.edge_id or p.edge_ipv4 == peer.edge_ipv4 or
           p.ingress_ipv4 == peer.ingress_ipv4 or
           p.wg_public_key == peer.wg_public_key for p in existing):
        raise OnboardHold("INGRESS_ALREADY_REGISTERED")
    render_registry(existing + [peer])
    return existing


def _publish_registry(peer: IngressPeer) -> None:
    """Atomic last step after both Stage folders exist; no silent overwrite."""
    directory = REGISTRY.parent
    _make_dir(directory)
    lock_path = directory / ".v1-ingress-peers.lock"
    if lock_path.is_symlink():
        raise OnboardHold("REGISTRY_LOCK_SYMLINK")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        st = os.fstat(fd)
        if st.st_uid != 0 or st.st_mode & 0o077:
            raise OnboardHold("REGISTRY_LOCK_PERMISSIONS")
        fcntl.flock(fd, fcntl.LOCK_EX)
        old = _checked_ingress_registry(peer)
        text = render_registry(old + [peer])
        name = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", prefix=".v1-registry-",
                dir=directory, delete=False,
            ) as temp:
                name = temp.name
                os.fchmod(temp.fileno(), 0o600)
                temp.write(text)
                temp.flush()
                os.fsync(temp.fileno())
            os.replace(name, REGISTRY)
            dirfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        finally:
            if name and os.path.exists(name):
                os.unlink(name)
    finally:
        os.close(fd)


def _remote_stage(ssh, spec: EgressSpec, edge_private: str,
                  core_public: str) -> str:
    """Stage with SFTP over the *same server host-key-pinned SSH identity*.

    No root password, secret, script contents or network mutations are logged.
    A partially staged folder is held for operator inspection, not purged.
    """
    remote_dir = f"{EDGE_HOME}/edge-{spec.edge_id}"
    cmd = (
        "set -eu; test \"$(id -u)\" = 0; "
        f"test ! -e {remote_dir}; "
        f"test ! -L {remote_dir}; "
        f"ip link show dev {spec.iface} >/dev/null 2>&1 && exit 4 || true; "
        f"ss -H -lun | grep -Eq ':{spec.edge_listen_port}([[:space:]]|$)' && exit 4 || true; "
        f"ip -o -4 route get 1.1.1.1 | grep -Eq ' dev {spec.edge_uplink}( |$)'; "
        "test \"$(sysctl -n net.ipv4.ip_forward)\" = 1"
    )
    _in, stdout, _err = ssh.exec_command(cmd, timeout=20)
    if stdout.channel.recv_exit_status() != 0:
        raise OnboardHold("EDGE_STAGE_PREFLIGHT_FAILED")
    manifest = json.dumps(
        dict(config=asdict(spec), role="edge", stage_only=True,
             user_routes_installed=False),
        sort_keys=True, indent=2,
    ) + "\n"
    artifacts = {
        "manifest.json": (manifest, 0o600),
        "wg.conf": (wireguard_config(spec, "edge", edge_private, core_public), 0o600),
        "up.sh": (edge_up_script(spec, Path(remote_dir)), 0o700),
        "down.sh": (edge_down_script(spec, Path(remote_dir)), 0o700),
    }
    sftp = ssh.open_sftp()
    try:
        try:
            sftp.stat(EDGE_HOME)
        except FileNotFoundError:
            sftp.mkdir(EDGE_HOME, mode=0o700)
        owner = sftp.stat(EDGE_HOME)
        if owner.st_uid != 0 or owner.st_mode & 0o077:
            raise OnboardHold("UNTRUSTED_REMOTE_STAGE_HOME")
        sftp.mkdir(remote_dir, mode=0o700)
        for name, (data, mode) in artifacts.items():
            with sftp.file(remote_dir + "/" + name, "x") as f:
                f.write(data)
                f.flush()
            sftp.chmod(remote_dir + "/" + name, mode)
    except OSError as exc:
        raise OnboardHold("EDGE_STAGE_WRITE_UNCERTAIN") from exc
    finally:
        sftp.close()
    return remote_dir


def onboard_after_ingress(*, edge_ip: str, core_ip: str, ingress_ip: str,
                          public_key: str, ssh_host_key, ssh_port: int,
                          root_password: str | None,
                          private_key_path: str | None = None,
                          core_stage_root: Path = STAGE_HOME,
                          ssh_client_factory=None) -> dict:
    """Existing bot's explicit opt-in hook after a successful wg0 setup.

    Stages dedicated Egress without touching running wg0, users or routing.
    Caller registers INGRESS_ONLY; no READY/assignment bit is set here.
    """
    peer = planned_peer(ingress_ip, edge_ip, public_key)
    spec = spec_for_new_edge(
        edge_ip=edge_ip, core_ip=core_ip, ingress_ip=ingress_ip
    )
    # A preexisting allocation, partial folder or duplicate ingress must HOLD.
    _checked_ingress_registry(peer)
    out = subprocess.run(
        ["wg", "show", "wg0", "allowed-ips"], text=True,
        capture_output=True, timeout=8, check=True,
    )
    assert_live_ingress(peer, out.stdout)
    pf = preflight(spec, "core")
    if not pf.get("ok"):
        raise OnboardHold("CORE_STAGE_PREFLIGHT_FAILED")
    _make_dir(core_stage_root)
    core_stage = core_stage_root / ("core-" + spec.edge_id)
    if core_stage.exists() or core_stage.is_symlink():
        raise OnboardHold("CORE_STAGE_EXISTS_HOLD")
    if ssh_host_key is None or type(ssh_port) is not int or not 1 <= ssh_port <= 65535:
        raise OnboardHold("UNPINNED_REMOTE_SSH")
    if ssh_client_factory is None:
        import paramiko
        ssh_client_factory = paramiko.SSHClient
    # Same SSH public host key observed during initial ingress install.
    # Never automatically trust a different key on the second connection.
    ssh = ssh_client_factory()
    port_host = edge_ip if ssh_port == 22 else f"[{edge_ip}]:{ssh_port}"
    ssh.get_host_keys().add(port_host, ssh_host_key.get_name(), ssh_host_key)
    try:
        import paramiko
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        connect = dict(hostname=edge_ip, port=ssh_port, username="root",
                       timeout=15, banner_timeout=15,
                       look_for_keys=False, allow_agent=False)
        if private_key_path:
            connect["pkey"] = paramiko.Ed25519Key.from_private_key_file(
                private_key_path
            )
        elif root_password:
            connect["password"] = root_password
        else:
            raise OnboardHold("REMOTE_AUTH_UNAVAILABLE")
        ssh.connect(**connect)
        core_priv, core_pub = _wg_keypair()
        edge_priv, edge_pub = _wg_keypair()
        _remote_stage(ssh, spec, edge_priv, core_pub)
        # Do not permit protected UIDs to attach to an unfinished Core stage.
        stage_files(spec, "core", core_stage, core_priv, edge_pub)
    except OnboardHold:
        raise
    except Exception as exc:
        # Omit exception text (may contain SSH credentials or remote paths).
        raise OnboardHold("EGRESS_STAGE_INCOMPLETE_HOLD") from exc
    finally:
        ssh.close()
    # Only publish trusted new ingress identity after both stages are written.
    _publish_registry(peer)
    return dict(edge_id=spec.edge_id, egress_state="STAGED_NOT_READY",
                core_stage=str(core_stage), remote_stage=f"{EDGE_HOME}/edge-{spec.edge_id}",
                ingress_ipv4=peer.ingress_ipv4)
