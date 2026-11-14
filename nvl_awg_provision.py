"""Pinned-SSH AWG 3.1 new Edge provisioning (NOT existing-Edge adoption).

Only callable from a journaled, operator-authorized Manual Edge install.
Holds the same exclusive file lease as legacy provisioning. Remote state
is write-once; no retries after an ambiguous network/installer error.
"""
from __future__ import annotations

import base64
import os
from datetime import datetime
import time
from pathlib import Path
import shlex
import sqlite3
import subprocess

from legacy_wg_install_lease import exclusive_legacy_edge_install
from nvl_awg_new_edge import AWGCoreProfile, public_key, render_new_edge_conf, ipv4, port
from nvl_awg_core_peer import plan_core_peer, commit_core_peer
from nvl_awg_nat_evidence import AWGNATEvidence, verify_awg_nat


class AWGProvisionHold(RuntimeError):
    pass


def _run(argv: list[str], *, input: str | None = None, timeout=10) -> str:
    output = subprocess.run(
        argv, input=input, capture_output=True, text=True,
        timeout=timeout, check=True,
    )
    return output.stdout.strip()


def _remote(ssh, cmd: str, *, timeout: int = 60) -> str:
    # Drain both channel streams BEFORE recv_exit_status to avoid SSH deadlock
    # when apt/dpkg output exceeds the remote channel's fixed window.
    _stdin, stdout, _stderr = ssh.exec_command(cmd, timeout=timeout)
    chan = stdout.channel
    deadline = time.monotonic() + timeout
    chunks = []
    total = 0
    while not chan.exit_status_ready() or chan.recv_ready() or chan.recv_stderr_ready():
        progressed = False
        if chan.recv_ready():
            data = chan.recv(4096)
            total += len(data)
            if total > 32768:
                raise AWGProvisionHold("EDGE_REMOTE_OUTPUT_EXCEEDED_LIMIT")
            chunks.append(data)
            progressed = True
        if chan.recv_stderr_ready():
            chan.recv_stderr(4096)  # never expose remote stderr
            progressed = True
        if not progressed:
            if time.monotonic() > deadline:
                raise AWGProvisionHold("EDGE_REMOTE_COMMAND_TIMEOUT")
            time.sleep(0.05)
    status = chan.recv_exit_status()
    if status != 0:
        raise AWGProvisionHold("EDGE_REMOTE_COMMAND_FAILED")
    return b"".join(chunks).decode("utf-8", "replace").strip()


def _root_only(path: Path) -> str:
    if (path.is_symlink() or not path.is_file()
            or path.stat().st_uid != 0 or path.stat().st_mode & 0o077):
        raise AWGProvisionHold("CORE_FILE_MISSING_OR_NOT_PRIVATE")
    return path.read_text(encoding="utf-8")


def _registered_awg_ips(db_factory) -> tuple[str, ...]:
    with db_factory() as db:
        exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='edge_tunnel_bindings'",
        ).fetchone()
        if not exists:
            return ()
        return tuple(r[0] for r in db.execute(
            "SELECT edge_tunnel_ip FROM edge_tunnel_bindings "
            "WHERE backend='amneziawg'",
        ))


@exclusive_legacy_edge_install
def provision_awg_new_edge_sync(
    host: str, admin_port: int, password: str,
    pinned_key: tuple[str, str], *,
    core_public_ip: str, customer_port: int, tls_port: int,
    db_factory, install_management_key,
    core_config_path="/etc/amnezia/amneziawg/awg0.conf",
    installer_path="/root/setup_edge_awg_relay.sh",
    edge_udp_port: int = 42371,
) -> tuple[bool, str, dict | None]:
    """Return (success, safe_code, nonsecret details), never print any key."""
    ssh = None
    try:
        if os.geteuid() != 0:
            raise AWGProvisionHold("CORE_ROOT_REQUIRED")
        if not callable(install_management_key):
            raise AWGProvisionHold("CORE_MANAGEMENT_KEY_INSTALL_REQUIRED")
        if not isinstance(password, str) or not password:
            raise AWGProvisionHold("SSH_PASSWORD_MISSING")
        host = ipv4(host, global_address=True)
        core_public_ip = ipv4(core_public_ip, global_address=True)
        if host == core_public_ip:
            raise AWGProvisionHold("EDGE_EQUALS_CORE")
        for p in (admin_port, customer_port, tls_port, edge_udp_port):
            port(p)
        if len({admin_port, customer_port, tls_port}) != 3:
            raise AWGProvisionHold("SSH_PORT_COLLISION")
        source = Path(installer_path)
        if source.is_symlink() or not source.is_file():
            raise AWGProvisionHold("AWG_INSTALLER_NOT_DEPLOYED")
        # Root-owned source installer is fetched from the pinned GitHub release.
        core_config = _root_only(Path(core_config_path))
        profile = AWGCoreProfile.parse(core_config)
        live = _run(["awg", "show", "awg0", "allowed-ips"])
        core_key = public_key(_run(["awg", "show", "awg0", "public-key"]))
        # Allocate once under the shared Legacy+AWG provision file lease.
        registered = _registered_awg_ips(db_factory)
        edge_private = public_key(_run(["awg", "genkey"]))
        edge_key = public_key(_run(
            ["awg", "pubkey"], input=edge_private + "\n",
        ))
        plan = plan_core_peer(
            core_config, live, edge_host=host, edge_udp_port=edge_udp_port,
            edge_public_key=edge_key, registered_ips=registered,
        )
        rendered = render_new_edge_conf(
            profile, edge_private_key=edge_private, core_public_key=core_key,
            core_public_ip=core_public_ip, edge_tunnel_ip=plan.edge_tunnel_ip,
            edge_port=edge_udp_port,
        )

        if pinned_key[0] != "ssh-ed25519":
            raise AWGProvisionHold("PINNED_SSH_HOSTKEY_TYPE_UNSUPPORTED")
        import paramiko
        known = paramiko.PKey.from_type_string(
            pinned_key[0], base64.b64decode(pinned_key[1], validate=True),
        )
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        ssh.get_host_keys().add(
            host if admin_port == 22 else f"[{host}]:{admin_port}",
            pinned_key[0], known,
        )
        ssh.connect(
            host, port=admin_port, username="root", password=password,
            look_for_keys=False, allow_agent=False,
            timeout=15, banner_timeout=15, auth_timeout=15,
        )
        key_ok, _reason = install_management_key(ssh)
        if key_ok is not True:
            raise AWGProvisionHold("CORE_MANAGEMENT_KEY_INSTALL_FAILED")
        # Never install over a pre-existing tunnel, even if the OS check was
        # passed earlier in the wizard. Pinned SSH prevents host spoofing.
        _remote(
            ssh,
            "test ! -e /etc/amnezia/amneziawg/awg0.conf"
            " && test ! -e /root/nvl-awg-stage/awg0.conf"
            " && test ! -e /root/nvl-awg-stage/setup_edge_awg_relay.sh"
            " && ! ip link show awg0 >/dev/null 2>&1"
            " && ! ip link show wg0 >/dev/null 2>&1",
            timeout=10,
        )
        _remote(ssh, "umask 077; install -d -m 700 /root/nvl-awg-stage",
                timeout=10)
        sftp = ssh.open_sftp()
        try:
            staged = "/root/nvl-awg-stage/awg0.conf"
            with sftp.file(staged, "w") as f:
                f.write(rendered)
                f.flush()
            sftp.chmod(staged, 0o600)
            sftp.put(str(source), "/root/nvl-awg-stage/setup_edge_awg_relay.sh")
            sftp.chmod("/root/nvl-awg-stage/setup_edge_awg_relay.sh", 0o700)
        finally:
            sftp.close()
        command = "timeout 300 bash /root/nvl-awg-stage/setup_edge_awg_relay.sh " + " ".join(
            shlex.quote(str(x)) for x in (
                core_public_ip, profile.core_tunnel_ip,
                plan.edge_tunnel_ip, customer_port, tls_port, admin_port,
            )
        )
        out = _remote(ssh, command, timeout=330)
        if "AWG_EDGE_STAGE=INSTALLED" not in out:
            raise AWGProvisionHold("EDGE_AWG_INSTALL_UNVERIFIED")

        # Atomic core config write + live peer update; NEVER restart awg0.
        commit_core_peer(plan)
        _run(["ping", "-I", "awg0", "-c", "2", "-W", "3",
              plan.edge_tunnel_ip], timeout=12)

        # Network evidence comes from the SAME pinned SSH transport used to
        # install the Edge. A live tunnel alone is insufficient for registration.
        wan = _remote(
            ssh, "ip -4 route get " + shlex.quote(core_public_ip) +
                 " | awk '{for(i=1;i<=NF;i++) if($i==\"dev\"){print $(i+1);exit}}'",
            timeout=8,
        ).strip()
        nat = AWGNATEvidence(
            wan=wan,
            core_tunnel_ip=profile.core_tunnel_ip,
            edge_tunnel_ip=plan.edge_tunnel_ip,
            customer_port=customer_port,
            tls_port=tls_port,
            live_nat=_remote(ssh, "iptables -t nat -S", timeout=8),
            saved_rules=_remote(
                ssh, "cat /etc/iptables/rules.v4", timeout=8,
            ),
            live_forward=_remote(ssh, "iptables -S FORWARD", timeout=8),
            forwarding=_remote(
                ssh, "sysctl -n net.ipv4.ip_forward", timeout=8,
            ),
            awg_service=_remote(
                ssh, "systemctl is-active awg-quick@awg0.service", timeout=8,
            ),
            awg_autostart=_remote(
                ssh, "systemctl is-enabled awg-quick@awg0.service", timeout=8,
            ),
            netfilter_autostart=_remote(
                ssh, "systemctl is-enabled netfilter-persistent", timeout=8,
            ),
        )
        if not verify_awg_nat(nat):
            raise AWGProvisionHold("AWG_NAT_PERSISTENCE_UNVERIFIED")

        # Only now attach a VERIFIED backend to an inactive manual Edge.
        with db_factory() as db:
            db.execute("BEGIN IMMEDIATE")
            from nvl_tunnel_backend import SCHEMA
            for stmt in SCHEMA.split(";"):
                if stmt.strip():
                    db.execute(stmt)
            if db.execute(
                "SELECT 1 FROM host_pool WHERE host=?", (host,),
            ).fetchone():
                raise AWGProvisionHold("EDGE_POOL_ALREADY_REGISTERED")
            if db.execute(
                "SELECT 1 FROM edge_tunnel_bindings WHERE host=? "
                "OR (backend='amneziawg' AND edge_tunnel_ip=?)",
                (host, plan.edge_tunnel_ip),
            ).fetchone():
                raise AWGProvisionHold("AWG_BINDING_COLLISION")
            now = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            db.execute(
                "INSERT INTO host_pool "
                "(host,active,is_default,is_standby,provider,provider_instance_id,"
                "added_at,ssh_port,service_port,admin_ssh_port) "
                "VALUES (?,0,0,0,'manual',NULL,?,?,?,?)",
                (host, now, customer_port, customer_port, admin_port),
            )
            db.execute(
                "INSERT INTO edge_tunnel_bindings "
                "(host,backend,interface,core_tunnel_ip,edge_tunnel_ip,"
                "peer_public_key,state,verified_at) "
                "VALUES (?,'amneziawg','awg0',?,?,?,'VERIFIED',?)",
                (host, profile.core_tunnel_ip, plan.edge_tunnel_ip,
                 edge_key, int(time.time())),
            )
        return True, "", dict(
            tunnel_ok=True, edge_wg_ip=plan.edge_tunnel_ip,
            edge_pubkey=edge_key, tunnel_backend="amneziawg",
        )
    except Exception:
        # Every failure after remote effect begins is a durable INSTALL_HOLD
        # in ManualEdgeWizard: never retry or start another installer.
        # No raw traceback/SSH error or profile/HPK are returned to Telegram.
        return False, "AWG_NEW_EDGE_REQUIRES_MANUAL_REVIEW", None
    finally:
        if ssh is not None:
            try:
                ssh.close()
            except Exception:
                pass
