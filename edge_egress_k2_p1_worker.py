"""K2 P1: root-only, pinned dedicated Egress transport activation.

A transport-only operation: no UID, SSH account, PAM, public DNS, wg0 mutation,
host pool enrollment, Core default route or Failover executor. Both host Stages
were written by the unified Edge wizard and pinned there before any operation.
Never treat an observed namespace public IP as F4 or customer cutover approval.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import re
import subprocess
import time
from typing import Callable

from edge_egress_v1_ingress import load_registry
from edge_egress_v1_onboarding import assert_live_ingress
from ops.edge_egress_v1_transport import stage_hash, pinned, observe, ensure

PIN_ROOT = Path("/etc/nvl-egress/k2-p1-pins")
STAGE_ROOT = Path("/root/nvl-egress-v1")
SSH_KEY = Path("/root/.ssh/edge_provision_ed25519")
_HEX = re.compile(r"^[a-f0-9]{64}$")
_EDGE = re.compile(r"^[a-z][a-z0-9]{0,6}$")
# These are also registered with the existing 6G crash-hold classifier.
INTENT = "EGRESS_P1_TRANSPORT_INTENT"
RECOVERY = "EGRESS_P1_TRANSPORT_RECOVERY_REQUIRED"


class Phase1Hold(ValueError):
    pass


@dataclass(frozen=True)
class StagePin:
    edge_id: str
    edge_ipv4: str
    core_ipv4: str
    ingress_ipv4: str
    core_sha: str
    edge_sha: str
    ssh_host_key: str
    ssh_port: int

    def validate(self):
        if not _EDGE.fullmatch(self.edge_id):
            raise Phase1Hold("INVALID_EDGE_ID")
        for value in (self.edge_ipv4, self.core_ipv4):
            try:
                ip = IPv4Address(value)
            except (ValueError, TypeError) as exc:
                raise Phase1Hold("BAD_PUBLIC_IP") from exc
            if str(ip) != value or not ip.is_global:
                raise Phase1Hold("BAD_PUBLIC_IP")
        if self.core_ipv4 == self.edge_ipv4:
            raise Phase1Hold("CORE_EDGE_COLLISION")
        if not isinstance(self.ingress_ipv4, str) or not re.fullmatch(
            r"10\.77\.0\.(?:[2-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-4])",
            self.ingress_ipv4,
        ):
            raise Phase1Hold("BAD_INGRESS_IP")
        if type(self.ssh_port) is not int or not 1 <= self.ssh_port <= 65535:
            raise Phase1Hold("BAD_SSH_PORT")
        if any(not isinstance(v, str) or not _HEX.fullmatch(v)
               for v in (self.core_sha, self.edge_sha)):
            raise Phase1Hold("STAGE_DIGEST_REQUIRED")
        try:
            import paramiko
            raw = base64.b64decode(self.ssh_host_key, validate=True)
            key = paramiko.Ed25519Key(data=raw)
            if key.get_name() != "ssh-ed25519" or key.get_base64() != self.ssh_host_key:
                raise ValueError("host key mismatch")
        except (ValueError, TypeError, ImportError, base64.binascii.Error) as exc:
            raise Phase1Hold("SSH_HOST_KEY_PIN_REQUIRED") from exc


def _owned_directory(folder: Path, *, create: bool = False) -> None:
    if folder.is_symlink():
        raise Phase1Hold("UNTRUSTED_PIN_ROOT")
    if create and not folder.exists():
        folder.mkdir(mode=0o700)
    st = folder.stat()
    if not folder.is_dir() or st.st_uid != 0 or st.st_mode & 0o077:
        raise Phase1Hold("UNTRUSTED_PIN_ROOT")


def publish_stage_pin(pin: StagePin, *, directory: Path = PIN_ROOT) -> None:
    """Called ONCE by the original onboarding while host-key evidence is live.

    Persist public SSH key and exact Stage digests only; no credentials or
    private WireGuard keys. Existing pins can never be silently overwritten.
    """
    from dataclasses import asdict
    pin.validate()
    if os.geteuid() != 0:
        raise Phase1Hold("ROOT_REQUIRED")
    _owned_directory(directory.parent, create=True)
    _owned_directory(directory, create=True)
    path = directory / (pin.edge_id + ".json")
    data = (json.dumps(asdict(pin), sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def load_stage_pin(edge_id: str, *, directory: Path = PIN_ROOT) -> StagePin:
    if not isinstance(edge_id, str) or not _EDGE.fullmatch(edge_id):
        raise Phase1Hold("INVALID_EDGE_ID")
    if os.geteuid() != 0:
        raise Phase1Hold("ROOT_REQUIRED")
    _owned_directory(directory)
    path = directory / (edge_id + ".json")
    if path.is_symlink():
        raise Phase1Hold("PIN_SYMLINK")
    st = path.stat()
    if not path.is_file() or st.st_uid != 0 or st.st_mode & 0o077 or st.st_size > 2048:
        raise Phase1Hold("PIN_FILE_UNTRUSTED")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        pin = StagePin(**data)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise Phase1Hold("INVALID_PIN_RECORD") from exc
    pin.validate()
    if pin.edge_id != edge_id:
        raise Phase1Hold("PIN_EDGE_ID_MISMATCH")
    return pin


def _check_stage(pin: StagePin):
    path = STAGE_ROOT / ("core-" + pin.edge_id)
    spec, peer = pinned(path, "core", pin.core_sha)
    if (spec.edge_id != pin.edge_id
            or spec.core_public_ipv4 != pin.core_ipv4
            or spec.edge_public_ipv4 != pin.edge_ipv4):
        raise Phase1Hold("CORE_STAGE_IDENTITY_CHANGED")
    registered = [p for p in load_registry()
                  if p.edge_id == pin.edge_id and p.edge_ipv4 == pin.edge_ipv4
                  and p.ingress_ipv4 == pin.ingress_ipv4]
    if len(registered) != 1:
        raise Phase1Hold("INGRESS_REGISTRY_IDENTITY_CHANGED")
    try:
        output = subprocess.run(
            ["wg", "show", "wg0", "allowed-ips"], capture_output=True,
            text=True, timeout=8, check=True,
        ).stdout
        assert_live_ingress(registered[0], output)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise Phase1Hold("INGRESS_WG0_OWNERSHIP_UNVERIFIED") from exc
    return spec, peer, path


def _remote_transport(pin: StagePin, action: str) -> str:
    """Reuse pinned SSH validation and reviewed pinned transport CLI in memory.

    No mutable scripts installed to remote /opt; stream both exact repository
    modules into root Python stdin over the verified SSH session.
    """
    if action not in ("inspect", "ensure"):
        raise Phase1Hold("REMOTE_VERB_NOT_ALLOWED")
    from edge_egress_v1_live_driver import RemotePinnedEdge
    remote = RemotePinnedEdge(
        ipv4=pin.edge_ipv4, port=pin.ssh_port,
        host_key_b64=pin.ssh_host_key, key_path=SSH_KEY,
        remote_stage=STAGE_ROOT / ("edge-" + pin.edge_id),
        stage_digest=pin.edge_sha,
    )
    home = Path(__file__).resolve().parent
    provision = (home / "ops" / "edge_egress_provision.py").read_text(encoding="utf-8")
    transport = (home / "ops" / "edge_egress_v1_transport.py").read_text(encoding="utf-8")
    boot = (
        "import sys,types\n"
        "pkg=types.ModuleType('ops');pkg.__path__=[];sys.modules['ops']=pkg\n"
        "m=types.ModuleType('ops.edge_egress_provision')\n"
        "m.__file__='edge_egress_provision.py';sys.modules[m.__name__]=m\n"
        "exec(compile(" + repr(provision) + ",m.__file__,'exec'),m.__dict__)\n"
        "exec(compile(" + repr(transport) +
        ",'edge_egress_v1_transport.py','exec'),{'__name__':'__main__'})\n"
    )
    command = ("python3 - " + action + " --stage "
               + "/root/nvl-egress-v1/edge-" + pin.edge_id
               + " --role edge --digest " + pin.edge_sha)
    try:
        ssh = remote._ssh()  # Same verified key and root-only identity as K2 driver.
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=55, get_pty=False)
            stdout.channel.settimeout(55)
            stdin.write(boot)
            stdin.flush()
            stdout.channel.shutdown_write()
            result = stdout.read(128).decode("utf-8").strip()
            code = stdout.channel.recv_exit_status()
            if code != 0 or result not in (
                "UP", "ABSENT", "EXACT_TRANSPORT_ALREADY_UP", "TRANSPORT_STARTED",
            ):
                raise Phase1Hold("REMOTE_PINNED_TRANSPORT_HOLD")
            return result
        finally:
            ssh.close()
    except Phase1Hold:
        raise
    except Exception as exc:
        raise Phase1Hold("REMOTE_PINNED_SSH_UNAVAILABLE") from exc


def inspect_phase1(edge_id: str, *, db_conn: Callable,
                   load_pin: Callable = load_stage_pin,
                   remote_transport: Callable = _remote_transport) -> dict:
    pin = load_pin(edge_id)
    spec, peer, _ = _check_stage(pin)
    with db_conn() as db:
        if db.execute(
            "SELECT 1 FROM host_pool WHERE host=?", (pin.edge_ipv4,)
        ).fetchone():
            raise Phase1Hold("CANDIDATE_ALREADY_IN_CUSTOMER_POOL")
        if db.execute(
            "SELECT 1 FROM failover_operations WHERE status='RUNNING' LIMIT 1"
        ).fetchone():
            raise Phase1Hold("SHARED_6G_BUSY")
    core = observe(spec, "core", peer)
    edge = remote_transport(pin, "inspect")
    return {"edge_id":pin.edge_id, "edge_ip":pin.edge_ipv4,
            "core":core, "edge":edge, "stage_pinned":True,
            "customer_ready":False}


def _check_lease(db_conn, op_id: int, source: str, target: str):
    with db_conn() as db:
        rows = db.execute(
            "SELECT id,source_host,target_host,detail_json "
            "FROM failover_operations WHERE status='RUNNING'"
        ).fetchall()
    if len(rows) != 1 or rows[0][:3] != (op_id, source, target):
        raise Phase1Hold("SHARED_6G_LEASE_LOST")
    try:
        detail = json.loads(rows[0][3])
    except (ValueError, TypeError) as exc:
        raise Phase1Hold("6G_INTENT_MISSING") from exc
    if (detail.get("kind") != "K2_P1" or detail.get("phase") not in
            (INTENT, RECOVERY)):
        raise Phase1Hold("6G_INTENT_MISMATCH")


def _prove_ipv4(spec, *, run=subprocess.run, sleep=time.sleep) -> str:
    for _ in range(3):
        try:
            p = run(
                ["ip", "netns", "exec", spec.namespace,
                 "curl", "-4", "-fsS", "--noproxy", "*",
                 "--connect-timeout", "5", "--max-time", "12",
                 "--resolve", "one.one.one.one:443:1.1.1.1",
                 "https://one.one.one.one/cdn-cgi/trace"],
                capture_output=True, text=True, timeout=16,
            )
            ip_line = re.search(
                r"(?m)^ip=(\d{1,3}(?:\.\d{1,3}){3})\s*$", p.stdout,
            )
            if p.returncode == 0 and ip_line:
                value = ip_line.group(1)
                if value == spec.edge_public_ipv4:
                    return value
        except (OSError, subprocess.SubprocessError):
            pass
        sleep(2)
    raise Phase1Hold("DEDICATED_EGRESS_IP_NOT_PROVEN")


def activate_phase1(edge_id: str, *, db_conn: Callable,
                    acquire: Callable, journal: Callable,
                    load_pin: Callable = load_stage_pin,
                    remote_transport: Callable = _remote_transport,
                    core_ensure: Callable = ensure,
                    ipv4_proof: Callable = _prove_ipv4) -> dict:
    """Exact operator-confirmed single-Edge transport start, never customer move.

    Persist the protected intent BEFORE host network mutation. An uncertain
    activation deliberately leaves the shared 6G RUNNING hold for operator
    reconciliation; never tear down another Edge or original wg0.
    """
    pin = load_pin(edge_id)
    spec, peer, core_path = _check_stage(pin)
    with db_conn() as db:
        source = db.execute(
            "SELECT host FROM host_pool WHERE is_default=1 AND active=1"
        ).fetchone()
        collision = db.execute(
            "SELECT 1 FROM host_pool WHERE host=?", (pin.edge_ipv4,)
        ).fetchone()
    if not source or source[0] in (pin.edge_ipv4, pin.core_ipv4) or collision:
        raise Phase1Hold("UNSAFE_ACTIVE_RELAY_OWNERSHIP")
    core_state = observe(spec, "core", peer)
    edge_state = remote_transport(pin, "inspect")
    if core_state not in ("ABSENT", "UP") or edge_state not in ("ABSENT", "UP"):
        raise Phase1Hold("UNTRUSTED_PARTIAL_TRANSPORT")
    op_id, busy = acquire(source[0], pin.edge_ipv4)
    if op_id is None:
        raise Phase1Hold("SHARED_6G_BUSY")
    intent = {"kind":"K2_P1", "phase":INTENT, "edge_id":pin.edge_id,
              "core_sha":pin.core_sha, "edge_sha":pin.edge_sha,
              "customers_moved":0}
    try:
        journal(op_id, status="RUNNING", detail=intent, require_running=True)
        _check_lease(db_conn, op_id, source[0], pin.edge_ipv4)
        # Start the NAT receiving peer first; then the isolated Core namespace.
        remote_transport(pin, "ensure")
        _check_lease(db_conn, op_id, source[0], pin.edge_ipv4)
        core_ensure(core_path, "core", pin.core_sha)
        _check_lease(db_conn, op_id, source[0], pin.edge_ipv4)
        observed = ipv4_proof(spec)
        _check_lease(db_conn, op_id, source[0], pin.edge_ipv4)
        journal(op_id, status="SUCCEEDED", detail={
            **intent, "phase":"EGRESS_P1_TRANSPORT_PROVEN",
            "observed_ipv4":observed, "customer_ready":False,
        }, finished=True, require_running=True)
        return {"edge_id":pin.edge_id, "edge_ip":pin.edge_ipv4,
                "observed_ipv4":observed, "transport_up":True,
                "customer_ready":False}
    except BaseException:
        # The protected intent is persisted before the first transport action:
        # do not auto-clear a potentially partially started dedicated peer.
        try:
            journal(op_id, status="RUNNING", detail={
                **intent, "phase":RECOVERY, "manual_recovery":True,
            }, require_running=True)
        except Exception:
            pass
        raise Phase1Hold("PHASE1_ACTIVATION_HELD_FOR_REVIEW") from None
