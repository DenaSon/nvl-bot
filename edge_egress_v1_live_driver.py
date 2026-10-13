"""K: root-only, opt-in HostActions for existing J positive handoff.

No bot registration, daemon, startup hook, credentials or automatic unlock.
Caller supplies reviewed EXACT new Edge stage pins, SSH host-key identity,
Cloudflare settings loader, and the ONE existing 6G adapter. The adapter
persists FROZEN before these actions. The runtime never changes wg0/main
routing or uses legacy DNS->Core. Failures bubble into 6G recovery HOLD.

One UID/one Edge V1. The process-idle scanner is deliberately conservative:
it rejects any process owned by the UID or sshd session matching username.
No process eviction/kill. First real new-Edge acceptance is K, NOT CI.
"""
from __future__ import annotations

import asyncio
import base64
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import tempfile
import time

from edge_egress_handoff import TargetObservation
from edge_egress_policy import EgressReadiness
from edge_egress_v1_admission import (
    GUARD_DIR, ROSTER, load_roster, checked_guard, render_roster,
    _trusted_bytes, _trusted_directory,
)
from edge_egress_v1_ingress import load_registry, _networks
from edge_egress_uid_boot import (
    BootGuardManifest, BootGuardApplier, arm_uid_deny, uid_deny_present,
    release_uid_deny,
)
from edge_egress_uid_policy import UIDPolicyRequest, build_policy_plan
from edge_egress_uid_dns import render_dns_required_unit
from edge_egress_uid_runtime_kernel import LocalLinuxProtectedRuntimeKernel
from edge_egress_f3_readiness import read_readiness, admission_eligible
from edge_egress_v1_cloudflare import ProtectedCloudflareDNS
from ops.edge_egress_v1_transport import pinned, observe, ensure, stage_hash


class LiveHold(ValueError):
    pass


def _command(*argv: str, timeout=15):
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LiveHold("HOST_COMMAND_UNAVAILABLE") from exc


def _checked(*argv: str, timeout=15) -> str:
    result = _command(*argv, timeout=timeout)
    if result.returncode:
        raise LiveHold("HOST_PROBE_OR_MUTATION_FAILED")
    return result.stdout


def _atomic_root(path: Path, data: bytes):
    """Durable owner-only replacement: no symlink, same directory fsync."""
    _trusted_directory(path.parent)
    if path.is_symlink():
        raise LiveHold("SYMLINK_TARGET_REJECTED")
    if path.exists():
        stat = path.stat()
        if not path.is_file() or stat.st_uid != 0 or stat.st_mode & 0o077:
            raise LiveHold("UNTRUSTED_OLD_ARTIFACT")
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".egress-j-",
                                         delete=False) as f:
            tmp = f.name
            os.fchmod(f.fileno(), 0o600)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


def assert_idle_process_snapshot(output: str, username: str, uid: int, *,
                                 allowed_dns_pid: int | None = None):
    """Conservative ps -eo snapshot, no assumption that SOCKS has a TTY.

    Under F2 FROZEN admission, require ZERO processes of this numeric UID
    AND no privileged SSH child containing the exact account name.
    """
    if not isinstance(output, str) or not output.strip() or len(output) > 2000000:
        raise LiveHold("PROCESS_INVENTORY_UNAVAILABLE")
    seen = 0
    verified_dns = False
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+(\d+)\s+(\S+)\s*(.*)$", line)
        if not match:
            raise LiveHold("PROCESS_INVENTORY_AMBIGUOUS")
        pid, owner, comm, args = match.groups()
        seen += 1
        if int(owner) == uid:
            # Only systemd's exact recorded MainPID for the mandatory DoH
            # helper is exempt. A second process, renamed binary, spoofed
            # username/UID or stale PID fails closed.
            expected_dns = (
                "/usr/bin/python3 /opt/nvl-egress/edge_egress_uid_dns.py "
                "serve --username " + username + " --uid " + str(uid) + " "
            )
            if (allowed_dns_pid is not None and int(pid) == allowed_dns_pid
                    and comm.startswith("python") and args.startswith(expected_dns)
                    and not verified_dns):
                verified_dns = True
                continue
            raise LiveHold("PROTECTED_UID_HAS_ACTIVE_PROCESS")
        if (comm in ("sshd", "sshd-session")
                and re.search(r"\bsshd(?:-session)?:\s*" +
                              re.escape(username) + r"(?=@|\s|$)", args)):
            raise LiveHold("SSH_PRIVILEGED_SESSION_STILL_ACTIVE")
    if seen < 2 or (allowed_dns_pid is not None and not verified_dns):
        raise LiveHold("PROCESS_INVENTORY_INCOMPLETE")


@dataclass(frozen=True)
class RemotePinnedEdge:
    ipv4: str
    port: int
    host_key_b64: str
    key_path: Path
    remote_stage: Path
    stage_digest: str

    def _ssh(self):
        try:
            import paramiko
            if not isinstance(self.host_key_b64, str) or len(self.host_key_b64) > 512:
                raise ValueError("untrusted host key")
            # Paramiko SSHKey.get_base64() is an RFC 4253 SSH public-key
            # *blob* (algorithm + encoded key), NOT the raw 32-byte Ed25519
            # public key. Round-trip the exact pinned host identity.
            raw = base64.b64decode(self.host_key_b64, validate=True)
            key = paramiko.Ed25519Key(data=raw)
            if key.get_name() != "ssh-ed25519" or key.get_base64() != self.host_key_b64:
                raise ValueError("host key identity changed")
            if self.key_path.is_symlink():
                raise ValueError("ssh key symlink")
            st = self.key_path.stat()
            if st.st_uid != 0 or st.st_mode & 0o077:
                raise ValueError("ssh key must be root only")
            private = paramiko.Ed25519Key.from_private_key_file(str(self.key_path))
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
            lookup = self.ipv4 if self.port == 22 else f"[{self.ipv4}]:{self.port}"
            ssh.get_host_keys().add(lookup, key.get_name(), key)
            ssh.connect(self.ipv4, port=self.port, username="root", pkey=private,
                        look_for_keys=False, allow_agent=False,
                        timeout=12, banner_timeout=12, auth_timeout=12)
            return ssh
        except (OSError, ValueError, ImportError) as exc:
            raise LiveHold("PINNED_EDGE_SSH_UNAVAILABLE") from exc

    def transport(self, action: str):
        if action not in ("ensure", "inspect"):
            raise LiveHold("REMOTE_COMMAND_NOT_ALLOWED")
        # No arbitrary shell-provided path: server-supplied stage is derived
        # only from a validated EgressSpec Edge ID under this fixed root.
        if not re.fullmatch(r"/root/nvl-egress-v1/edge-[a-z][a-z0-9_-]{1,23}",
                            str(self.remote_stage)):
            raise LiveHold("REMOTE_STAGE_PATH_UNSAFE")
        if not re.fullmatch(r"[0-9a-f]{64}", self.stage_digest):
            raise LiveHold("REMOTE_STAGE_DIGEST_UNPINNED")
        command = ("cd /opt/nvl-egress && /usr/bin/python3 -m "
                   "ops.edge_egress_v1_transport " + action +
                   " --stage " + str(self.remote_stage) +
                   " --role edge --digest " + self.stage_digest)
        ssh = self._ssh()
        try:
            _stdin, stdout, _stderr = ssh.exec_command(command, timeout=50)
            status = stdout.channel.recv_exit_status()
            if status != 0:
                raise LiveHold("PINNED_EDGE_TRANSPORT_HOLD")
            result = stdout.read().decode("utf-8").strip()
            if result not in ("UP", "EXACT_TRANSPORT_ALREADY_UP",
                              "TRANSPORT_STARTED"):
                raise LiveHold("REMOTE_TRANSPORT_RESPONSE_UNTRUSTED")
            return result
        finally:
            ssh.close()


@dataclass(frozen=True)
class LiveDriverConfig:
    core_stage: Path
    core_digest: str
    edge: RemotePinnedEdge
    acceptance_enabled: bool = False


class ProtectedLiveHostActions:
    """Actual local Core/remote Edge/DNS driver. Explicit K acceptance flag.

    Never construct from Telegram callbacks. Use after K operator's real
    backup, tested independent root rescue, PAM/guard boot readiness and
    registration of the new Edge; a flag alone is NOT sufficient evidence.
    """
    def __init__(self, config: LiveDriverConfig, db_conn, cf_config_loader,
                 *, run=_command, clock=time.monotonic):
        self.config = config
        self.db_conn = db_conn
        self.clock = clock
        self.run = run
        self.cf = ProtectedCloudflareDNS(cf_config_loader)
        self.kernel = LocalLinuxProtectedRuntimeKernel(
            explicitly_enabled=True, run=run,
        )
        self.guards = BootGuardApplier(run=run)
        self._proven: dict[str, float] = {}
        self._adapter = None  # Bound ONLY by make_live_adapter(), never by bot callbacks.
        if config.acceptance_enabled is not True or os.geteuid() != 0:
            raise LiveHold("K_ACCEPTANCE_AND_ROOT_REQUIRED")
        self.spec, _peer = pinned(config.core_stage, "core", config.core_digest)
        if (self.spec.edge_public_ipv4 != config.edge.ipv4
                or self.config.edge.remote_stage.name != "edge-" + self.spec.edge_id):
            raise LiveHold("EDGE_STAGE_IDENTITY_MISMATCH")

    def _lease(self):
        adapter = self._adapter
        if adapter is None or adapter.operation_id is None or adapter.snapshot is None:
            raise LiveHold('ACTIVE_6G_ADAPTER_LEASE_REQUIRED')
        with self.db_conn() as conn:
            adapter._locked(conn, source=adapter.snapshot.source_host,
                            target=adapter.snapshot.target_host)

    def _call(self, *cmd, timeout=15):
        out = self.run(*cmd, timeout=timeout)
        if out.returncode != 0:
            raise LiveHold("HOST_COMMAND_FAILED")
        return out.stdout

    def _owner(self, username: str, uid: int):
        if not isinstance(username, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username):
            raise LiveHold("INVALID_USER")
        if type(uid) is not int or uid < 1000 or uid >= 60000:
            raise LiveHold("INVALID_UID")
        if pwd.getpwnam(username).pw_uid != uid:
            raise LiveHold("CHANGED_OS_UID")
        members = load_roster()
        if username not in members or members[username].uid != uid:
            raise LiveHold("ROSTER_IDENTITY_NOT_PROTECTED")
        return members

    def _manifest(self, username: str, uid: int):
        members = self._owner(username, uid)
        manifest = checked_guard(members[username])
        if manifest.request.uid != uid or manifest.request.username != username:
            raise LiveHold("MANIFEST_IDENTITY_CHANGED")
        return manifest

    def _req(self, username, uid):
        return self._manifest(username, uid).request

    def _attested(self, target):
        if target != self.spec.edge_public_ipv4:
            raise LiveHold("UNKNOWN_TARGET_EDGE")
        with self.db_conn() as db:
            evidence = read_readiness(db, self.spec.edge_id)
            if not evidence or evidence.edge_ipv4 != target or not admission_eligible(evidence):
                raise LiveHold("F4_ACCEPTANCE_REQUIRED")
        return evidence

    async def ensure_target_transport(self, target):
        self._lease()
        self._attested(target)
        await asyncio.to_thread(self.config.edge.transport, "ensure")
        if self.spec.edge_public_ipv4 != target:
            raise LiveHold("TARGET_NOT_THE_PINNED_EDGE")
        await asyncio.to_thread(ensure, self.config.core_stage, "core",
                                self.config.core_digest)
        await self.assert_target_peer(target)

    async def assert_target_peer(self, target):
        self._lease()
        self._attested(target)
        # WG ingress identity is from H's immutable, root-only registry.
        peers = load_registry()
        chosen = [p for p in peers if p.edge_id == self.spec.edge_id
                  and p.edge_ipv4 == target]
        if len(chosen) != 1:
            raise LiveHold("INGRESS_PEER_REGISTRY_MISSING")
        output = self._call("wg", "show", "wg0", "allowed-ips")
        mapping = _networks(output)
        ingress = chosen[0]
        expected = ipaddress.ip_network(ingress.ingress_ipv4 + "/32")
        if expected not in mapping.get(ingress.wg_public_key, ()):
            raise LiveHold("INGRESS_WG0_PEER_MISMATCH")
        address = ipaddress.IPv4Address(ingress.ingress_ipv4)
        if any(address in network for key, nets in mapping.items()
               if key != ingress.wg_public_key for network in nets):
            raise LiveHold("INGRESS_WG0_SOURCE_OVERLAP")
        if await asyncio.to_thread(observe, self.spec, "core",
                                   pinned(self.config.core_stage, "core",
                                          self.config.core_digest)[1]) != "UP":
            raise LiveHold("CORE_TRANSPORT_DOWN")
        if await asyncio.to_thread(self.config.edge.transport, "inspect") != "UP":
            raise LiveHold("EDGE_TRANSPORT_DOWN")

    def _trace(self, args):
        output = self._call(
            *args, "curl", "-4", "-fsS", "--noproxy", "*",
            "--connect-timeout", "5", "--max-time", "12",
            "--resolve", "one.one.one.one:443:1.1.1.1",
            "https://one.one.one.one/cdn-cgi/trace",
            timeout=18,
        )
        match = re.search(r"(?m)^ip=(\d{1,3}(?:\.\d{1,3}){3})\s*$", output)
        if not match:
            raise LiveHold("EXTERNAL_TRACE_MISSING")
        return match.group(1)

    async def external_target_observation(self, target):
        self._lease()
        await self.assert_target_peer(target)
        if self._trace(("ip", "netns", "exec", self.spec.namespace)) != target:
            raise LiveHold("NEW_EDGE_EGRESS_IP_MISMATCH")
        # Other gates are the existing F4, *not* independently inferred from
        # a WG handshake. K must have attested them before READY is stored.
        self._attested(target)
        return TargetObservation(EgressReadiness(
            edge_host=target, public_ipv4=target, observed_egress_ipv4=target,
            ingress_service_ok=True, management_ssh_ok=True,
            ingress_wireguard_ok=True, egress_wireguard_ok=True,
            egress_nat_ok=True, fail_closed_policy_ok=True,
            ipv6_leak_protected=True, fresh=True,
        ), datetime.now(timezone.utc), self.spec.edge_id)

    async def assert_pam_admission(self):
        self._lease()
        # No hot PAM installation: inspect actual order and effective sshd.
        # An independent disposable-VPS direct-tcpip test remains K acceptance.
        from edge_egress_v1_admission import inspect_pam
        try:
            contents = Path("/etc/pam.d/sshd").read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise LiveHold("PAM_ACCOUNT_HOOK_UNAVAILABLE") from exc
        effective = self._call("sshd", "-T", timeout=10)
        if not inspect_pam(contents, effective):
            raise LiveHold("F2_PAM_ACCOUNT_GATE_NOT_ATTESTED")

    async def assert_real_ingress(self, target):
        self._lease()
        await self.assert_target_peer(target)

    async def assert_no_ssh_sessions(self, username, uid):
        self._lease()
        self._owner(username, uid)
        service = "nvl-egress-dns-" + username + ".service"
        raw_pid = self._call(
            "systemctl", "show", service, "-p", "MainPID", "--value",
            timeout=8,
        ).strip()
        if not raw_pid.isascii() or not raw_pid.isdecimal() or int(raw_pid) < 2:
            raise LiveHold("PROTECTED_DOH_UNIT_NOT_RUNNING")
        self._call("systemctl", "is-active", "--quiet", service)
        snapshot = self._call("ps", "-eo", "pid=,uid=,comm=,args=", timeout=8)
        assert_idle_process_snapshot(snapshot, username, uid,
                                     allowed_dns_pid=int(raw_pid))

    async def freeze_uid(self, username, uid):
        self._lease()
        req = self._req(username, uid)
        await asyncio.to_thread(self.kernel.freeze, req)

    async def assert_uid_frozen(self, username, uid):
        self._lease()
        req = self._req(username, uid)
        await asyncio.to_thread(self.kernel.assert_frozen, req)

    @staticmethod
    def _dns_unit_path(username):
        return Path("/etc/systemd/system") / ("nvl-egress-dns-" + username + ".service")

    @staticmethod
    def _dns_unit_content(req, port):
        return render_dns_required_unit(req, port)

    def _check_current_dns_unit(self, req, port):
        path = self._dns_unit_path(req.username)
        _trusted_directory(path.parent)
        st = path.lstat()
        if (not path.is_file() or path.is_symlink() or st.st_uid != 0
                or st.st_mode & 0o022 or st.st_size > 8192):
            raise LiveHold("UNTRUSTED_EXISTING_DOH_UNIT")
        text = path.read_text(encoding="utf-8")
        expected = self._dns_unit_content(req, port)
        optional_install = "\n[Install]\nWantedBy=multi-user.target\n"
        if text not in (expected, expected + optional_install):
            raise LiveHold("DOH_SERVICE_NOT_OWNED_BY_MANIFEST")
        return path, text[len(expected):]

    async def repin_frozen_uid(self, username, uid, old_edge, new_edge):
        self._lease()
        if new_edge != self.spec.edge_public_ipv4 or new_edge == old_edge:
            raise LiveHold("TARGET_EDGE_UNTRUSTED")
        old = self._manifest(username, uid)
        if old.request.spec.edge_public_ipv4 != old_edge:
            raise LiveHold("STALE_SOURCE_MANIFEST")
        await self.assert_no_ssh_sessions(username, uid)
        await self.assert_uid_frozen(username, uid)

        old_req = old.request
        dns_unit, dns_suffix = self._check_current_dns_unit(
            old_req, old.dns_port
        )
        new_req = UIDPolicyRequest(self.spec, username, uid, old_req.priority)
        new_req.validate()
        newer = BootGuardManifest(new_req, old.mode, old.dns_port,
                                  ingress_return=True, shared_edge=True)
        new_data = (json.dumps({
            "mode": newer.mode, "username": username, "uid": uid,
            "priority": new_req.priority, "spec": asdict(self.spec),
            "dns_port": old.dns_port, "ingress_return": True, "shared_edge": True,
        }, sort_keys=True) + "\n").encode()
        # Verify ALL new roster manifests before touching kernel: no cross
        # Edge identity/UID/table collision, no deletion of other accounts.
        members = self._owner(username, uid)
        manifest_map = {
            name: (new_data if name == username else
                   _trusted_bytes(GUARD_DIR / (name + ".json"), 4096))
            for name in members
        }
        roster_data = render_roster(manifest_map).encode()
        # Keep UID REJECT from source through old selector deletion and new
        # selector arm. No shared Edge next hop is deleted on either side.
        self.kernel.freeze(old_req)
        if not uid_deny_present(self.run, uid):
            raise LiveHold("UID_DENY_MISSING_BEFORE_REPIN")
        self._call(
            "ip", "-4", "rule", "del", "priority", str(old_req.priority),
            "uidrange", old_req.uidrange,
            "lookup", str(old_req.spec.route_table),
        )
        self.guards.apply(newer)
        plan = build_policy_plan(new_req)
        for cmd in plan.attach:
            self._call(*cmd.argv)
        self.guards.verify(newer, require_frozen=True)
        self.kernel.assert_frozen(new_req)
        # PAM still denies FROZEN runtime during two-file replacement. A crash
        # between these writes results in hash mismatch=> DENY, not legacy.
        _atomic_root(GUARD_DIR / (username + ".json"), new_data)
        _atomic_root(ROSTER, roster_data)
        # DNS unit verifies route table and peer identity on every restart.
        # Updating manifest without updating this immutable ExecStart would
        # strand the user on its former Edge after systemd restart/reboot.
        new_unit = self._dns_unit_content(new_req, old.dns_port) + dns_suffix
        _atomic_root(dns_unit, new_unit.encode())
        self._call("systemctl", "daemon-reload", timeout=15)
        self._call(
            "systemctl", "restart",
            "nvl-egress-dns-" + username + ".service", timeout=25
        )
        self._call(
            "systemctl", "is-active", "--quiet",
            "nvl-egress-dns-" + username + ".service"
        )
        if checked_guard(load_roster()[username]).request.spec.edge_id != self.spec.edge_id:
            raise LiveHold("ROSTER_REPIN_NOT_VERIFIED")

    async def prove_uid_ipv4(self, username, uid, target_ip):
        self._lease()
        req = self._req(username, uid)
        if req.spec.edge_public_ipv4 != target_ip:
            raise LiveHold("UID_TARGET_NOT_PINNED")
        await self.assert_no_ssh_sessions(username, uid)
        await self.assert_uid_frozen(username, uid)
        # The UID OUTPUT deny blocks the curl probe. Temporarily release only
        # this UID in a time-bounded, idle-account window, then re-arm in a
        # FINALLY clause. F2 PAM remains FROZEN for the entire probe.
        try:
            release_uid_deny(self.run, uid)
            observed = await asyncio.to_thread(self.kernel.public_ipv4, req)
            await asyncio.to_thread(self.kernel.assert_dns_ipv6, req)
            if observed != target_ip:
                raise LiveHold("UID_EGRESS_PUBLIC_IP_MISMATCH")
        finally:
            arm_uid_deny(self.run, uid)
        await self.assert_uid_frozen(username, uid)
        self._proven[username] = self.clock()

    async def switch_dns_edge_to_edge(self, source, target):
        self._lease()
        # Adapter has already CAS-rebound every UID while keeping PAM FROZEN.
        if target != self.spec.edge_public_ipv4:
            raise LiveHold('DNS_TARGET_NOT_PINNED_EDGE')
        # Never rely on one pre-cutover 6G snapshot: the provider may make
        # several non-atomic updates. Recheck the shared lease before EACH.
        await asyncio.to_thread(
            self.cf.switch_edge_to_edge, source, target, guard=self._lease,
        )

    async def assert_dns_target(self, target):
        self._lease()
        if target != self.spec.edge_public_ipv4:
            raise LiveHold('DNS_TARGET_NOT_PINNED_EDGE')
        await asyncio.to_thread(self.cf.assert_target, target)

    async def assert_uid_target(self, username, uid, target_ip):
        self._lease()
        if (self._req(username, uid).spec.edge_public_ipv4 != target_ip
                or username not in self._proven
                or self.clock() - self._proven[username] > 45):
            raise LiveHold("UID_FRESH_EGRESS_PROOF_REQUIRED")
        await self.assert_uid_frozen(username, uid)

    async def release_uid(self, username, uid):
        self._lease()
        req = self._req(username, uid)
        if username not in self._proven or self.clock() - self._proven[username] > 45:
            raise LiveHold("UID_PROOF_EXPIRED")
        self.kernel.attach(req)


def make_live_adapter(*, config: LiveDriverConfig, db_conn, acquire_fn,
                      journal_fn, core_ip: str, cf_config_loader):
    """Construct one per-operation 6G adapter; no global live singleton."""
    from edge_egress_v1_handoff_adapter import Existing6GProtectedHandoffAdapter
    driver = ProtectedLiveHostActions(config, db_conn, cf_config_loader)
    adapter = Existing6GProtectedHandoffAdapter(
        db_conn=db_conn, acquire_fn=acquire_fn, journal_fn=journal_fn,
        core_ip=core_ip, host_actions=driver,
    )
    driver._adapter = adapter
    return adapter
