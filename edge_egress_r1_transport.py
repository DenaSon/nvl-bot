"""R1: read-only transport ownership audit and opt-in guarded F2 shadow port.

This is NOT a unit installer, boot activator, PAM hook or production cutover.
It may be injected into the EXISTING F2/6G runtime bridge only after the
independent lease, UID boot guard and PAM/session gate are attested.

Most importantly, live stg1 resources from the 2026-10-11 pilot are NOT
implicitly adopted, stopped, restarted, or cleaned up.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Awaitable, Callable

from edge_egress_uid_policy import UIDPolicyRequest
from ops.edge_egress_provision import EgressSpec


class R1Unsafe(ValueError):
    pass


STAGE_ROOT = Path("/root/nvl-egress-staging")
UNIT_ROOT = Path("/etc/systemd/system")
_TOKEN = re.compile(r"^[a-f0-9]{32,64}$")


def _run(*argv: str):
    # Read-only commands ONLY. Never use shell=True or print wg secrets.
    return subprocess.run(list(argv), capture_output=True, text=True,
                          timeout=8, check=False)


def _root_owned(path: Path, *, directory: bool = False) -> bool:
    """Reject symlinks, non-root ownership and group/other-accessible assets."""
    try:
        if path.is_symlink():
            return False
        s = path.stat()
        return (s.st_uid == 0 and not s.st_mode & 0o077
                and (stat.S_ISDIR(s.st_mode) if directory
                     else stat.S_ISREG(s.st_mode)))
    except OSError:
        return False


def _stage_owned(spec: EgressSpec, role: str, root: Path,
                 reviewed_stage_sha256: dict[str, str] | None = None) -> bool:
    """Offline provenance check; does not grant ownership of live interfaces."""
    stage = root / (spec.edge_id + "-" + role)
    if not (_root_owned(root, directory=True)
            and _root_owned(stage, directory=True)):
        return False
    files = ("manifest.json", "wg.conf", "up.sh", "down.sh")
    if not isinstance(reviewed_stage_sha256, dict) or set(reviewed_stage_sha256) != set(files):
        return False
    for filename in files:
        f = stage / filename
        digest = reviewed_stage_sha256[filename]
        if (not _root_owned(f) or
                not isinstance(digest, str) or
                re.fullmatch(r"[a-f0-9]{64}", digest) is None):
            return False
        try:
            if f.stat().st_size > 65536 or hashlib.sha256(f.read_bytes()).hexdigest() != digest:
                return False
        except OSError:
            return False
    try:
        manifest = stage / "manifest.json"
        if manifest.stat().st_size > 8192:
            return False
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return False
    return (data.get("config") == asdict(spec)
            and data.get("role") == role
            and data.get("stage_only") is True
            and data.get("user_routes_installed") is False
            and isinstance(data.get("owner_token"), str)
            and bool(_TOKEN.fullmatch(data["owner_token"])))


@dataclass(frozen=True)
class R1Observation:
    role: str
    interface_present: bool
    namespace_present: bool
    veth_present: bool
    stage_owned: bool
    unit_owned: bool
    unit_active: bool
    nat_tagged: bool
    nat_shadowed: bool
    probe_errors: tuple[str, ...] = ()
    identity_proven: bool = False


@dataclass(frozen=True)
class R1Decision:
    state: str
    reason: str
    customer_ready: bool = False
    activation_authorized: bool = False


def decide(observation: R1Observation) -> R1Decision:
    """Default-deny. 'MANAGED_RUNNING' means *transport only*, never READY."""
    o = observation
    if o.role not in ("core", "edge"):
        return R1Decision("HOLD", "INVALID_ROLE")
    if o.probe_errors:
        return R1Decision("HOLD", "INCOMPLETE_READ_ONLY_EVIDENCE")
    occupied = o.interface_present or o.namespace_present or o.veth_present
    if occupied and (not o.stage_owned or not o.unit_owned or not o.unit_active):
        return R1Decision("HOLD", "UNMANAGED_EXISTING_SHADOW")
    if o.role == "edge" and o.nat_shadowed:
        return R1Decision("HOLD", "LEGACY_NAT_PRECEDENCE_UNREVIEWED")
    if occupied:
        if not o.identity_proven:
            return R1Decision("HOLD", "WIREGUARD_OR_ROUTE_IDENTITY_UNVERIFIED")
        complete = (o.interface_present and
                    (o.namespace_present and o.veth_present if o.role == "core"
                     else o.nat_tagged))
        if not complete:
            return R1Decision("HOLD", "PARTIAL_TRANSPORT_RESOURCES")
        return R1Decision("MANAGED_RUNNING", "TRANSPORT_ONLY_NOT_UID_PROOF")
    if o.unit_active:
        return R1Decision("HOLD", "ACTIVE_UNIT_WITHOUT_TRANSPORT")
    if not (o.stage_owned and o.unit_owned):
        return R1Decision("HOLD", "ROOT_OWNED_STAGE_AND_UNIT_REQUIRED")
    if o.role == "edge" and o.nat_tagged:
        return R1Decision("HOLD", "STRAY_TAGGED_NAT_WITHOUT_INTERFACE")
    return R1Decision("STAGED_OFFLINE", "REQUIRES_6G_AND_GUARD_GATE")


def inspect_linux(spec: EgressSpec, role: str, *, run=_run,
                  stage_root: Path = STAGE_ROOT,
                  unit_root: Path = UNIT_ROOT,
                  reviewed_stage_sha256: dict[str, str] | None = None,
                  reviewed_unit_sha256: str | None = None) -> R1Observation:
    """Observe only the selected role's dedicated resources, without mutation.

    The public Core root namespace deliberately does not carry wg-nvl-stg1;
    its interface lives inside nvl-egress-stg1. Error output is never returned.
    """
    spec.validate()
    if role not in ("core", "edge"):
        raise R1Unsafe("INVALID_ROLE")
    errors = []

    def check(label: str, *args: str) -> bool:
        try:
            p = run(*args)
            if not isinstance(p.returncode, int):
                raise ValueError("BAD_RESULT")
            return p.returncode == 0
        except (OSError, ValueError, subprocess.TimeoutExpired):
            errors.append(label)
            return False

    def output(label: str, *args: str) -> str:
        try:
            p = run(*args)
            if p.returncode != 0:
                errors.append(label)
                return ""
            return p.stdout
        except (OSError, ValueError, subprocess.TimeoutExpired):
            errors.append(label)
            return ""

    ns = False
    veth = False
    if role == "core":
        lines = output("NETNS_INVENTORY_FAILED", "ip", "netns", "list")
        ns = spec.namespace in {s.split()[0] for s in lines.splitlines()
                                if s.strip()}
        iface = ns and check("NETNS_INTERFACE_PROBE_FAILED", "ip", "netns",
                             "exec", spec.namespace, "ip", "link", "show",
                             "dev", spec.iface)
        veth = check("VETH_PROBE_FAILED", "ip", "link", "show",
                     "dev", spec.veth_root)
    else:
        iface = check("EDGE_INTERFACE_PROBE_FAILED", "ip", "link", "show",
                      "dev", spec.iface)

    # Existing interfaces yield a nonzero 'ip link show' only when absent.
    # Treat absent link as a normal observation, not a command failure.
    unit = unit_root / ("nvl-egress-" + spec.edge_id + "-transport.service")
    try:
        us = unit_root.stat()
        trusted_unit_root = (not unit_root.is_symlink() and
                             stat.S_ISDIR(us.st_mode) and us.st_uid == 0 and
                             not us.st_mode & 0o022)
    except OSError:
        trusted_unit_root = False
    unit_owned = False
    if (_root_owned(unit) and trusted_unit_root and
            isinstance(reviewed_unit_sha256, str) and
            re.fullmatch(r"[a-f0-9]{64}", reviewed_unit_sha256)):
        try:
            unit_owned = (unit.stat().st_size <= 16384 and
                          hashlib.sha256(unit.read_bytes()).hexdigest()
                          == reviewed_unit_sha256)
        except OSError:
            pass
    active = False
    if unit_owned:
        state = output("SYSTEMD_STATE_UNKNOWN", "systemctl", "show",
                       unit.name, "-p", "ActiveState",
                       "-p", "FragmentPath", "--no-pager")
        active = ("ActiveState=active" in state.splitlines() and
                  ("FragmentPath=" + str(unit)) in state.splitlines())

    tagged = False
    shadowed = False
    forward_ok = False
    if role == "edge":
        nat = output("NAT_INVENTORY_FAILED", "iptables", "-t", "nat",
                     "-S", "POSTROUTING")
        prior_broad = False
        for line in nat.splitlines():
            if not line.startswith("-A POSTROUTING "):
                continue
            if (re.search(r"\s-j MASQUERADE\s*$", line)
                    and "-s " not in line and "-o " not in line):
                prior_broad = True
            if (f"--comment nvl-egress-{spec.edge_id}" in line
                    and f"-s {spec.core_tunnel_ip}/32" in line
                    and f"-o {spec.edge_uplink}" in line
                    and re.search(r"\s-j MASQUERADE\s*$", line)):
                tagged = True
                shadowed = prior_broad
        forward = output("FORWARD_INVENTORY_FAILED", "iptables", "-S", "FORWARD")
        forward_ok = (f'-i {spec.iface} -o {spec.edge_uplink}' in forward
                      and f'-s {spec.core_tunnel_ip}/32' in forward
                      and f'--comment nvl-egress-{spec.edge_id}' in forward)
        forwarding = output("FORWARD_SYSCTL_FAILED", "sysctl", "-n",
                            "net.ipv4.ip_forward")
        forward_ok = forward_ok and forwarding.strip() == "1"

    stage_owned = _stage_owned(spec, role, stage_root,
                               reviewed_stage_sha256)
    identity = False
    if iface and stage_owned:
        # Compare only PUBLIC peer identity from the root-only staged config.
        # Never return/read out its private key or include command output.
        stage = stage_root / (spec.edge_id + "-" + role)
        try:
            wg_text = (stage / "wg.conf").read_text(encoding="utf-8")
            peer_keys = re.findall(r"(?m)^PublicKey\\s*=\\s*(\\S+)\\s*$", wg_text)
        except (OSError, UnicodeError):
            peer_keys = []
        if len(peer_keys) == 1:
            prefix = ("ip", "netns", "exec", spec.namespace) if role == "core" else ()
            peers = output("WG_PEER_INVENTORY_FAILED", *prefix,
                           "wg", "show", spec.iface, "peers")
            identity = peers.split() == peer_keys
            allowed = output("WG_ALLOWED_IPS_FAILED", *prefix,
                             "wg", "show", spec.iface, "allowed-ips")
            expected = "0.0.0.0/0" if role == "core" else spec.core_tunnel_ip + "/32"
            identity = identity and (len(allowed.splitlines()) == 1 and
                                      allowed.split()[-1:] == [expected])
            if role == "core":
                default = output("CORE_NS_DEFAULT_FAILED", "ip", "netns",
                                 "exec", spec.namespace, "ip", "-4",
                                 "route", "show", "default")
                identity = identity and (len(default.splitlines()) == 1 and
                                          f"dev {spec.iface}" in default)
            else:
                port = output("WG_LISTEN_PORT_FAILED", "wg", "show",
                              spec.iface, "listen-port")
                identity = identity and port.strip() == str(spec.edge_listen_port)
                identity = identity and forward_ok and tagged
    return R1Observation(role, bool(iface), ns, veth,
                         stage_owned, unit_owned, active, tagged, shadowed,
                         tuple(errors), identity)


@dataclass
class GuardedR1ShadowPort:
    """Opt-in RuntimeShadowPort for the existing F2 6G bridge.

    The caller supplies the SAME 6G lease verification, independent UID guard
    attestation and a reviewed host launcher. No default start/SSH transport.
    Partial failure is HOLD: never auto-stop someone else's shadow resources.
    """
    spec: EgressSpec
    observe: Callable[[], R1Observation]
    lease_check: Callable[[UIDPolicyRequest], bool]
    guard_check: Callable[[UIDPolicyRequest], bool]
    start_edge: Callable[[UIDPolicyRequest], Awaitable[None]]
    start_core: Callable[[UIDPolicyRequest], Awaitable[None]]
    explicitly_enabled: bool = False
    disposable_vps: bool = False

    async def start(self, request: UIDPolicyRequest) -> None:
        request.validate()
        if request.spec != self.spec:
            raise R1Unsafe("SPEC_IDENTITY_CHANGED")
        if not (self.explicitly_enabled and self.disposable_vps):
            raise R1Unsafe("R1_TRANSPORT_ACTIVATION_DISABLED")
        if not self.lease_check(request):
            raise R1Unsafe("SAME_SHARED_6G_LEASE_REQUIRED")
        if not self.guard_check(request):
            raise R1Unsafe("UID_FAIL_CLOSED_GUARD_NOT_ATTESTED")
        before = decide(self.observe())
        if before.state == "MANAGED_RUNNING":
            return
        if before.state != "STAGED_OFFLINE":
            raise R1Unsafe("EXISTING_TRANSPORT_NOT_OWNED:" + before.reason)
        try:
            await self.start_edge(request)
            if not self.lease_check(request) or not self.guard_check(request):
                raise R1Unsafe("LEASE_OR_GUARD_LOST_DURING_EDGE_START")
            await self.start_core(request)
            if not self.lease_check(request) or not self.guard_check(request):
                raise R1Unsafe("LEASE_OR_GUARD_LOST_DURING_CORE_START")
            if decide(self.observe()).state != "MANAGED_RUNNING":
                raise R1Unsafe("POST_START_OWNER_PROOF_MISSING")
        except Exception as exc:
            # F2 coordinator handles 6G HOLD and per-UID freeze. Never
            # auto-delete live interfaces or release the shared 6G lease.
            raise R1Unsafe("R1_TRANSPORT_START_UNCERTAIN_HOLD") from exc
