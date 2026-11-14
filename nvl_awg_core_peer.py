"""NVL-AWG-02: plan safe Core AWG peer additions (no live mutation).

Adding a new Edge MUST NOT restart awg0, wg0, SSH or the NVL bot.
The future commit worker must acquire the shared installer lease and only
apply a fresh, CAS-verified plan with awg set (never wg syncconf).
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import ipaddress
import fcntl
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time

from nvl_awg_new_edge import (
    AWGPlanHold, AWGCoreProfile, allocated_edge_ip, expected_peer_block,
    ipv4, public_key, port,
)
from nvl_awg_core_routes import (
    AWGRouteHold, ensure_core_route, remove_owned_core_route,
)


@dataclass(frozen=True)
class AWGCorePeerPlan:
    before_sha256: str
    after_conf: str = field(repr=False)  # contains Core secrets; never log
    edge_tunnel_ip: str
    edge_public_key: str
    edge_host: str
    edge_udp_port: int
    apply_argv: tuple[str, ...]
    registered_ips: tuple[str, ...]


def plan_core_peer(
    core_conf: str, live_allowed_ips: str, *,
    edge_host: str, edge_udp_port: int, edge_public_key: str,
    registered_ips: tuple[str, ...] = (),
) -> AWGCorePeerPlan:
    """Pure planning. Refuse overlapping peer identities, subnets and markers."""
    core = AWGCoreProfile.parse(core_conf)
    host = ipv4(edge_host, global_address=True)
    key = public_key(edge_public_key)
    port(edge_udp_port)
    raw = core_conf
    if raw.count("[Interface]") != 1:
        raise AWGPlanHold("CORE_AWG_CONFIG_INVALID")
    # Existing registered/public peer addresses and live kernel state are
    # both authoritative. A configured peer missing from the runtime is not
    # cause to reuse its address.
    lines = [line.strip() for line in raw.splitlines()]
    for line in lines:
        if line.startswith("PublicKey"):
            if line.split("=", 1)[-1].strip() == key:
                raise AWGPlanHold("EDGE_PEER_ALREADY_CONFIGURED")
    for row in live_allowed_ips.splitlines():
        fields = row.split()
        if len(fields) != 2:
            raise AWGPlanHold("CORE_LIVE_ALLOWED_IPS_UNVERIFIED")
        if fields[0] == key:
            raise AWGPlanHold("EDGE_PEER_ALREADY_LIVE")
    if "# edge-" + host.replace(".", "-") in lines:
        raise AWGPlanHold("EDGE_HOST_MARKER_EXISTS")
    address = allocated_edge_ip(
        raw, core_tunnel_ip=core.core_tunnel_ip,
        registered_ips=registered_ips, live_allowed_ips=live_allowed_ips,
    )
    updated = raw.rstrip("\n") + "\n" + expected_peer_block(
        host=host, peer_key=key, tunnel_ip=address,
        edge_port=edge_udp_port,
    )
    # Core must be able to contact the new Edge before it has learned endpoint.
    command = (
        "awg", "set", "awg0", "peer", key,
        "allowed-ips", address + "/32",
        "endpoint", host + ":" + str(edge_udp_port),
        "persistent-keepalive", "25",
    )
    return AWGCorePeerPlan(
        before_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        after_conf=updated, edge_tunnel_ip=address,
        edge_public_key=key, edge_host=host,
        edge_udp_port=edge_udp_port, apply_argv=command,
        registered_ips=registered_ips,
    )


def verify_core_peer_plan(plan: AWGCorePeerPlan, *,
                          current_conf: str,
                          current_live_allowed: str) -> None:
    """Recheck under a lock before any executor writes the root-owned Core config."""
    if hashlib.sha256(current_conf.encode()).hexdigest() != plan.before_sha256:
        raise AWGPlanHold("CORE_AWG_CONFIG_CHANGED")
    expected = plan_core_peer(
        current_conf, current_live_allowed,
        edge_host=plan.edge_host, edge_udp_port=plan.edge_udp_port,
        edge_public_key=plan.edge_public_key,
        registered_ips=plan.registered_ips,
    )
    if (expected.edge_tunnel_ip != plan.edge_tunnel_ip or
            expected.after_conf != plan.after_conf or
            expected.apply_argv != plan.apply_argv):
        raise AWGPlanHold("CORE_AWG_PEER_PLAN_CHANGED")


def _core_allowed_ip_output(runner, interface: str) -> str:
    res = runner(
        ["awg", "show", interface, "allowed-ips"],
        capture_output=True, text=True, timeout=10, check=True,
    )
    return res.stdout


def commit_core_peer(
    plan: AWGCorePeerPlan, *,
    config_path: str = "/etc/amnezia/amneziawg/awg0.conf",
    lock_path: str = "/run/lock/nvl-awg-core-peer.lock",
    runner=subprocess.run,
    root_check=os.geteuid,
) -> str:
    """Apply ONLY one new peer to existing awg0; no interface or bot restarts.

    Must be called after journaled manual install intent + pinned Edge staging.
    Crash mid-commit leaves a root-only backup and an INSTALL_HOLD needing review.
    """
    if root_check() != 0:
        raise AWGPlanHold("CORE_ROOT_REQUIRED")
    conf = Path(config_path)
    if conf.is_symlink() or not conf.is_file():
        raise AWGPlanHold("CORE_AWG_CONFIG_MISSING_OR_SYMLINK")
    mode = conf.stat()
    if not stat.S_ISREG(mode.st_mode) or mode.st_mode & 0o077:
        raise AWGPlanHold("CORE_AWG_CONFIG_NOT_PRIVATE")
    lock = Path(lock_path)
    lock.parent.mkdir(parents=True, exist_ok=True)
    fd_lock = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd_lock, fcntl.LOCK_EX)
        current = conf.read_text(encoding="utf-8")
        live = _core_allowed_ip_output(runner, "awg0")
        verify_core_peer_plan(
            plan, current_conf=current, current_live_allowed=live,
        )
        # Explicitly ensure the new peer key is not in the live interface.
        if any(row.split()[:1] == [plan.edge_public_key]
               for row in live.splitlines()):
            raise AWGPlanHold("EDGE_PEER_ALREADY_LIVE")

        # Keep the private AWG profile in its pre-existing 0600 Core dir.
        backup_fd, backup_name = tempfile.mkstemp(
            prefix=".awg0.pre-peer.", dir=str(conf.parent),
        )
        backup_path = Path(backup_name)
        try:
            with os.fdopen(backup_fd, "wb") as back:
                back.write(current.encode("utf-8"))
                back.flush()
                os.fsync(back.fileno())
            new_fd, new_name = tempfile.mkstemp(
                prefix=".awg0.new-peer.", dir=str(conf.parent),
            )
            next_path = Path(new_name)
            try:
                with os.fdopen(new_fd, "wb") as nxt:
                    nxt.write(plan.after_conf.encode("utf-8"))
                    nxt.flush()
                    os.fsync(nxt.fileno())
                # Persistent peer config is atomic. 'awg set' alone does
                # not add the Linux /32 return route needed for Core TCP.
                os.replace(next_path, conf)
                route_added = False
                try:
                    runner(list(plan.apply_argv), capture_output=True, text=True,
                           timeout=15, check=True)
                    observed = _core_allowed_ip_output(runner, "awg0")
                    # awg show <interface> allowed-ips emits a TAB between
                    # the peer key and its CIDR, not a literal space. Compare
                    # parsed fields and require exactly one exact /32 entry.
                    # The prior string comparison always rejected a healthy
                    # newly admitted peer, then rolled it back.
                    rows = [line.split() for line in observed.splitlines()]
                    target = [row for row in rows
                              if row and row[0] == plan.edge_public_key]
                    if target != [[plan.edge_public_key,
                                   plan.edge_tunnel_ip + "/32"]]:
                        raise AWGPlanHold("AWG_PEER_LIVE_POSTCHECK_FAILED")
                    route_added = ensure_core_route(
                        plan.edge_tunnel_ip,
                        AWGCoreProfile.parse(plan.after_conf).core_tunnel_ip,
                        runner=runner,
                    )
                except BaseException as exc:
                    core_ip = AWGCoreProfile.parse(plan.after_conf).core_tunnel_ip
                    if isinstance(exc, AWGRouteHold) and str(exc) == (
                            "AWG_CORE_ROUTE_ROLLBACK_UNCERTAIN"):
                        # Preserve config/peer if route rollback was ambiguous.
                        raise AWGPlanHold(
                            "AWG_CORE_ROUTE_ROLLBACK_UNCERTAIN") from None
                    if route_added:
                        try:
                            remove_owned_core_route(
                                plan.edge_tunnel_ip, core_ip, runner=runner)
                        except Exception:
                            raise AWGPlanHold(
                                "AWG_CORE_ROUTE_ROLLBACK_UNCERTAIN") from None
                    # This peer was absent before the operation.
                    try:
                        runner(
                            ["awg", "set", "awg0", "peer",
                             plan.edge_public_key, "remove"],
                            capture_output=True, text=True, timeout=15,
                            check=True,
                        )
                    except Exception as rollback:
                        raise AWGPlanHold(
                            "AWG_PEER_ROLLBACK_UNCERTAIN_MANUAL_HOLD"
                        ) from rollback
                    os.replace(backup_path, conf)
                    code = (str(exc) if isinstance(exc, AWGRouteHold)
                            else "AWG_PEER_LIVE_POSTCHECK_FAILED"
                            if isinstance(exc, AWGPlanHold) and str(exc) ==
                            "AWG_PEER_LIVE_POSTCHECK_FAILED"
                            else "AWG_PEER_LIVE_INSTALL_FAILED")
                    raise AWGPlanHold(code) from None
            finally:
                if next_path.exists():
                    next_path.unlink()
        except BaseException:
            raise
        return str(backup_path)
    finally:
        fcntl.flock(fd_lock, fcntl.LOCK_UN)
        os.close(fd_lock)
