"""F4 read-only UID/Edge kernel consistency audit.

Requires an operator-supplied ROOT-OWNED F1 manifest. No rules, routes, DNS,
WireGuard, ssh.service, SQLite or customer mappings are changed. Passing means
*local consistency only*, never actual public Edge IP or no packet leaks.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
from typing import Callable

from edge_egress_uid_boot import (
    BootGuardApplier, BootGuardError, BootGuardManifest,
    read_root_only_manifest,
)
from edge_egress_uid_route_state import inspect_owned_routes, ProtectedRouteError


@dataclass(frozen=True)
class F4KernelAudit:
    locally_consistent: bool
    code: str
    issues: tuple[str, ...]
    customer_ready: bool = False


def inspect_uid_kernel(manifest: BootGuardManifest, *,
                       expected_state: str,
                       guard_factory: Callable = BootGuardApplier,
                       run: Callable = subprocess.run) -> F4KernelAudit:
    """Use existing F1 exact policy verifier, then independent route/service facts."""
    if expected_state not in ("PROTECTED", "FROZEN", "HOLD"):
        return F4KernelAudit(False, "STATE_NOT_ATTESTABLE", ("INVALID_STATE",))
    if manifest.mode != "PROTECTED_BOOT_GUARD" or manifest.dns_port is None:
        return F4KernelAudit(False, "INVALID_MANIFEST", ("DNS_GUARD_REQUIRED",))
    req=manifest.request
    try:
        req.validate()
        guard_factory().verify(manifest)
    except (BootGuardError, ValueError, OSError):
        return F4KernelAudit(False,"UID_BOOT_GUARD_UNVERIFIED",
                             ("BOOT_GUARD_OR_DNS_IPV6_RULE_MISSING",))
    try:
        routes=run(
            ["ip","-4","route","show","table",str(req.spec.route_table)],
            capture_output=True,text=True,timeout=8,check=False,
        )
        if routes.returncode:
            raise OSError()
        state=inspect_owned_routes(
            routes.stdout,next_hop=req.spec.ns_veth_ip,
            device=req.spec.veth_root,source=req.spec.root_veth_ip,
        )
        if not state.terminal_blackhole:
            raise ProtectedRouteError("MISSING_BLACKHOLE")
    except (OSError,ValueError,subprocess.TimeoutExpired):
        return F4KernelAudit(False,"OWNED_ROUTING_UNVERIFIED",
                             ("ROUTE_TABLE_AMBIGUOUS",))
    if expected_state in ("FROZEN","HOLD"):
        if state.edge_attached:
            return F4KernelAudit(False,"DENY_ONLY_NOT_ENFORCED",
                                 ("EDGE_ATTACHED_WHILE_FROZEN",))
        return F4KernelAudit(True,"LOCAL_DENY_ONLY_CONSISTENT",())
    if not state.edge_attached:
        return F4KernelAudit(False,"EXPECTED_EDGE_NOT_ATTACHED",
                             ("EDGE_DEFAULT_MISSING",))
    try:
        link=run(
            ["ip","link","show","dev",req.spec.veth_root],
            capture_output=True,text=True,timeout=8,check=False,
        )
        dns=run(
            ["systemctl","is-active","--quiet",
             "nvl-egress-dns-"+req.username+".service"],
            capture_output=True,text=True,timeout=8,check=False,
        )
        if link.returncode or dns.returncode:
            return F4KernelAudit(False,"EDGE_OR_DNS_UNIT_UNAVAILABLE",
                                 ("VETH_OR_UID_DNS_SERVICE_INACTIVE",))
    except (OSError,subprocess.TimeoutExpired):
        return F4KernelAudit(False,"HOST_OBSERVATION_FAILED",
                             ("HOST_COMMAND_UNAVAILABLE",))
    return F4KernelAudit(True,"LOCAL_EDGE_ROUTE_CONSISTENT",())


def main(argv=None) -> int:
    cli=argparse.ArgumentParser(
        description="F4 UID routing audit (READ ONLY, never customer ready)"
    )
    cli.add_argument("--manifest",type=Path,required=True)
    cli.add_argument("--expected-state",
                     choices=("PROTECTED","FROZEN","HOLD"),required=True)
    args=cli.parse_args(argv)
    try:
        manifest=read_root_only_manifest(args.manifest)
        result=inspect_uid_kernel(manifest,expected_state=args.expected_state)
    except (BootGuardError,OSError,ValueError):
        result=F4KernelAudit(False,"ROOT_MANIFEST_INVALID",
                             ("ROOT_MANIFEST_NOT_VERIFIED",))
    print(json.dumps({
        "locally_consistent":result.locally_consistent,
        "customer_ready":False,
        "code":result.code,"issues":list(result.issues),
        "host_mutations":0,
    },sort_keys=True))
    return 0 if result.locally_consistent else 2


if __name__=="__main__":
    raise SystemExit(main())
