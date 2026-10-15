"""Explicit Root-only initial K2 Single Cross-Edge UID plan staging.

This does NOT create, change, or migrate a Linux user, socket, WG peer,
iptables rule or global setting. The plan is inert until the independent
Root-only A3/M2/P3/6G release. Never called from Telegram automatically.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable

from edge_egress_k2_a3_host_plans import ROOT_PLAN_DIR, MAX_MANIFEST
from edge_egress_k2_m3_waves import build_wave_plan, m4_cross_edge_single_reviewed
from edge_egress_k2_migration_inventory import MigrationInventory
from edge_egress_uid_boot import BootGuardManifest
from edge_egress_k2_m4_root_worker import _read_checked, _verify_root_directory

K2_INITIAL_UID_PLAN_STAGE_ENABLED = False
_USERNAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")


class UIDPlanStageHold(ValueError):
    pass


def stage_single_uid_plan(
    *, inventory: MigrationInventory, manifest: BootGuardManifest,
    root_dir: Path = ROOT_PLAN_DIR, geteuid: Callable[[], int] = os.geteuid,
    release_enabled: bool = False,
) -> str:
    """Single O_EXCL owner-only write after fresh M1 & typed manifest review.

    Insecure/stale evidence, no-root, global mode, existing plan, symlink,
    or incorrect UID/target is HOLD with no deletion or file replacement.
    This file does NOT authorize an operation: original M2 replans and P3
    rechecks under the original 6G ticket at execution time.
    """
    if (not K2_INITIAL_UID_PLAN_STAGE_ENABLED or release_enabled is not True
        or not callable(geteuid) or geteuid() != 0
        or not isinstance(root_dir, Path)
        or not root_dir.is_absolute() or root_dir != ROOT_PLAN_DIR
        or type(inventory) is not MigrationInventory
        or type(manifest) is not BootGuardManifest):
        raise UIDPlanStageHold("K2_UID_PLAN_STAGING_NOT_RELEASED")
    wave = build_wave_plan(inventory,wave_size=1)
    if not m4_cross_edge_single_reviewed(wave):
        raise UIDPlanStageHold("K2_UID_PLAN_SOURCE_TARGET_NOT_ATTESTED")
    member = wave.members[0]
    req=manifest.request
    if (not _USERNAME.fullmatch(member.username)
        or manifest.mode != "PROTECTED_BOOT_GUARD"
        or manifest.ingress_return is not True
        or manifest.shared_edge is not True
        or type(manifest.dns_port) is not int
        or not 1024 <= manifest.dns_port <= 65535
        or req.username != member.username
        or req.uid != member.uid
        or req.spec.edge_id != member.target_edge_id
        or req.spec.edge_public_ipv4 != member.target_ipv4):
        raise UIDPlanStageHold("K2_UID_PLAN_MANIFEST_SCOPE_CHANGED")
    try:
        req.validate()
        body={
            "mode":manifest.mode, "username":req.username,
            "uid":req.uid, "priority":req.priority,
            "spec":dict(vars(req.spec)),
            "dns_port":manifest.dns_port, "ingress_return":True,
            "shared_edge":True,
        }
        data=(json.dumps(body,sort_keys=True,
                         separators=(",",":"),ensure_ascii=True)+"\n").encode()
        checked=BootGuardManifest.parse(json.loads(data))
        if checked != manifest or not 0 < len(data) <= MAX_MANIFEST:
            raise UIDPlanStageHold("K2_UID_PLAN_NOT_CANONICAL")
        _verify_root_directory(root_dir,group=None,private=True)
        target = root_dir/(member.username+".json")
        # O_EXCL is the only allowed create path. No replacement, rename or
        # unlink even on a failed post-write verification: manual recovery.
        if target.is_symlink() or target.exists():
            raise UIDPlanStageHold("K2_UID_PLAN_ALREADY_EXISTS")
        flags=(os.O_WRONLY|os.O_CREAT|os.O_EXCL
               |getattr(os,"O_NOFOLLOW",0)
               |getattr(os,"O_CLOEXEC",0))
        fd=os.open(target,flags,0o600)
        with os.fdopen(fd,"wb") as out:
            os.fchmod(out.fileno(),0o600)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        dir_fd=os.open(root_dir,os.O_RDONLY|os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        if _read_checked(target,maximum=MAX_MANIFEST,strict=True) != data:
            raise UIDPlanStageHold("K2_UID_PLAN_STAGED_BYTES_CHANGED")
        return sha256(data).hexdigest()
    except UIDPlanStageHold:
        raise
    except (OSError,ValueError,TypeError,KeyError) as exc:
        raise UIDPlanStageHold("K2_UID_PLAN_STAGE_IO_OR_SCOPE_HOLD") from exc
