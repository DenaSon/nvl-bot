"""Prepare one UID using the original M2 installer, only inside original 6G.

Plans are built in memory from pinned Stage/OS/DB/root artifacts. There is no
per-user CLI or pre-created uid-plans file. The deferred bootstrap installs
the reviewed import closure and fixed directories before invoking M2.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Callable

from edge_egress_k2_a3_host_plans import RootHostSafetyGates
from edge_egress_k2_a_host_factory import ReviewedUIDHostSnapshot
from edge_egress_k2_m3_waves import build_wave_plan
from edge_egress_k2_m4_bootstrap import GuardBootstrap
from edge_egress_k2_migration_inventory import select_migration
from edge_egress_k2_m4_root_worker import _read_checked, _verify_root_directory
from edge_egress_k2_p1_worker import load_stage_pin, _check_stage
from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, _scope_digest, assert_guarded_6g_intent,
)
from edge_egress_uid_boot import BootGuardManifest
from edge_egress_uid_policy import UIDPolicyRequest
from edge_egress_v1_admission import GUARD_DIR, ROSTER, render_roster
from ops.k2_m2_guard_append import plan_next_uid, CASRootRosterPort
from ops.k2_p3_guard_installer import (
    PAM, RootFilePort, plan_guard_install,
)
from ops.k2_p3_module_stage import (
    TARGET, NAME, REQUIRED, _deps, validate_module_bundle,
    inspect_installed_module_bundle, stage_module_bundle,
    create_public_root_module,
)


class CorePrerequisiteHold(ValueError):
    pass


def read_reviewed_module_bundle(source_root: Path, pins: dict[str, str]
                                ) -> dict[str, bytes]:
    """Follow the complete local import graph, including ops.k2 modules."""
    import ast
    pending = list(REQUIRED) + ["ops/__init__.py"]
    blobs: dict[str, bytes] = {}
    while pending:
        name = pending.pop()
        if name in blobs:
            continue
        if not NAME.fullmatch(name) or name not in pins or len(blobs) >= 180:
            raise CorePrerequisiteHold("CORE_UNPINNED_MODULE_DEPENDENCY")
        path = source_root / name
        _verify_root_directory(path.parent, group=None)
        # ops/__init__.py is allowed to be empty; the checked reader rejects
        # empty security manifests, so handle this one inert file explicitly.
        if name == "ops/__init__.py":
            raw = _read_checked(path, maximum=1, allow_empty=True)
            if raw != b"":
                raise CorePrerequisiteHold("CORE_OPS_PACKAGE_NOT_EMPTY")
        else:
            raw = _read_checked(path, maximum=600000)
        if sha256(raw).hexdigest() != pins[name]:
            raise CorePrerequisiteHold("CORE_MODULE_SOURCE_DRIFT")
        blobs[name] = raw
        pending.extend(_deps(ast.parse(raw.decode("utf-8"), filename=name)))
    validate_module_bundle(blobs, {n: pins[n] for n in blobs})
    return blobs


def _private_directory(path: Path) -> None:
    """Only callers holding original 6G may create these fixed directories."""
    if path not in (ROSTER.parent, GUARD_DIR):
        raise CorePrerequisiteHold("CORE_UNREVIEWED_DIRECTORY")
    _verify_root_directory(path.parent, group=None)
    if not path.exists() and not path.is_symlink():
        path.mkdir(mode=0o700)
    _verify_root_directory(path, group=None, private=True)


@dataclass(frozen=True)
class CoreGuardBootstrap(GuardBootstrap):
    module_blobs: dict[str, bytes]
    module_pins: dict[str, str]
    bundle_digest: str

    def run(self, scope: ExecutionScope, ticket: ExecutionTicket) -> None:
        if self.scope != scope or self.ticket != ticket:
            raise CorePrerequisiteHold("CORE_BOOTSTRAP_SCOPE_CHANGED")
        db_conn = self.kwargs["db_conn"]

        def locked():
            return assert_guarded_6g_intent(db_conn, scope, ticket)

        locked()
        if validate_module_bundle(self.module_blobs, self.module_pins) != self.bundle_digest:
            raise CorePrerequisiteHold("CORE_BOOTSTRAP_BUNDLE_CHANGED")
        if TARGET.exists() or TARGET.is_symlink():
            # Existing bytes must be exactly this release. Never overwrite
            # live PAM/DoH code or silently adopt a partially staged bundle.
            inspect_installed_module_bundle(self.module_pins)
        else:
            def create(path, raw):
                locked()
                create_public_root_module(path, raw)
                locked()
            stage_module_bundle(
                blobs=self.module_blobs, reviewed_sha256=self.module_pins,
                approved_bundle_digest=self.bundle_digest,
                port=create, release_enabled=True,
            )
        for folder in (ROSTER.parent, GUARD_DIR):
            locked()
            _private_directory(folder)
        locked()
        # The policy file may be absent for the first UID. Its initializer
        # refuses existing malformed bytes and never replaces a policy.
        from edge_egress_k2_uid_ingress_egress import (
            ROOT_BINDINGS, initialize_empty_root_policy,
            load_root_uid_ingress_egress_bindings,
        )
        if ROOT_BINDINGS.exists() or ROOT_BINDINGS.is_symlink():
            load_root_uid_ingress_egress_bindings()
        else:
            initialize_empty_root_policy(release_enabled=True)
        locked()
        super().run(scope, ticket)


def _installed_guards() -> tuple[bytes | None, dict[str, bytes]]:
    if not ROSTER.exists() and not ROSTER.is_symlink():
        if GUARD_DIR.exists() or GUARD_DIR.is_symlink():
            _verify_root_directory(GUARD_DIR, group=None, private=True)
            if any(GUARD_DIR.iterdir()):
                raise CorePrerequisiteHold("CORE_ORPHANED_GUARD")
        return None, {}
    roster = _read_checked(ROSTER, maximum=262144, strict=True)
    _verify_root_directory(GUARD_DIR, group=None, private=True)
    guards = {}
    for path in GUARD_DIR.iterdir():
        if not path.name.endswith(".json"):
            raise CorePrerequisiteHold("CORE_FOREIGN_GUARD_ARTIFACT")
        raw = _read_checked(path, maximum=4096, strict=True)
        man = BootGuardManifest.parse(json.loads(raw))
        if path.name != man.request.username + ".json":
            raise CorePrerequisiteHold("CORE_GUARD_FILENAME_DRIFT")
        guards[man.request.username] = raw
    if not guards or roster != render_roster(guards).encode():
        raise CorePrerequisiteHold("CORE_ROSTER_GUARD_DRIFT")
    return roster, guards


def build_single_manifest(scope: ExecutionScope, *, spec, guards: dict[str, bytes],
                          rule_priorities: set[int], listening_ports: set[int]
                          ) -> BootGuardManifest:
    if (spec.edge_id != scope.edge_id
        or spec.edge_public_ipv4 != scope.target_host):
        raise CorePrerequisiteHold("CORE_STAGE_TARGET_DRIFT")
    existing = [BootGuardManifest.parse(json.loads(raw)) for raw in guards.values()]
    priorities = rule_priorities | {m.request.priority for m in existing}
    ports = listening_ports | {m.dns_port for m in existing}
    priority = next((p for p in range(10000, 32000) if p not in priorities), None)
    dns_port = next((p for p in range(40000, 60000) if p not in ports), None)
    if priority is None or dns_port is None:
        raise CorePrerequisiteHold("CORE_UID_RESOURCES_EXHAUSTED")
    req = UIDPolicyRequest(spec, scope.username, scope.uid, priority)
    req.validate()
    return BootGuardManifest(req, "PROTECTED_BOOT_GUARD", dns_port,
                             ingress_return=True, shared_edge=True)


class CoreUIDSnapshotSource:
    """Concrete first/Nth UID plans, automatically constructed in memory.

    The gates provider reads the independently signed pre/post observations
    and actual local kernel/PAM state; it is fixed by Core startup, never
    supplied in Telegram data. No host writes occur while constructing plans.
    """

    def __init__(self, *, db_conn: Callable, os_uid: Callable,
                 inventory_provider: Callable, gates_provider: Callable,
                 module_blobs: dict[str, bytes], run: Callable = subprocess.run,
                 geteuid: Callable = os.geteuid):
        self.db_conn, self.os_uid = db_conn, os_uid
        self.inventory_provider, self.gates_provider = inventory_provider, gates_provider
        self.blobs, self.run, self.geteuid = module_blobs, run, geteuid
        self.pins = {n: sha256(raw).hexdigest() for n, raw in module_blobs.items()}
        self.bundle_digest = validate_module_bundle(module_blobs, self.pins)

    def _resources(self, uid: int | None = None):
        rules = self.run(["ip", "-j", "-4", "rule", "show"],
                         capture_output=True, text=True, timeout=5, check=False)
        sockets = self.run(["ss", "-H", "-lntu"],
                           capture_output=True, text=True, timeout=5, check=False)
        if rules.returncode != 0 or sockets.returncode != 0:
            raise CorePrerequisiteHold("CORE_RESOURCE_INVENTORY_UNAVAILABLE")
        rows = json.loads(rules.stdout)
        if not isinstance(rows, list) or any(
            not isinstance(r, dict) or type(r.get("priority")) is not int for r in rows
        ):
            raise CorePrerequisiteHold("CORE_RULE_INVENTORY_INVALID")
        for row in rows:
            if "uidrange" not in row:
                continue
            value = row["uidrange"]
            if isinstance(value, str) and re.fullmatch(r"[0-9]+-[0-9]+", value):
                first, last = map(int, value.split("-"))
            elif (type(value) is dict and set(value) == {"start", "end"}
                  and type(value["start"]) is int and type(value["end"]) is int):
                first, last = value["start"], value["end"]
            else:
                raise CorePrerequisiteHold("CORE_UID_RULE_INVENTORY_INVALID")
            if first < 0 or last < first or uid is not None and first <= uid <= last:
                raise CorePrerequisiteHold("CORE_UID_ALREADY_HAS_KERNEL_POLICY")
        ports = set()
        for line in sockets.stdout.splitlines():
            fields = line.split()
            if len(fields) < 5:
                raise CorePrerequisiteHold("CORE_SOCKET_INVENTORY_INVALID")
            tail = fields[4].rsplit(":", 1)[-1]
            if not tail.isdecimal():
                raise CorePrerequisiteHold("CORE_SOCKET_PORT_INVALID")
            ports.add(int(tail))
        return {r["priority"] for r in rows}, ports

    def __call__(self, scope: ExecutionScope, ticket: ExecutionTicket):
        if (self.geteuid() != 0 or type(scope) is not ExecutionScope
            or type(ticket) is not ExecutionTicket
            or ticket.scope_digest != _scope_digest(scope)
            or scope.action not in ("UID_ATTACH", "UID_ENROLL_SOURCE")
            or self.os_uid(scope.username) != scope.uid):
            raise CorePrerequisiteHold("CORE_EXACT_UID_SCOPE_REQUIRED")
        selected = select_migration("SINGLE", (scope.username,), scope.edge_id)
        wave = build_wave_plan(self.inventory_provider(selected), wave_size=1)
        if wave.global_blockers or len(wave.members) != 1 or not wave.members[0].selectable:
            raise CorePrerequisiteHold("CORE_FRESH_UID_INVENTORY_HOLD")
        member = wave.members[0]
        if (member.uid != scope.uid or member.source_ipv4 != scope.source_host
            or member.target_ipv4 != scope.target_host):
            raise CorePrerequisiteHold("CORE_INVENTORY_SCOPE_DRIFT")
        pin = load_stage_pin(scope.edge_id)
        spec, _, _ = _check_stage(pin)
        with self.db_conn() as db:
            allocated = db.execute(
                "SELECT edge_public_ipv4,status,route_table FROM edge_egress_allocations "
                "WHERE edge_id=?", (scope.edge_id,),
            ).fetchall()
            if allocated != [(scope.target_host, "STAGED", spec.route_table)]:
                raise CorePrerequisiteHold("CORE_F3_STAGE_ALLOCATION_DRIFT")
            for table in ("edge_egress_uid_runtime", "edge_egress_uid_bindings"):
                if db.execute("SELECT 1 FROM " + table +
                              " WHERE username=? OR uid=? LIMIT 1",
                              (scope.username, scope.uid)).fetchone():
                    raise CorePrerequisiteHold("CORE_UID_ALREADY_BOUND")
        current, guards = _installed_guards()
        if current is None:
            with self.db_conn() as db:
                if any(db.execute("SELECT 1 FROM " + table + " LIMIT 1").fetchone()
                       for table in ("edge_egress_uid_runtime", "edge_egress_uid_bindings")):
                    raise CorePrerequisiteHold("CORE_ROSTER_MISSING_WITH_PROTECTED_USERS")
        priorities, ports = self._resources(scope.uid)
        man = build_single_manifest(scope, spec=spec, guards=guards,
                                    rule_priorities=priorities, listening_ports=ports)
        body = asdict(man.request)
        body.update(mode=man.mode, dns_port=man.dns_port,
                    ingress_return=True, shared_edge=True)
        raw = (json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n").encode()
        pam = _read_checked(PAM, maximum=131072)
        module_sha = self.pins["edge_egress_v1_admission.py"]
        gates = self.gates_provider(scope, ticket, member, man, module_sha)
        if type(gates) is not RootHostSafetyGates:
            raise CorePrerequisiteHold("CORE_TYPED_HOST_GATES_REQUIRED")
        kwargs = dict(scope=scope, ticket=ticket, db_conn=self.db_conn,
                      os_uid=self.os_uid, release_enabled=True, geteuid=self.geteuid)
        if current is None:
            kind = "FIRST_UID"
            plan = plan_guard_install(
                username=scope.username, manifest_bytes=raw, pam_before=pam,
                module_sha256=module_sha, existing_guard_bytes={}, os_uid=self.os_uid,
                expected_pam_sha256=sha256(pam).hexdigest(),
            )
            kwargs.update(plan=plan, current_pam=pam, port=RootFilePort(),
                          independent_rescue_ok=gates.independent_rescue_ok,
                          independent_f4_ok=gates.independent_f4_ok,
                          mixed_legacy_pam_ok=gates.mixed_legacy_pam_ok,
                          account_idle_ok=gates.account_idle_ok,
                          sshd_effective_probe=gates.sshd_effective_probe,
                          guard_frozen_ok=gates.guard_frozen_ok,
                          dns_ipv6_ok=gates.dns_ipv6_ok)
        else:
            kind = "NEXT_UID"
            plan = plan_next_uid(
                username=scope.username, manifest_bytes=raw, current_roster=current,
                installed_manifests=guards, pam_bytes=pam,
                module_digest=module_sha, os_uid=self.os_uid,
            )
            kwargs.update(plan=plan, port=CASRootRosterPort(),
                          rescue_ok=gates.independent_rescue_ok,
                          independent_f4_ok=gates.independent_f4_ok,
                          legacy_pam_ok=gates.mixed_legacy_pam_ok,
                          idle_ok=gates.account_idle_ok,
                          sshd_effective=gates.sshd_effective_probe,
                          guard_verify=gates.guard_frozen_ok,
                          dns_ipv6_verify=gates.dns_ipv6_ok, resume_partial=False)
        bootstrap = CoreGuardBootstrap(scope, ticket, kind, kwargs,
                                       self.blobs, self.pins, self.bundle_digest)
        return ReviewedUIDHostSnapshot(scope, member, bootstrap, man.request,
                                       man.dns_port, gates.safety)
