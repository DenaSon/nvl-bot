"""Single-UID startup composition for the existing root-running Telegram bot.

All OS/file/P3 providers below are fixed repository implementations. No new
poller, daemon, IPC, generic command API or customer credentials are created.
The release profile is OFF when absent; source CI never enables a live host.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import pwd
import secrets
import subprocess
import time

from edge_egress_k2_a_6g_shared import Original6GRootCallbacks
from edge_egress_k2_a3_host_plans import RootHostSafetyGates
from edge_egress_k2_a_host_factory import ReviewedM2P3HostFactory
from edge_egress_k2_core_prerequisites import (
    CoreUIDSnapshotSource, read_reviewed_module_bundle,
)
from edge_egress_k2_m42_bindings import (
    HostReviewedPorts, RootAdminPolicy, RootM42Bindings, LegacyCurrentAdminRole,
)
from edge_egress_k2_m42_evidence import (
    load_external_evidence, load_post_attach_evidence,
)
from edge_egress_k2_m4_checkpoint import DurableWaveCheckpoint, install_checkpoint_schema
from edge_egress_k2_m4_cross_edge_port import (
    CrossEdgeIndependentSafety, root_fresh_source_evidence,
)
from edge_egress_k2_m4_root_worker import (
    WorkerPaths, verify_reviewed_release, load_root_secret, _read_checked,
    _verify_root_directory,
)
from edge_egress_k2_m2_ingress_journal import _validated
from edge_egress_k2_root_direct import register_root_portal
from edge_egress_k2_runtime_release import load_core_profile
from edge_egress_f4_preflight import sshd_connection_spec
from edge_egress_uid_boot import BootGuardApplier
from edge_egress_uid_runtime_kernel import LocalLinuxProtectedRuntimeKernel
from edge_egress_v1_live_driver import assert_idle_process_snapshot
from ops.k2_p3_uid_worker import IndependentSafety


class CoreRuntimeHold(ValueError):
    pass


@dataclass(frozen=True)
class CoreStartupResult:
    state: str
    release_sha: str = ""


def _checked(*argv: str) -> str:
    result = subprocess.run(list(argv), capture_output=True, text=True,
                            timeout=8, check=False)
    if result.returncode != 0:
        raise CoreRuntimeHold("CORE_HOST_OBSERVATION_UNAVAILABLE")
    return result.stdout


class CoreHostSources:
    """Real local inspections plus mandatory independent pre/post witnesses."""

    def __init__(self, db_conn):
        self.db_conn = db_conn
        self.os_uid = lambda name: pwd.getpwnam(name).pw_uid
        self.geteuid = os.geteuid
        self.now = lambda: int(time.time())

    def protected_mode(self):
        if not load_core_profile().enabled:
            raise CoreRuntimeHold("CORE_SINGLE_RELEASE_DISABLED")
        with self.db_conn() as db:
            rows = db.execute("SELECT value FROM settings "
                              "WHERE key='edge_egress_protected_mode'").fetchall()
        if rows != [("0",)]:
            raise CoreRuntimeHold("CORE_SINGLE_REQUIRES_UNCHANGED_LEGACY_MODE")
        return "0"

    def policy(self):
        with self.db_conn() as db:
            rows = db.execute("SELECT value FROM settings "
                              "WHERE key='admin_chat_ids'").fetchall()
        if len(rows) != 1 or type(rows[0][0]) is not str:
            raise CoreRuntimeHold("CORE_CURRENT_ADMINS_UNAVAILABLE")
        role = LegacyCurrentAdminRole(self.db_conn)
        tokens = rows[0][0].split(",")
        if (not 1 <= len(tokens) <= 20 or len(set(tokens)) != len(tokens)
            or any(not token.isascii() or not token.isdecimal()
                   or not role(int(token), int(token)) for token in tokens)):
            raise CoreRuntimeHold("CORE_CURRENT_ADMINS_INVALID")
        return RootAdminPolicy(frozenset((int(t), int(t)) for t in tokens))

    def pre(self, scope=None):
        proof = load_external_evidence(now=self.now())
        proof.verify_pre_attach()
        if scope is not None:
            proof.verify_target(scope.edge_id, scope.target_host, (scope.username,))
            proof.verify_account(scope.username, scope.uid, source_ipv4=scope.source_host)
        return proof

    def idle(self, username, uid):
        # The independent witness supplies session count; /proc/ps is an
        # additional local check, never a substitute for source attribution.
        proof = self.pre()
        proof.verify_account(username, uid)
        if self.os_uid(username) != uid:
            return False
        snapshot = _checked("ps", "-eo", "pid,uid,comm,args", "--no-headers")
        service = "nvl-egress-dns-" + username + ".service"
        process = subprocess.run(
            ["systemctl", "show", service, "-p", "MainPID", "--value"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        text = process.stdout.strip()
        if process.returncode == 0 and text.isdecimal() and int(text) > 1:
            assert_idle_process_snapshot(snapshot, username, uid,
                                         allowed_dns_pid=int(text))
        else:
            # Before the first bootstrap there is no DNS process. Require
            # an actually empty UID process set in addition to signed idle.
            for line in snapshot.splitlines():
                fields = line.split(None, 3)
                if len(fields) < 3 or not fields[0].isdecimal() or not fields[1].isdecimal():
                    raise CoreRuntimeHold("CORE_PROCESS_SNAPSHOT_INVALID")
                if int(fields[1]) == uid:
                    return False
        return True

    def gates(self, scope, ticket, member, manifest, module_sha):
        current = root_fresh_source_evidence()
        record = _validated(current.raw).get(scope.username)
        witness = current(scope.username)
        if (record is None or record.uid != scope.uid
            or witness.edge_id != member.source_edge_id
            or witness.edge_ipv4 != scope.source_host):
            raise CoreRuntimeHold("CORE_CURRENT_INGRESS_NOT_ATTESTED")
        # Use the original pinned ingress connection context. The customer
        # listener port is read from the trusted source Edge's Stage pin.
        from edge_egress_k2_p1_worker import load_stage_pin
        try:
            source_pin = load_stage_pin(member.source_edge_id)
            port = source_pin.customer_port
        except (OSError, ValueError):
            # Ingress-only Legacy Edges may predate the K2 stage. Their
            # canonical service port must still be uniquely present in DB.
            with self.db_conn() as db:
                columns = {r[1] for r in db.execute("PRAGMA table_info(host_pool)")}
                if "service_port" not in columns:
                    raise CoreRuntimeHold("CORE_SOURCE_LISTENER_NOT_VERIFIED")
                rows = db.execute("SELECT service_port FROM host_pool WHERE host=?",
                                  (scope.source_host,)).fetchall()
            if len(rows) != 1:
                raise CoreRuntimeHold("CORE_SOURCE_LISTENER_NOT_VERIFIED")
            port = rows[0][0]
        if type(port) is not int or not 1 <= port <= 65535:
            raise CoreRuntimeHold("CORE_SOURCE_LISTENER_NOT_VERIFIED")
        context = sshd_connection_spec(
            username=scope.username, local_addr="10.77.0.1",
            remote_addr=record.ingress_ipv4, local_port=port,
        )

        def packet(req):
            if req != manifest.request:
                return False
            load_post_attach_evidence(scope=scope, ticket=ticket,
                                      db_conn=self.db_conn, now=self.now())
            return True

        def uid_packet(req):
            if req != manifest.request:
                return False
            load_post_attach_evidence(scope=scope, ticket=ticket,
                                      db_conn=self.db_conn, now=self.now(),
                                      phase="UID_ROUTE")
            return True

        def neighbour(req):
            if req != manifest.request:
                return False
            return "neighbour_isolation" in self.pre(scope).checks

        args = dict(
            db_conn=self.db_conn, target_edge_id=scope.edge_id,
            source_ipv4=scope.source_host, ingress_rhost=record.ingress_ipv4,
            ssh_local_addr="10.77.0.1", ssh_local_port=port,
            reviewed_module_sha256=module_sha, packet_witness=packet,
            neighbour_witness=neighbour, now=self.now,
            precommit_packet_witness=uid_packet,
        )
        safety = (CrossEdgeIndependentSafety(
            **args, ingress_edge_id=member.source_edge_id,
            source_evidence=root_fresh_source_evidence,
        ) if scope.source_host != scope.target_host else IndependentSafety(**args))

        def mixed_pam():
            self.protected_mode()
            effective = _checked("sshd", "-T", "-C", context)
            # M2 itself verifies the full, exact PAM diff and preserves all
            # other accounts. Require effective UsePAM before that first edit.
            return "usepam yes" in effective.splitlines()

        def frozen(man):
            if man != manifest:
                return False
            BootGuardApplier().verify(man, require_frozen=True)
            return True

        def dns_ipv6(man):
            if man != manifest:
                return False
            kernel = LocalLinuxProtectedRuntimeKernel(explicitly_enabled=True)
            kernel.assert_frozen(man.request)
            kernel.assert_dns_ipv6(man.request)
            return True

        return RootHostSafetyGates(
            safety=safety,
            independent_rescue_ok=lambda: "operator_rescue" in self.pre(scope).checks,
            independent_f4_ok=lambda current_scope: (
                current_scope == scope and "f4_accepted" in self.pre(scope).checks
            ),
            mixed_legacy_pam_ok=mixed_pam, account_idle_ok=self.idle,
            sshd_effective_probe=lambda: _checked("sshd", "-T", "-C", context),
            guard_frozen_ok=frozen, dns_ipv6_ok=dns_ipv6,
        )


def _single_switches():
    """The exact in-process Single release; Batch/IPC/global mode stay OFF."""
    import edge_egress_k2_root_direct as direct
    import edge_egress_k2_m4_root_portal as portal
    import edge_egress_k2_m42_bindings as bindings
    import edge_egress_k2_m42_evidence as evidence
    import edge_egress_k2_a_host_factory as factory
    import edge_egress_k2_m3_waves as waves
    import edge_egress_k2_m4_bootstrap as bootstrap
    import edge_egress_k2_m4_cross_edge_port as cross
    import edge_egress_k2_uid_ingress_egress as policy
    import edge_egress_uid_runtime_store as store
    import edge_egress_p3_executor as executor
    import edge_egress_k2_m4_checkpoint as checkpoint
    import edge_egress_k2_m3_ingress_port as ingress
    import edge_egress_k2_m44_recovery as recovery
    import ops.k2_m2_first_uid as first
    import ops.k2_m2_guard_append as append
    return (
        (direct, "K2_ROOT_DIRECT_ENABLED"),
        (portal, "M4_ROOT_PORTAL_ENABLED"), (portal, "M4_CROSS_EDGE_SINGLE_ENABLED"),
        (bindings, "M42_LIVE_BINDINGS_ENABLED"),
        (bindings, "M42_CROSS_EDGE_LEGACY_SINGLE_ENABLED"),
        (evidence, "M42_EVIDENCE_ENABLED"),
        (factory, "M4A_REAL_HOST_FACTORY_ENABLED"), (factory, "M4A_CROSS_EDGE_FACTORY_ENABLED"),
        (waves, "M3_WAVE_EXECUTION_ENABLED"), (waves, "M3_CROSS_EDGE_LEGACY_SINGLE_ENABLED"),
        (bootstrap, "M42_CROSS_EDGE_DEFERRED_ENABLED"),
        (cross, "M4_CROSS_EDGE_UID_PORT_ENABLED"), (cross, "CROSS_EDGE_PAM_SAFETY_ENABLED"),
        (policy, "K2_M4_POLICY_STAGE_ENABLED"), (policy, "K2_ROOT_POLICY_INIT_ENABLED"),
        (store, "K2_CROSS_EDGE_RUNTIME_STORE_ENABLED"),
        (executor, "P3_CROSS_EDGE_LEGACY_UID_ATTACH_ENABLED"),
        (executor, "P3_UID_POST_COMMIT_PROBE_ENABLED"),
        (checkpoint, "M4_CHECKPOINT_RELEASE_ENABLED"),
        (ingress, "M3_VERIFIED_INGRESS_ADAPTER_ENABLED"),
        (recovery, "M44_ROOT_STATUS_ENABLED"),
        (first, "M2_FIRST_UID_ENABLED"), (append, "M2_APPEND_ENABLED"),
    )


def _ensure_secret(paths):
    _verify_root_directory(paths.secret_file.parent, group=None, private=True)
    if not paths.secret_file.exists() and not paths.secret_file.is_symlink():
        fd = os.open(paths.secret_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(secrets.token_bytes(48))
            out.flush()
            os.fsync(out.fileno())
        parent = os.open(paths.secret_file.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    return load_root_secret(paths)


def start_core_single_runtime(application, *, db_conn,
                              source_root: Path) -> CoreStartupResult:
    """Called once by the existing bot's post_init; never installs a daemon.

    Missing configuration is a normal OFF state. Failed release validation
    leaves the old bot running with no new mutating registration. Core host
    setup is deferred until the first UID's original 6G intent is persisted.
    """
    profile = load_core_profile()
    if not profile.enabled:
        return CoreStartupResult("OFF")
    if os.geteuid() != 0 or not callable(db_conn):
        raise CoreRuntimeHold("CORE_ROOT_SINGLE_STARTUP_REQUIRED")
    paths = WorkerPaths(
        source_root=source_root,
        manifest_file=Path("/etc/nvl-egress/k2-m4/release.json"),
        secret_file=Path("/etc/nvl-egress/k2-m4/root-hmac.key"),
        runtime_dir=Path("/run/nvl-k2-m4"), bot_uid=1, ipc_gid=1,
    )
    # Only release verification is reused; no nonroot/socket validation,
    # service unit, IPC group or additional process is constructed.
    release_sha = verify_reviewed_release(paths)
    manifest = json.loads(_read_checked(paths.manifest_file,
                                        maximum=16384, strict=True))
    pins = manifest["files"]
    if pins.get("edge_egress_v1_admission.py") != profile.pam_module_sha256:
        raise CoreRuntimeHold("CORE_PROFILE_RELEASE_DIGEST_DRIFT")
    blobs = read_reviewed_module_bundle(source_root, pins)
    host = CoreHostSources(db_conn)
    host.protected_mode()
    policy = host.policy()
    secret = _ensure_secret(paths)
    callbacks = Original6GRootCallbacks(db_conn)
    # The snapshot source needs the very same M42 inventory it later checks.
    # The late binding only closes this known composition cycle; it cannot
    # replace the reviewed port with a Telegram-supplied callback.
    root_holder = {}
    snapshot = CoreUIDSnapshotSource(
        db_conn=db_conn, os_uid=host.os_uid, geteuid=host.geteuid,
        inventory_provider=lambda selected: root_holder["root"].review(selected),
        gates_provider=host.gates, module_blobs=blobs,
    )
    factory = ReviewedM2P3HostFactory(
        db_conn=db_conn, read_root_snapshot=snapshot, os_uid=host.os_uid,
        geteuid=host.geteuid, release_enabled=True,
    )
    ports = HostReviewedPorts(
        db_conn=db_conn, acquire_6g=callbacks.acquire,
        journal_6g=callbacks.journal, port_factory=factory,
        live_admin_role=LegacyCurrentAdminRole(db_conn),
        protected_mode=host.protected_mode, os_uid=host.os_uid,
        external_evidence=host.pre,
        now=host.now, geteuid=host.geteuid,
    )
    switches = _single_switches()
    previous = [(module, name, getattr(module, name)) for module, name in switches]
    try:
        for module, name, _ in previous:
            setattr(module, name, True)
        root = RootM42Bindings(ports=ports, root_secret=secret,
                               admin_policy=policy, reviewed_release=True)
        root_holder["root"] = root
        checkpoint = DurableWaveCheckpoint(
            db_conn=db_conn, geteuid=host.geteuid, clock=host.now,
            release_enabled=True,
        )
        with db_conn() as db:
            install_checkpoint_schema(db)
        register_root_portal(application, portal=root.portal(checkpoint=checkpoint),
                             geteuid=host.geteuid, released=True)
    except BaseException:
        for module, name, value in previous:
            setattr(module, name, value)
        raise
    return CoreStartupResult("SINGLE_REGISTERED", release_sha)
