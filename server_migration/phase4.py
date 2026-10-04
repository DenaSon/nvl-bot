from __future__ import annotations

from typing import Callable

from .detector import inspect_server
from .final_sync import (
    _exists,
    acquire_final_sync_lock,
    backup_destination_database,
    compose_running,
    create_final_source_snapshot,
    database_integrity,
    install_final_database,
    mark_phase4_complete,
    matching_host_rows,
    migration_paths,
    new_attempt_id,
    normalize_ipv4,
    relay_final_database,
    release_final_sync_lock,
    restore_destination_database,
    rewrite_hosts_address,
    scan_database_for_old_ip,
    scan_runtime_configs_for_old_ip,
    stop_compose,
)
from .models import ServerCredentials
from .phase3_models import PHASE3_MODE_INSPECT, Phase3Policy
from .phase4_models import (
    PHASE4_MODE_FINALIZE,
    PHASE4_MODE_PLAN,
    Phase4Error,
    Phase4Plan,
    Phase4Policy,
    Phase4Result,
)
from .restore import start_runtime_and_verify, verify_incoming_bundle
from .ssh import ParamikoRemoteExecutor


ExecutorFactory = Callable[[ServerCredentials], object]


def _validate_pair_identity(
    *,
    source_credentials: ServerCredentials,
    destination_credentials: ServerCredentials,
    source_facts,
    destination_facts,
    metadata: dict,
) -> tuple[str, str]:
    if source_credentials.host == destination_credentials.host:
        raise Phase4Error("source and destination credentials point to the same host")

    source_meta = dict(metadata.get("source") or {})
    metadata_host = str(source_meta.get("host") or "").strip()
    metadata_ip = str(source_meta.get("primary_ipv4") or "").strip()

    if metadata_host and metadata_host != source_credentials.host:
        raise Phase4Error(
            f"bundle source host mismatch: {metadata_host} != "
            f"{source_credentials.host}"
        )

    old_ip = normalize_ipv4(
        metadata_ip or source_facts.primary_ipv4,
        label="old/source IP",
    )
    actual_source_ip = normalize_ipv4(
        source_facts.primary_ipv4 or source_credentials.host,
        label="connected source IP",
    )
    if old_ip != actual_source_ip:
        raise Phase4Error(
            f"bundle source IP mismatch: {old_ip} != {actual_source_ip}"
        )

    new_ip = normalize_ipv4(
        destination_facts.primary_ipv4 or destination_credentials.host,
        label="new/destination IP",
    )
    if old_ip == new_ip:
        raise Phase4Error("old and new server IPs are identical")

    return old_ip, new_ip


def _runtime_paths_match_metadata(facts, metadata: dict, *, role: str) -> None:
    marzban = dict(metadata.get("marzban") or {})
    expected_dir = str(marzban.get("directory") or "").strip()
    expected_db = str(marzban.get("database_path") or "").strip()
    expected_xray = str(marzban.get("xray_config_path") or "").strip()

    if facts.marzban_dir != expected_dir:
        raise Phase4Error(
            f"{role} Marzban directory mismatch: "
            f"{facts.marzban_dir!r} != {expected_dir!r}"
        )
    if facts.database_path != expected_db:
        raise Phase4Error(
            f"{role} database path mismatch: "
            f"{facts.database_path!r} != {expected_db!r}"
        )
    if facts.xray_config_path != expected_xray:
        raise Phase4Error(
            f"{role} Xray config mismatch: "
            f"{facts.xray_config_path!r} != {expected_xray!r}"
        )


def build_phase4_plan(
    source_executor,
    destination_executor,
    source_credentials: ServerCredentials,
    destination_credentials: ServerCredentials,
    *,
    job_id: str,
    policy: Phase4Policy,
) -> tuple[Phase4Plan, dict, object, object]:
    source = inspect_server(
        source_executor,
        source_credentials,
        role="source",
    )
    destination = inspect_server(
        destination_executor,
        destination_credentials,
        role="destination",
    )

    _incoming, metadata, _manifest = verify_incoming_bundle(
        destination_executor,
        job_id=job_id,
        policy=Phase3Policy(
            remote_root=policy.remote_root,
            mode=PHASE3_MODE_INSPECT,
            expected_bundle_schema_version=policy.expected_bundle_schema_version,
        ),
    )

    old_ip, new_ip = _validate_pair_identity(
        source_credentials=source_credentials,
        destination_credentials=destination_credentials,
        source_facts=source,
        destination_facts=destination,
        metadata=metadata,
    )
    _runtime_paths_match_metadata(source, metadata, role="source")
    _runtime_paths_match_metadata(destination, metadata, role="destination")

    source_running = compose_running(
        source_executor,
        marzban_dir=source.marzban_dir,
    )
    destination_running = compose_running(
        destination_executor,
        marzban_dir=destination.marzban_dir,
    )

    paths = migration_paths(job_id, policy=policy)
    phase3_complete = _exists(
        destination_executor,
        paths["phase3_complete"],
    )
    phase4_complete = _exists(
        destination_executor,
        paths["phase4_complete"],
    )

    source_integrity = database_integrity(
        source_executor,
        source.database_path,
    )
    destination_integrity = database_integrity(
        destination_executor,
        destination.database_path,
    )
    rewrite_rows = matching_host_rows(
        source_executor,
        source.database_path,
        old_ip,
    )

    blockers: list[str] = []
    if source_integrity.lower() != "ok":
        blockers.append(
            f"source database integrity is {source_integrity!r}"
        )
    if destination_integrity.lower() != "ok":
        blockers.append(
            f"destination database integrity is {destination_integrity!r}"
        )
    if policy.require_phase3_restore_marker and not phase3_complete:
        blockers.append("Phase 3 RESTORE_COMPLETE marker is missing")
    if destination_running:
        blockers.append(
            "destination Marzban is running; final sync requires it stopped"
        )
    if phase4_complete:
        blockers.append("Phase 4 FINAL_SYNC_COMPLETE already exists")

    plan = Phase4Plan(
        job_id=job_id,
        source_host=source.host,
        destination_host=destination.host,
        old_ip=old_ip,
        new_ip=new_ip,
        source_running=source_running,
        destination_running=destination_running,
        phase3_restore_complete=phase3_complete,
        source_database_integrity=source_integrity,
        destination_database_integrity=destination_integrity,
        matching_host_rows=rewrite_rows,
        finalization_ready=not blockers,
        blockers=tuple(blockers),
    )
    return plan, metadata, source, destination


def run_phase4(
    source_credentials: ServerCredentials,
    destination_credentials: ServerCredentials,
    *,
    job_id: str,
    confirmation: str = "",
    policy: Phase4Policy | None = None,
    executor_factory: ExecutorFactory = ParamikoRemoteExecutor,
) -> Phase4Plan | Phase4Result:
    """Plan or execute the controlled final database synchronization.

    PLAN_ONLY is non-disruptive and does not stop/start either server.

    FINALIZE requires:
      - explicit confirmation phrase
      - a Phase 3 RESTORE_COMPLETE destination
      - destination runtime stopped
      - valid source/destination databases
      - exclusive final-sync locks on both servers

    DNS/Cloudflare is intentionally not changed in Phase 4.
    """
    policy = policy or Phase4Policy()
    if policy.mode not in {PHASE4_MODE_PLAN, PHASE4_MODE_FINALIZE}:
        raise Phase4Error(f"unsupported Phase 4 mode: {policy.mode!r}")

    source_executor = None
    destination_executor = None
    source_lock = False
    destination_lock = False

    try:
        source_executor = executor_factory(source_credentials)
        destination_executor = executor_factory(destination_credentials)

        plan, metadata, source, destination = build_phase4_plan(
            source_executor,
            destination_executor,
            source_credentials,
            destination_credentials,
            job_id=job_id,
            policy=policy,
        )

        if policy.mode == PHASE4_MODE_PLAN:
            return plan

        if confirmation != policy.confirmation_phrase:
            raise Phase4Error(
                "final sync confirmation phrase did not match; "
                f"expected {policy.confirmation_phrase!r}"
            )
        if not plan.finalization_ready:
            raise Phase4Error(
                "Phase 4 finalization is blocked: "
                + "; ".join(plan.blockers)
            )

        attempt_id = new_attempt_id()
        paths = migration_paths(
            job_id,
            policy=policy,
            attempt_id=attempt_id,
        )

        acquire_final_sync_lock(
            destination_executor,
            lock_path=paths["global_lock"],
            job_id=job_id,
        )
        destination_lock = True

        acquire_final_sync_lock(
            source_executor,
            lock_path=paths["global_lock"],
            job_id=job_id,
        )
        source_lock = True

        source_was_running = plan.source_running
        source_stopped = False
        destination_backup = ""
        local_database_path = ""
        destination_started = False
        api_healthy = False
        listening_ports: tuple[int, ...] = ()
        source_recovered = False

        try:
            if source_was_running:
                stop_compose(
                    source_executor,
                    marzban_dir=source.marzban_dir,
                )
            source_stopped = not compose_running(
                source_executor,
                marzban_dir=source.marzban_dir,
            )
            if not source_stopped:
                raise Phase4Error("source runtime could not be stopped")

            final_sha = create_final_source_snapshot(
                source_executor,
                database_path=source.database_path,
                output_path=paths["source_final_db"],
            )

            local_database_path = relay_final_database(
                source_executor,
                destination_executor,
                source_remote_path=paths["source_final_db"],
                destination_remote_path=paths["destination_final_db"],
                expected_sha256=final_sha,
                job_id=job_id,
                attempt_id=attempt_id,
                policy=policy,
            )

            destination_backup = backup_destination_database(
                destination_executor,
                database_path=destination.database_path,
                backup_path=paths["destination_backup"],
            )

            install_final_database(
                destination_executor,
                staged_database=paths["destination_final_db"],
                runtime_database=destination.database_path,
            )

            rewritten_rows = rewrite_hosts_address(
                destination_executor,
                database_path=destination.database_path,
                old_ip=plan.old_ip,
                new_ip=plan.new_ip,
            )

            residual_db = scan_database_for_old_ip(
                destination_executor,
                database_path=destination.database_path,
                old_ip=plan.old_ip,
            )
            residual_configs = scan_runtime_configs_for_old_ip(
                destination_executor,
                metadata=metadata,
                old_ip=plan.old_ip,
            )

            if policy.fail_on_residual_old_ip and (
                residual_db or residual_configs
            ):
                details = list(residual_db) + list(residual_configs)
                raise Phase4Error(
                    "old IP remains after targeted rewrite: "
                    + ", ".join(details)
                )

            destination_integrity = database_integrity(
                destination_executor,
                destination.database_path,
            )
            if destination_integrity.lower() != "ok":
                raise Phase4Error(
                    "destination database integrity failed after final sync: "
                    f"{destination_integrity!r}"
                )

            if policy.start_destination:
                (
                    destination_started,
                    api_healthy,
                    listening_ports,
                ) = start_runtime_and_verify(
                    destination_executor,
                    metadata,
                    destination.xray_ports,
                )

            marker_payload = {
                "job_id": job_id,
                "attempt_id": attempt_id,
                "old_ip": plan.old_ip,
                "new_ip": plan.new_ip,
                "final_database_sha256": final_sha,
                "rewritten_host_rows": rewritten_rows,
                "database_integrity": destination_integrity,
                "destination_started": destination_started,
                "api_healthy": api_healthy,
                "dns_cutover_performed": False,
            }
            mark_phase4_complete(
                destination_executor,
                marker_path=paths["phase4_complete"],
                payload=marker_payload,
            )

            return Phase4Result(
                job_id=job_id,
                attempt_id=attempt_id,
                old_ip=plan.old_ip,
                new_ip=plan.new_ip,
                source_was_running=source_was_running,
                source_stopped=source_stopped,
                final_database_sha256=final_sha,
                local_database_path=local_database_path,
                destination_staging_path=paths["destination_final_db"],
                destination_backup_path=destination_backup,
                rewritten_host_rows=rewritten_rows,
                residual_database_references=residual_db,
                residual_config_files=residual_configs,
                destination_database_integrity=destination_integrity,
                destination_started=destination_started,
                api_healthy=api_healthy,
                listening_ports=listening_ports,
                source_recovered=False,
            )

        except Exception as exc:
            recovery_errors: list[str] = []

            # Destination has not been cut over yet. Keep it stopped while
            # restoring its pre-final-sync DB so a retry starts from a known
            # offline state.
            try:
                if compose_running(
                    destination_executor,
                    marzban_dir=destination.marzban_dir,
                ):
                    stop_compose(
                        destination_executor,
                        marzban_dir=destination.marzban_dir,
                    )
            except Exception as recovery_exc:
                recovery_errors.append(
                    f"destination stop recovery failed: {recovery_exc}"
                )

            if destination_backup:
                try:
                    restore_destination_database(
                        destination_executor,
                        backup_path=destination_backup,
                        runtime_database=destination.database_path,
                    )
                except Exception as recovery_exc:
                    recovery_errors.append(
                        f"destination DB recovery failed: {recovery_exc}"
                    )

            if source_was_running and policy.recover_source_on_failure:
                try:
                    (
                        _started,
                        _healthy,
                        _ports,
                    ) = start_runtime_and_verify(
                        source_executor,
                        metadata,
                        source.xray_ports,
                    )
                    source_recovered = True
                except Exception as recovery_exc:
                    recovery_errors.append(
                        f"source restart recovery failed: {recovery_exc}"
                    )

            try:
                mark_phase4_complete(
                    destination_executor,
                    marker_path=paths["failed_marker"],
                    payload={
                        "job_id": job_id,
                        "attempt_id": attempt_id,
                        "error": f"{type(exc).__name__}: {exc}",
                        "source_recovered": source_recovered,
                        "recovery_errors": recovery_errors,
                    },
                )
            except Exception as marker_exc:
                recovery_errors.append(
                    f"failed-marker write failed: {marker_exc}"
                )

            message = f"{type(exc).__name__}: {exc}"
            if recovery_errors:
                message += " | recovery: " + " | ".join(recovery_errors)
            elif source_was_running and source_recovered:
                message += " | source service recovered"
            raise Phase4Error(message) from exc

    finally:
        if source_executor is not None and source_lock:
            try:
                release_final_sync_lock(
                    source_executor,
                    lock_path=migration_paths(
                        job_id,
                        policy=policy,
                    )["global_lock"],
                    job_id=job_id,
                )
            except Exception:
                pass

        if destination_executor is not None and destination_lock:
            try:
                release_final_sync_lock(
                    destination_executor,
                    lock_path=migration_paths(
                        job_id,
                        policy=policy,
                    )["global_lock"],
                    job_id=job_id,
                )
            except Exception:
                pass

        for executor in (destination_executor, source_executor):
            if executor is None:
                continue
            close = getattr(executor, "close", None)
            if callable(close):
                close()
