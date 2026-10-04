from __future__ import annotations

from typing import Callable

from .detector import inspect_server
from .models import ServerCredentials
from .phase3_models import (
    PHASE3_MODE_INSPECT,
    PHASE3_MODE_RESTORE,
    Phase3Error,
    Phase3Policy,
    Phase3Result,
)
from .restore import (
    ensure_docker,
    inspect_docker_image_archive,
    load_docker_images,
    prepare_preview,
    preview_database_integrity,
    preview_xray_ports,
    restore_runtime_from_preview,
    start_runtime_and_verify,
    validate_bundle_archives,
    validate_preview_compose,
    validate_restore_target,
    validate_restored_compose,
    validate_restored_database,
    verify_incoming_bundle,
)
from .ssh import ParamikoRemoteExecutor


ExecutorFactory = Callable[[ServerCredentials], object]


def run_phase3(
    destination_credentials: ServerCredentials,
    *,
    job_id: str,
    policy: Phase3Policy | None = None,
    executor_factory: ExecutorFactory = ParamikoRemoteExecutor,
) -> Phase3Result:
    """Verify a Phase 2 bundle, build a restore preview, and optionally restore.

    INSPECT_ONLY:
      - verifies checksums and archive safety
      - extracts only under the migration job directory
      - validates SQLite, Docker image archive, and Compose config
      - never writes to Marzban runtime paths or Docker image store

    RESTORE:
      - performs all inspection steps
      - requires clean/non-conflicting runtime paths
      - installs Docker/Compose only when explicitly allowed by policy
      - loads exact Docker image(s)
      - copies preview data into runtime paths without overwriting
      - validates restored SQLite/Compose
      - starts runtime only when policy.start_runtime=True
    """
    policy = policy or Phase3Policy()
    if policy.mode not in {PHASE3_MODE_INSPECT, PHASE3_MODE_RESTORE}:
        raise Phase3Error(f"unsupported Phase 3 mode: {policy.mode!r}")

    executor = None
    try:
        executor = executor_factory(destination_credentials)
        destination = inspect_server(
            executor,
            destination_credentials,
            role="destination",
        )

        incoming_dir, metadata, manifest = verify_incoming_bundle(
            executor,
            job_id=job_id,
            policy=policy,
        )
        validate_bundle_archives(
            executor,
            incoming_dir,
            metadata,
            manifest,
        )
        docker_archive_valid, archive_image_identity_verified = inspect_docker_image_archive(
            executor,
            incoming_dir,
            metadata,
        )

        preview_root = prepare_preview(
            executor,
            job_id=job_id,
            incoming_dir=incoming_dir,
            metadata=metadata,
            manifest=manifest,
            policy=policy,
        )
        database_integrity = preview_database_integrity(
            executor,
            preview_root,
            metadata,
        )
        xray_ports = preview_xray_ports(
            executor,
            preview_root,
            metadata,
        )

        if policy.mode == PHASE3_MODE_INSPECT:
            ensure_docker(executor, policy=policy)
            compose_valid = validate_preview_compose(
                executor,
                preview_root,
                metadata,
            )
            return Phase3Result(
                job_id=job_id,
                mode=policy.mode,
                incoming_dir=incoming_dir,
                preview_root=preview_root,
                metadata=metadata,
                bundle_verified=True,
                archives_verified=True,
                preview_extracted=True,
                database_integrity=database_integrity,
                compose_valid=compose_valid,
                docker_archive_valid=docker_archive_valid,
                image_identity_verified=archive_image_identity_verified,
                runtime_restored=False,
                docker_images_loaded=False,
                runtime_started=False,
                api_healthy=False,
                listening_ports=(),
            )

        validate_restore_target(
            executor,
            destination,
            metadata,
            xray_ports,
            incoming_dir=incoming_dir,
            policy=policy,
        )

        ensure_docker(executor, policy=policy)
        compose_valid = validate_preview_compose(
            executor,
            preview_root,
            metadata,
        )

        docker_images_loaded = load_docker_images(
            executor,
            incoming_dir,
            metadata,
        )

        restore_runtime_from_preview(
            executor,
            job_id=job_id,
            preview_root=preview_root,
            metadata=metadata,
            policy=policy,
        )
        restored_integrity = validate_restored_database(executor, metadata)
        if restored_integrity.lower() != "ok":
            raise Phase3Error(
                f"unexpected restored database integrity: {restored_integrity!r}"
            )
        validate_restored_compose(executor, metadata)

        runtime_started = False
        api_healthy = False
        listening_ports: tuple[int, ...] = ()
        if policy.start_runtime:
            (
                runtime_started,
                api_healthy,
                listening_ports,
            ) = start_runtime_and_verify(
                executor,
                metadata,
                xray_ports,
            )

        return Phase3Result(
            job_id=job_id,
            mode=policy.mode,
            incoming_dir=incoming_dir,
            preview_root=preview_root,
            metadata=metadata,
            bundle_verified=True,
            archives_verified=True,
            preview_extracted=True,
            database_integrity=restored_integrity,
            compose_valid=compose_valid,
            docker_archive_valid=docker_archive_valid,
            image_identity_verified=archive_image_identity_verified,
            runtime_restored=True,
            docker_images_loaded=docker_images_loaded,
            runtime_started=runtime_started,
            api_healthy=api_healthy,
            listening_ports=listening_ports,
        )
    finally:
        if executor is not None:
            close = getattr(executor, "close", None)
            if callable(close):
                close()
