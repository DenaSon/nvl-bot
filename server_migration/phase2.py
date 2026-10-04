from __future__ import annotations

from typing import Callable

from .backup import create_source_bundle
from .models import MigrationPreflightReport, ServerCredentials
from .phase2_models import Phase2Error, Phase2Policy, Phase2Result
from .ssh import ParamikoRemoteExecutor
from .transfer import relay_bundle


ExecutorFactory = Callable[[ServerCredentials], object]

_STAGING_ONLY_BLOCKERS = {"DEST_CLEAN", "DEST_PORTS"}


def _validate_preflight_for_phase2(
    report: MigrationPreflightReport,
    policy: Phase2Policy,
) -> None:
    if report.source is None or report.destination is None:
        raise Phase2Error("Phase 2 requires complete source/destination facts")

    if report.ready:
        return

    blocker_codes = {check.code for check in report.blockers}
    if policy.require_preflight_ready:
        raise Phase2Error(
            "Phase 2 blocked by preflight: "
            + ", ".join(sorted(blocker_codes or {"UNKNOWN"}))
        )

    # Explicit staging-only override is intentionally narrow. It exists for
    # controlled verification against an already-running destination and can
    # bypass only runtime-cleanliness/port-conflict blockers. SSH, database,
    # OS, architecture, disk, identity, and all source safety checks still
    # remain fail-closed.
    unexpected = blocker_codes - _STAGING_ONLY_BLOCKERS
    if unexpected:
        raise Phase2Error(
            "unsafe preflight blockers cannot be bypassed for staging: "
            + ", ".join(sorted(unexpected))
        )


def _validate_credentials_match(
    report: MigrationPreflightReport,
    source_credentials: ServerCredentials,
    destination_credentials: ServerCredentials,
) -> None:
    assert report.source is not None
    assert report.destination is not None

    if str(source_credentials.host).strip() != str(report.source.host).strip():
        raise Phase2Error("source credentials do not match preflight source")
    if str(destination_credentials.host).strip() != str(report.destination.host).strip():
        raise Phase2Error(
            "destination credentials do not match preflight destination"
        )


def run_phase2(
    preflight: MigrationPreflightReport,
    source_credentials: ServerCredentials,
    destination_credentials: ServerCredentials,
    *,
    job_id: str | None = None,
    policy: Phase2Policy | None = None,
    executor_factory: ExecutorFactory = ParamikoRemoteExecutor,
) -> Phase2Result:
    """Build a live source bundle and relay it through NVL to destination.

    Phase 2 intentionally does not restore the bundle and does not stop/start
    Marzban, Xray, Docker, or any system service.
    """
    policy = policy or Phase2Policy()
    _validate_preflight_for_phase2(preflight, policy)
    _validate_credentials_match(
        preflight,
        source_credentials,
        destination_credentials,
    )

    source_executor = None
    destination_executor = None
    try:
        source_executor = executor_factory(source_credentials)
        destination_executor = executor_factory(destination_credentials)

        bundle = create_source_bundle(
            source_executor,
            preflight.source,
            job_id=job_id,
            policy=policy,
        )
        transfer = relay_bundle(
            source_executor,
            destination_executor,
            bundle,
            policy=policy,
        )
        return Phase2Result(
            job_id=bundle.job_id,
            source_bundle=bundle,
            transfer=transfer,
        )
    finally:
        for executor in (destination_executor, source_executor):
            if executor is None:
                continue
            close = getattr(executor, "close", None)
            if callable(close):
                close()
