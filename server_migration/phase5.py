from __future__ import annotations

import json
import shlex
from typing import Callable

from .cloudflare_cutover import (
    CloudflareClient,
    verify_origin_api,
    verify_tcp_ports,
    wait_for_hostname_api,
    wait_for_record_content,
)
from .detector import inspect_server
from .final_sync import (
    acquire_final_sync_lock,
    compose_running,
    mark_phase4_complete,
    normalize_ipv4,
    release_final_sync_lock,
    stop_compose,
)
from .models import ServerCredentials
from .phase5_models import (
    PHASE5_MODE_CUTOVER,
    PHASE5_MODE_PLAN,
    Phase5Error,
    Phase5Plan,
    Phase5Policy,
    Phase5Result,
)
from .restore import start_runtime_and_verify
from .ssh import ParamikoRemoteExecutor


ExecutorFactory = Callable[[ServerCredentials], object]


def _run_text(executor, command: str, *, timeout: int = 30, label: str = "remote command") -> str:
    result = executor.run(command, timeout=timeout)
    if int(result.exit_code) != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise Phase5Error(
            f"{label} failed with exit code {result.exit_code}"
            + (f": {detail[-1200:]}" if detail else "")
        )
    return str(result.stdout or "").strip()


def _exists(executor, path: str) -> bool:
    result = executor.run(f"test -e {shlex.quote(path)}", timeout=10)
    return int(result.exit_code) == 0


def _normalize_name(value: str, *, label: str) -> str:
    raw = str(value or "").strip().lower().rstrip(".")
    if not raw or "/" in raw or " " in raw:
        raise Phase5Error(f"invalid {label}: {value!r}")
    return raw


def _paths(job_id: str, policy: Phase5Policy) -> dict[str, str]:
    root = str(policy.remote_root or "").rstrip("/")
    if not root.startswith("/") or root == "":
        raise Phase5Error("remote migration root must be an absolute path")
    safe_job = str(job_id or "").strip()
    if not safe_job.startswith("chg-") or not all(c.isalnum() or c in "-_" for c in safe_job):
        raise Phase5Error(f"invalid job id: {safe_job!r}")
    job_root = f"{root}/{safe_job}"
    return {
        "job_root": job_root,
        "phase4_complete": f"{job_root}/FINAL_SYNC_COMPLETE",
        "cutover_complete": f"{job_root}/CUTOVER_COMPLETE",
        "rollback_complete": f"{job_root}/CUTOVER_ROLLBACK_COMPLETE",
        "cutover_lock": f"{root}/.cutover-lock",
    }


def _read_json(executor, path: str, *, label: str) -> dict:
    raw = _run_text(
        executor,
        f"cat {shlex.quote(path)}",
        timeout=20,
        label=label,
    )
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise Phase5Error(f"{label} contains invalid JSON") from exc
    if not isinstance(payload, dict):
        raise Phase5Error(f"{label} must contain a JSON object")
    return payload


def _runtime_metadata(facts) -> dict:
    return {
        "marzban": {
            "directory": facts.marzban_dir,
            "api_port": facts.api_port,
            "ssl_cert_path": facts.ssl_cert_path,
            "ssl_key_path": facts.ssl_key_path,
        }
    }


def build_phase5_plan(
    source_executor,
    destination_executor,
    source_credentials: ServerCredentials,
    destination_credentials: ServerCredentials,
    *,
    job_id: str,
    hostname: str,
    zone_name: str,
    cloudflare: CloudflareClient,
    policy: Phase5Policy,
) -> tuple[Phase5Plan, object, object, dict | None]:
    hostname = _normalize_name(hostname, label="hostname")
    zone_name = _normalize_name(zone_name, label="zone name")
    if hostname != zone_name and not hostname.endswith("." + zone_name):
        raise Phase5Error(
            f"hostname {hostname!r} is not inside zone {zone_name!r}"
        )

    source = inspect_server(source_executor, source_credentials, role="source")
    destination = inspect_server(
        destination_executor,
        destination_credentials,
        role="destination",
    )

    old_ip = normalize_ipv4(
        source.primary_ipv4 or source_credentials.host,
        label="old/source IP",
    )
    new_ip = normalize_ipv4(
        destination.primary_ipv4 or destination_credentials.host,
        label="new/destination IP",
    )
    if old_ip == new_ip:
        raise Phase5Error("source and destination IPs are identical")

    paths = _paths(job_id, policy)
    phase4_complete = _exists(destination_executor, paths["phase4_complete"])
    marker: dict | None = None
    if phase4_complete:
        marker = _read_json(
            destination_executor,
            paths["phase4_complete"],
            label="Phase 4 completion marker",
        )

    zone_id = cloudflare.resolve_zone_id(zone_name)
    record = cloudflare.get_a_record(zone_id=zone_id, hostname=hostname)

    source_running = compose_running(
        source_executor,
        marzban_dir=source.marzban_dir,
    )
    destination_running = compose_running(
        destination_executor,
        marzban_dir=destination.marzban_dir,
    )

    destination_api_precheck = False
    verified_ports: tuple[int, ...] = ()
    if destination_running:
        api_port = int(destination.api_port or 0)
        if api_port:
            destination_api_precheck = verify_origin_api(
                ip=new_ip,
                hostname=hostname,
                port=api_port,
                timeout=policy.connect_timeout_seconds,
            )
        verified_ports = verify_tcp_ports(
            ip=new_ip,
            ports=tuple(destination.xray_ports),
            timeout=policy.connect_timeout_seconds,
        )

    blockers: list[str] = []
    if record.content != old_ip:
        blockers.append(
            f"Cloudflare A record points to {record.content}, expected source {old_ip}"
        )
    if policy.require_proxied_record and record.proxied is not True:
        blockers.append("Cloudflare A record is not proxied")
    if not phase4_complete:
        blockers.append("Phase 4 FINAL_SYNC_COMPLETE marker is missing")
    else:
        marker_old = str(marker.get("old_ip") or "").strip()
        marker_new = str(marker.get("new_ip") or "").strip()
        if marker_old != old_ip or marker_new != new_ip:
            blockers.append(
                "Phase 4 marker source/destination IPs do not match connected servers"
            )
        if marker.get("dns_cutover_performed") is not False:
            blockers.append("Phase 4 marker has unexpected DNS cutover state")
        if source_running:
            blockers.append("source Marzban is still running after Phase 4")
        if not destination_running:
            blockers.append("destination Marzban is not running after Phase 4")
        if destination_running and not destination_api_precheck:
            blockers.append("destination direct API precheck failed")
        expected_ports = tuple(sorted(set(int(p) for p in destination.xray_ports)))
        if destination_running and tuple(sorted(verified_ports)) != expected_ports:
            missing = sorted(set(expected_ports) - set(verified_ports))
            blockers.append(
                "destination direct TCP ports failed: "
                + ",".join(str(p) for p in missing)
            )

    plan = Phase5Plan(
        job_id=job_id,
        hostname=hostname,
        zone_name=zone_name,
        old_ip=old_ip,
        new_ip=new_ip,
        phase4_complete=phase4_complete,
        source_running=source_running,
        destination_running=destination_running,
        cloudflare_record=record,
        destination_api_precheck=destination_api_precheck,
        destination_direct_ports=verified_ports,
        cutover_ready=not blockers,
        blockers=tuple(blockers),
    )
    return plan, source, destination, marker


def run_phase5(
    source_credentials: ServerCredentials,
    destination_credentials: ServerCredentials,
    *,
    job_id: str,
    hostname: str,
    zone_name: str,
    cloudflare_api_token: str,
    confirmation: str = "",
    policy: Phase5Policy | None = None,
    executor_factory: ExecutorFactory = ParamikoRemoteExecutor,
    cloudflare_factory=CloudflareClient,
) -> Phase5Plan | Phase5Result:
    policy = policy or Phase5Policy()
    if policy.mode not in {PHASE5_MODE_PLAN, PHASE5_MODE_CUTOVER}:
        raise Phase5Error(f"unsupported Phase 5 mode: {policy.mode!r}")

    source_executor = None
    destination_executor = None
    source_lock = False
    destination_lock = False
    cloudflare = cloudflare_factory(cloudflare_api_token)
    paths = _paths(job_id, policy)

    try:
        source_executor = executor_factory(source_credentials)
        destination_executor = executor_factory(destination_credentials)

        plan, source, destination, _marker = build_phase5_plan(
            source_executor,
            destination_executor,
            source_credentials,
            destination_credentials,
            job_id=job_id,
            hostname=hostname,
            zone_name=zone_name,
            cloudflare=cloudflare,
            policy=policy,
        )

        if policy.mode == PHASE5_MODE_PLAN:
            return plan

        if confirmation != policy.confirmation_phrase:
            raise Phase5Error(
                "cutover confirmation phrase did not match; "
                f"expected {policy.confirmation_phrase!r}"
            )
        if not plan.cutover_ready:
            raise Phase5Error(
                "Phase 5 cutover is blocked: " + "; ".join(plan.blockers)
            )

        acquire_final_sync_lock(
            destination_executor,
            lock_path=paths["cutover_lock"],
            job_id=job_id,
        )
        destination_lock = True
        acquire_final_sync_lock(
            source_executor,
            lock_path=paths["cutover_lock"],
            job_id=job_id,
        )
        source_lock = True

        dns_updated = False
        rollback_performed = False
        rollback_record_verified = False
        source_restarted = False
        destination_stopped = False

        try:
            before = plan.cloudflare_record
            patched = cloudflare.patch_record_content(before, plan.new_ip)
            dns_updated = True
            if patched.content != plan.new_ip:
                raise Phase5Error(
                    f"Cloudflare PATCH returned unexpected content: {patched.content}"
                )
            if patched.proxied != before.proxied:
                raise Phase5Error("Cloudflare proxy state changed unexpectedly")

            current = wait_for_record_content(
                cloudflare,
                zone_id=before.zone_id,
                hostname=plan.hostname,
                expected_ip=plan.new_ip,
                attempts=policy.verify_attempts,
                interval_seconds=policy.verify_interval_seconds,
            )
            record_verified = current.content == plan.new_ip

            api_port = int(destination.api_port or 0)
            if api_port:
                (
                    hostname_api_healthy,
                    hostname_api_detail,
                ) = wait_for_hostname_api(
                    hostname=plan.hostname,
                    port=api_port,
                    attempts=policy.verify_attempts,
                    interval_seconds=policy.verify_interval_seconds,
                    timeout=policy.connect_timeout_seconds,
                )
            else:
                hostname_api_healthy = False
                hostname_api_detail = "destination API port is missing"

            if not hostname_api_healthy:
                raise Phase5Error(
                    "Cloudflare hostname API verification failed after cutover: "
                    + hostname_api_detail
                )

            expected_ports = tuple(sorted(set(int(p) for p in destination.xray_ports)))
            verified_ports = verify_tcp_ports(
                ip=plan.new_ip,
                ports=expected_ports,
                timeout=policy.connect_timeout_seconds,
            )
            if tuple(sorted(verified_ports)) != expected_ports:
                missing = sorted(set(expected_ports) - set(verified_ports))
                raise Phase5Error(
                    "destination direct TCP verification failed after cutover: "
                    + ",".join(str(p) for p in missing)
                )

            marker_payload = {
                "job_id": job_id,
                "hostname": plan.hostname,
                "zone_name": plan.zone_name,
                "old_ip": plan.old_ip,
                "new_ip": plan.new_ip,
                "record_id": before.record_id,
                "proxied": before.proxied,
                "cloudflare_record_verified": record_verified,
                "hostname_api_healthy": hostname_api_healthy,
                "direct_ports_verified": list(verified_ports),
                "rollback_performed": False,
            }
            mark_phase4_complete(
                destination_executor,
                marker_path=paths["cutover_complete"],
                payload=marker_payload,
            )

            return Phase5Result(
                job_id=job_id,
                hostname=plan.hostname,
                zone_name=plan.zone_name,
                old_ip=plan.old_ip,
                new_ip=plan.new_ip,
                record_id=before.record_id,
                proxied=before.proxied,
                dns_updated=dns_updated,
                cloudflare_record_verified=record_verified,
                hostname_api_healthy=hostname_api_healthy,
                direct_ports_verified=verified_ports,
                rollback_performed=False,
                rollback_record_verified=False,
                source_restarted=False,
                destination_stopped_on_rollback=False,
                cutover_complete_marker=paths["cutover_complete"],
            )

        except Exception as exc:
            recovery_errors: list[str] = []
            if dns_updated and policy.rollback_on_failure:
                rollback_performed = True
                try:
                    restored = cloudflare.patch_record_content(
                        plan.cloudflare_record,
                        plan.old_ip,
                    )
                    restored = wait_for_record_content(
                        cloudflare,
                        zone_id=restored.zone_id,
                        hostname=plan.hostname,
                        expected_ip=plan.old_ip,
                        attempts=policy.verify_attempts,
                        interval_seconds=policy.verify_interval_seconds,
                    )
                    rollback_record_verified = restored.content == plan.old_ip
                except Exception as recovery_exc:
                    recovery_errors.append(
                        f"Cloudflare rollback failed: {recovery_exc}"
                    )

                if policy.stop_destination_on_rollback:
                    try:
                        if compose_running(
                            destination_executor,
                            marzban_dir=destination.marzban_dir,
                        ):
                            stop_compose(
                                destination_executor,
                                marzban_dir=destination.marzban_dir,
                            )
                        destination_stopped = not compose_running(
                            destination_executor,
                            marzban_dir=destination.marzban_dir,
                        )
                    except Exception as recovery_exc:
                        recovery_errors.append(
                            f"destination stop rollback failed: {recovery_exc}"
                        )

                if policy.restart_source_on_rollback:
                    try:
                        if not compose_running(
                            source_executor,
                            marzban_dir=source.marzban_dir,
                        ):
                            start_runtime_and_verify(
                                source_executor,
                                _runtime_metadata(source),
                                source.xray_ports,
                            )
                        source_restarted = compose_running(
                            source_executor,
                            marzban_dir=source.marzban_dir,
                        )
                    except Exception as recovery_exc:
                        recovery_errors.append(
                            f"source restart rollback failed: {recovery_exc}"
                        )

                try:
                    mark_phase4_complete(
                        destination_executor,
                        marker_path=paths["rollback_complete"],
                        payload={
                            "job_id": job_id,
                            "old_ip": plan.old_ip,
                            "new_ip": plan.new_ip,
                            "rollback_record_verified": rollback_record_verified,
                            "source_restarted": source_restarted,
                            "destination_stopped": destination_stopped,
                            "warning": (
                                "Rollback after DNS cutover can lose writes that "
                                "reached the destination before rollback."
                            ),
                            "recovery_errors": recovery_errors,
                        },
                    )
                except Exception as recovery_exc:
                    recovery_errors.append(
                        f"rollback marker write failed: {recovery_exc}"
                    )

            message = f"{type(exc).__name__}: {exc}"
            if rollback_performed:
                message += (
                    f" | rollback_record_verified={rollback_record_verified}"
                    f" source_restarted={source_restarted}"
                    f" destination_stopped={destination_stopped}"
                )
            if recovery_errors:
                message += " | recovery: " + " | ".join(recovery_errors)
            raise Phase5Error(message) from exc

    finally:
        if source_executor is not None and source_lock:
            try:
                release_final_sync_lock(
                    source_executor,
                    lock_path=paths["cutover_lock"],
                    job_id=job_id,
                )
            except Exception:
                pass
        if destination_executor is not None and destination_lock:
            try:
                release_final_sync_lock(
                    destination_executor,
                    lock_path=paths["cutover_lock"],
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
