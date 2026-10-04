from __future__ import annotations

import ipaddress
import re
import threading
from dataclasses import dataclass, field
from typing import Any

from .models import ServerCredentials
from .phase2 import run_phase2
from .phase3 import run_phase3
from .phase3_models import PHASE3_MODE_RESTORE, Phase3Policy
from .phase4 import run_phase4
from .phase4_models import PHASE4_MODE_FINALIZE, PHASE4_MODE_PLAN, Phase4Policy
from .phase5 import run_phase5
from .phase5_models import PHASE5_MODE_CUTOVER, PHASE5_MODE_PLAN, Phase5Policy
from .preflight import run_preflight


class TelegramWizardError(RuntimeError):
    pass


class TelegramWizardBusy(TelegramWizardError):
    pass


_HOST_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def normalize_host(value: str) -> str:
    raw = str(value or "").strip().rstrip(".")
    if not raw or len(raw) > 253 or any(ch.isspace() for ch in raw):
        raise ValueError("invalid host")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        pass
    labels = raw.split(".")
    if not all(_HOST_LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("invalid host")
    return raw.lower()


def normalize_port(value: str | int) -> int:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    return port


def normalize_dns_name(value: str) -> str:
    name = normalize_host(value)
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ValueError("DNS name cannot be an IP address")


def suggest_zone(hostname: str) -> str:
    try:
        name = normalize_dns_name(hostname)
    except ValueError:
        return ""
    parts = name.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else ""


@dataclass
class TelegramMigrationSession:
    chat_id: int
    source_host: str = ""
    source_port: int = 22
    source_password: str | None = field(default=None, repr=False)
    destination_host: str = ""
    destination_port: int = 22
    destination_password: str | None = field(default=None, repr=False)
    hostname: str = ""
    zone_name: str = ""
    suggested_hostname: str = ""
    suggested_zone: str = ""
    stage: str = "SOURCE_HOST"
    busy: bool = False
    preflight: Any = field(default=None, repr=False)
    job_id: str = ""
    last_result: Any = field(default=None, repr=False)
    last_error: str = ""

    def source_credentials(self) -> ServerCredentials:
        if not self.source_host or not self.source_password:
            raise TelegramWizardError("source credentials are incomplete")
        return ServerCredentials(
            host=self.source_host,
            port=self.source_port,
            username="root",
            password=self.source_password,
        )

    def destination_credentials(self) -> ServerCredentials:
        if not self.destination_host or not self.destination_password:
            raise TelegramWizardError("destination credentials are incomplete")
        return ServerCredentials(
            host=self.destination_host,
            port=self.destination_port,
            username="root",
            password=self.destination_password,
        )

    def scrub_secrets(self) -> None:
        self.source_password = None
        self.destination_password = None
        self.preflight = None
        self.last_result = None

    def safe_summary(self) -> dict[str, Any]:
        return {
            "chat_id": self.chat_id,
            "source_host": self.source_host,
            "source_port": self.source_port,
            "destination_host": self.destination_host,
            "destination_port": self.destination_port,
            "hostname": self.hostname,
            "zone_name": self.zone_name,
            "stage": self.stage,
            "busy": self.busy,
            "job_id": self.job_id,
            "last_error": self.last_error,
        }


_SESSIONS: dict[int, TelegramMigrationSession] = {}
_SESSIONS_LOCK = threading.RLock()


def begin_session(
    chat_id: int,
    *,
    suggested_hostname: str = "",
    suggested_zone: str = "",
) -> TelegramMigrationSession:
    chat_id = int(chat_id)
    with _SESSIONS_LOCK:
        for owner, session in list(_SESSIONS.items()):
            if owner != chat_id:
                raise TelegramWizardBusy(
                    "another administrator already has an active Marzban migration wizard"
                )
        old = _SESSIONS.pop(chat_id, None)
        if old is not None:
            old.scrub_secrets()
        session = TelegramMigrationSession(
            chat_id=chat_id,
            suggested_hostname=str(suggested_hostname or "").strip(),
            suggested_zone=str(suggested_zone or "").strip(),
        )
        _SESSIONS[chat_id] = session
        return session


def get_session(chat_id: int) -> TelegramMigrationSession | None:
    with _SESSIONS_LOCK:
        return _SESSIONS.get(int(chat_id))


def require_session(chat_id: int) -> TelegramMigrationSession:
    session = get_session(chat_id)
    if session is None:
        raise TelegramWizardError("migration wizard session is not active")
    return session


def cancel_session(chat_id: int) -> None:
    with _SESSIONS_LOCK:
        session = _SESSIONS.pop(int(chat_id), None)
    if session is not None:
        session.scrub_secrets()


def finish_session(chat_id: int) -> None:
    cancel_session(chat_id)


def _begin_step(session: TelegramMigrationSession, allowed_stages: set[str]) -> None:
    if session.busy:
        raise TelegramWizardBusy("a migration step is already running")
    if session.stage not in allowed_stages:
        raise TelegramWizardError(
            f"step is not allowed from stage {session.stage!r}"
        )
    session.busy = True
    session.last_error = ""


def _end_step(
    session: TelegramMigrationSession,
    *,
    stage: str | None = None,
    result: Any = None,
    error: Exception | None = None,
) -> None:
    session.busy = False
    if error is not None:
        session.last_error = f"{type(error).__name__}: {error}"
        return
    session.last_result = result
    if stage:
        session.stage = stage


def run_preflight_step(session: TelegramMigrationSession):
    _begin_step(session, {"READY_FOR_PREFLIGHT", "PREFLIGHT_FAILED"})
    try:
        report = run_preflight(
            session.source_credentials(),
            session.destination_credentials(),
        )
        session.preflight = report
        _end_step(
            session,
            stage="PREFLIGHT_READY" if report.ready else "PREFLIGHT_FAILED",
            result=report,
        )
        return report
    except Exception as exc:
        _end_step(session, error=exc)
        raise


def run_backup_step(session: TelegramMigrationSession):
    _begin_step(session, {"PREFLIGHT_READY"})
    try:
        if session.preflight is None or not session.preflight.ready:
            raise TelegramWizardError("successful preflight is required")
        result = run_phase2(
            session.preflight,
            session.source_credentials(),
            session.destination_credentials(),
        )
        session.job_id = result.job_id
        _end_step(session, stage="BACKUP_COMPLETE", result=result)
        return result
    except Exception as exc:
        _end_step(session, error=exc)
        raise


def run_restore_step(session: TelegramMigrationSession):
    _begin_step(session, {"BACKUP_COMPLETE"})
    try:
        if not session.job_id:
            raise TelegramWizardError("migration job id is missing")
        result = run_phase3(
            session.destination_credentials(),
            job_id=session.job_id,
            policy=Phase3Policy(
                mode=PHASE3_MODE_RESTORE,
                start_runtime=False,
            ),
        )
        _end_step(session, stage="RESTORE_COMPLETE", result=result)
        return result
    except Exception as exc:
        _end_step(session, error=exc)
        raise


def run_final_plan_step(session: TelegramMigrationSession):
    _begin_step(session, {"RESTORE_COMPLETE", "FINAL_PLAN_BLOCKED"})
    try:
        result = run_phase4(
            session.source_credentials(),
            session.destination_credentials(),
            job_id=session.job_id,
            policy=Phase4Policy(mode=PHASE4_MODE_PLAN),
        )
        _end_step(
            session,
            stage="FINAL_PLAN_READY" if result.finalization_ready else "FINAL_PLAN_BLOCKED",
            result=result,
        )
        return result
    except Exception as exc:
        _end_step(session, error=exc)
        raise


def run_final_sync_step(session: TelegramMigrationSession):
    _begin_step(session, {"FINAL_PLAN_READY"})
    try:
        result = run_phase4(
            session.source_credentials(),
            session.destination_credentials(),
            job_id=session.job_id,
            confirmation="FINAL-SYNC",
            policy=Phase4Policy(mode=PHASE4_MODE_FINALIZE),
        )
        _end_step(session, stage="FINAL_SYNC_COMPLETE", result=result)
        return result
    except Exception as exc:
        _end_step(session, error=exc)
        raise


def run_cutover_plan_step(session: TelegramMigrationSession):
    _begin_step(session, {"FINAL_SYNC_COMPLETE", "CUTOVER_PLAN_BLOCKED"})
    try:
        if not session.hostname or not session.zone_name:
            raise TelegramWizardError("Cloudflare hostname/zone are incomplete")
        result = run_phase5(
            session.source_credentials(),
            session.destination_credentials(),
            job_id=session.job_id,
            hostname=session.hostname,
            zone_name=session.zone_name,
            policy=Phase5Policy(mode=PHASE5_MODE_PLAN),
        )
        _end_step(
            session,
            stage="CUTOVER_PLAN_READY" if result.cutover_ready else "CUTOVER_PLAN_BLOCKED",
            result=result,
        )
        return result
    except Exception as exc:
        _end_step(session, error=exc)
        raise


def run_cutover_step(session: TelegramMigrationSession):
    _begin_step(session, {"CUTOVER_PLAN_READY"})
    try:
        result = run_phase5(
            session.source_credentials(),
            session.destination_credentials(),
            job_id=session.job_id,
            hostname=session.hostname,
            zone_name=session.zone_name,
            confirmation="CUTOVER",
            policy=Phase5Policy(mode=PHASE5_MODE_CUTOVER),
        )
        _end_step(session, stage="CUTOVER_COMPLETE", result=result)
        return result
    except Exception as exc:
        _end_step(session, error=exc)
        raise
