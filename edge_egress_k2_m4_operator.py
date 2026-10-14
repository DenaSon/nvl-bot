"""K2 M4 operator read-only live preview: no guessed UID/source/session.

Uses only Linux passwd UID, M2 root-owned short-lived PAM/WG ingress journal
and M1 F4/control-plane preview. If privileged proof is missing, render HOLD.
No sudo/shell execution, DB writes, network mutation or approval issuance.
"""
from __future__ import annotations

import os
import pwd
import subprocess
import time
from typing import Callable

from edge_egress_k2_migration_inventory import (
    MigrationSelection, MigrationInventory, preview_migration,
)
from edge_egress_k2_m2_ingress_journal import (
    DurableIngressHold, make_m1_readonly_ingress_provider,
)


def inspect_telegram_migration(
    db_conn: Callable, selection: MigrationSelection, *,
    now: int | None = None,
    uid_lookup: Callable[[str],int] | None = None,
    source_provider: Callable | None = None,
    session_provider: Callable | None = None,
    geteuid: Callable[[],int] = os.geteuid,
    run: Callable = subprocess.run,
) -> MigrationInventory:
    """Preview only. Optional injected providers support hermetic tests.

    Session count MUST be from independent, trusted sshd session evidence.
    Zero is never inferred from /proc process absence or old DB host fields.
    """
    ts=int(time.time()) if now is None else now
    if not isinstance(selection,MigrationSelection) or not callable(db_conn):
        raise ValueError("M4_SELECTION_OR_DB_UNTRUSTED")
    if type(ts) is not int or ts<=0:
        raise ValueError("M4_TIME_UNTRUSTED")
    uid_fn = uid_lookup or (lambda name:pwd.getpwnam(name).pw_uid)
    if source_provider is None and geteuid()==0:
        try:
            source_provider=make_m1_readonly_ingress_provider(
                now=ts,run=run,geteuid=geteuid,resolve_uid=uid_fn)
        except (DurableIngressHold,OSError,ValueError,KeyError,TypeError):
            # Explicit unknown evidence, never historical-DB fallback.
            source_provider=None
    if source_provider is not None and not callable(source_provider):
        raise ValueError("M4_INGRESS_PROVIDER_UNTRUSTED")
    if session_provider is not None and not callable(session_provider):
        raise ValueError("M4_SESSION_PROVIDER_UNTRUSTED")
    return preview_migration(
        db_conn,selection,os_uid=uid_fn,
        ingress_witness=source_provider,
        session_count=session_provider,now=ts,
    )
