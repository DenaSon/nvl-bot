"""Isolated, read-only-to-NVL storage for operator-owned ESP32 observations.

Data plane for NVL DenaProbe v1. NOT a filtering oracle, not an input to
6G/6H, host pool, DNS changes, or failover decisions.
"""
from __future__ import annotations

import ipaddress
import os
import re
import sqlite3
import time
from pathlib import Path
from contextlib import contextmanager

SCHEMA_VERSION = 1
DEVICE_RE = re.compile(r"^[a-zA-Z0-9_-]{3,40}$")
BOOT_RE = re.compile(r"^[a-fA-F0-9]{8,16}$")
HOST_RE = re.compile(r"^[a-zA-Z0-9.-]{3,253}$")
MAX_DURATION_MS = 120000
MAX_SEQUENCE = 2147483647
RETAIN_SECONDS = 14 * 86400

class InvalidReport(ValueError):
    pass


def _int_field(doc: dict, name: str, maximum: int, *, minimum: int = 0) -> int:
    value = doc.get(name)
    if type(value) is not int or not (minimum <= value <= maximum):
        raise InvalidReport(f"invalid_{name}")
    return value


def _optional_duration(doc: dict, name: str) -> int | None:
    value = doc.get(name)
    if value is None:
        return None
    if type(value) is not int or not (0 <= value <= MAX_DURATION_MS):
        raise InvalidReport(f"invalid_{name}")
    return value


def _optional_bool(doc: dict, name: str) -> int | None:
    value = doc.get(name)
    if value is None:
        return None
    if type(value) is not bool:
        raise InvalidReport(f"invalid_{name}")
    return int(value)


def validate_report(doc: object, *, allowed_host: str, authenticated_device: str) -> dict:
    """Validate a small, fixed schema. No raw logs or customer identifiers."""
    if not isinstance(doc, dict):
        raise InvalidReport("invalid_payload")
    if doc.get("schema_version") != SCHEMA_VERSION or type(doc.get("schema_version")) is not int:
        raise InvalidReport("unsupported_schema")
    device = doc.get("device_id")
    if not isinstance(device, str) or not DEVICE_RE.fullmatch(device):
        raise InvalidReport("invalid_device")
    if device != authenticated_device:
        raise InvalidReport("device_token_mismatch")
    boot = doc.get("boot_id")
    if not isinstance(boot, str) or not BOOT_RE.fullmatch(boot):
        raise InvalidReport("invalid_boot")
    host = doc.get("edge_host")
    if not isinstance(host, str) or not HOST_RE.fullmatch(host):
        raise InvalidReport("invalid_edge_host")
    if host.rstrip(".").lower() != allowed_host.rstrip(".").lower():
        raise InvalidReport("wrong_edge_host")
    ip = doc.get("edge_ipv4")
    if ip is not None:
        try:
            address = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            raise InvalidReport("invalid_edge_ip") from None
        if address.version != 4:
            raise InvalidReport("invalid_edge_ip")
        ip = str(address)
    carrier = doc.get("carrier_declared", "UNKNOWN")
    if carrier not in ("MCI", "IRANCELL", "RIGHTEL", "UNKNOWN"):
        raise InvalidReport("invalid_carrier")
    wifi = doc.get("wifi_rssi_dbm")
    if type(wifi) is not int or not -120 <= wifi <= 0:
        raise InvalidReport("invalid_rssi")

    result = {
        "device_id": device,
        "boot_id": boot.lower(),
        "seq": _int_field(doc, "sequence", MAX_SEQUENCE),
        "uptime_ms": _int_field(doc, "uptime_ms", MAX_SEQUENCE),
        "edge_host": host.rstrip(".").lower(),
        "edge_ipv4": ip,
        "edge_port": _int_field(doc, "edge_port", 65535, minimum=1),
        "carrier_declared": carrier,  # operator declaration, NOT verified ASN
        "wifi_rssi_dbm": wifi,
    }
    for name in ("dns_ok", "tcp_ok", "ssh_id_ok", "control_ok"):
        result[name] = _optional_bool(doc, name)
    for name in ("dns_ms", "tcp_ms", "ssh_id_ms", "control_ms"):
        result[name] = _optional_duration(doc, name)
    if result["dns_ok"] is None:
        raise InvalidReport("missing_dns_result")
    if result["dns_ok"] == 0 and (result["tcp_ok"] is not None or result["ssh_id_ok"] is not None):
        raise InvalidReport("inconsistent_dns_failure")
    if result["tcp_ok"] == 0 and result["ssh_id_ok"] is not None:
        raise InvalidReport("inconsistent_tcp_failure")
    if result["ssh_id_ok"] == 1 and (result["dns_ok"] != 1 or result["tcp_ok"] != 1):
        raise InvalidReport("inconsistent_ssh_success")
    if result["dns_ok"] == 1 and result["dns_ms"] is None:
        raise InvalidReport("missing_dns_duration")
    if result["tcp_ok"] is not None and result["tcp_ms"] is None:
        raise InvalidReport("missing_tcp_duration")
    if result["ssh_id_ok"] is not None and result["ssh_id_ms"] is None:
        raise InvalidReport("missing_ssh_duration")

    # Server reconstructs the observed stage, never trusts a client "healthy" flag.
    if result["dns_ok"] == 0:
        result["stage"] = "DNS_FAIL"
    elif result["tcp_ok"] == 0:
        result["stage"] = "TCP_FAIL"
    elif result["ssh_id_ok"] == 0:
        result["stage"] = "SSH_ID_FAIL"
    elif result["ssh_id_ok"] == 1:
        result["stage"] = "SSH_ID_PASS"
    else:
        raise InvalidReport("incomplete_stages")
    return result


DDL = """
CREATE TABLE IF NOT EXISTS denaprobe_reports (
    device_id TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    uptime_ms INTEGER NOT NULL,
    edge_host TEXT NOT NULL,
    edge_ipv4 TEXT,
    edge_port INTEGER NOT NULL,
    carrier_declared TEXT NOT NULL,
    wifi_rssi_dbm INTEGER NOT NULL,
    dns_ok INTEGER,
    dns_ms INTEGER,
    tcp_ok INTEGER,
    tcp_ms INTEGER,
    ssh_id_ok INTEGER,
    ssh_id_ms INTEGER,
    control_ok INTEGER,
    control_ms INTEGER,
    stage TEXT NOT NULL,
    PRIMARY KEY (device_id, boot_id, seq)
);
CREATE INDEX IF NOT EXISTS denaprobe_by_device_time
ON denaprobe_reports(device_id, received_at DESC);
"""


@contextmanager
def open_db(db_path: str, *, readonly: bool = False):
    if readonly:
        connection = sqlite3.connect(Path(db_path).resolve().as_uri() + "?mode=ro", uri=True, timeout=3)
    else:
        connection = sqlite3.connect(db_path, timeout=5)
        connection.execute("PRAGMA busy_timeout=5000")
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        if not readonly:
            connection.commit()
    except BaseException:
        if not readonly:
            connection.rollback()
        raise
    finally:
        connection.close()


def init_db(db_path: str) -> None:
    Path(db_path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with open_db(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(DDL)


def save_report(db_path: str, report: dict, *, received_at: int | None = None) -> bool:
    """Idempotent on (device, boot, sequence). Returns True only for new samples."""
    now = int(time.time()) if received_at is None else int(received_at)
    fields = (
        "device_id", "boot_id", "seq", "received_at", "uptime_ms",
        "edge_host", "edge_ipv4", "edge_port", "carrier_declared", "wifi_rssi_dbm",
        "dns_ok", "dns_ms", "tcp_ok", "tcp_ms", "ssh_id_ok", "ssh_id_ms",
        "control_ok", "control_ms", "stage",
    )
    values = dict(report)
    values["received_at"] = now
    sql = (
        f"INSERT OR IGNORE INTO denaprobe_reports ({', '.join(fields)}) "
        f"VALUES ({', '.join('?' for _ in fields)})"
    )
    with open_db(db_path) as conn:
        cursor = conn.execute(sql, tuple(values[name] for name in fields))
        inserted = cursor.rowcount == 1
        # Prune with a bounded cadence; no other NVL tables are ever touched.
        if inserted and report["seq"] % 100 == 0:
            conn.execute("DELETE FROM denaprobe_reports WHERE received_at < ?", (now - RETAIN_SECONDS,))
        return inserted


def latest_reports(db_path: str, *, limit: int = 10) -> list[dict]:
    """Read-only SQLite query; return last server-received sample per device."""
    if not os.path.isfile(db_path):
        return []
    with open_db(db_path, readonly=True) as conn:
        rows = conn.execute(
            """SELECT r.* FROM denaprobe_reports r
               WHERE r.rowid = (
                   SELECT r2.rowid FROM denaprobe_reports r2
                   WHERE r2.device_id = r.device_id
                   ORDER BY r2.received_at DESC, r2.rowid DESC LIMIT 1
               )
               ORDER BY r.received_at DESC LIMIT ?""",
            (min(max(limit, 1), 20),),
        ).fetchall()
        return [dict(row) for row in rows]
