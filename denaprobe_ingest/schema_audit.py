"""DenaProbe R3 offline schema doctor and fresh-DB initializer.

This module never deletes/clears historical telemetry. The preferred clean
pilot is a NEW SQLite file and a retained ONLINE backup of the old one.
The historical DB and private devices.json are managed separately.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3

from denaprobe_ingest import collector, dpt2, detector

SCHEMA = {
    "devices": {"id", "current_boot", "enabled"},
    "targets": {"target_id", "revision", "hostname", "port"},
    "device_boots": {"device_id", "boot_id", "max_sequence", "registered"},
    "telemetry_events": {"device_id", "boot_id", "sequence", "raw_json", "history_only"},
    "device_latest_state": {"device_id", "boot_id", "ssh_sequence", "https_sequence", "monitoring_gap"},
    "dpt2_events": {"device_id", "boot_id", "sequence", "target_revision",
                    "raw_json", "history_only", "tcp_code", "deep_code", "https_code",
                    "sender_age_ms", "received_at_ms"},
    "dpt2_boots": {"device_id", "boot_id", "max_sequence", "registered"},
    "dpt2_latest": {"device_id", "boot_id", "ssh_sequence", "https_sequence",
                    "monitoring_gap"},
    "dp3_states": {"device_id", "target_id", "revision", "last_seq",
                   "candidate", "streak", "observation", "open_incident"},
    "dp3_incidents": {"id", "device_id", "target_id", "revision",
                      "observed_class", "confidence", "opened_at",
                      "recovered_at", "superseded_at"},
    "dp3_transitions": {"id", "incident_id", "kind", "evidence_sequence"},
    "dp3_delivery": {"transition_id", "recipient_id", "status",
                     "attempt", "updated_at"},
    "dp3_rich_cards": {"chat_id", "actor", "message_id"},
    "dp3_operator_labels": {"device_id", "declared_operator"},
}

INDEXES = {
    "ix_dpt2_history", "ix_dp3_incidents_active",
    "ix_dp3_transitions_created",
}


def fresh_prepare(path: Path) -> dict:
    if path.exists() or path.is_symlink():
        raise FileExistsError("refusing to overwrite or reinitialize an existing database")
    if sqlite3.sqlite_version_info < (3, 24, 0):
        raise RuntimeError("SQLite >=3.24 required for UPSERT")
    # Creation happens only in the operator-selected new DB path, never by
    # renaming/moving the existing DB (WAL may be live).
    collector.initialize(path)
    dpt2.initialize(path)
    with closing(collector.connect_db(path)) as db:
        detector.initialize(db)
    os.chmod(path, 0o600)
    return audit(path)


def audit(path: Path) -> dict:
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError("database missing or not a regular file")
    uri = "file:" + str(path.resolve()) + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=5)) as db:
        result = db.execute("PRAGMA quick_check").fetchone()[0]
        bad_fk = db.execute("PRAGMA foreign_key_check").fetchall()
        journal = db.execute("PRAGMA journal_mode").fetchone()[0]
        tables = {r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        indexes = {r[0] for r in db.execute(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        missing = {name: sorted(fields - {
            c[1] for c in db.execute(f'PRAGMA table_info("{name}")')
        }) for name, fields in SCHEMA.items() if name in tables}
        missing = {name: fields for name, fields in missing.items() if fields}
        missing_tables = sorted(SCHEMA.keys() - tables)
        missing_indexes = sorted(INDEXES - indexes)
        counts = {name: db.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
                  for name in SCHEMA if name in tables}
    status = (result == "ok" and not bad_fk and not missing_tables and
              not missing and not missing_indexes)
    return {
        "schema": "DPT/1+DPT/2+DP3",
        "status": "PASS" if status else "FAIL",
        "sqlite": sqlite3.sqlite_version,
        "journal": journal,
        "quick_check": result,
        "foreign_key_errors": len(bad_fk),
        "missing_tables": missing_tables,
        "missing_columns": missing,
        "missing_indexes": missing_indexes,
        "rows": counts,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Read-only DenaProbe R3 audit or explicit fresh DB prepare")
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("operation", choices=("audit", "prepare-fresh"))
    args = parser.parse_args()
    result = (fresh_prepare(args.db) if args.operation == "prepare-fresh"
              else audit(args.db))
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] != "PASS":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
