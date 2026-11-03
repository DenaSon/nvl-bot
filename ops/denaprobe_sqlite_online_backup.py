#!/usr/bin/env python3
"""Atomic, operator-selected online SQLite backup of DenaProbe history.

Does NOT modify the source DB, delete records, change live state, or copy
private HMAC keys. Can be run while collector is active (SQLite backup API).
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import sqlite3


def snapshot(source: Path, destination: Path):
    if not source.is_file() or source.is_symlink():
        raise ValueError("source database missing, nonregular or symlink")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("refusing to overwrite existing backup")
    if source.resolve() == destination.resolve():
        raise ValueError("source and destination coincide")
    if not destination.parent.is_dir():
        raise ValueError("destination directory must exist and be restricted")
    if destination.parent.stat().st_mode & 0o077:
        raise PermissionError("backup directory must be private 0700")
    uri = "file:" + str(source.resolve()) + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=30) as old:
        if old.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise RuntimeError("source quick_check failed")
        try:
            with sqlite3.connect(destination) as new:
                os.chmod(destination, 0o600)
                old.backup(new, pages=128, sleep=0.05)
                if new.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise RuntimeError("backup quick_check failed")
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
    return {"backup": str(destination), "status": "VERIFIED", "mode": "0600"}


def main():
    parser = argparse.ArgumentParser(description="Online backup; never deletes the original")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    # No private data in stdout except the operator-chosen destination path.
    result = snapshot(args.source, args.destination)
    print("DPT_R3_BACKUP_VERIFIED=" + result["backup"])


if __name__ == "__main__":
    main()
