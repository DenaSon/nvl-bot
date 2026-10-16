"""Read-only legacy privilege review; prints unresolved sink inventory, exits HOLD."""
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path

from edge_egress_k2_a3_privilege_audit import audit_legacy_bot_file


def main() -> int:
    project=Path(__file__).resolve().parents[1]
    report=audit_legacy_bot_file(project/"bot_final_v49-2.py")
    print(json.dumps({
        "state":"HOLD",
        "source_sha256":report.source_sha256,
        "functions_scanned":report.functions_scanned,
        "dynamic_calls":report.dynamic_calls,
        "privileged_or_review_calls":len(report.callsites),
        "ready_for_nonroot":report.ready_for_nonroot,
        "callsites":[asdict(x) for x in report.callsites],
    },ensure_ascii=False,sort_keys=True,indent=2))
    return 78


if __name__=="__main__":
    raise SystemExit(main())
