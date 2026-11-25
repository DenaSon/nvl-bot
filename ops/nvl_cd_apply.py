"""Accepted Core-only automatic release tick. Never enables itself."""
import json
import os
import sqlite3
import subprocess
import sys
import time

if __package__:
    from . import nvl_cd_planner as p
    from . import nvl_cd_publisher as pub
else:
    import nvl_cd_planner as p
    import nvl_cd_publisher as pub


def planner_disabled():
    # Only one scheduler should consume the discovery/API cooldown.
    # Unknown systemd state is not equivalent to a disabled timer.
    raw = subprocess.check_output(
        ["/usr/bin/systemctl", "show", "nvl-deploy-plan.timer",
         "-p", "ActiveState", "-p", "UnitFileState"],
        text=True, timeout=10, stderr=subprocess.DEVNULL)
    status = dict(line.split("=", 1) for line in raw.splitlines())
    return (status.get("ActiveState") == "inactive"
            and status.get("UnitFileState") in ("disabled", "masked"))


def tick(state, config, now=time.time):
    # Caller holds the existing non-blocking deploy/observer lock.
    checkpoint = state / "release-state.json"
    saved = p.load_json(checkpoint) if checkpoint.exists() else None
    if saved and saved["phase"] not in pub.FINAL:
        return {"status": "RECOVERY_REQUIRED"}
    try:
        plan = p.poll(config, state, now=now)
    except p.Hold as exc:
        plan = {"status": "HOLD", "reason": str(exc)}
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        pub.report_failure("DISCOVERY", exc)
        plan = {"status": "HOLD", "reason": "DISCOVERY_FAILED"}
    plan.update(mode="AUTO_APPLY", apply_enabled=True, observed_at=int(now()))
    pub.durable_json(state / "latest-plan.json", plan)
    if plan["status"] != "PLAN_READY":
        return {"status": plan["status"], "reason": plan.get("reason")}
    candidate = p.exact_sha(plan["candidate"])
    baseline = p.exact_sha(saved["deployed"] if saved else config["baseline"])
    if candidate == baseline or plan.get("baseline") != baseline:
        return {"status": "STALE_PLAN"}
    if saved and saved["phase"] == "ROLLED_BACK" and saved["candidate"] == candidate:
        return {"status": "FAILED_CANDIDATE_REQUIRES_REVIEW", "candidate": candidate}
    # Ordinary busy operations defer automatically, without changing their
    # state or acquiring a lock in the application.
    if plan["updates"]:
        host = pub.Host()
        if not host.active() or not host.idle():
            return {"status": "BOT_OR_OPERATION_BUSY", "candidate": candidate}
    # Recheck acceptance immediately before release, including config
    # changes. Planner output is only a hint; release revalidates everything.
    if pub.accepted_config() != config:
        raise p.Hold("ACCEPTANCE_CONFIG_CHANGED")
    try:
        result = pub.release(state, config, candidate)
    except p.Hold as exc:
        return {"status": "DEFERRED", "reason": str(exc), "candidate": candidate}
    return {key: result.get(key) for key in ("phase", "candidate", "deployed", "reason")}


def main():
    os.umask(0o077)
    try:
        if os.geteuid() != 0:
            raise p.Hold("ROOT_REQUIRED")
        config = pub.accepted_config()
        if not planner_disabled():
            raise p.Hold("DISABLE_DRY_RUN_TIMER_FIRST")
        state = p.trusted(pub.STATE, directory=True)
        with pub.exclusive(state):
            result = tick(state, config)
    except (FileNotFoundError, BlockingIOError):
        result = {"status": "NOT_ACCEPTED_OR_BUSY"}
    except p.Hold as exc:
        result = {"status": "DEFERRED", "reason": str(exc)}
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, subprocess.SubprocessError) as exc:
        pub.report_failure("AUTO_APPLY", exc)
        result = {"status": "DEFERRED", "reason": "LOCAL_OR_RELEASE_CHECK_FAILED"}
    print(json.dumps(result, sort_keys=True))
    return 2 if result.get("phase") == "HOLD" or result.get("status") == "RECOVERY_REQUIRED" else 0


if __name__ == "__main__":
    sys.exit(main())
