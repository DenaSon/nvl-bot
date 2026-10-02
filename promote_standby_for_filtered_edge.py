#!/usr/bin/env python3
"""
promote_standby_for_filtered_edge.py
=====================================
موتورِ گامِ دومِ سیستمِ Failover (طبقِ درخواستِ صریح، بندِ ۴):

  گامِ اول (جای دیگر، فوری): وقتی یک Edge فیلتر تشخیص داده شد، دامنه بلافاصله روی Core
    ست می‌شود (کاربران چون روی Core هم Mirror شده‌اند، بی‌درنگ کانکت می‌شوند).
  گامِ دوم (همین اسکریپت): اگر یک سرورِ Standby از پیش‌آماده وجود دارد (چه به‌صورتِ خودکار،
    چه با کلیکِ دستیِ ادمین روی «فعال‌سازیِ این Edge»)، این اسکریپت را روی Core اجرا می‌کند:
    فقط اکانت‌های متعلق به همان Edgeِ فیلترشده (ستونِ host در ssh_accounts) را از راه دور،
    با همان کلید دائمیِ SSH که خودِ ربات برای مدیریتِ Edgeها استفاده می‌کند
    (edge_provision_ed25519)، روی Standby بازسازی می‌کند — دقیقاً همان منطقِ
    02_recreate_ssh_users.py، با این دو تفاوت:
      ۱) فقط اکانت‌های یک host مشخص هدف قرار می‌گیرند، نه کلِ دیتابیس.
      ۲) دستورات به‌جای اجرای محلی، یک‌جا (batch، در یک اتصالِ SSH) روی Standby اجرا می‌شوند.
  گامِ سوم (جای دیگر): orchestrator امن Phase 6G نتیجهٔ JSON را می‌خواند، فقط در صورت
    موفقیت کاملِ همهٔ اکانت‌ها DB را به‌صورت scoped/atomic تغییر می‌دهد و سپس routing را
    سوییچ می‌کند. این اسکریپت به‌صورت پیش‌فرض دیگر DB را تغییر نمی‌دهد.

این اسکریپت هم CLI مستقل است (برای دکمهٔ «فعال‌سازیِ دستیِ این Edge» در پنل) و هم قرار است
از داخلِ bot_final_v61.py با asyncio.create_subprocess_exec صدا زده شود (نگاه کنید به
bot_patch_notes.md، تابعِ _activate_standby_for_filtered_edge).

اجرا:
    python3 promote_standby_for_filtered_edge.py \\
        --filtered-host 1.2.3.4 --target-host 5.6.7.8 [--target-port 22] \\
        [--db-path /root/master_bot.db] [--ssh-key /root/.ssh/edge_provision_ed25519] \\
        [--include-inactive] [--dry-run] [--commit-db]

خروجیِ استاندارد: یک خط JSON خلاصه در انتها (برای پارس‌شدنِ آسان توسطِ ربات) + پیام‌های
خوانا برای انسان قبل از آن. کدِ خروج: ۰ = همهٔ اکانت‌های هدف با موفقیت rebuild شدند
(یا لیست خالی بود)، ۲ = خطای زیرساختی یا هرگونه partial failure.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys

try:
    import paramiko
except ImportError:
    paramiko = None


def _default_db_path() -> str:
    return os.environ.get("BOT_DB_PATH") or os.path.join(
        os.environ.get("BOT_DIR_OVERRIDE", "/root"), "master_bot.db"
    )


def _fetch_accounts(db_path: str, filtered_host: str, include_inactive: bool):
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        base = "SELECT username, password, expire_date FROM ssh_accounts WHERE host = ? AND service_type='ssh'"
        if not include_inactive:
            base += " AND status LIKE '%فعال%' AND status NOT LIKE '%غیر%'"
        cur.execute(base, (filtered_host,))
        return cur.fetchall()
    finally:
        conn.close()


def _mark_accounts_host(db_path: str, usernames: list[str], new_host: str):
    if not usernames:
        return
    conn = sqlite3.connect(db_path)
    try:
        conn.executemany(
            "UPDATE ssh_accounts SET host=? WHERE username=?",
            [(new_host, u) for u in usernames],
        )
        conn.commit()
    finally:
        conn.close()


_REMOTE_BATCH_SCRIPT = r"""
set -u
while IFS=$'\t' read -r un pw exp; do
    [ -z "$un" ] && continue
    if id "$un" >/dev/null 2>&1; then
        usermod -e "$exp" "$un" >/tmp/.nvl_err 2>&1
    else
        useradd -s /bin/false -e "$exp" "$un" >/tmp/.nvl_err 2>&1
        if [ $? -ne 0 ]; then
            echo "FAIL:${un}:$(cat /tmp/.nvl_err | tr '\n' ' ')"
            continue
        fi
    fi
    if printf '%s:%s\n' "$un" "$pw" | chpasswd >/tmp/.nvl_err2 2>&1; then
        echo "OK:${un}"
    else
        echo "FAIL:${un}:$(cat /tmp/.nvl_err2 | tr '\n' ' ')"
    fi
done
rm -f /tmp/.nvl_err /tmp/.nvl_err2
"""


def _run_batch_on_standby(target_host: str, target_port: int, ssh_key_path: str,
                           rows: list[tuple], timeout: int = 120):
    """
    خروجی: (ok_usernames: list[str], failed: list[tuple[str, str]], error: str|None)
    error فقط وقتی مقدار دارد که خودِ اتصال/اجرا (نه یک اکانتِ تکی) شکست خورده باشد.
    """
    if paramiko is None:
        return [], [], "کتابخانهٔ paramiko نصب نیست (pip install paramiko --break-system-packages)."
    if not os.path.exists(ssh_key_path):
        return [], [], f"کلیدِ SSH پیدا نشد: {ssh_key_path}"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        pkey = paramiko.Ed25519Key.from_private_key_file(ssh_key_path)
        ssh.connect(target_host, port=target_port, username="root", pkey=pkey,
                    timeout=15, banner_timeout=20)
    except Exception as e:
        return [], [], f"اتصالِ SSH به Standby ({target_host}:{target_port}) شکست خورد: {e}"

    try:
        stdin, stdout, stderr = ssh.exec_command(
            f"bash -c {_shell_quote(_REMOTE_BATCH_SCRIPT)}", timeout=timeout
        )
        payload = "".join(f"{un}\t{pw}\t{exp}\n" for un, pw, exp in rows)
        stdin.write(payload)
        stdin.channel.shutdown_write()
        out = stdout.read().decode(errors="ignore")
        err_txt = stderr.read().decode(errors="ignore").strip()
    except Exception as e:
        return [], [], f"اجرای batch روی Standby شکست خورد: {e}"
    finally:
        ssh.close()

    ok, failed = [], []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("OK:"):
            ok.append(line[3:])
        elif line.startswith("FAIL:"):
            _, _, rest = line.partition(":")
            un, _, reason = rest.partition(":")
            failed.append((un, reason))
    if not ok and not failed and err_txt:
        return [], [], f"خروجیِ نامعتبر از Standby (هیچ OK/FAIL برنگشت): {err_txt}"
    return ok, failed, None


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--filtered-host", required=True, help="آی‌پیِ Edgeِ فیلترشده (همان مقدارِ ستونِ host)")
    ap.add_argument("--target-host", required=True, help="آی‌پیِ سرورِ Standby مقصد")
    ap.add_argument("--target-port", type=int, default=22)
    ap.add_argument("--db-path", default=_default_db_path())
    ap.add_argument("--ssh-key", default="/root/.ssh/edge_provision_ed25519")
    ap.add_argument("--include-inactive", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument(
        "--commit-db",
        action="store_true",
        help="Legacy/standalone mode only: after complete success, update only rebuilt usernames in DB. Phase 6G bot orchestration does not use this.",
    )
    args = ap.parse_args()

    if not os.path.exists(args.db_path):
        print(f"❌ دیتابیس پیدا نشد: {args.db_path}", file=sys.stderr)
        sys.exit(2)

    rows = _fetch_accounts(args.db_path, args.filtered_host, args.include_inactive)
    print(f"📋 {len(rows)} اکانتِ متعلق به {args.filtered_host} برای بازسازی روی {args.target_host} پیدا شد.")

    if not rows:
        print(json.dumps({
            "ok": True,
            "source_host": args.filtered_host,
            "target_host": args.target_host,
            "requested": 0,
            "rebuilt": 0,
            "failed": 0,
            "rebuilt_usernames": [],
            "failed_usernames": [],
            "db_committed": False,
        }))
        sys.exit(0)

    if args.dry_run:
        for un, _pw, exp in rows:
            print(f"  🔍 [dry-run] بازسازی می‌شد: {un} (انقضا: {exp})")
        print(json.dumps({
            "ok": True,
            "dry_run": True,
            "source_host": args.filtered_host,
            "target_host": args.target_host,
            "requested": len(rows),
            "would_rebuild": len(rows),
            "usernames": [un for un, _pw, _exp in rows],
            "db_committed": False,
        }))
        sys.exit(0)

    ok, failed, error = _run_batch_on_standby(args.target_host, args.target_port, args.ssh_key, rows)
    if error:
        print(f"❌ خطای زیرساختی: {error}", file=sys.stderr)
        print(json.dumps({"ok": False, "error": error, "target_host": args.target_host}))
        sys.exit(2)

    for un in ok:
        print(f"  ✅ {un} روی Standby بازسازی شد.")
    for un, reason in failed:
        print(f"  ❌ {un} شکست خورد: {reason}")

    complete_success = len(ok) == len(rows) and not failed
    db_committed = False

    # Phase 6G default is rebuild-only. Keeping DB mutation behind an explicit flag
    # prevents the helper from racing the orchestrator or leaving partial host moves.
    if complete_success and args.commit_db and ok:
        _mark_accounts_host(args.db_path, ok, args.target_host)
        db_committed = True
        print(f"🔄 [legacy --commit-db] ستون host برای {len(ok)} اکانت به {args.target_host} به‌روز شد.")

    print(f"\n=== خلاصه: {len(ok)} موفق، {len(failed)} ناموفق، از کلِ {len(rows)} ===")
    print(json.dumps({
        "ok": complete_success,
        "source_host": args.filtered_host,
        "target_host": args.target_host,
        "requested": len(rows),
        "rebuilt": len(ok),
        "failed": len(failed),
        "rebuilt_usernames": ok,
        "failed_usernames": [u for u, _ in failed],
        "db_committed": db_committed,
    }))
    sys.exit(0 if complete_success else 2)


if __name__ == "__main__":
    main()