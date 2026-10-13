"""Reviewable stage-only source patch for the large NVL Telegram entrypoint.

The GitHub connector cannot replace the >1MB entrypoint in one write.
This helper edits ONLY a pinned, non-production Git worktree copy when run
explicitly with --apply; it never touches /root/bot_final_v49-2.py.
The reviewed Phase-2 retirement logic itself is edge_egress_phase2_retire.py.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile
import os
import sys

PINNED_BLOB = "79c83787d24ef7c1be1b94fe7fe5bcc0b88d7ffc"
BOT_FILENAME = "bot_final_v49-2.py"


def _once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError("SOURCE_DRIFT_OR_ALREADY_PATCHED")
    return source.replace(old, new, 1)


def patch_source(source: str) -> str:
    source = _once(
        source,
        "from edge_egress_f3_admin import render_assignment_preview",
        """from edge_egress_phase2_retire import (
    plan_retirement as plan_egress_retirement,
    issue_ticket as issue_egress_retire_ticket,
    retire_metadata as apply_egress_retire_metadata,
    legacy_delete_managed as is_managed_egress_deletion,
    plan_html as egress_retire_plan_html,
    RetireHold,
)
from edge_egress_f3_admin import render_assignment_preview"""
    )

    source = _once(
        source,
        '    elif d == "hpeg_status" or d.startswith("hpeg_page_"):',
        """    elif d.startswith("hpeg_retire_open_") or d.startswith("hpeg_retire_yes_"):
        # Metadata-only, always refuse if any WG/UID/route/Stage dependency.
        if role != 'admin':
            await query.message.reply_text("⛔️ فقط مدیر")
            return
        is_confirm = d.startswith("hpeg_retire_yes_")
        edge_id = d[len("hpeg_retire_yes_" if is_confirm else "hpeg_retire_open_"):]
        try:
            edge_id_checked(edge_id)
            actor_id = update.effective_user.id
            chat_id = update.effective_chat.id
            if is_confirm:
                # Remove one-shot ticket BEFORE awaiting any I/O.
                ticket = context.user_data.pop('egress_retire_ticket', None)
                backup_dir = await asyncio.to_thread(
                    apply_egress_retire_metadata, db_conn, ticket,
                    actor_id=actor_id, chat_id=chat_id, edge_id=edge_id,
                )
                log.warning("K2 egress metadata retired: edge=%s backup=%s",
                            edge_id, backup_dir)
                await query.edit_message_text(
                    "✅ <b>Edge از فهرست NVL حذف شد.</b>\\n"
                    "هیچ مسیر شبکه، کاربر، WG یا DNS تغییر نکرد.",
                    parse_mode="HTML",
                    reply_markup=InlineKeyboardMarkup([
                        [InlineKeyboardButton("🔙 مدیریت Egress",
                                              callback_data="hpeg_status")],
                    ]),
                )
            else:
                context.user_data.pop('egress_retire_ticket', None)
                plan = await asyncio.to_thread(
                    plan_egress_retirement, db_conn, edge_id,
                )
                buttons = []
                if plan.allowed:
                    context.user_data['egress_retire_ticket'] = (
                        issue_egress_retire_ticket(plan, actor_id, chat_id)
                    )
                    buttons.append([InlineKeyboardButton(
                        "✅ تأیید حذف از NVL",
                        callback_data=f"hpeg_retire_yes_{edge_id}",
                    )])
                buttons.append([InlineKeyboardButton(
                    "❌ انصراف / جزئیات", callback_data=f"hpeg_edge_{edge_id}",
                )])
                await query.edit_message_text(
                    egress_retire_plan_html(plan), parse_mode="HTML",
                    reply_markup=InlineKeyboardMarkup(buttons),
                )
        except (RetireHold, EgressConsoleHold, ValueError, OSError, sqlite3.Error):
            context.user_data.pop('egress_retire_ticket', None)
            await query.edit_message_text(
                "⛔️ <b>HOLD — حذف Edge مجاز نیست.</b>\\n"
                "وابستگی‌ها یا تأیید عملیات تغییر کرده‌اند؛ هیچ عملیاتی اجرا نشد.",
                parse_mode="HTML",
                reply_markup=InlineKeyboardMarkup([
                    [InlineKeyboardButton("🔙 مدیریت Egress",
                                          callback_data="hpeg_status")],
                ]),
            )
        except Exception:
            context.user_data.pop('egress_retire_ticket', None)
            log.exception("K2 Edge retirement unavailable")
            await query.message.reply_text(
                "⛔️ حذف Edge متوقف شد؛ وضعیت را بررسی کنید."
            )
        return

    elif d == "hpeg_status" or d.startswith("hpeg_page_"):"""
    )

    source = _once(
        source,
        '''            buttons.extend([
                [InlineKeyboardButton("📋 جزئیات Edge", callback_data=f"hpeg_edge_{edge_id}")],
                [InlineKeyboardButton("🔙 مدیریت Egress", callback_data="hpeg_status")],
            ])''',
        '''            buttons.extend([
                [InlineKeyboardButton("🗑 حذف ایمن Edge", callback_data=f"hpeg_retire_open_{edge_id}")],
                [InlineKeyboardButton("📋 جزئیات Edge", callback_data=f"hpeg_edge_{edge_id}")],
                [InlineKeyboardButton("🔙 مدیریت Egress", callback_data="hpeg_status")],
            ])'''
    )

    for prefix in ("hpdelconfirm_", "hpdelyes_"):
        old = (f'    elif d.startswith("{prefix}") and role == \'admin\':\n'
               f'        host = d[len("{prefix}"):]\n'
               f'        active_now =')
        new = (f'    elif d.startswith("{prefix}") and role == \'admin\':\n'
               f'        host = d[len("{prefix}"):]\n'
               '        try:\n'
               '            if await asyncio.to_thread(is_managed_egress_deletion, db_conn, host):\n'
               '                await query.answer("⛔️ حذف Edge جدید فقط از «مدیریت Egress» مجاز است.", show_alert=True)\n'
               '                return\n'
               '        except Exception:\n'
               '            log.exception("K2 legacy host deletion preflight unavailable")\n'
               '            await query.answer("⛔️ کنترل ایمنی حذف در دسترس نیست.", show_alert=True)\n'
               '            return\n'
               '        active_now =')
        source = _once(source, old, new)
    return source


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worktree", required=True, type=Path)
    parser.add_argument("--apply", action="store_true",
                        help="Write only a pinned Git worktree (never production)")
    opts = parser.parse_args()
    root = opts.worktree.resolve(strict=True)
    bot = root / BOT_FILENAME
    if bot.resolve() == Path("/root/bot_final_v49-2.py"):
        raise ValueError("PRODUCTION_FILE_FORBIDDEN")
    if bot.is_symlink() or not bot.is_file():
        raise ValueError("UNTRUSTED_SOURCE_PATH")
    git_root = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        text=True, capture_output=True, check=True,
    ).stdout.strip()
    if Path(git_root).resolve() != root:
        raise ValueError("NOT_A_WORKTREE_ROOT")
    digest = subprocess.run(
        ["git", "-C", str(root), "hash-object", BOT_FILENAME],
        text=True, capture_output=True, check=True,
    ).stdout.strip()
    if digest != PINNED_BLOB:
        raise ValueError("SOURCE_BLOB_NOT_PINNED")
    original = bot.read_text(encoding="utf-8")
    updated = patch_source(original)
    import ast
    ast.parse(updated, filename=BOT_FILENAME)
    print("PATCH_PREVIEW=PASS")
    print("CHANGED_LINES=", len(updated.splitlines()) - len(original.splitlines()))
    if not opts.apply:
        print("NO_SOURCE_WRITES")
        return 0
    fd, name = tempfile.mkstemp(prefix=".nvl-k2-bot-", dir=str(root))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(updated)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, bot.stat().st_mode & 0o777)
        os.replace(name, bot)
        print("STAGED_GIT_WORKTREE_PATCHED=YES")
        print("NO_PRODUCTION_RUNTIME_CHANGE")
    finally:
        if os.path.exists(name):
            os.unlink(name)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print("HOLD:" + str(exc), file=sys.stderr)
        raise SystemExit(2)
