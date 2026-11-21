"""Read-only NVL Core server health presentation and on-demand large-file audit.

The heavy filesystem walk is never part of the ordinary health refresh.
This module is deliberately stdlib-only; no changes to system state or DB.
"""
from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime
import html
import os
from pathlib import PurePath
from zoneinfo import ZoneInfo


LARGE_FILE_THRESHOLD_BYTES = 3 * 1024 ** 3
LARGE_FILE_TIMEOUT_SECONDS = 15
LARGE_FILE_MAX_RESULTS = 10
_PRUNED_DIRS = ("/proc", "/sys", "/dev", "/run")


def _fa(value) -> str:
    return str(value).translate(str.maketrans("0123456789", "۰۱۲۳۴۵۶۷۸۹"))


def _gb(value: float) -> str:
    return _fa(f"{value:.1f}")


def _percent_bar(value: float) -> str:
    filled = max(0, min(10, round(float(value) / 10)))
    return f"<code>{'▰' * filled}{'▱' * (10 - filled)}</code>"


def _uptime_label(seconds: float | None) -> str:
    if seconds is None:
        return "نامشخص"
    mins = max(0, int(seconds)) // 60
    days, rem = divmod(mins, 1440)
    hours, minutes = divmod(rem, 60)
    if days:
        return f"{_fa(days)} روز و {_fa(hours)} ساعت"
    if hours:
        return f"{_fa(hours)} ساعت و {_fa(minutes)} دقیقه"
    return f"{_fa(minutes)} دقیقه"


def collect_extra_metrics() -> dict:
    """Use /proc and statvfs only, never sudo or external commands."""
    result: dict = {"disk": None, "uptime_seconds": None, "swap": None}
    try:
        stat = os.statvfs("/")
        unit = stat.f_frsize or stat.f_bsize
        total = stat.f_blocks * unit
        used = max(0, (stat.f_blocks - stat.f_bfree) * unit)
        available = max(0, stat.f_bavail * unit)
        result["disk"] = {
            "total_gb": total / 1024 ** 3,
            "used_gb": used / 1024 ** 3,
            "available_gb": available / 1024 ** 3,
            "pct": (100 * used / (used + available)) if (used + available) else 0.0,
        }
    except (OSError, ValueError, ZeroDivisionError):
        pass
    try:
        with open("/proc/uptime", encoding="ascii") as file:
            result["uptime_seconds"] = float(file.readline().split()[0])
    except (OSError, ValueError, IndexError):
        pass
    try:
        mem = {}
        with open("/proc/meminfo", encoding="ascii") as file:
            for line in file:
                key, _, remainder = line.partition(":")
                if key in ("SwapTotal", "SwapFree"):
                    mem[key] = int(remainder.split()[0])
        if "SwapTotal" in mem and "SwapFree" in mem:
            total = mem["SwapTotal"]
            used = max(0, total - mem["SwapFree"])
            result["swap"] = {
                "total_mb": round(total / 1024),
                "used_mb": round(used / 1024),
                "pct": 100 * used / total if total else 0.0,
            }
    except (OSError, ValueError, IndexError):
        pass
    return result


def _health_state(health: dict, extra: dict, connection_error: str | None):
    warnings, critical, missing = [], [], []
    cpu = float(health.get("cpu_pct", 0))
    ram = float(health.get("ram_pct", 0))
    cores = max(1, int(health.get("cpu_count", 1)))
    load1 = float(health.get("load1", 0))
    disk = extra.get("disk")
    if cpu >= 95:
        critical.append("مصرف CPU بحرانی است")
    elif cpu >= 85:
        warnings.append("مصرف CPU بالاست")
    if ram >= 95:
        critical.append("مصرف RAM بحرانی است")
    elif ram >= 85:
        warnings.append("مصرف RAM بالاست")
    if load1 >= cores * 2:
        critical.append("فشار پردازشی بسیار بالاست")
    elif load1 >= cores * 1.5:
        warnings.append("فشار پردازشی بالاست")
    if disk is None:
        missing.append("دیسک")
    elif disk["pct"] >= 90:
        critical.append("فضای دیسک در آستانه تکمیل است")
    elif disk["pct"] >= 80:
        warnings.append("فضای دیسک رو به اتمام است")
    if connection_error:
        missing.append("آمار اتصال‌های SSH")
    if critical:
        return "🔴", "بحرانی", critical + warnings, missing
    if warnings:
        return "🟠", "نیازمند توجه", warnings, missing
    if missing:
        return "⚪", "پایش ناقص", [], missing
    return "🟢", "منابع عادی", [], []


def render_health(health: dict, extra: dict, *,
                  sessions: int | None, unique_accounts: int | None,
                  connection_error: str | None = None,
                  details: bool = False,
                  socket_count: int | None = None,
                  socket_error: str | None = None) -> str:
    icon, state, alerts, missing = _health_state(health, extra, connection_error)
    cpu = float(health["cpu_pct"])
    ram = float(health["ram_pct"])
    cores = max(1, int(health["cpu_count"]))
    disk = extra.get("disk")
    swap = extra.get("swap")
    now = datetime.now(ZoneInfo("Asia/Tehran")).strftime("%H:%M")
    lines = [
        "🖥 <b>سلامت سرور | NVL Core</b>",
        f"<blockquote>{icon} <b>{state}</b>  ·  بروزرسانی: {_fa(now)}</blockquote>",
        "",
        "📊 <b>منابع سرور</b>",
        f"⚙️ CPU  <b>{_fa(f'{cpu:.1f}')}٪</b>  {_percent_bar(cpu)}  ({_fa(cores)} هسته)",
        f"🧠 RAM  <b>{_fa(f'{ram:.1f}')}٪</b>  {_percent_bar(ram)}",
        f"   {_fa(health['ram_used_mb'])} از {_fa(health['ram_total_mb'])} مگابایت",
    ]
    if disk is None:
        lines.append("💾 دیسک  <b>نامشخص</b>")
    else:
        lines += [
            f"💾 دیسک  <b>{_fa(f'{disk['pct']:.1f}')}٪</b>  {_percent_bar(disk['pct'])}",
            f"   {_gb(disk['used_gb'])} از {_gb(disk['total_gb'])} گیگابایت · {_gb(disk['available_gb'])} آزاد",
        ]
    if swap is None:
        swap_label = "نامشخص"
    elif not swap["total_mb"]:
        swap_label = "غیرفعال"
    else:
        swap_label = f"{_fa(swap['used_mb'])} از {_fa(swap['total_mb'])} مگابایت"
    lines += [
        f"🔁 Swap  <b>{swap_label}</b>",
        "",
        "📡 <b>فعالیت سیستم</b>",
        f"📈 بار پردازشی  <b>{_fa(health['load1'])}</b> (۱ دقیقه)",
        f"⏱ روشن‌بودن سرور  <b>{_uptime_label(extra.get('uptime_seconds'))}</b>",
    ]
    if connection_error:
        lines += ["🔌 نشست‌های SSH  <b>نامشخص</b>", "👥 حساب‌های متصل  <b>نامشخص</b>"]
    else:
        lines += [
            f"🔌 نشست‌های SSH  <b>{_fa(sessions if sessions is not None else 0)}</b>",
            f"👥 حساب‌های متصل  <b>{_fa(unique_accounts if unique_accounts is not None else 0)}</b>",
        ]
    if details:
        lines += [
            "",
            "🔎 <b>جزئیات فنی</b>",
            f"Load (۱ / ۵ / ۱۵ دقیقه): <code>{_fa(health['load1'])} / {_fa(health['load5'])} / {_fa(health['load15'])}</code>",
            f"سوکت‌های TCP در پورت اصلی: <b>{_fa(socket_count) if socket_count is not None else 'نامشخص'}</b>",
            "<i>شمارش سوکت‌ها و نشست‌های SSH لزوماً برابر نیست.</i>",
        ]
        if socket_error:
            lines.append("⚠️ بررسی سوکت‌های TCP کامل نشد.")
    if alerts:
        lines.extend(["", "<blockquote>" + icon + " " + "؛ ".join(html.escape(item) for item in alerts) + "</blockquote>"])
    if missing:
        lines.append("⚠️ داده ناقص: " + "، ".join(html.escape(item) for item in missing))
    if not alerts and not missing:
        lines.append("\n✅ <i>منابع پایش‌شده در محدوده عادی هستند.</i>")
    return "\n".join(lines)


async def scan_large_files(*, root: str = "/",
                           threshold_bytes: int = LARGE_FILE_THRESHOLD_BYTES,
                           timeout_seconds: float = LARGE_FILE_TIMEOUT_SECONDS,
                           max_results: int = LARGE_FILE_MAX_RESULTS) -> dict:
    """Run a bounded, read-only GNU find on one filesystem without shell/sudo.

    A timeout or inaccessible subtree is reported as a partial scan, never as
    evidence that no large files exist. Symlinks and other mounts are not followed.
    """
    if threshold_bytes < 1 or max_results < 1 or timeout_seconds <= 0:
        raise ValueError("invalid scanner parameters")
    root = os.fspath(root)
    prune = ["("]
    for index, path in enumerate(_PRUNED_DIRS):
        if index:
            prune.append("-o")
        prune.extend(("-path", path))
    prune.extend((")", "-prune", "-o"))
    args = (
        "find", root, "-xdev", *prune,
        "-type", "f", "-size", f"+{threshold_bytes}c",
        "-printf", r"%s\t%p\0",
    )
    try:
        process = await asyncio.create_subprocess_exec(
            *args, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except OSError:
        return {"files": [], "total": 0, "complete": False, "timed_out": False,
                "error": "ابزار اسکن فایل در دسترس نیست."}
    timed_out = False
    try:
        raw, stderr = await asyncio.wait_for(process.communicate(), timeout_seconds)
    except asyncio.TimeoutError:
        timed_out = True
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        raw, stderr = await process.communicate()
    complete = (not timed_out and process.returncode == 0)
    # Ignore a truncated final record when killed by timeout.
    chunks = raw.split(b"\0")
    if chunks[-1]:
        chunks.pop()
    found = []
    for record in chunks:
        try:
            raw_size, raw_path = record.split(b"\t", 1)
            size = int(raw_size)
        except (ValueError, TypeError):
            continue
        if size > threshold_bytes:
            found.append((size, os.fsdecode(raw_path)))
    found.sort(key=lambda item: (-item[0], item[1]))
    return {
        "files": found[:max_results],
        "total": len(found),
        "complete": complete,
        "timed_out": timed_out,
        "error": "" if complete else (
            "اسکن به محدودیت زمانی رسید." if timed_out
            else "برخی مسیرها قابل‌خواندن نبودند یا ابزار اسکن خطا داد."
        ),
    }


def _safe_path(path: str, max_chars: int = 230) -> str:
    clean = "".join(ch if ch.isprintable() else "�" for ch in path)
    if len(clean) > max_chars:
        clean = clean[:100] + "…" + clean[-(max_chars - 101):]
    return html.escape(clean, quote=False)


def render_large_files(result: dict) -> str:
    lines = [
        "📂 <b>فایل‌های حجیم | NVL Core</b>",
        "<blockquote>🔎 فایل‌های بزرگ‌تر از <b>۳ گیگابایت</b>\n"
        "📍 دیسک اصلی سرور (/) · بدون تغییر فایل‌ها</blockquote>",
    ]
    for index, (size, path) in enumerate(result["files"], 1):
        filename = PurePath(path).name
        lines += [
            "",
            f"<b>{_fa(index)}.</b> {_safe_path(filename, 90)}  ·  <b>{_gb(size / 1024 ** 3)} GB</b>",
            f"<code>{_safe_path(path)}</code>",
        ]
    if not result["files"]:
        lines.append("\nهیچ فایل بزرگ‌تر از ۳ گیگابایت در مسیرهای بررسی‌شده پیدا نشد.")
    lines.append("")
    if result["complete"]:
        lines.append(f"✅ اسکن کامل شد · {_fa(result['total'])} فایل شناسایی شد.")
    else:
        lines.append("⚠️ <b>اسکن ناقص است.</b> " + html.escape(result.get("error") or "بخشی از مسیرها بررسی نشد."))
        lines.append("نتیجه ممکن است شامل همه فایل‌های حجیم نباشد.")
    if result["total"] > len(result["files"]):
        lines.append(f"ℹ️ فقط {_fa(len(result['files']))} فایل بزرگ‌تر نمایش داده شده است.")
    lines.append("<i>فایل‌های حذف‌شده ولی هنوز باز و محتویات سایر دیسک‌های mount‌شده در این فهرست نیستند.</i>")
    return "\n".join(lines)
