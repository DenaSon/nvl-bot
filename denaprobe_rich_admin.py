"""DenaProbe R3 Bot API 10.3 Rich Messages: admin-only, read-only UI.

Uses existing NVL bot and Cloudzy's tested RichBotAPI adapter. No HTML/miniapp
fallback, no customer identifiers, no credentials, no network mutation.
"""
from __future__ import annotations

from contextlib import closing
import asyncio
from datetime import datetime
from pathlib import Path
import re
import sqlite3
from zoneinfo import ZoneInfo

from cloudzy_rich_bridge import can_view
from cloudzy_rich_transport import RichBotAPI, RichDeliveryHold
from denaprobe_ingest import detector

ENTRY = "apps_dp3_home"
PREFIX = "dp3:"
ID = re.compile(r"[a-f0-9]{24}\Z")
CLASSES = {
    detector.D0: "D0 · اتصال TCP برقرار نشد",
    detector.D1: "D1 · نشست یا کانال SSH مختل",
    detector.D2: "D2 · انتقال داده مختل",
}
TZ = ZoneInfo("Asia/Tehran")


def _time(value):
    if type(value) is not int or value <= 0:
        return "اندازه‌گیری نشد"
    return datetime.fromtimestamp(value / 1000, TZ).strftime("%H:%M:%S")


def _age(ms, now):
    if type(ms) is not int or ms <= 0:
        return "نامشخص"
    delta = now - ms
    return f"{delta // 1000} ثانیه پیش" if 0 <= delta < 86_400_000 else "قدیمی / نامشخص"


def _table(rows):
    return {"type": "table", "is_compact": True,
            "cells": [[{"text": str(k)}, {"text": str(v)}] for k, v in rows]}


def _controls(*items):
    return {"type": "buttons", "align": "right",
            "buttons": [{"text": title, "callback_data": code}
                        for title, code in items]}


def _rich(blocks):
    return {"blocks": blocks, "is_rtl": True, "skip_entity_detection": True}


def _state(model):
    active = model["active"]
    if active and model["stale"]:
        return "🟠 اختلال ثبت‌شده · داده تازه در دسترس نیست"
    if active:
        return "🔴 اختلال احتمالی"
    probes = model.get("probes", [])
    if not probes or not model["fresh"]:
        return "⚪ پایش نامشخص"
    if any(p["ssh_fresh"] and p["tcp_code"] in (20, 21, 22) for p in probes):
        return "🟠 اتصال اولیه نیازمند بررسی"
    if any(p["ssh_fresh"] and p["tcp_code"] == 1
           and p["ssh_code"] == 1 for p in probes):
        return "🟢 اتصال اولیه برقرار"
    return "⚪ وضعیت اتصال نامشخص"


def _tcp_status(probe):
    if not probe["ssh_fresh"]:
        return "داده تازه ندارد"
    if probe["tcp_code"] == 1:
        return "✅ برقرار"
    if probe["tcp_code"] in (20, 21, 22):
        return "🔴 ناموفق"
    return "نامشخص"


def _ssh_status(probe):
    if not probe["ssh_fresh"]:
        return "داده تازه ندارد"
    if probe["ssh_code"] == 1:
        return "✅ پاسخ دریافت شد"
    return "ناموفق / نامشخص"


def _https_status(probe):
    if not probe["https_fresh"]:
        return "قدیمی / اندازه‌گیری نشده"
    return {
        1: "✅ موفق",
        2: "🟠 کند",
        10: "وای‌فای قطع",
        11: "ساعت نامعتبر",
        12: "منابع ناکافی",
    }.get(probe["https_code"], "ناموفق / نامشخص")


def render_home(model):
    probes = model.get("probes", [])
    active = model["active"]
    latest = max((p["last_received_at"] for p in probes), default=0)
    rows = [
        ("بردهای با داده تازه", f"{model['fresh']} از {len(probes)}"),
        ("اختلال فعال", len(active)),
        ("آخرین داده", _age(latest, model["now"])),
    ]
    if len(probes) == 1:
        p = probes[0]
        rows += [
            ("مقصد", p["target_id"] if p["target_id"] is not None else "نامشخص"),
            ("اتصال TCP", _tcp_status(p)),
            ("پاسخ SSH اولیه", _ssh_status(p)),
            ("HTTPS مستقیم", _https_status(p)),
            ("پیوستگی داده", "برقرار" if p["ssh_fresh"] and
             not p["monitoring_gap"] else "نامشخص / دارای وقفه"),
            ("تونل VPN", "اندازه‌گیری نشده"),
        ]
        operator = model.get("operators", {}).get(p["device_id"])
        if operator:
            rows.insert(4, ("اپراتور (اعلام‌شده)", operator))
    elif len(probes) > 1:
        for index, p in enumerate(probes[:4], 1):
            rows.append((f"برد {index} · مقصد {p['target_id'] or '—'}",
                         f"TCP {_tcp_status(p)} · HTTPS {_https_status(p)}"))
        if len(probes) > 4:
            rows.append(("سایر بردها", len(probes) - 4))
    return _rich([
        {"type": "heading", "size": 3, "text": "📡 DenaProbe | پایش اتصال"},
        {"type": "paragraph", "text": _state(model)},
        _table(rows),
        {"type": "paragraph", "text":
            "💡 پاسخ SSH اولیه به معنی سلامت تونل VPN نیست."},
        _controls(("🔴 اختلال‌های فعال", "dp3:active"),
                  ("📋 تاریخچه", "dp3:history:0"),
                  ("🔄 بروزرسانی", "dp3:home")),
    ])

def render_active(model):
    active = model["active"]
    rows = [(f"{i+1}. رله {x['target_id']}",
             CLASSES.get(x["observed_class"], "نامشخص"))
            for i, x in enumerate(active[:8])]
    return _rich([
        {"type": "heading", "size": 3, "text": "🔴 اختلال‌های فعال · DenaProbe"},
        _table(rows or [("وضعیت", "اختلال فعالی ثبت نشده")]),
        {"type": "paragraph", "text": "💡 وضعیت هر رله به زمان نمونهٔ معتبر آن وابسته است."},
        *([_controls(*[(f"جزئیات {i+1}", f"dp3:detail:{x['id']}")
                       for i, x in enumerate(active[:4])])] if active else []),
        _controls(("↩️ داشبورد", "dp3:home"), ("🔄 بروزرسانی", "dp3:active")),
    ])


def render_history(model, page=0):
    events = model["incidents"]
    start = page * 5
    batch = events[start:start+5]
    rows = [
        (f"رله {x['target_id']} · {_time(x['opened_at'])}",
         (CLASSES.get(x["observed_class"], "نامشخص") +
          (" · بازیابی" if x["recovered_at"] else
           " · مقصد تغییر کرده" if x["superseded_at"] else " · فعال")))
        for x in batch
    ]
    controls = [("↩️ داشبورد", "dp3:home")]
    if page:
        controls.append(("قبلی", f"dp3:history:{page-1}"))
    if start+5 < len(events):
        controls.append(("بعدی", f"dp3:history:{page+1}"))
    if batch:
        controls.append(("🔎 جزئیات", f"dp3:detail:{batch[0]['id']}"))
    return _rich([
        {"type": "heading", "size": 3, "text": "📋 تاریخچهٔ DenaProbe"},
        _table(rows or [("وضعیت", "تاریخچه‌ای ثبت نشده")]),
        {"type": "paragraph", "text":
            "💡 تاریخچه صرفاً مشاهدات ثبت‌شده است؛ منشأ اختلال قطعاً مشخص نیست."},
        _controls(*controls),
    ])


def render_detail(model, identifier):
    if not ID.fullmatch(identifier):
        raise ValueError("INVALID_INCIDENT_ID")
    record = next((r for r in model["incidents"] if r["id"] == identifier), None)
    if record is None:
        raise ValueError("INCIDENT_NOT_FOUND")
    key = (record["device_id"], record["target_id"], record["revision"])
    sample = model.get("samples", {}).get(key, {})
    rows = [
        ("شناسه", record["id"][:12]),
        ("مقصد", record["target_id"]),
        ("نوع", CLASSES.get(record["observed_class"], "نامشخص")),
        ("زمان شروع", _time(record["opened_at"])),
        ("آخرین شاهد", _time(record["last_evidence_at"])),
    ]
    operator = model.get("operators", {}).get(record["device_id"])
    if operator:
        rows.insert(2, ("اپراتور (اعلام‌شده)", operator))
    if sample:
        rows += [
            ("اتصال TCP", "موفق" if sample.get("tcp_code") == 1 else "ناموفق"),
            ("زمان TCP", str(sample["tcp_ms"]) + " ms"
             if sample.get("tcp_ms") is not None else "اندازه‌گیری نشده"),
            ("HTTPS مستقیم", {1: "موفق", 2: "کند"}.get(
                sample.get("direct_code"), "نامشخص")),
            ("آخرین دریافت", _time(sample.get("received_at"))),
        ]
        if sample.get("deep_code") is not None:
            for label, field in (("احراز هویت", "auth_ms"),
                                 ("نشست", "session_ms")):
                if sample.get(field) is not None:
                    rows.append((label, str(sample[field]) + " ms"))
            for label, field in (("انتقال اول", "first"),
                                 ("انتقال دوم", "second")):
                transfer = sample.get(field)
                if transfer:
                    rows.append((label,
                        f"{transfer.get('n', 0)}/{transfer.get('r', 0)} بایت"))
    if record["recovered_at"]:
        rows.append(("زمان بازیابی", _time(record["recovered_at"])))
    if record["superseded_at"]:
        rows.append(("وضعیت مقصد", "تغییر کرده"))
    return _rich([
        {"type": "heading", "size": 3, "text":
            "🟢 DenaProbe | بازیابی اتصال" if record["recovered_at"]
            else "🔴 DenaProbe | جزئیات اختلال"},
        _table(rows),
        {"type": "paragraph", "text":
            "💡 نتیجه فقط به مسیرهای اندازه‌گیری‌شده مربوط است؛ سلامت VPN قطعی نیست."},
        _controls(("↩️ داشبورد", "dp3:home"),
                  ("📋 تاریخچه", "dp3:history:0"),
                  ("🔄 بروزرسانی", f"dp3:detail:{identifier}")),
    ])


def render_transition(model, entry):
    incident = next((x for x in model["incidents"]
                     if x["id"] == entry["incident_id"]), None)
    if incident is None:
        raise ValueError("MISSING_INCIDENT")
    kind = entry["kind"]
    tcp_only = incident["observed_class"] == detector.D0
    if kind == "RECOVERED":
        title = ("🟢 DenaProbe | اتصال TCP/SSH اولیه بازیابی شد" if tcp_only
                 else "🟢 DenaProbe | ارتباط بازیابی شد")
    elif kind == "OPEN":
        title = "🔴 DenaProbe | اختلال احتمالی اتصال"
    else:
        title = "🟠 DenaProbe | تغییر وضعیت اتصال"
    rows = [
        ("مقصد", incident["target_id"]),
        ("مسیر", CLASSES.get(incident["observed_class"], "ارتباط شبکه")),
        ("زمان", _time(entry["occurred_at"])),
    ]
    operator = model.get("operators", {}).get(incident["device_id"])
    if operator:
        rows.insert(1, ("اپراتور (اعلام‌شده)", operator))
    if kind == "RECOVERED":
        rows.append(("نتیجه", "دو بررسی متوالی موفق"))
    elif kind == "OPEN":
        rows.append(("شواهد", "دو بررسی متوالی ناموفق"))
    else:
        rows.append(("نتیجه", "تغییر وضعیت تأیید شد"))
    foot = ("💡 دسترسی TCP/SSH اولیه بازیابی شده؛ سلامت NPV نامشخص است."
            if kind == "RECOVERED" and tcp_only else
            "💡 این گزارش فقط مسیر اندازه‌گیری‌شده را پوشش می‌دهد؛ منشأ اختلال قطعی نیست.")
    return _rich([
        {"type": "heading", "size": 3, "text": title},
        _table(rows),
        {"type": "paragraph", "text": foot},
        _controls(("📡 مشاهده وضعیت", ENTRY)),
    ])

def _open_readonly(path):
    conn = sqlite3.connect(f"file:{Path(path).resolve()}?mode=ro",
                           uri=True, timeout=3)
    conn.row_factory = sqlite3.Row
    return conn


def _pointer(path, chat):
    with closing(_open_readonly(path)) as db:
        row = db.execute(
            "SELECT actor,message_id FROM dp3_rich_cards WHERE chat_id=?",
            (chat,)).fetchone()
        return tuple(row) if row else None


def _set_pointer(path, actor, chat, message_id, now):
    with closing(sqlite3.connect(path, timeout=4)) as db:
        db.execute(
            "INSERT INTO dp3_rich_cards(chat_id,actor,message_id,updated_at)"
            " VALUES(?,?,?,?) ON CONFLICT(chat_id) DO UPDATE SET "
            "actor=excluded.actor,message_id=excluded.message_id,"
            "updated_at=excluded.updated_at",
            (chat, actor, message_id, now))
        db.commit()


def _render(data, model):
    if data in (ENTRY, "dp3:home"):
        return render_home(model)
    if data == "dp3:active":
        return render_active(model)
    if data.startswith("dp3:history:"):
        value = data[len("dp3:history:"):]
        if not value.isdecimal() or len(value) > 3 or int(value) > 9:
            raise ValueError("INVALID_PAGE")
        return render_history(model, int(value))
    if data.startswith("dp3:detail:"):
        return render_detail(model, data[len("dp3:detail:"):])
    raise ValueError("UNKNOWN_CALLBACK")


async def handle_callback(*, data, query, context, db_path,
                          role, actor, chat, is_private, active_admin_ids,
                          api_factory=RichBotAPI):
    if data != ENTRY and not data.startswith(PREFIX):
        return "NOT_OURS"
    if not can_view(role=role, actor=actor, chat=chat,
                    is_private=is_private, active_admin_ids=active_admin_ids):
        return "DENIED"
    # Buttons are valid ONLY on this authenticated admin's most recently
    # acknowledged Rich card. Forwarded/replayed cards cannot control views.
    try:
        if data != ENTRY:
            ptr = await asyncio.to_thread(_pointer, db_path, chat)
            message = getattr(query, "message", None)
            if (ptr is None or ptr[0] != actor or
                ptr[1] != getattr(message, "message_id", None)):
                return "STALE_OR_FORWARDED_CARD"
        model = await asyncio.to_thread(detector.read_dashboard, db_path)
        rich = _render(data, model)
        api = api_factory(context.bot.token)
        if data == ENTRY:
            mid = await api.send(chat_id=chat, rich_message=rich)
            await asyncio.to_thread(_set_pointer, db_path, actor, chat,
                                    mid, model["now"])
            return "SENT"
        await api.edit(chat_id=chat, message_id=ptr[1], rich_message=rich)
        return "EDITED"
    except (OSError, sqlite3.Error, ValueError, RichDeliveryHold):
        # Do not emit HTML or plain-text fallback dashboards.
        return "RICH_UNAVAILABLE"
