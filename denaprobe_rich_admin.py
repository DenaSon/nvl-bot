"""DenaProbe R3 Bot API 10.3 Rich Messages: admin-only, read-only UI.

Uses existing NVL bot and Cloudzy's tested RichBotAPI adapter. No HTML/miniapp
fallback, no customer identifiers, no credentials, no network mutation.
"""
from __future__ import annotations

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
    if active:
        return "🔴 اختلال احتمالی"
    if not model["states"] or model["stale"]:
        return "⚪ پایش نامشخص"
    return "🟢 بدون اختلال تأییدشده"


def render_home(model):
    states = model["states"]
    active = model["active"]
    latest = max((r["last_received_at"] for r in states), default=0)
    status = _state(model)
    return _rich([
        {"type": "heading", "size": 3, "text": "📡 پایش اتصال · DenaProbe"},
        {"type": "paragraph", "text": status},
        _table([
            ("رله‌های ثبت‌شده", len({(s["target_id"], s["revision"]) for s in states})),
            ("اختلال فعال", len(active)),
            ("بردهای تازه", model["fresh"]),
            ("بردهای قدیمی/نامشخص", model["stale"]),
            ("آخرین داده", _age(latest, model["now"])),
            ("ارزیابی فیلترینگ", "مشکوک؛ منشأ تأییدنشده" if active else "نامشخص"),
        ]),
        {"type": "divider"},
        {"type": "paragraph", "text":
            "💡 آخرین وضعیت فقط از داده‌های معتبر DPT/2 خوانده می‌شود؛ قطع پایش به معنی فیلترینگ نیست."},
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
          (" · بازیابی" if x["recovered_at"] else " · فعال")))
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
    state = next((s for s in model["states"] if
                  s["device_id"] == record["device_id"] and
                  s["target_id"] == record["target_id"] and
                  s["revision"] == record["revision"]), None)
    stale = (not state or state["observation"] == detector.UNKNOWN or
             model["now"] - state["last_received_at"] > detector.FRESH_MS)
    return _rich([
        {"type": "heading", "size": 3, "text":
            ("🟢 بازیابی اتصال" if record["recovered_at"] else "🔴 اختلال احتمالی") +
            " · DenaProbe"},
        _table([
            ("کد", record["id"][:12]),
            ("رله", record["target_id"]),
            ("نسخه مقصد", record["revision"]),
            ("نوع", CLASSES.get(record["observed_class"], "نامشخص")),
            ("اطمینان", "مشکوک" if record["confidence"] == detector.SUSPECTED else
                         "قابل قضاوت نیست"),
            ("شواهد", record["reason"]),
            ("شروع", _time(record["opened_at"])),
            ("آخرین شاهد", _time(record["last_evidence_at"])),
            ("بازیابی", _time(record["recovered_at"]) if record["recovered_at"] else "ثبت نشده"),
            ("تازگی پایش", "نامشخص / قدیمی" if stale else
                            _age(state["last_received_at"], model["now"])),
        ]),
        {"type": "paragraph", "text":
            "💡 موفقیت TCP یا SSH اولیه به‌تنهایی سلامت اتصال کاربران NPV را ثابت نمی‌کند."},
        _controls(("↩️ داشبورد", "dp3:home"),
                  ("📋 تاریخچه", "dp3:history:0"),
                  ("🔄 بروزرسانی", f"dp3:detail:{identifier}")),
    ])


def render_transition(model, entry):
    incident = next((x for x in model["incidents"]
                     if x["id"] == entry["incident_id"]), None)
    if not incident:
        raise ValueError("MISSING_INCIDENT")
    kind = entry["kind"]
    title = "🟢 اتصال بازیابی شد" if kind == "RECOVERED" else (
        "🔴 هشدار اختلال احتمالی" if kind == "OPEN" else "🟠 تغییر نوع اختلال")
    return _rich([
        {"type": "heading", "size": 3, "text": title},
        _table([
            ("شناسه", incident["id"][:12]),
            ("رله", incident["target_id"]),
            ("نوع", CLASSES.get(entry["observed_class"], "بازیابی")),
            ("اطمینان", "مشکوک؛ نیازمند تأیید مستقل"
                        if kind != "RECOVERED" else "دو آزمون سالم جدید"),
            ("زمان", _time(entry["occurred_at"])),
            ("نمونهٔ تأیید", entry["evidence_sequence"]),
        ]),
        {"type": "paragraph", "text":
            "💡 این پیام از دادهٔ پایش خودکار تهیه شده است؛ تغییر خودکار رله انجام نشده."},
        _controls(("📡 داشبورد پایش", ENTRY)),
    ])


def _open_readonly(path):
    conn = sqlite3.connect(f"file:{Path(path).resolve()}?mode=ro",
                           uri=True, timeout=3)
    conn.row_factory = sqlite3.Row
    return conn


def _pointer(path, chat):
    with _open_readonly(path) as db:
        row = db.execute(
            "SELECT actor,message_id FROM dp3_rich_cards WHERE chat_id=?",
            (chat,)).fetchone()
        return tuple(row) if row else None


def _set_pointer(path, actor, chat, message_id, now):
    with sqlite3.connect(path, timeout=4) as db:
        db.execute(
            "INSERT INTO dp3_rich_cards(chat_id,actor,message_id,updated_at)"
            " VALUES(?,?,?,?) ON CONFLICT(chat_id) DO UPDATE SET "
            "actor=excluded.actor,message_id=excluded.message_id,"
            "updated_at=excluded.updated_at",
            (chat, actor, message_id, now))


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
