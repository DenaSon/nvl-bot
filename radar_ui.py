"""Pure HTML render helpers for NVL Radar monitoring UI."""

from __future__ import annotations

import html
from typing import Iterable, Mapping, Optional


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def state_icon(state: str) -> str:
    return {
        "NORMAL": "🟢",
        "DEGRADED": "🟡",
        "OUTAGE": "🔴",
        "UNKNOWN": "⚪️",
    }.get(str(state or "UNKNOWN").upper(), "⚪️")


def state_label_fa(state: str) -> str:
    return {
        "NORMAL": "عادی",
        "DEGRADED": "اختلال نسبی",
        "OUTAGE": "اختلال گسترده",
        "UNKNOWN": "نامشخص",
    }.get(str(state or "UNKNOWN").upper(), "نامشخص")


def provider_label_fa(status: str) -> str:
    return {
        "OK": "✅ پایدار",
        "PARTIAL": "🟡 ناقص",
        "RATE_LIMITED": "⏳ محدودشده",
        "AUTH_ERROR": "🔐 خطای دسترسی",
        "CONFIG_ERROR": "⚙️ تنظیم نشده",
        "ERROR": "❌ خطا",
        "NEVER": "⚪ بدون داده",
    }.get(str(status or "NEVER").upper(), "⚪ نامشخص")


def _metric_text(metric: Optional[Mapping], *, delta: bool = False) -> str:
    metric = dict(metric or {})
    value = metric.get("value")
    if value is None:
        return "—"
    unit = str(metric.get("unit") or "").strip()
    if isinstance(value, float):
        value_text = f"{value:.2f}".rstrip("0").rstrip(".")
    else:
        value_text = str(value)
    text = f"{_esc(value_text)}{(' ' + _esc(unit)) if unit else ''}"
    change = metric.get("delta_pct")
    if delta and change is not None:
        try:
            sign = "+" if float(change) > 0 else ""
            text += f" ({sign}{float(change):.1f}%)"
        except (TypeError, ValueError):
            pass
    return text


def render_summary(snapshot: Optional[Mapping], provider_runtime: Optional[Mapping]) -> str:
    if not snapshot:
        provider = provider_label_fa((provider_runtime or {}).get("status"))
        return (
            "🌐 <b>وضعیت اینترنت ایران</b>\n"
            "⚪️ وضعیت: <b>هنوز داده‌ای ثبت نشده</b>\n"
            f"Cloudflare Radar: <b>{provider}</b>"
        )

    state = str(snapshot.get("state") or "UNKNOWN").upper()
    provider = provider_label_fa(snapshot.get("provider_status"))
    observed = _esc(snapshot.get("observed_at") or "—")
    return (
        "🌐 <b>وضعیت اینترنت ایران</b>\n"
        f"{state_icon(state)} وضعیت: <b>{state_label_fa(state)}</b>\n"
        f"Cloudflare Radar: <b>{provider}</b>\n"
        f"Traffic: <b>{_metric_text(snapshot.get('traffic'), delta=True)}</b> · "
        f"Latency: <b>{_metric_text(snapshot.get('latency'))}</b>\n"
        f"DNS: <b>{_metric_text(snapshot.get('dns'))}</b> · "
        f"Bandwidth: <b>{_metric_text(snapshot.get('bandwidth'))}</b>\n"
        f"آخرین داده: <code>{observed}</code>"
    )


def render_detail(
    snapshot: Optional[Mapping],
    provider_runtime: Optional[Mapping],
    history: Iterable[Mapping] = (),
) -> str:
    runtime = dict(provider_runtime or {})
    if not snapshot:
        return (
            "🌐 <b>جزئیات وضعیت اینترنت ایران</b>\n\n"
            "هنوز snapshot معتبری ثبت نشده است.\n"
            f"Cloudflare Radar: <b>{provider_label_fa(runtime.get('status'))}</b>\n"
            f"آخرین خطا: <code>{_esc(runtime.get('last_error') or '—')}</code>"
        )

    state = str(snapshot.get("state") or "UNKNOWN").upper()
    statuses = dict(snapshot.get("source_statuses") or {})
    source_lines = []
    labels = (
        ("traffic_anomalies", "Traffic Anomalies"),
        ("outages", "Outages"),
        ("netflows", "NetFlows"),
        ("latency", "IQI Latency"),
        ("dns", "IQI DNS"),
        ("bandwidth", "IQI Bandwidth"),
    )
    for key, label in labels:
        raw = str(statuses.get(key) or "—").upper()
        badge = "✅" if raw == "OK" else ("⏳" if raw in {"SKIPPED", "RATE_LIMITED"} else "⚠️")
        source_lines.append(f"{badge} {label}: <code>{_esc(raw)}</code>")

    history_lines = []
    for item in tuple(history or ())[:8]:
        item_state = str(item.get("state") or "UNKNOWN").upper()
        history_lines.append(
            f"{state_icon(item_state)} <b>{state_label_fa(item_state)}</b> · "
            f"<code>{_esc(item.get('observed_at') or '—')}</code>"
        )
    if not history_lines:
        history_lines.append("—")

    return (
        "🌐 <b>جزئیات وضعیت اینترنت ایران</b>\n\n"
        f"{state_icon(state)} وضعیت فعلی: <b>{state_label_fa(state)}</b>\n"
        f"دلیل: <code>{_esc(snapshot.get('reason') or '—')}</code>\n"
        f"Cloudflare Radar: <b>{provider_label_fa(snapshot.get('provider_status'))}</b>\n"
        f"آخرین بررسی: <code>{_esc(snapshot.get('observed_at') or '—')}</code>\n\n"
        f"📉 Traffic: <b>{_metric_text(snapshot.get('traffic'), delta=True)}</b>\n"
        f"⏱ Latency: <b>{_metric_text(snapshot.get('latency'))}</b>\n"
        f"🧭 DNS: <b>{_metric_text(snapshot.get('dns'))}</b>\n"
        f"📶 Bandwidth: <b>{_metric_text(snapshot.get('bandwidth'))}</b>\n"
        f"Confidence: <b>{_esc(snapshot.get('confidence_level') if snapshot.get('confidence_level') is not None else '—')}</b>\n\n"
        f"🚨 Anomalies فعال: <b>{int(snapshot.get('active_anomaly_count') or 0)}</b> "
        f"از {int(snapshot.get('anomaly_count') or 0)}\n"
        f"🛑 Outages فعال: <b>{int(snapshot.get('active_outage_count') or 0)}</b> "
        f"از {int(snapshot.get('outage_count') or 0)}\n\n"
        "🔌 <b>منابع داده</b>\n"
        + "\n".join(source_lines)
        + "\n\n🕘 <b>تاریخچه اخیر</b>\n"
        + "\n".join(history_lines)
        + f"\n\nآخرین خطای Radar: <code>{_esc(runtime.get('last_error') or '—')}</code>"
    )
