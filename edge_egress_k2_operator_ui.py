"""Ephemeral display state for the existing bot; never an execution authority.

No tickets, credentials or root callbacks enter this store. Navigation can
discard a late screen without cancelling a host operation. The original
portal/checkpoint remains the only source of execution and recovery status.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from html import escape
import re

PAGE_SIZE = 15
_PAGE = re.compile(r"hpeg_list_([0-9]{1,3})_([a-z][a-z0-9_-]{1,23})\Z")


def reason_text(code: str) -> str:
    if code in ("ACTIVE_SESSIONS_PRESENT", "SELECTED_USER_HAS_ACTIVE_SESSIONS",
                "SOURCE_PROBE_SESSION_NOT_DRAINED"):
        return "اتصال فعال دارد؛ پس از خروج کاربر دوباره بررسی کنید"
    if code == "TARGET_ALREADY_PROTECTED":
        return "از قبل روی همین خروجی است"
    if code in ("SOURCE_OR_SESSION_UNVERIFIED", "SOURCE_INGRESS_NOT_ATTESTED",
                "SOURCE_WITNESS_INVALID_OR_STALE", "SESSION_STATE_NOT_ATTESTED",
                "SOURCE_JOURNAL_NOT_ATTESTED"):
        return "اتصال کاربر تأیید نشد؛ دسترسی سرور ورودی را بررسی کنید"
    if code in ("ACCOUNT_UID_NOT_ATTESTED", "DUPLICATE_LINUX_UID",
                "DUPLICATE_OR_INVALID_ACTIVE_ACCOUNT"):
        return "اطلاعات حساب نیاز به بررسی دارد"
    if code in ("PROTECTED_IDENTITY_CONFLICT", "PARTIAL_PROTECTED_IDENTITY",
                "PROTECTED_SOURCE_DRIFT"):
        return "مسیر قبلی حساب نیاز به بررسی دارد"
    if code == "SHARED_6G_BUSY":
        return "عملیات دیگری در جریان است؛ ابتدا وضعیت آن را بررسی کنید"
    if code in ("TARGET_F4_NOT_ACCEPTED", "TARGET_F3_NOT_STAGED"):
        return "آماده‌سازی و سلامت سرور مقصد را بررسی کنید"
    return "نیازمند بررسی؛ وضعیت حساب و اتصال سرور را بررسی کنید"


def error_html(error: Exception, *, executing: bool = False) -> str:
    code = str(error)
    if code == "CORE_REVIEW_STOPPED":
        return "⏸ <b>بررسی متوقف شد</b>\n\nانتقالی تأیید نشد. برای ادامه، کاربران را دوباره انتخاب کنید."
    if executing:
        return ("⛔️ <b>نتیجهٔ عملیات نیاز به بررسی دارد</b>\n\n"
                "از «وضعیت» نتیجهٔ هر حساب را ببینید. درخواست را تکرار نکنید؛ "
                "ممکن است بخشی از انتقال انجام شده باشد.")
    if any(x in code for x in ("NOT_RELEASED", "NOT_REGISTERED", "NOT_ATTESTED")):
        return "🔒 <b>انتقال فعلاً در دسترس نیست</b>\n\nآماده‌سازی و سلامت مسیر باید تأیید شود. وضعیت سرور را بررسی کنید."
    if code.startswith("RECOVERY_"):
        return ("⛔️ <b>ادامهٔ عملیات هنوز ایمن نیست</b>\n\n"
                "وضعیت برخی حساب‌ها قطعی نیست. از «وضعیت» آن‌ها را بررسی کنید. "
                "انتقال یا راه‌اندازی سرور را تکرار نکنید؛ بررسی فنی لازم است.")
    if any(x in code for x in ("EXPIRED", "MISSING", "NOT_IN_MEMORY", "SCOPE_MISSING")):
        return ("⌛️ <b>درخواست قبلی در دسترس نیست</b>\n\n"
                "برای انتقال جدید، کاربران را دوباره انتخاب و بررسی کنید. "
                "اگر قبلاً تأیید کرده‌اید، ابتدا «وضعیت» را ببینید.")
    if any(x in code for x in ("BUSY", "INFLIGHT", "IN_PROGRESS")):
        return ("⏳ <b>یک عملیات در جریان است</b>\n\n"
                "از «وضعیت» آن را پیگیری کنید. توقف، پس از پایان حساب جاری انجام می‌شود.")
    if code in ("INPUT_TOO_LONG", "USERS_INVALID_OR_DUPLICATED"):
        return ("✏️ <b>نام‌های کاربری را بررسی کنید</b>\n\n"
                "نام تکراری نفرستید. برای انتقال تکی یک نام و برای انتقال گروهی "
                "حداکثر ۱۰ نام را با فاصله یا ویرگول جدا کنید.")
    return ("⛔️ <b>بررسی کامل نشد</b>\n\n"
            "وضعیت سرور و اتصال کاربران را بررسی کنید، سپس بررسی را تکرار کنید. "
            "تأیید انتقال صادر نشده است.")


def running_html(edge_id: str, *, reviewing: bool = False) -> str:
    title = "بررسی کاربران" if reviewing else "انتقال کاربران"
    tip = ("بررسی اتصال هر حساب ممکن است زمان ببرد. هنوز انتقالی تأیید نشده است."
           if reviewing else "کاربران به‌ترتیب بررسی و منتقل می‌شوند. توقف پس از پایان حساب جاری است.")
    return f"⏳ <b>{title}</b>\n\nمقصد: <code>{escape(edge_id)}</code>\n\n{tip}"


def running_buttons(edge_id: str, *, reviewing: bool = False):
    status = f"hpeg_scan_{edge_id}" if reviewing else f"hpeg_m4_status_{edge_id}"
    return [[("📋 وضعیت", status), ("⏸ توقف", f"hpeg_m4_stop_{edge_id}")],
            [("↩️ مدیریت خروجی", "hpeg_status")]]


@dataclass
class Screen:
    generation: int
    message_id: int
    edge_id: str
    kind: str = "running"
    payload: object = None
    selection: object = None
    skipped: tuple = ()
    activate_relay: bool = False


class DisplayStore:
    """Bounded process-local views. Old buttons cannot address another screen."""
    def __init__(self):
        self._screens = OrderedDict()
        self._generation = 0

    def navigate(self, actor_id, chat_id):
        self._screens.pop((actor_id, chat_id), None)

    def begin(self, actor_id, chat_id, message_id, edge_id, **kwargs):
        self._generation += 1
        screen = Screen(self._generation, message_id, edge_id, **kwargs)
        key = (actor_id, chat_id)
        self._screens[key] = screen
        self._screens.move_to_end(key)
        while len(self._screens) > 32:
            self._screens.popitem(last=False)
        return screen

    def current(self, actor_id, chat_id, screen):
        return self._screens.get((actor_id, chat_id)) is screen

    def get(self, actor_id, chat_id, message_id, edge_id):
        screen = self._screens.get((actor_id, chat_id))
        if (screen is None or screen.message_id != message_id
                or screen.edge_id != edge_id):
            raise ValueError("UI_SCREEN_EXPIRED")
        return screen


def parse_page(data):
    match = _PAGE.fullmatch(data or "")
    if not match or len(data.encode()) > 64:
        raise ValueError("UI_PAGE_INVALID")
    return int(match[1]), match[2]


def accounts_page(screen: Screen, page: int):
    """Paginated detail from a bounded read-only snapshot, never approval."""
    selection = screen.selection
    rows = []
    if screen.kind == "preview":
        for a in screen.payload.accounts:
            if a.selected:
                rows.append((a.username, reason_text(a.issues[0]) if a.issues else "آمادهٔ بررسی نهایی"))
        rows.extend((n, reason_text(reason)) for n, reason in screen.skipped)
    elif screen.kind == "skipped":
        rows = [(n, reason_text(reason)) for n, reason in screen.skipped]
    elif screen.kind in ("result", "status"):
        entries = screen.payload["accounts" if screen.kind == "result" else "users"]
        if selection is None or tuple(x.get("username") for x in entries) != selection.usernames:
            raise ValueError("UI_RESULT_SCOPE_CHANGED")
        labels = {"VERIFIED": "✅ انتقال تأیید شد", "HOLD": "⛔️ نیازمند بررسی",
                  "DEFERRED": "⚪️ انجام نشد؛ پس از توقف عملیات باقی ماند",
                  "UNKNOWN": "⚪️ نامشخص", "NOT_STARTED": "⚪️ هنوز شروع نشده",
                  "RECEIPT_SCOPED": "🟡 نتیجهٔ ثبت‌شده تطبیق دارد",
                  "RECEIPT_UNVERIFIED": "⛔️ نتیجهٔ ثبت‌شده نیازمند بررسی است"}
        for item in entries:
            if item.get("state") not in labels:
                raise ValueError("UI_RESULT_STATE_UNKNOWN")
            rows.append((item["username"], labels[item["state"]]))
        rows.extend((n, "⚪️ کنارگذاشته‌شده؛ "+reason_text(reason)) for n, reason in screen.skipped)
    else:
        raise ValueError("UI_DETAILS_NOT_AVAILABLE")
    pages = max(1, (len(rows) + PAGE_SIZE - 1) // PAGE_SIZE)
    if type(page) is not int or not 0 <= page < pages:
        raise ValueError("UI_PAGE_INVALID")
    body = ["📋 <b>جزئیات کاربران</b>", "",
            f"مقصد: <code>{escape(screen.edge_id)}</code>",
            f"صفحهٔ {page+1} از {pages} · {len(rows)} حساب", ""]
    body.extend(f"<code>{escape(str(name)[:32])}</code> — {label}"
                for name, label in rows[page*PAGE_SIZE:(page+1)*PAGE_SIZE])
    body.extend(("", "💡 این فهرست نتیجهٔ آخرین بررسی است؛ برای وضعیت تازه «وضعیت» را بزنید."))
    nav = []
    if page:
        nav.append(("◀️ قبلی", f"hpeg_list_{page-1}_{screen.edge_id}"))
    if page+1 < pages:
        nav.append(("بعدی ▶️", f"hpeg_list_{page+1}_{screen.edge_id}"))
    buttons = [nav] if nav else []
    buttons.append([("↩️ خلاصه", f"hpeg_summary_{screen.edge_id}")])
    if selection is not None:
        buttons.append([("📋 وضعیت", f"hpeg_m4_status_{screen.edge_id}")])
    buttons.append([("👥 انتخاب کاربران", f"hpeg_m4_home_{screen.edge_id}"),
                    ("↩️ مدیریت خروجی", "hpeg_status")])
    return "\n".join(body), buttons


def detail_button(edge_id):
    return [("📄 جزئیات کاربران", f"hpeg_list_0_{edge_id}")]


VIEWS = DisplayStore()
