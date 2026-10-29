"""Private, memory-only Telegram WebApp intake for manual Edge credentials.

NO password in Telegram, persistence, SQLite, logging or URLs. The HTTP listener
binds loopback only; a separately configured HTTPS reverse proxy is mandatory.
This module does not contact Cloudzy or Cloudflare.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import ipaddress
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

TTL = 180
_MAX_BODY = 8192


class IntakeHold(ValueError):
    pass


def public_ip(value):
    try:
        ip = ipaddress.IPv4Address(str(value))
        if (not ip.is_global or ip.is_multicast or ip.is_reserved
                or ip.is_loopback or ip.is_link_local or ip.is_unspecified):
            raise ValueError("non-public")
        return str(ip)
    except ValueError as exc:
        raise IntakeHold("PUBLIC_IPV4_REQUIRED") from exc


def ssh_port(value):
    try:
        if isinstance(value, bool) or not str(value).isdigit():
            raise ValueError("invalid port")
        port = int(value)
        if not 1 <= port <= 65535:
            raise ValueError("port range")
        return port
    except (ValueError, TypeError) as exc:
        raise IntakeHold("SSH_PORT_INVALID") from exc


def validate_init_data(data, bot_token, actor, now=None):
    """Telegram WebApp HMAC check, including actor binding and short auth_age."""
    if not isinstance(data, str) or len(data) > 4096 or not bot_token:
        raise IntakeHold("TELEGRAM_IDENTITY_MISSING")
    query = parse_qs(data, keep_blank_values=True, strict_parsing=True)
    if any(len(v) != 1 for v in query.values()):
        raise IntakeHold("TELEGRAM_IDENTITY_DUPLICATED")
    provided = query.get("hash", [""])[0]
    if len(provided) != 64 or any(ch not in "0123456789abcdef" for ch in provided):
        raise IntakeHold("TELEGRAM_SIGNATURE_INVALID")
    check = "\n".join(f"{key}={values[0]}" for key, values in sorted(query.items())
                      if key != "hash")
    secret = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    expected = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(provided, expected):
        raise IntakeHold("TELEGRAM_SIGNATURE_INVALID")
    try:
        timestamp = int(query["auth_date"][0])
        uid = json.loads(query["user"][0])["id"]
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise IntakeHold("TELEGRAM_IDENTITY_INVALID") from exc
    now = int(time.time() if now is None else now)
    if type(uid) is not int or uid != actor or abs(now-timestamp) > TTL:
        raise IntakeHold("TELEGRAM_IDENTITY_EXPIRED")
    return True


class ManualFormStore:
    """Bot-created one-use tickets. Secrets remain process-private for <=180s."""
    def __init__(self, *, clock=time.time):
        self.clock = clock
        self.lock = threading.RLock()
        self._tickets = {}

    def _prune(self):
        now = self.clock()
        for key, rec in list(self._tickets.items()):
            if now >= rec["until"]:
                self._tickets.pop(key, None)

    def issue(self, *, actor, chat, stage, op_id):
        if stage not in ("server", "password") or type(actor) is not int or type(chat) is not int:
            raise IntakeHold("INTAKE_STATE_INVALID")
        with self.lock:
            self._prune()
            nonce = secrets.token_urlsafe(24)
            self._tickets[nonce] = {
                "actor": actor, "chat": chat, "stage": stage, "op": op_id,
                "until": self.clock()+TTL, "value": None,
            }
            return nonce

    def info(self, nonce, *, actor=None):
        with self.lock:
            self._prune()
            rec = self._tickets.get(nonce)
            if not rec or (actor is not None and actor != rec["actor"]):
                raise IntakeHold("INTAKE_EXPIRED")
            return {k:v for k,v in rec.items() if k != "value"}

    def submit(self, nonce, *, actor, stage, value):
        with self.lock:
            self._prune()
            rec = self._tickets.get(nonce)
            if not rec or rec["actor"] != actor or rec["stage"] != stage or rec["value"] is not None:
                raise IntakeHold("INTAKE_EXPIRED")
            if stage == "server":
                if not isinstance(value, dict):
                    raise IntakeHold("INTAKE_INVALID")
                clean = {"ip":public_ip(value.get("ip")), "port":ssh_port(value.get("port"))}
            else:
                if not isinstance(value, dict) or not isinstance(value.get("password"), str):
                    raise IntakeHold("PASSWORD_REQUIRED")
                pwd = value["password"]
                if not 1 <= len(pwd) <= 1024 or "\x00" in pwd or "\r" in pwd or "\n" in pwd:
                    raise IntakeHold("PASSWORD_INVALID")
                clean = {"password":pwd}
            rec["value"] = clean
            return True

    def consume(self, nonce, *, actor, chat, stage, op_id):
        with self.lock:
            self._prune()
            rec = self._tickets.get(nonce)
            if (not rec or rec["actor"] != actor or rec["chat"] != chat
                    or rec["stage"] != stage or rec["op"] != op_id
                    or rec["value"] is None):
                raise IntakeHold("FORM_NOT_SUBMITTED_OR_EXPIRED")
            self._tickets.pop(nonce)
            return rec["value"]

    def revoke(self, nonce):
        with self.lock:
            self._tickets.pop(nonce, None)


HTML = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<style>body{font-family:system-ui,sans-serif;margin:24px;background:#0b1220;color:#f8fafc}
input,button{width:100%;box-sizing:border-box;padding:15px;margin:9px 0;border-radius:12px;border:0}
input{background:#1e293b;color:#fff}button{background:#14b8a6;color:#062c29;font-weight:700}
small{color:#94a3b8}</style></head><body>
<h3>افزودن سرور دستی</h3>
<p id="tip"></p><form id="f">__FIELDS__<button type="submit">ثبت امن</button></form>
<small>داده‌ها فقط یک‌بار دریافت می‌شوند و رمز در پیام تلگرام ثبت نمی‌شود.</small>
<script>
const t=window.Telegram?.WebApp, ticket=new URLSearchParams(location.search).get("ticket");
t?.ready();document.getElementById("tip").textContent="__TIP__";
document.getElementById("f").onsubmit=async e=>{
 e.preventDefault();
 const values=Object.fromEntries(new FormData(e.target).entries());
 const r=await fetch("/manual-edge/api/submit",{method:"POST",
  headers:{"Content-Type":"application/json"},
  body:JSON.stringify({ticket,initData:t?.initData||"",values})});
 const m=await r.json();
 if(r.ok){document.body.textContent="✅ اطلاعات دریافت شد. به بات بازگردید و «ادامه» را بزنید."}
 else {document.getElementById("tip").textContent="⛔️ "+(m.message||"دریافت انجام نشد.")}
};
</script></body></html>"""


def serve_private(store, *, token, host="127.0.0.1", port=3107):
    """Runs in a background daemon thread; call only when feature is enabled.

    HTTPS must be terminated at the fronting reverse proxy and only the
    explicit /manual-edge path may be exposed. No access/body logs.
    """
    if host not in ("127.0.0.1", "::1"):
        raise IntakeHold("LOOPBACK_ONLY")
    if not token:
        raise IntakeHold("BOT_TOKEN_REQUIRED")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            pass

        def _send(self, status, data, mime="application/json"):
            raw = (json.dumps(data, ensure_ascii=False) if mime == "application/json"
                   else data).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", mime+"; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; script-src 'unsafe-inline' https://telegram.org; "
                             "style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; "
                             "frame-ancestors https://web.telegram.org https://*.telegram.org")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            url = urlsplit(self.path)
            if url.path != "/manual-edge/form":
                return self._send(404, {"message":"Not found"})
            ticket = parse_qs(url.query).get("ticket", [""])[0]
            try:
                stage = store.info(ticket)["stage"]
            except IntakeHold:
                return self._send(403, {"message":"این فرم منقضی شده است."})
            if stage == "server":
                fields = ('<label>IP عمومی</label><input name="ip" required '
                          'placeholder="203.0.113.10" inputmode="decimal">'
                          '<label>پورت مدیریت SSH</label><input name="port" '
                          'type="number" min="1" max="65535" value="22" required>')
                tip="مشخصات سرور را ثبت کنید؛ رمز در مرحله بعد از تأیید هویت دریافت می‌شود."
            else:
                fields='<label>رمز ورود SSH</label><input name="password" type="password" autocomplete="off" required>'
                tip="فقط پس از تأیید مستقل اثرانگشت سرور، رمز را ثبت کنید."
            self._send(200, HTML.replace("__FIELDS__", fields).replace("__TIP__",tip),
                       "text/html")

        def do_POST(self):
            if self.path != "/manual-edge/api/submit":
                return self._send(404, {"message":"Not found"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 1 <= length <= _MAX_BODY:
                    raise IntakeHold("REQUEST_TOO_LARGE")
                payload=json.loads(self.rfile.read(length).decode("utf-8"))
                ticket=payload.get("ticket")
                info=store.info(ticket)
                validate_init_data(payload.get("initData", ""),token,info["actor"])
                store.submit(ticket,actor=info["actor"],stage=info["stage"],
                             value=payload.get("values"))
            except (ValueError,UnicodeError,TypeError,KeyError):
                return self._send(400, {"message":"فرم معتبر نیست یا اعتبار آن پایان یافته است."})
            return self._send(200, {"message":"ok"})

    server=ThreadingHTTPServer((host,port), Handler)
    worker=threading.Thread(target=server.serve_forever,daemon=True,name="nvl-manual-form")
    worker.start()
    return server
