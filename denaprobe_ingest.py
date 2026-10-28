"""Localhost-only HTTP receiver for ESP32 DenaProbe telemetry.

Expose it only through a separate authenticated HTTPS reverse proxy.
Does not share the NVL bot's SQLite, threads, token or Telegram event loop.
"""
from __future__ import annotations

import hmac
import json
import logging
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable

from denaprobe_store import InvalidReport, init_db, save_report, validate_report

MAX_BODY_BYTES = 2048
DEVICE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{3,40}$")
LOG = logging.getLogger("denaprobe_ingest")


def load_config(environ: dict | None = None) -> tuple[str, str, dict[str, str], int]:
    env = os.environ if environ is None else environ
    db_path = env.get("DENAPROBE_DB_PATH", "/var/lib/nvl-denaprobe/telemetry.sqlite3")
    allowed_host = env.get("DENAPROBE_EDGE_HOST", "").strip().lower().rstrip(".")
    if not allowed_host or not re.fullmatch(r"[a-z0-9.-]{3,253}", allowed_host):
        raise ValueError("DENAPROBE_EDGE_HOST must be configured")
    try:
        keys = json.loads(env.get("DENAPROBE_DEVICE_TOKENS_JSON", ""))
    except (json.JSONDecodeError, TypeError):
        raise ValueError("DENAPROBE_DEVICE_TOKENS_JSON must be a JSON object") from None
    if (not isinstance(keys, dict) or not keys
            or any(not isinstance(k, str) or not DEVICE_ID_PATTERN.fullmatch(k)
                   or not isinstance(v, str) or len(v) < 32 or len(v) > 256
                   for k, v in keys.items())):
        raise ValueError("DENAPROBE_DEVICE_TOKENS_JSON contains invalid device/token")
    try:
        port = int(env.get("DENAPROBE_PORT", "8765"))
    except ValueError:
        raise ValueError("invalid DENAPROBE_PORT") from None
    if not 1 <= port <= 65535:
        raise ValueError("invalid DENAPROBE_PORT")
    return db_path, allowed_host, keys, port


def make_handler(
    *,
    db_path: str,
    allowed_host: str,
    keys: dict[str, str],
    writer: Callable = save_report,
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "DenaProbeReceiver/1"
        sys_version = ""

        def log_message(self, format: str, *args: object) -> None:
            # No IP, device ID, URL, header or bearer token in production logs.
            return

        def _send(self, status: int, payload: dict) -> None:
            raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            if self.path == "/healthz":
                self._send(200, {"ok": True})
            else:
                self._send(404, {"error": "not_found"})

        def do_POST(self) -> None:
            if self.path != "/v1/reports":
                self._send(404, {"error": "not_found"})
                return
            device = self.headers.get("X-DenaProbe-Device", "")
            auth = self.headers.get("Authorization", "")
            # Check exactly one value for security-relevant headers.
            if (len(self.headers.get_all("Authorization", [])) != 1
                    or len(self.headers.get_all("X-DenaProbe-Device", [])) != 1
                    or not DEVICE_ID_PATTERN.fullmatch(device)
                    or device not in keys
                    or not auth.startswith("Bearer ")
                    or not hmac.compare_digest(auth[7:], keys[device])):
                self._send(401, {"error": "unauthorized"})
                return
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                self._send(415, {"error": "json_required"})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not lengths[0].isdigit():
                self._send(411, {"error": "length_required"})
                return
            length = int(lengths[0])
            if length <= 0 or length > MAX_BODY_BYTES:
                self._send(413, {"error": "invalid_size"})
                return
            try:
                doc = json.loads(self.rfile.read(length))
                validated = validate_report(doc, allowed_host=allowed_host, authenticated_device=device)
            except (UnicodeDecodeError, json.JSONDecodeError, InvalidReport, ValueError):
                self._send(400, {"error": "invalid_report"})
                return
            try:
                inserted = writer(db_path, validated)
            except Exception:
                LOG.exception("denaprobe_storage_error")  # No customer/credential data.
                self._send(503, {"error": "store_unavailable"})
                return
            self._send(200, {"ok": True, "duplicate": not inserted})

    return Handler


class LocalHTTPServer(HTTPServer):
    allow_reuse_address = True

    def get_request(self):
        socket, address = super().get_request()
        socket.settimeout(8)
        return socket, address


def main() -> None:
    logging.basicConfig(level=logging.WARNING)
    os.umask(0o077)
    db_path, allowed_host, keys, port = load_config()
    init_db(db_path)
    srv = LocalHTTPServer(
        ("127.0.0.1", port),
        make_handler(db_path=db_path, allowed_host=allowed_host, keys=keys),
    )
    LOG.warning("DenaProbe receiver started (loopback only)")
    try:
        srv.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
