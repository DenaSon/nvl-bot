"""D1-C3C: opt-in per-UID DNS-over-HTTPS relay; NO Core DNS fallback.

Run this unprivileged as the same protected UID whose IPv4 egress rule
terminates at the dedicated Edge table. The upstream is contacted by a
literal IPv4 address; TLS validates the fixed hostname via SNI. This avoids
using systemd-resolved for *this proxy's* bootstrap and ensures its egress
is subject to the same UID route/blackhole.

NOT a general DNS leak guarantee. NSS via resolve/Varlink, nscd, custom
DoH clients and other privileged helpers require independent interception
and proof. No bot, iptables or systemd auto-registration in this module.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import http.client
import ipaddress
import os
import pwd
import re
import socket
import socketserver
import ssl
import subprocess
import sys

from edge_egress_uid_policy import UIDPolicyRequest, _cmd, Command

DOH_IP = "1.1.1.1"
DOH_HOST = "cloudflare-dns.com"
DOH_PATH = "/dns-query"
MAX_WIRE = 4096
TIMEOUT = 6


class DNSError(ValueError):
    pass


def validate_wire_query(data: bytes) -> bytes:
    if not isinstance(data, bytes) or not 12 <= len(data) <= MAX_WIRE:
        raise DNSError("INVALID_DNS_WIRE_SIZE")
    if data[2] & 0x80:  # response supplied as a query
        raise DNSError("NOT_A_QUERY")
    if not int.from_bytes(data[4:6], "big"):  # no question section
        raise DNSError("NO_DNS_QUESTION")
    return data


def validate_wire_answer(query: bytes, answer: bytes) -> bytes:
    if not isinstance(answer, bytes) or not 12 <= len(answer) <= MAX_WIRE:
        raise DNSError("INVALID_DNS_RESPONSE_SIZE")
    if answer[:2] != query[:2] or not (answer[2] & 0x80):
        raise DNSError("DNS_REPLY_TRANSACTION_MISMATCH")
    return answer


class PinnedIPDoH:
    """TLS-authenticated DoH; no redirect, no proxy env or DNS bootstrap."""

    def __init__(self, endpoint: str = DOH_IP,
                 host: str = DOH_HOST):
        # These are fixed reviewed bindings, not user-supplied URLs.
        if endpoint != DOH_IP or host != DOH_HOST:
            raise DNSError("UNREVIEWED_DOH_ENDPOINT")
        self.endpoint = endpoint
        self.host = host

    def exchange(self, query: bytes) -> bytes:
        validate_wire_query(query)
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((self.endpoint, 443), timeout=TIMEOUT) as tcp:
                with ctx.wrap_socket(tcp, server_hostname=self.host) as tls:
                    tls.settimeout(TIMEOUT)
                    header = (
                        f"POST {DOH_PATH} HTTP/1.1\r\n"
                        f"Host: {self.host}\r\n"
                        "Accept: application/dns-message\r\n"
                        "Content-Type: application/dns-message\r\n"
                        f"Content-Length: {len(query)}\r\n"
                        "Connection: close\r\n\r\n"
                    ).encode("ascii")
                    tls.sendall(header + query)
                    response = http.client.HTTPResponse(tls)
                    response.begin()
                    if response.status != 200:
                        raise DNSError("DOH_UPSTREAM_NOT_SUCCESSFUL")
                    mime = response.getheader("Content-Type", "")
                    if mime.split(";", 1)[0].strip().lower() != "application/dns-message":
                        raise DNSError("DOH_CONTENT_TYPE_INVALID")
                    answer = response.read(MAX_WIRE + 1)
                    return validate_wire_answer(query, answer)
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            # Never switch to the system resolver or plaintext DNS.
            raise DNSError("DOH_CONNECT_FAILED") from exc


@dataclass(frozen=True)
class DNSRedirectPlan:
    udp: Command
    tcp: Command
    udp_check: Command
    tcp_check: Command
    # No removal is proposed for a protected customer when Edge is down.


def plan_transparent_dns(request: UIDPolicyRequest, port: int) -> DNSRedirectPlan:
    request.validate()
    if type(port) is not int or not 1024 <= port <= 65535:
        raise DNSError("INVALID_LOCAL_DNS_PORT")
    uid = str(request.uid)
    def make(protocol: str, op: str, with_index: bool):
        base = ("iptables", "-w", "-t", "nat", op, "OUTPUT")
        if with_index:
            base += ("1",)
        return base + ("-m", "owner", "--uid-owner", uid,
                       "-p", protocol, "--dport", "53",
                       "-j", "REDIRECT", "--to-ports", str(port))
    return DNSRedirectPlan(
        _cmd("redirect-udp-dns", *make("udp", "-I", True)),
        _cmd("redirect-tcp-dns", *make("tcp", "-I", True)),
        _cmd("verify-udp-dns", *make("udp", "-C", False)),
        _cmd("verify-tcp-dns", *make("tcp", "-C", False)),
    )


def validate_nss_hosts(contents: str) -> None:
    """Deny 'NSS resolve' delegated outside protected UID.

    This gate is intentionally strict. It doesn't rewrite system-wide NSS
    config or claim to catch cache daemons/other privileged lookups.
    """
    if not isinstance(contents, str):
        raise DNSError("NSS_CONFIG_REQUIRED")
    lines = [
        line.split("#", 1)[0].split(":", 1)[1].strip().split()
        for line in contents.splitlines()
        if line.lstrip().startswith("hosts:") and ":" in line
    ]
    if len(lines) != 1 or lines[0] != ["files", "dns"]:
        raise DNSError("NSS_DELEGATION_UNSAFE")
    # Nscd and other per-host caches require separate live inspection.


def ensure_running_as_uid(uid: int, username: str) -> None:
    if type(uid) is not int or not 1000 <= uid < 60000:
        raise DNSError("UNSAFE_SERVICE_UID")
    try:
        if pwd.getpwnam(username).pw_uid != uid or os.geteuid() != uid:
            raise DNSError("SERVICE_MUST_RUN_AS_PROTECTED_UID")
    except KeyError as exc:
        raise DNSError("USER_NOT_FOUND") from exc


def ensure_terminal_policy(uid: int, priority: int, table: int):
    """Read-only fail-before-bind check; caller must also ensure 6G lease."""
    result = subprocess.run(["ip", "-4", "rule", "show"],
                            capture_output=True, text=True, timeout=6)
    if result.returncode or not re.search(
        rf"(?m)^\s*{priority}:\s+.*\buidrange {uid}-{uid}\b.*\blookup {table}\b",
        result.stdout,
    ):
        raise DNSError("PROTECTED_UID_RULE_MISSING")
    result = subprocess.run(
        ["ip", "-4", "route", "show", "table", str(table)],
        capture_output=True, text=True, timeout=6
    )
    if result.returncode or not re.search(
        r"(?m)^blackhole default\b", result.stdout
    ):
        raise DNSError("TERMINAL_BLACKHOLE_MISSING")


class _UDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _read_n(sock, length: int) -> bytes:
    out = bytearray()
    while len(out) < length:
        block = sock.recv(length - len(out))
        if not block:
            raise DNSError("DNS_TCP_TRUNCATED")
        out.extend(block)
    return bytes(out)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        wire, udp = self.request
        try:
            answer = self.server.upstream.exchange(wire)
            udp.sendto(answer, self.client_address)
        except (DNSError, OSError):
            pass  # fail closed, never ask the host's DNS resolver


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(TIMEOUT)
            size = int.from_bytes(_read_n(self.request, 2), "big")
            if not 12 <= size <= MAX_WIRE:
                return
            answer = self.server.upstream.exchange(_read_n(self.request, size))
            self.request.sendall(len(answer).to_bytes(2, "big") + answer)
        except (DNSError, OSError):
            pass


def serve(uid: int, username: str, priority: int, table: int,
          port: int, *, upstream=None):
    ensure_running_as_uid(uid, username)
    if not 1024 <= port <= 65535:
        raise DNSError("INVALID_PORT")
    ensure_terminal_policy(uid, priority, table)
    upstream = upstream if upstream is not None else PinnedIPDoH()
    with _UDP(("127.0.0.1", port), UDPHandler) as udp:
        with _TCP(("127.0.0.1", port), TCPHandler) as tcp:
            udp.upstream = upstream
            tcp.upstream = upstream
            # Both protocols share a fixed local-only high port.
            import threading
            thread = threading.Thread(target=udp.serve_forever, daemon=True)
            thread.start()
            try:
                tcp.serve_forever()
            finally:
                udp.shutdown()
                thread.join(timeout=3)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Opt-in per-UID Edge DoH proxy")
    parser.add_argument("action", choices=("serve",))
    parser.add_argument("--username", required=True)
    parser.add_argument("--uid", required=True, type=int)
    parser.add_argument("--priority", required=True, type=int)
    parser.add_argument("--table", required=True, type=int)
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", args.username):
            raise DNSError("INVALID_USERNAME")
        serve(args.uid, args.username, args.priority, args.table, args.port)
    except (DNSError, OSError, subprocess.TimeoutExpired):
        print("DNS_PROXY_UNAVAILABLE", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
