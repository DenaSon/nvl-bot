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
from edge_egress_uid_route_state import inspect_owned_routes, ProtectedRouteError

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
                    mime = response.getheader("Content-Type", "") or ""
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


def render_dns_required_unit(request: UIDPolicyRequest, port: int) -> str:
    """Isolated per-UID DNS unit, not a shared ssh.service dependency.

    The F2 session gate must still prevent unguarded protected account logins.
    """
    plan_transparent_dns(request, port)
    name = request.username
    return (
        "[Unit]\n"
        f"Description=NVL UID Edge DoH local stub for {name}\n"
        "After=nvl-egress-guard-" + name + ".service\n"
        "Requires=nvl-egress-guard-" + name + ".service\n"
        "\n[Service]\n"
        "Type=notify\n"
        "NotifyAccess=main\n"
        "TimeoutStartSec=20\n"
        f"User={name}\n"
        "NoNewPrivileges=yes\n"
        "PrivateTmp=yes\n"
        "ProtectSystem=strict\n"
        "ProtectHome=yes\n"
        "Restart=on-failure\n"
        "RestartSec=2\n"
        "ExecStart=/usr/bin/python3 /opt/nvl-egress/edge_egress_uid_dns.py "
        f"serve --username {name} --uid {request.uid} "
        f"--priority {request.priority} --table {request.spec.route_table} "
        f"--edge-next-hop {request.spec.ns_veth_ip} "
        f"--edge-veth {request.spec.veth_root} "
        f"--edge-src {request.spec.root_veth_ip} "
        f"--port {port}\n"
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


def ensure_terminal_policy(uid: int, priority: int, table: int, *,
                           edge_next_hop: str | None = None,
                           edge_veth: str | None = None,
                           edge_src: str | None = None):
    """Check complete UID selector and only exact owned Edge+blackhole routes.

    Missing Edge identity is accepted for the blackhole-only lab state. A
    production-generated DNS unit always supplies the immutable Edge identity.
    """
    result = subprocess.run(["ip", "-4", "rule", "show"],
                            capture_output=True, text=True, timeout=6)
    expected = f"{priority}: from all uidrange {uid}-{uid} lookup {table}"
    rules = [" ".join(x.strip().split()) for x in result.stdout.splitlines()]
    if result.returncode or rules.count(expected) != 1:
        raise DNSError("PROTECTED_UID_RULE_MISSING")
    # A second uidrange selector (including a broader overlapping range)
    # can precede the owned route and send the DoH daemon to Core/main.
    # Fail closed before opening any DNS proxy socket.
    for line in rules:
        if "uidrange" not in line:
            continue
        match = re.search(r"\buidrange\s+(\d+)-(\d+)\b", line)
        if not match:
            raise DNSError("UNRECOGNIZED_UID_ROUTING_RULE")
        low, high = map(int, match.groups())
        if low <= uid <= high and line != expected:
            raise DNSError("PROTECTED_UID_ALREADY_ROUTED_ELSEWHERE")
    if any(x is not None for x in (edge_next_hop, edge_veth, edge_src)) and not all(
        x is not None for x in (edge_next_hop, edge_veth, edge_src)
    ):
        raise DNSError("INCOMPLETE_EDGE_IDENTITY")
    result = subprocess.run(["ip", "-4", "route", "show", "table", str(table)],
                            capture_output=True, text=True, timeout=6)
    if result.returncode:
        raise DNSError("TERMINAL_BLACKHOLE_MISSING")
    try:
        state = inspect_owned_routes(
            result.stdout, next_hop=edge_next_hop or "0.0.0.0",
            device=edge_veth or "_not_an_edge_",
            source=edge_src or "0.0.0.0",
        )
    except ProtectedRouteError as exc:
        raise DNSError("PROTECTED_ROUTE_TABLE_NOT_OWNED") from exc
    if state.edge_attached and edge_next_hop is None:
        raise DNSError("EDGE_IDENTITY_REQUIRED")


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


def sd_notify_ready() -> None:
    """Signal systemd readiness only after both listening sockets exist.

    Pure startup notification, not a claim that Edge is online. A missing
    NOTIFY_SOCKET is allowed for explicitly invoked disposable lab runs.
    """
    addr = os.environ.get("NOTIFY_SOCKET", "")
    if not addr:
        return
    if not (addr.startswith("/") or addr.startswith("@")):
        raise DNSError("INVALID_NOTIFY_SOCKET")
    target = ("\0" + addr[1:]) if addr.startswith("@") else addr
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
        try:
            client.sendto(b"READY=1", target)
        except OSError as exc:
            raise DNSError("SYSTEMD_READY_NOTIFY_FAILED") from exc


def serve(uid: int, username: str, priority: int, table: int,
          port: int, *, upstream=None, edge_next_hop=None,
          edge_veth=None, edge_src=None):
    ensure_running_as_uid(uid, username)
    if not 1024 <= port <= 65535:
        raise DNSError("INVALID_PORT")
    ensure_terminal_policy(uid, priority, table, edge_next_hop=edge_next_hop,
                           edge_veth=edge_veth, edge_src=edge_src)
    upstream = upstream if upstream is not None else PinnedIPDoH()
    with _UDP(("127.0.0.1", port), UDPHandler) as udp:
        with _TCP(("127.0.0.1", port), TCPHandler) as tcp:
            udp.upstream = upstream
            tcp.upstream = upstream
            # Both protocols share a fixed local-only high port.
            import threading
            thread = threading.Thread(target=udp.serve_forever, daemon=True)
            thread.start()
            # Type=notify: SSH may only start once the DNS listeners are
            # actually bound and the UDP serving thread has been started.
            # No network/DNS-bootstrap operation happens in this signal.
            sd_notify_ready()
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
    parser.add_argument("--edge-next-hop", required=True)
    parser.add_argument("--edge-veth", required=True)
    parser.add_argument("--edge-src", required=True)
    args = parser.parse_args(argv)
    try:
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", args.username):
            raise DNSError("INVALID_USERNAME")
        serve(args.uid, args.username, args.priority, args.table, args.port,
              edge_next_hop=args.edge_next_hop, edge_veth=args.edge_veth,
              edge_src=args.edge_src)
    except (DNSError, OSError, subprocess.TimeoutExpired):
        print("DNS_PROXY_UNAVAILABLE", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
