#!/usr/bin/env python3
"""R3 standalone relay-local fixed-body responder; NEVER expose publicly.

Deploy only after explicit operator acceptance. This is NOT started or imported
by Core Collector or the NVLBot. Lock SSH PermitOpen to 127.0.0.1:18180.
Each accepted TCP connection receives a bounded deterministic body (0x5A).
No HTTP listener, credentials, command execution or external data collection.
"""
from __future__ import annotations
import argparse
import socket
import threading

DEFAULT_BYTES = 16384
MAX_CLIENTS = 4


def serve(port: int, count: int, stop_event=None) -> None:
    if not 1 <= count <= 65536:
        raise ValueError("bytes must be 1..65536")
    if not 1024 <= port <= 65535:
        raise ValueError("invalid private port")
    slots = threading.BoundedSemaphore(MAX_CLIENTS)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(MAX_CLIENTS)
        listener.settimeout(0.5)
        while stop_event is None or not stop_event.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            if not slots.acquire(blocking=False):
                conn.close()
                continue
            def send_body(sock):
                try:
                    with sock:
                        sock.settimeout(8)
                        remaining = count
                        chunk = b"Z" * 1024
                        while remaining:
                            size = min(remaining, len(chunk))
                            sock.sendall(chunk[:size])
                            remaining -= size
                        # Graceful EOF; no request parsing or public egress.
                        sock.shutdown(socket.SHUT_WR)
                except (OSError, TimeoutError):
                    pass
                finally:
                    slots.release()
            threading.Thread(target=send_body, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Loopback-only DenaProbe static payload")
    p.add_argument("--port", type=int, default=18180)
    p.add_argument("--bytes", type=int, default=DEFAULT_BYTES)
    args = p.parse_args()
    serve(args.port, args.bytes)
