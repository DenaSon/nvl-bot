#!/usr/bin/env python3
"""D1-C3D fake TLS DoH Internet endpoint; ephemeral GitHub netns ONLY.

The lab root generates a disposable test certificate trusted by the
UID-local DNS proxy. This fixture is NOT Cloudflare, not a public resolver,
and must never be deployed or treated as a production DNS guarantee.
"""
import argparse
import os
import socket
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer


class FakeDoH(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/dns-query" or self.headers.get("Content-Type") != "application/dns-message":
            self.send_error(400)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if not 12 <= length <= 4096:
            self.send_error(400)
            return
        query = self.rfile.read(length)
        if query[2] & 0x80 or query[4:6] != b"\x00\x01":
            self.send_error(400)
            return
        # One DNS A RR with 203.0.113.51; echo original question.
        payload = (query[:2] + b"\x81\x80" + query[4:6] +
                   b"\x00\x01\x00\x00\x00\x00" + query[12:] +
                   b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04" +
                   bytes((203, 0, 113, 51)))
        with open(self.server.peer_log, "a", encoding="ascii") as f:
            f.write(self.client_address[0] + "\n")
            f.flush()
            os.fsync(f.fileno())
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        pass


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--peer-log", required=True)
    args = p.parse_args()
    server = HTTPServer(("1.1.1.1", 443), FakeDoH)
    server.peer_log = args.peer_log
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
