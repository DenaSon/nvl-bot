#!/usr/bin/env python3
"""C3D probe for DNS-port-53 redirect to UID-local DoH in isolated CI."""
import argparse
import socket


def build_query():
    return (b"\x54\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x07example\x04test\x00\x00\x01\x00\x01")


def check_answer(response: bytes):
    if len(response) < 16 or response[:2] != b"\x54\x34":
        raise ValueError("WRONG_DNS_TRANSACTION")
    if response[2] & 0x80 == 0 or b"\xcb\x00\x71\x33" not in response:
        raise ValueError("NO_EXPECTED_EDGE_DNS_ANSWER")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    p.add_argument("--must-fail", action="store_true")
    args = p.parse_args()
    q = build_query()
    try:
        if args.protocol == "udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(8)
                s.sendto(q, ("8.8.8.8", 53))
                answer, _ = s.recvfrom(4096)
        else:
            with socket.create_connection(("8.8.8.8", 53), timeout=8) as s:
                s.settimeout(8)
                s.sendall(len(q).to_bytes(2, "big") + q)
                length = int.from_bytes(s.recv(2), "big")
                data = b""
                while len(data) < length:
                    next_data = s.recv(length - len(data))
                    if not next_data:
                        raise ValueError("TRUNCATED_DNS_TCP_RESPONSE")
                    data += next_data
                answer = data
        check_answer(answer)
        if args.must_fail:
            raise RuntimeError("DNS_LEAK: QUERY_SUCCEEDED_WITH_EDGE_DOWN")
        print("DNS_%s_THROUGH_EDGE_OK" % args.protocol.upper())
    except (TimeoutError, OSError, ValueError):
        if args.must_fail:
            print("DNS_%s_FAIL_CLOSED_OK" % args.protocol.upper())
        else:
            raise


if __name__ == "__main__":
    main()
