"""D1-C3C: per-UID protected DNS transport, NSS gate and no fallback."""
import socket
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from edge_egress_uid_dns import (
    DNSError, DOH_IP, DOH_HOST, PinnedIPDoH, DNSRedirectPlan,
    UDPHandler, TCPHandler, _UDP, _TCP, ensure_running_as_uid,
    plan_transparent_dns, render_dns_required_unit,
    validate_nss_hosts, validate_wire_answer, validate_wire_query,
)
from edge_egress_uid_policy import UIDPolicyRequest
from ops.edge_egress_provision import EgressSpec


def req():
    return UIDPolicyRequest(EgressSpec.from_json({
        "edge_id": "fra1", "edge_public_ipv4": "216.126.229.12",
        "core_public_ipv4": "209.200.246.198",
        "tunnel_network": "10.78.100.0/30",
        "veth_network": "10.78.101.0/30",
        "edge_uplink": "eth0", "edge_listen_port": 51832,
        "route_table": 1780, "mode": "relay",
    }), "nvl0557", 1644, priority=1780)


QUERY = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
         b"\x07example\x03com\x00\x00\x01\x00\x01")
ANSWER = QUERY[:2] + b"\x81\x80" + QUERY[4:]


class FakeUpstream:
    def exchange(self, query):
        assert query == QUERY
        return ANSWER


class FakeTLS:
    def __init__(self):
        self.sent = b""
        self.timeout = None
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def settimeout(self, v): self.timeout = v
    def sendall(self, payload): self.sent += payload


class FakeContext:
    def __init__(self):
        self.server_name = None
        self.tls = FakeTLS()
    def wrap_socket(self, sock, *, server_hostname):
        self.server_name = server_hostname
        return self.tls


class FakeTCP:
    def __enter__(self): return self
    def __exit__(self, *args): pass


class DNSPolicyTests(unittest.TestCase):
    def test_wire_query_validates_id_and_direction(self):
        self.assertEqual(validate_wire_query(QUERY), QUERY)
        self.assertEqual(validate_wire_answer(QUERY, ANSWER), ANSWER)
        with self.assertRaises(DNSError):
            validate_wire_answer(QUERY, b"\xaa\xbb" + ANSWER[2:])
        with self.assertRaises(DNSError):
            validate_wire_query(ANSWER)
        with self.assertRaises(DNSError):
            validate_wire_query(b"x" * 5000)

    def test_only_reviewed_doh_hostname_and_ip(self):
        with self.assertRaises(DNSError):
            PinnedIPDoH("8.8.8.8", "dns.google")
        ctx = FakeContext()
        with patch("edge_egress_uid_dns.ssl.create_default_context",
                   return_value=ctx), \
             patch("edge_egress_uid_dns.socket.create_connection",
                   return_value=FakeTCP()) as connect, \
             patch("edge_egress_uid_dns.http.client.HTTPResponse") as response:
            response.return_value.status = 200
            response.return_value.getheader.return_value = "application/dns-message"
            response.return_value.read.return_value = ANSWER
            self.assertEqual(PinnedIPDoH().exchange(QUERY), ANSWER)
        self.assertEqual(connect.call_args.args[0], (DOH_IP, 443))
        self.assertEqual(ctx.server_name, DOH_HOST)
        self.assertIn(b"POST /dns-query HTTP/1.1\r\n", ctx.tls.sent)
        self.assertIn(b"Host: cloudflare-dns.com\r\n", ctx.tls.sent)
        self.assertIn(QUERY, ctx.tls.sent)

    def test_doh_error_does_not_use_host_dns_or_another_ip(self):
        with patch("edge_egress_uid_dns.socket.create_connection",
                   side_effect=OSError("blocked")) as connect, \
             patch("edge_egress_uid_dns.socket.getaddrinfo",
                   side_effect=AssertionError("DNS bootstrap")):
            with self.assertRaisesRegex(DNSError, "DOH_CONNECT_FAILED"):
                PinnedIPDoH().exchange(QUERY)
        self.assertEqual(connect.call_count, 1)

    def test_redirect_only_selected_uid_udp_and_tcp(self):
        policy = plan_transparent_dns(req(), 10553)
        self.assertIsInstance(policy, DNSRedirectPlan)
        for rule in (policy.udp.argv, policy.tcp.argv):
            self.assertIn("--uid-owner", rule)
            self.assertIn("1644", rule)
            self.assertIn("--dport", rule)
            self.assertIn("53", rule)
            self.assertIn("10553", rule)
            self.assertNotIn("209.200.246.198", rule)
        self.assertIn("udp", policy.udp.argv)
        self.assertIn("tcp", policy.tcp.argv)
        with self.assertRaises(DNSError):
            plan_transparent_dns(req(), 53)

    def test_denies_systemd_resolved_nss_delegation(self):
        validate_nss_hosts("passwd: files\nhosts: files dns\n")
        for config in (
            "hosts: files resolve [!UNAVAIL=return] dns",
            "hosts: files myhostname dns", "hosts: files mdns4_minimal dns",
            "hosts: files dns\nhosts: files dns",
            "hosts: files",
        ):
            with self.subTest(config=config), self.assertRaises(DNSError):
                validate_nss_hosts(config)

    def test_proxy_cannot_run_as_root_or_wrong_uid(self):
        with patch("edge_egress_uid_dns.pwd.getpwnam",
                   return_value=SimpleNamespace(pw_uid=1644)), \
             patch("edge_egress_uid_dns.os.geteuid", return_value=0):
            with self.assertRaisesRegex(DNSError, "PROTECTED_UID"):
                ensure_running_as_uid(1644, "nvl0557")

    def test_ssh_depends_on_guard_and_dns(self):
        unit = render_dns_required_unit(req(), 10553)
        self.assertIn("RequiredBy=ssh.service", unit)
        self.assertIn("Requires=nvl-egress-guard-nvl0557.service", unit)
        self.assertIn("After=nvl-egress-guard-nvl0557.service", unit)
        self.assertIn("Before=ssh.service", unit)
        self.assertIn("User=nvl0557", unit)
        self.assertIn("--port 10553", unit)
        self.assertNotIn("PrivateNetwork=yes", unit)

    def test_udp_local_loopback_transport_with_mock_upstream(self):
        with _UDP(("127.0.0.1", 0), UDPHandler) as udp:
            udp.upstream = FakeUpstream()
            thread = threading.Thread(target=udp.serve_forever, daemon=True)
            thread.start()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    client.sendto(QUERY, udp.server_address)
                    self.assertEqual(client.recvfrom(512)[0], ANSWER)
            finally:
                udp.shutdown()
                thread.join(timeout=2)

    def test_tcp_local_loopback_dns_framing(self):
        with _TCP(("127.0.0.1", 0), TCPHandler) as tcp:
            tcp.upstream = FakeUpstream()
            thread = threading.Thread(target=tcp.serve_forever, daemon=True)
            thread.start()
            try:
                with socket.create_connection(tcp.server_address, timeout=2) as client:
                    client.settimeout(2)
                    client.sendall(len(QUERY).to_bytes(2, "big") + QUERY)
                    size = int.from_bytes(client.recv(2), "big")
                    self.assertEqual(size, len(ANSWER))
                    self.assertEqual(client.recv(size), ANSWER)
            finally:
                tcp.shutdown()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
