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
    ensure_terminal_policy,
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

    def test_dns_proxy_starts_only_with_full_uid_guard_and_frozen_table(self):
        def command(argv, **kwargs):
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "1780: from all uidrange 1644-1644 lookup 1780\n"
                    if argv == ["ip", "-4", "rule", "show"]
                    else "blackhole default metric 4096\n"
                ),
            )
        with patch("edge_egress_uid_dns.subprocess.run", side_effect=command) as run:
            ensure_terminal_policy(1644, 1780, 1780)
        self.assertEqual(run.call_count, 2)

    def test_dns_proxy_rejects_single_destination_uid_rule(self):
        def command(argv, **kwargs):
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "1780: from all to 1.1.1.1 uidrange 1644-1644 lookup 1780\n"
                    if argv == ["ip", "-4", "rule", "show"]
                    else "blackhole default metric 4096\n"
                ),
            )
        with patch("edge_egress_uid_dns.subprocess.run", side_effect=command):
            with self.assertRaisesRegex(DNSError, "UID_RULE_MISSING"):
                ensure_terminal_policy(1644, 1780, 1780)

    def test_dns_service_fails_closed_on_unknown_route(self):
        def cmd(argv, **kwargs):
            if argv == ["ip", "-4", "rule", "show"]:
                return SimpleNamespace(
                    returncode=0,
                    stdout="1780: from all uidrange 1644-1644 lookup 1780\n")
            return SimpleNamespace(
                returncode=0,
                stdout="blackhole default metric 4096\n"
                       "default via 192.0.2.1 dev eth0\n")
        with patch("edge_egress_uid_dns.subprocess.run", side_effect=cmd):
            with self.assertRaisesRegex(DNSError, "NOT_OWNED"):
                ensure_terminal_policy(1644, 1780, 1780)

    def test_dns_restart_accepts_exact_attached_edge_and_terminal_blackhole(self):
        request = req()
        table = ("default via " + request.spec.ns_veth_ip +
                 " dev " + request.spec.veth_root +
                 " src " + request.spec.root_veth_ip + " metric 100\n" +
                 "blackhole default metric 4096\n")
        def command(argv, **kwargs):
            return SimpleNamespace(returncode=0, stdout=(
                "1780: from all uidrange 1644-1644 lookup 1780\n"
                if argv == ["ip", "-4", "rule", "show"] else table
            ))
        with patch("edge_egress_uid_dns.subprocess.run", side_effect=command):
            ensure_terminal_policy(1644, 1780, 1780,
                                   edge_next_hop=request.spec.ns_veth_ip,
                                   edge_veth=request.spec.veth_root,
                                   edge_src=request.spec.root_veth_ip)
            with self.assertRaises(DNSError):
                ensure_terminal_policy(1644, 1780, 1780)

    def test_real_protected_guard_output_can_start_and_restart_its_dns_service(self):
        # Exercise the actual guard and DNS validators against the SAME
        # modeled kernel state, instead of omitting wg0 from DNS fixtures.
        from edge_egress_uid_boot import BootGuardApplier
        from tests.test_edge_egress_v1_f2 import FakeIngressKernel,protected_fixture
        kernel=FakeIngressKernel()
        manifest=protected_fixture()
        guard=BootGuardApplier(run=kernel,get_uid=lambda _:manifest.request.uid,
            geteuid=lambda:0,read_nss=lambda:'hosts: files dns\n')
        guard.apply(manifest)
        for attached in (False,True):
            kernel.edge_attached=attached
            guard.verify(manifest,require_frozen=True)
            with patch('edge_egress_uid_dns.subprocess.run',
                       side_effect=lambda argv,**kw:kernel(*argv)):
                ensure_terminal_policy(manifest.request.uid,manifest.request.priority,
                    manifest.request.spec.route_table,
                    edge_next_hop=manifest.request.spec.ns_veth_ip,
                    edge_veth=manifest.request.spec.veth_root,
                    edge_src=manifest.request.spec.root_veth_ip)
        self.assertTrue(kernel.ingress_return)

    def test_dns_accepts_only_exact_ssh_return_route_and_never_a_core_default(self):
        request=req()
        good='10.77.0.0/24 dev wg0 scope link src 10.77.0.1\n'
        for route in (good+good,good.replace('wg0','eth0'),
                      good.replace('10.77.0.1','209.200.246.198'),
                      'default via 209.200.246.198 dev eth0\n'):
            with self.subTest(route=route):
                def run(argv,**kw):
                    return SimpleNamespace(returncode=0,stdout=(
                        '1780: from all uidrange 1644-1644 lookup 1780\n'
                        if argv==['ip','-4','rule','show'] else
                        'blackhole default metric 4096\n'+route))
                with patch('edge_egress_uid_dns.subprocess.run',side_effect=run):
                    with self.assertRaisesRegex(DNSError,'NOT_OWNED'):
                        ensure_terminal_policy(1644,1780,1780,
                            edge_next_hop=request.spec.ns_veth_ip,
                            edge_veth=request.spec.veth_root,edge_src=request.spec.root_veth_ip)

    def test_dns_restart_rejects_foreign_edge_or_missing_blackhole(self):
        request = req()
        owned = ("default via " + request.spec.ns_veth_ip +
                 " dev " + request.spec.veth_root +
                 " src " + request.spec.root_veth_ip + " metric 100\n")
        for routes in (
            owned,
            "blackhole default metric 4096\ndefault via 209.200.246.198 dev eth0\n",
            owned + "blackhole default metric 4096\nblackhole default metric 4096\n",
        ):
            with self.subTest(routes=routes):
                def command(argv, **kwargs):
                    return SimpleNamespace(returncode=0, stdout=(
                        "1780: from all uidrange 1644-1644 lookup 1780\n"
                        if argv == ["ip", "-4", "rule", "show"] else routes
                    ))
                with patch("edge_egress_uid_dns.subprocess.run", side_effect=command):
                    with self.assertRaisesRegex(DNSError, "NOT_OWNED"):
                        ensure_terminal_policy(1644, 1780, 1780,
                                               edge_next_hop=request.spec.ns_veth_ip,
                                               edge_veth=request.spec.veth_root,
                                               edge_src=request.spec.root_veth_ip)

    def test_dns_rejects_competing_uidrule_before_core_leak(self):
        request = req()
        good = "1780: from all uidrange 1644-1644 lookup 1780\n"
        for rival in (
            "100: from all uidrange 1644-1644 lookup main\n",
            "101: from all uidrange 1600-1700 lookup main\n",
            "1781: from all uidrange 1644-1644 lookup main\n",
        ):
            with self.subTest(rival=rival):
                def command(argv, **kwargs):
                    if argv == ["ip", "-4", "rule", "show"]:
                        return SimpleNamespace(returncode=0, stdout=rival + good)
                    return SimpleNamespace(
                        returncode=0, stdout="blackhole default metric 4096\n"
                    )
                with patch("edge_egress_uid_dns.subprocess.run", side_effect=command):
                    with self.assertRaisesRegex(
                        DNSError, "PROTECTED_UID_ALREADY_ROUTED_ELSEWHERE"
                    ):
                        ensure_terminal_policy(
                            1644,1780,1780,
                            edge_next_hop=request.spec.ns_veth_ip,
                            edge_veth=request.spec.veth_root,
                            edge_src=request.spec.root_veth_ip,
                        )

    def test_other_uidrule_does_not_block_owned_dns(self):
        def command(argv, **kwargs):
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "100: from all uidrange 1658-1658 lookup 77\n"
                    "1780: from all uidrange 1644-1644 lookup 1780\n"
                    if argv == ["ip","-4","rule","show"] else
                    "blackhole default metric 4096\n"
                ),
            )
        with patch("edge_egress_uid_dns.subprocess.run", side_effect=command):
            ensure_terminal_policy(1644,1780,1780)

    def test_dns_is_isolated_from_global_ssh(self):
        unit = render_dns_required_unit(req(), 10553)
        self.assertNotIn("ssh.service", unit)
        self.assertIn("Requires=nvl-egress-guard-nvl0557.service", unit)
        self.assertIn("After=nvl-egress-guard-nvl0557.service", unit)
        self.assertIn("User=nvl0557", unit)
        self.assertIn("--port 10553", unit)
        self.assertIn("--edge-next-hop " + req().spec.ns_veth_ip, unit)
        self.assertIn("--edge-veth " + req().spec.veth_root, unit)
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
