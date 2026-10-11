import unittest

from egress_pilot import PilotSpec, RouteEvidence, render_manifests, route_blockers


class EgressPilotTests(unittest.TestCase):
    def setUp(self):
        self.spec = PilotSpec(
            username="nvl0557", namespace="nvl-egress-stg1", wg_interface="wg-nvl-stg1",
            internal_ip="10.78.111.2", expected_edge_ip="216.126.229.12",
            core_ip="209.200.246.198",
        )

    def test_manifests_are_local_only_and_not_auto_enabled(self):
        files = render_manifests(self.spec)
        self.assertEqual(len(files), 4)
        socket = files["/etc/systemd/system/nvl-egress-pilot-proxy.socket"]
        self.assertIn("ListenStream=127.0.0.1:22284", socket)
        self.assertNotIn("[Install]", socket)
        self.assertNotIn("[Install]", files["/etc/systemd/system/nvl-egress-pilot-sshd.service"])
        self.assertTrue(all("ExecStartPost=systemctl" not in v for v in files.values()))

    def test_limited_auth_but_tunnel_allowed(self):
        config = render_manifests(self.spec)["/etc/nvl/egress-pilot/sshd_config"]
        for required in (
            "AllowUsers nvl0557", "PasswordAuthentication yes", "UsePAM yes",
            "PermitRootLogin no", "MaxSessions 0", "PermitTTY no",
            "AllowTcpForwarding local", "PermitUserRC no", "KbdInteractiveAuthentication no",
            "ListenAddress 10.78.111.2", "Port 22284",
        ):
            self.assertIn(required, config)
        self.assertNotIn("ForceCommand", config)

    def test_rejects_unsafe_names_and_ips(self):
        for field, value in (
            ("username", "root"), ("username", "bad user"),
            ("namespace", "nvl;rm -rf /"), ("wg_interface", "bad/interface"),
            ("internal_ip", "8.8.8.8"), ("expected_edge_ip", "10.2.1.1"),
            ("expected_edge_ip", "209.200.246.198"),
            ("ssh_port", 22), ("ssh_port", 70000),
        ):
            data = vars(self.spec).copy()
            data[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                PilotSpec(**data)

    def test_good_route_and_expected_ip(self):
        actual = RouteEvidence(
            ipv4_default_routes="default dev wg-nvl-stg1 scope link\n",
            ipv6_default_routes="",
            wg_interfaces="wg-nvl-stg1\n",
            observed_egress_ip="216.126.229.12",
        )
        self.assertEqual(route_blockers(self.spec, actual), [])

    def test_fails_closed_on_default_core_or_secondary_route(self):
        for bad in (
            "default via 148.113.199.41 dev eth0",
            "default dev wg-nvl-stg1\ndefault via 148.113.199.41 dev eth0",
            "default dev tun0",
            "",
        ):
            evidence = RouteEvidence(bad, "", "wg-nvl-stg1", "216.126.229.12")
            self.assertIn("IPV4_DEFAULT_NOT_EXCLUSIVELY_WIREGUARD", route_blockers(self.spec, evidence))

    def test_fails_closed_on_unreviewed_ipv6_and_wrong_edge(self):
        bad = RouteEvidence(
            "default dev wg-nvl-stg1", "default via fe80::1 dev eth0",
            "wg-nvl-stg1", "209.200.246.198")
        self.assertEqual(set(route_blockers(self.spec, bad)), {
            "UNREVIEWED_IPV6_DEFAULT_ROUTE", "EGRESS_IP_MISMATCH"})

    def test_no_mutation_functions_present_in_contract(self):
        files = render_manifests(self.spec)
        self.assertFalse(any("iptables " in v or "ip rule add" in v
                             or "sqlite3" in v for v in files.values()))


if __name__ == "__main__":
    unittest.main()
