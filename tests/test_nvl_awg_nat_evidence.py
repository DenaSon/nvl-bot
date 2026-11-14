"""Read-only, synthetic AWG NAT evidence regression tests; no firewall writes."""
import unittest
from dataclasses import replace

from nvl_awg_nat_evidence import AWGNATEvidence, verify_awg_nat


def nat_rules(port=2252, tls=2088):
    lines = []
    for p in (port, tls):
        lines.extend([
            f"-A PREROUTING -i eth1 -p tcp -m tcp --dport {p} "
            f"-j DNAT --to-destination 10.231.55.1:{p}",
            f"-A POSTROUTING -d 10.231.55.1/32 -o awg0 -p tcp -m tcp "
            f"--dport {p} -j SNAT --to-source 10.231.55.3",
        ])
    return "\n".join(lines)


def forwards(port=2252, tls=2088):
    lines = []
    for p in (port, tls):
        lines.extend([
            f"-A FORWARD -d 10.231.55.1/32 -i eth1 -o awg0 -p tcp "
            f"-m tcp --dport {p} -j ACCEPT",
            f"-A FORWARD -s 10.231.55.1/32 -i awg0 -o eth1 -p tcp "
            f"-m tcp --sport {p} -m conntrack "
            f"--ctstate RELATED,ESTABLISHED -j ACCEPT",
        ])
    return "\n".join(lines)


class AWGNATTests(unittest.TestCase):
    def setUp(self):
        self.evidence = AWGNATEvidence(
            wan="eth1", core_tunnel_ip="10.231.55.1",
            edge_tunnel_ip="10.231.55.3", customer_port=2252,
            tls_port=2088,
            live_nat=nat_rules(), saved_rules=nat_rules()+"\n"+forwards(),
            live_forward=forwards(), forwarding="1",
            awg_service="active", awg_autostart="enabled",
            netfilter_autostart="enabled",
        )

    def test_new_edge_ssh_and_tls_success(self):
        self.assertTrue(verify_awg_nat(self.evidence))

    def test_saved_vs_runtime_rules_must_both_match(self):
        self.assertFalse(verify_awg_nat(replace(
            self.evidence, saved_rules=nat_rules(),
        )))
        self.assertFalse(verify_awg_nat(replace(
            self.evidence, live_forward="",
        )))
        self.assertFalse(verify_awg_nat(replace(
            self.evidence, live_nat=nat_rules().replace(
                "10.231.55.1:2088", "10.231.55.9:2088"
            ),
        )))

    def test_wrong_egress_ip_duplicate_rules_and_backend(self):
        self.assertFalse(verify_awg_nat(replace(
            self.evidence, saved_rules=self.evidence.saved_rules +
            "\n" + nat_rules().splitlines()[0],
        )))
        self.assertFalse(verify_awg_nat(replace(
            self.evidence, live_nat=nat_rules().replace(
                "10.231.55.3", "10.231.55.9"
            ),
        )))
        self.assertFalse(verify_awg_nat(replace(
            self.evidence, wan="awg0",
        )))

    def test_enabled_service_not_equal_live_service(self):
        for x in ("awg_service", "awg_autostart", "netfilter_autostart"):
            with self.subTest(x=x):
                self.assertFalse(verify_awg_nat(replace(
                    self.evidence, **{x:"inactive"},
                )))

    def test_disabled_forwarding_and_port_collision(self):
        self.assertFalse(verify_awg_nat(replace(
            self.evidence, forwarding="0",
        )))
        self.assertFalse(verify_awg_nat(replace(
            self.evidence, tls_port=2252,
        )))


if __name__ == "__main__":
    unittest.main()
