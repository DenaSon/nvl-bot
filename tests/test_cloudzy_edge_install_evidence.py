"""Hermetic P4 evidence-parser tests: no SSH, provider API or system changes."""
import unittest
from pathlib import Path
from cloudzy_edge_install_evidence import (
    EdgeEvidenceHold, CHECKS, inspect_edge_evidence, legacy_installer_repeat_hazards,
)

CORE_KEY = "A" * 43 + "="
SSH_PORT = 2252
TLS_PORT = 2088

def nat(port=SSH_PORT, tls=TLS_PORT):
    return "\n".join((
        f"-A PREROUTING -p tcp -m tcp --dport {port} -j DNAT "
        f"--to-destination 10.77.0.1:{port}",
        f"-A PREROUTING -p tcp -m tcp --dport {tls} -j DNAT "
        f"--to-destination 10.77.0.1:{tls}",
        "-A POSTROUTING ! -o lo -j MASQUERADE",
    ))

def inspect(**changes):
    facts = dict(wg_peers=CORE_KEY+"\n", core_public_key=CORE_KEY,
                 ip_forward="1\n", active_nat=nat(), saved_nat=nat(),
                 customer_port=SSH_PORT, tls_port=TLS_PORT)
    facts.update(changes)
    return inspect_edge_evidence(**facts)

class EdgeManifestTests(unittest.TestCase):
    def test_full_read_only_observations_still_not_adoption(self):
        manifest = inspect()
        self.assertEqual(manifest.blockers, ())
        self.assertEqual(manifest.disposition, "COMPLETE_OBSERVATIONS_NOT_ADOPTION")
        self.assertEqual(tuple(x.code for x in manifest.lines),
                         tuple(x[0] for x in CHECKS))
        self.assertTrue(all(x.status == "PASS" for x in manifest.lines))

    def test_half_configured_or_wrong_wireguard_peer_blocks(self):
        for peers in ("", "B"*43+"=\n", CORE_KEY+"\n"+"C"*43+"=\n",
                      "unexpected non-key value\n"):
            with self.subTest(peers=peers[:8]):
                manifest = inspect(wg_peers=peers)
                self.assertIn("WG_CORE_PEER", manifest.blockers)
                self.assertEqual(manifest.disposition, "INSPECT_ONLY")
        self.assertIn("IP_FORWARD", inspect(ip_forward="0\n").blockers)

    def test_nat_duplicate_rules_not_accepted(self):
        duplicate = nat() + "\n" + nat().splitlines()[0]
        manifest = inspect(active_nat=duplicate)
        self.assertIn("SSH_DNAT", manifest.blockers)
        self.assertNotIn("TLS_DNAT", manifest.blockers)
        self.assertEqual(manifest.disposition, "INSPECT_ONLY")
        duplicate_masq = nat()+"\n-A POSTROUTING ! -o lo -j MASQUERADE"
        self.assertIn("MASQUERADE", inspect(active_nat=duplicate_masq).blockers)

    def test_nat_conflicting_destination_or_missing_tls_blocks(self):
        modified = nat().replace("10.77.0.1:2252", "10.77.0.9:2252")
        self.assertIn("SSH_DNAT", inspect(active_nat=modified).blockers)
        no_tls = "\n".join(nat().splitlines()[::2])
        self.assertIn("TLS_DNAT", inspect(active_nat=no_tls).blockers)

    def test_missing_persistent_rules_blocks_even_if_live_is_ok(self):
        manifest = inspect(saved_nat="")
        self.assertIn("PERSISTED_NAT", manifest.blockers)
        self.assertNotIn("SSH_DNAT", manifest.blockers)
        self.assertNotIn("MASQUERADE", manifest.blockers)

    def test_malformed_evidence_is_not_trusted(self):
        with self.assertRaisesRegex(EdgeEvidenceHold, "INVALID_PORT"):
            inspect(customer_port=0)
        with self.assertRaisesRegex(EdgeEvidenceHold, "DUPLICATE"):
            inspect(tls_port=SSH_PORT)
        with self.assertRaisesRegex(EdgeEvidenceHold, "INVALID_PINNED"):
            inspect(core_public_key="secret")
        with self.assertRaisesRegex(EdgeEvidenceHold, "EVIDENCE_MISSING"):
            inspect(active_nat=None)
        with self.assertRaisesRegex(EdgeEvidenceHold, "EVIDENCE_MISSING"):
            inspect(wg_peers="A"*8192)

    def test_real_legacy_installer_has_repeat_unsafe_effects(self):
        source = (Path(__file__).resolve().parents[1] /
                  "setup_edge_relay.sh").read_text()
        risks = legacy_installer_repeat_hazards(source)
        self.assertTrue(all(risks.values()))
        self.assertEqual(
            set(risks),
            {"APPEND_NAT_PREROUTING", "APPEND_NAT_POSTROUTING",
             "REWRITE_WG0_CONFIG", "RESTART_WG0"})


if __name__ == "__main__":
    unittest.main()
