"""D1-D2D standalone SSH canary pure contract tests; NO host mutations."""
import unittest
from unittest.mock import patch

from ops.labs import edge_egress_stg1_ssh_canary as canary


class SSHCanaryContractTests(unittest.TestCase):
    def test_nonproduction_unique_identity_and_endpoint(self):
        self.assertEqual(canary.USERNAME, "nvlstg1")
        self.assertEqual(canary.LISTEN_IP, "10.78.111.2")
        self.assertEqual(canary.CORE_VETH_IP, "10.78.111.1")
        self.assertEqual(canary.EXPECTED_EDGE, "216.126.229.12")
        self.assertEqual(canary.PORT, 22282)
        self.assertNotEqual(canary.CORE_IP, canary.EXPECTED_EDGE)
        self.assertNotIn("wg0", canary.NS)

    def test_independent_server_config_never_imports_production_sshd(self):
        s=canary.ssh_config()
        for line in (
            "ListenAddress 10.78.111.2",
            "Port 22282",
            "AllowUsers nvlstg1",
            "PermitRootLogin no",
            "PubkeyAuthentication yes",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "AuthenticationMethods publickey",
            "DisableForwarding yes",
            "PermitTTY no",
            "ForceCommand /var/lib/nvl-egress-stg1-sshd/egress-proof.sh",
        ):
            self.assertIn(line, s)
        for forbidden in ("Include /etc/ssh", "ListenAddress 0.0.0.0",
                          "Port 22\n", "AuthorizedKeysFile .ssh/authorized_keys",
                          "PasswordAuthentication yes", "PermitRootLogin yes"):
            self.assertNotIn(forbidden,s)
        self.assertTrue(str(canary.CONFIG).startswith("/var/lib/nvl-egress-stg1-sshd/"))
        self.assertNotIn("ssh.service",s)

    def test_only_forced_command_may_prove_egress(self):
        script=canary.proof_script()
        self.assertIn('id -un',script)
        self.assertIn('nvlstg1',script)
        self.assertIn('https://api.ipify.org',script)
        self.assertIn('216.126.229.12',script)
        self.assertIn("SSH_CANARY_AUTH=PASS",script)
        self.assertIn("SSH_CANARY_EGRESS=PASS",script)
        self.assertNotIn("209.200.246.198",script)
        self.assertNotIn("sudo",script)
        self.assertNotIn("iptables",script)

    def test_prepare_already_existent_user_rejected_prior_to_mutation(self):
        with patch.object(canary,"preflight",return_value={"issues":[]}),\
             patch.object(canary,"is_root_owned",return_value=True),\
             patch.object(canary,"cmd") as command,\
             patch.object(canary.pwd,"getpwnam",return_value=object()),\
             patch.object(canary.DIR.__class__,"exists",return_value=False),\
             patch.object(canary.DIR.__class__,"is_symlink",return_value=False):
            with self.assertRaisesRegex(canary.Unsafe,"STAGING_ACCOUNT_ALREADY_EXISTS"):
                canary.prepare()
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
