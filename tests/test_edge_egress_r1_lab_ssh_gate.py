"""R1 authorized_keys read-only forced-command tests; no real SSH calls."""
import unittest
from unittest.mock import patch

from edge_egress_r1_lab_ssh_gate import (
    AGENT, COORDINATOR_IP, execute_ssh_readonly,
)


class ForcedReadOnlyGateTests(unittest.TestCase):
    def test_exact_agent_inspect_and_probe(self):
        for action in ("probe", "inspect"):
            with self.subTest(action=action), patch(
                "edge_egress_r1_lab_ssh_gate._request",
                return_value=(object(), "06d10e9cceae38c8519834e69ac3a2717ef8c18b"),
            ), patch(
                "edge_egress_r1_lab_ssh_gate.execute",
                return_value={"ok": True, "role": "edge",
                              "state": "TRANSPORT_VERIFIED"},
            ) as invoked:
                cmd = f"/usr/bin/python3 {AGENT} {action} TEST_PAYLOAD"
                answer = execute_ssh_readonly(
                    cmd, f"{COORDINATOR_IP} 12345 216.126.229.12 22",
                )
                self.assertTrue(answer["ok"])
                invoked.assert_called_once_with(action, "TEST_PAYLOAD")

    def test_start_and_arbitrary_shell_never_execute(self):
        for candidate in (
            f"/usr/bin/python3 {AGENT} start PAYLOAD",
            "id",
            f"/usr/bin/python3 {AGENT} inspect PAYLOAD; /bin/bash",
            f"/usr/bin/python3 {AGENT} inspect PAYLOAD && whoami",
            f"/bin/sh -c '{AGENT} inspect PAYLOAD'",
        ):
            with self.subTest(candidate=candidate), patch(
                "edge_egress_r1_lab_ssh_gate.execute"
            ) as dispatched:
                with self.assertRaises(ValueError):
                    execute_ssh_readonly(
                        candidate, f"{COORDINATOR_IP} 12345 216.126.229.12 22",
                    )
                dispatched.assert_not_called()

    def test_other_source_cannot_use_gate(self):
        with self.assertRaisesRegex(ValueError, "UNTRUSTED_SOURCE"):
            execute_ssh_readonly(
                f"/usr/bin/python3 {AGENT} inspect P",
                "209.200.246.198 123 216.126.229.12 22",
            )

    def test_unknown_source_commit_denied_before_dispatch(self):
        with patch(
            "edge_egress_r1_lab_ssh_gate._request",
            return_value=(object(), "a" * 40),
        ), patch("edge_egress_r1_lab_ssh_gate.execute") as dispatched:
            with self.assertRaisesRegex(ValueError, "UNPINNED_LAB_COMMIT"):
                execute_ssh_readonly(
                    f"/usr/bin/python3 {AGENT} inspect P",
                    f"{COORDINATOR_IP} 12345 216.126.229.12 22",
                )
            dispatched.assert_not_called()


if __name__ == "__main__":
    unittest.main()
