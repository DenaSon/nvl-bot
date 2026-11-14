"""Regression tests for the SSH limiter embedded in the Core promotion script.

These tests execute only the extracted Python source with mocked OS commands.
They never invoke the promotion script, iptables, ipset, SSH or process signals.
"""
import pathlib
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROMOTION = ROOT / "promote_edge_to_core.sh"
HEREDOC_START = "cat << 'EOF' > /root/ip_limiter.py\n"


def load_embedded_limiter():
    shell = PROMOTION.read_text(encoding="utf-8")
    assert shell.count(HEREDOC_START) == 1, "Expected one embedded limiter"
    embedded = shell.split(HEREDOC_START, 1)[1].split("\nEOF\n", 1)[0]
    module = types.ModuleType("embedded_ssh_limiter_under_test")
    exec(compile(embedded, str(PROMOTION) + ":ip_limiter.py", "exec"), module.__dict__)
    return module


def tick_with_peers(module, ips, limit=1):
    rows = []
    pids = {}
    for index, ip in enumerate(ips, start=1):
        pid = 4000 + index
        pids[pid] = "testuser"
        rows.append(
            f'ESTAB 0 0 10.77.0.1:2252 {ip}:{50000 + index} '
            f'users:(("sshd",pid={pid},fd=4))'
        )
    with (
        mock.patch.object(module, "_run", return_value="\n".join(rows)),
        mock.patch.object(module, "_pid_to_user_map", return_value=pids),
        mock.patch.object(module, "_read_limit", return_value=limit),
        mock.patch.object(module, "apply_cooldown") as cooldown,
        mock.patch.object(module.os, "kill") as kill,
    ):
        module._tick()
        return cooldown.call_args_list, kill.call_args_list


class SharedEdgeIPLimiterTests(unittest.TestCase):
    def test_shared_edge_subnet_is_recognized(self):
        limiter = load_embedded_limiter()
        for ip in ("10.77.0.1", "10.77.0.35", "10.77.0.175", "10.77.0.254"):
            with self.subTest(ip=ip):
                self.assertTrue(limiter.is_shared_edge_ip(ip))
        for ip in ("10.77.1.1", "10.78.0.175", "203.0.113.9", "::1", "bad-ip"):
            with self.subTest(ip=ip):
                self.assertFalse(limiter.is_shared_edge_ip(ip))

    def test_shared_edge_ip_is_never_added_to_penalty_set(self):
        limiter = load_embedded_limiter()
        with mock.patch.object(limiter.subprocess, "run") as run:
            limiter.apply_cooldown("10.77.0.175")
            limiter.apply_cooldown("10.77.0.176")
            run.assert_not_called()

            limiter.apply_cooldown("203.0.113.10")
            run.assert_called_once()
            self.assertEqual(
                run.call_args.args[0],
                ["ipset", "add", "ssh_penalty", "203.0.113.10", "timeout", "10"],
            )

    def test_two_edges_same_user_cannot_trigger_penalty_or_kill(self):
        limiter = load_embedded_limiter()
        penalties, kills = tick_with_peers(
            limiter, ("10.77.0.175", "10.77.0.176"), limit=1
        )
        self.assertEqual(penalties, [])
        self.assertEqual(kills, [])

    def test_mixed_edge_and_one_direct_ip_does_not_trigger_penalty(self):
        limiter = load_embedded_limiter()
        penalties, kills = tick_with_peers(
            limiter, ("10.77.0.175", "203.0.113.10"), limit=1
        )
        self.assertEqual(penalties, [])
        self.assertEqual(kills, [])

    def test_verified_awg_shared_source_is_not_penalized(self):
        limiter = load_embedded_limiter()
        with mock.patch.object(limiter, "_awg_shared_ips",
                               return_value=frozenset({"10.231.55.2"})):
            self.assertTrue(limiter.is_shared_edge_ip("10.231.55.2"))
            self.assertFalse(limiter.is_shared_edge_ip("10.231.55.3"))
            penalties, kills = tick_with_peers(
                limiter, ("10.77.0.175", "10.231.55.2"), limit=1
            )
            self.assertEqual(penalties, [])
            self.assertEqual(kills, [])

    def test_two_direct_ips_keep_existing_penalty_behavior(self):
        limiter = load_embedded_limiter()
        direct_ips = ("203.0.113.10", "198.51.100.20")
        penalties, kills = tick_with_peers(
            limiter, ("10.77.0.175", *direct_ips), limit=1
        )
        self.assertEqual(len(penalties), 1)
        self.assertIn(penalties[0].args[0], direct_ips)
        self.assertEqual(len(kills), 1)
        self.assertEqual(kills[0].args[1], limiter.signal.SIGKILL)


if __name__ == "__main__":
    unittest.main()
