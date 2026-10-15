"""K2 M4 cross-Edge ingress/egress binding parser: pure root-file checks.

These tests intentionally do not activate PAM, WireGuard, routing or P3.
"""
from __future__ import annotations

import json
from pathlib import Path
import unittest
from unittest.mock import patch

from edge_egress_uid_runtime_store import RuntimeBinding
from edge_egress_k2_uid_ingress_egress import (
    FIELDS, IngressEgressHold, ROOT_BINDINGS,
    UIDIngressEgressBinding, parse_uid_ingress_egress_bindings,
    load_root_uid_ingress_egress_bindings,
)

SRC = "172.86.111.69"
DST = "45.61.163.75"


def record(**changes):
    row = dict(
        username="nvl0555", uid=1636, ingress_edge="s8",
        ingress_ipv4=SRC, egress_edge="e9", egress_ipv4=DST,
        runtime_generation=3, operation_id=44, guard_sha256="f"*64,
    )
    row.update(changes)
    return row


def encode(items, **changes):
    document = dict(version=2, bindings=items)
    document.update(changes)
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


class K2UIDIngressEgressTests(unittest.TestCase):
    def test_exact_readonly_source_and_protected_egress_are_distinct(self):
        found = parse_uid_ingress_egress_bindings(encode([record()]))
        self.assertEqual(set(found), {"nvl0555"})
        row = found["nvl0555"]
        self.assertIs(type(row), UIDIngressEgressBinding)
        runtime = RuntimeBinding(
            "nvl0555", 1636, "e9", DST,
            20009, 1780, 10553, "PROTECTED", 3, 44,
        )
        self.assertTrue(row.matches_runtime(
            runtime,installed_guard_sha256="f"*64))
        self.assertFalse(row.matches_runtime(
            RuntimeBinding("nvl0555", 1636, "s8", SRC,
                           20008, 1780, 10553, "PROTECTED", 3, 44),
            installed_guard_sha256="f"*64))
        self.assertFalse(row.matches_runtime(
            RuntimeBinding("nvl0555", 1636, "e9", DST,
                           20009, 1780, 10553, "HOLD", 3, 44),
            installed_guard_sha256="f"*64))
        self.assertFalse(row.matches_runtime(object()))

    def test_stale_runtime_generation_operation_or_guard_digest_denies(self):
        policy = parse_uid_ingress_egress_bindings(encode([record()]))["nvl0555"]
        for generation, operation in ((2,44),(4,44),(3,43),(3,45)):
            with self.subTest(generation=generation,operation=operation):
                row = RuntimeBinding(
                    "nvl0555",1636,"e9",DST,20009,1780,10553,
                    "PROTECTED",generation,operation,
                )
                self.assertFalse(policy.matches_runtime(
                    row,installed_guard_sha256="f"*64))
        row = RuntimeBinding(
            "nvl0555",1636,"e9",DST,20009,1780,10553,
            "PROTECTED",3,44,
        )
        for digest in (None,"e"*64,"F"*64,"f"*63):
            self.assertFalse(policy.matches_runtime(
                row,installed_guard_sha256=digest))

    def test_invalid_or_ambiguous_root_policy_is_rejected(self):
        bad = [
            encode([record(uid=True)]),
            encode([record(runtime_generation=0)]),
            encode([record(runtime_generation=True)]),
            encode([record(operation_id=0)]),
            encode([record(operation_id=True)]),
            encode([record(guard_sha256="fake")]),
            encode([record(guard_sha256="F"*64)]),
            encode([record(uid=100)]),
            encode([record(username="root")]),
            encode([record(username="nvl0555;x")]),
            encode([record(ingress_edge="s8;bad")]),
            encode([record(egress_edge="s8")]),
            encode([record(ingress_ipv4=DST)]),
            encode([record(egress_ipv4=SRC)]),
            encode([record(ingress_ipv4="10.77.0.8")]),
            encode([record(egress_ipv4="127.0.0.1")]),
            encode([record(ingress_ipv4="0172.86.111.69")]),
            encode([record(), record()]),
            encode([record(), record(username="nvl0557")]),
            encode([record(), record(username="nvl0557", uid=1636)]),
            encode([record(extra="unapproved")]),
            encode([record()], version=1),
            b'{"version":2,"version":2,"bindings":[]}',
            b'{"version":2,"bindings":[{"username":"a","username":"b"}]}',
            b'{}',
            b'\x00invalid',
            b"x" * 262145,
        ]
        for item in bad:
            with self.subTest(raw=item[:100]), self.assertRaises(IngressEgressHold):
                parse_uid_ingress_egress_bindings(item)

    def test_existing_v1_pam_still_denies_cross_edge_ingress(self):
        # Merely parsing a new root policy cannot change the operational V1
        # SSH login rule. Any rollout must explicitly wire and independently
        # verify the new per-UID ingress-vs-egress contract later.
        import base64
        from edge_egress_v1_ingress import IngressPeer, verify_ingress
        row = RuntimeBinding(
            "nvl0555", 1636, "e9", DST,
            20009, 1780, 10553, "PROTECTED", 3, 44,
        )
        key = base64.b64encode(bytes(range(32))).decode()
        peers = (IngressPeer("s8", SRC, "10.77.0.8", key),)
        allowed = key + " 10.77.0.8/32\n"
        self.assertFalse(verify_ingress(
            row, "10.77.0.8", peers, allowed,
        ))
        self.assertTrue(verify_ingress(
            row, "10.77.0.8",
            (IngressPeer("e9", DST, "10.77.0.8", key),), allowed,
        ))

    def test_empty_policy_does_not_confer_any_cross_edge_permission(self):
        self.assertEqual(parse_uid_ingress_egress_bindings(encode([])), {})

    def test_fixed_root_path_is_checked_before_access(self):
        with patch(
            "edge_egress_k2_uid_ingress_egress._trusted_bytes",
            side_effect=AssertionError("must not read arbitrary path"),
        ):
            with self.assertRaisesRegex(IngressEgressHold, "PATH_NOT_PINNED"):
                load_root_uid_ingress_egress_bindings(
                    Path("/tmp/untrusted/uid-ingress-egress.json")
                )

    def test_root_read_errors_fail_closed_without_empty_fallback(self):
        with patch(
            "edge_egress_k2_uid_ingress_egress._trusted_directory",
            side_effect=OSError("no trusted directory"),
        ):
            with self.assertRaisesRegex(
                IngressEgressHold, "ROOT_SOURCE_UNTRUSTED"
            ):
                load_root_uid_ingress_egress_bindings()

    def test_valid_root_file_is_parsed_but_never_installed(self):
        with patch(
            "edge_egress_k2_uid_ingress_egress._trusted_directory"
        ) as directory, patch(
            "edge_egress_k2_uid_ingress_egress._trusted_bytes",
            return_value=encode([record()]),
        ) as file_read:
            result = load_root_uid_ingress_egress_bindings()
        self.assertIn("nvl0555", result)
        directory.assert_called_once_with(ROOT_BINDINGS.parent)
        file_read.assert_called_once_with(ROOT_BINDINGS, 262144)


if __name__ == "__main__":
    unittest.main()
