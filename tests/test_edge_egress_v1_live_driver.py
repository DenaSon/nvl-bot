"""K: narrow DNS, session-idle and UID-probe fail-closed contract tests."""
import asyncio
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

from edge_egress_v1_cloudflare import ProtectedCloudflareDNS, DnsHold
from edge_egress_v1_live_driver import (
    assert_idle_process_snapshot, LiveHold, RemotePinnedEdge,
    ProtectedLiveHostActions,
)

SRC, TGT = "144.172.84.76", "144.172.84.82"
DOMAIN = "edge.example.net"
ZONE = "a" * 32
RID = "b" * 32


class Response:
    def __init__(self, obj):
        self.value = obj
    def __enter__(self):
        return io.BytesIO(json.dumps(self.value).encode())
    def __exit__(self, *_):
        return False


class CloudflareFake:
    def __init__(self, content=SRC, proxied=False, domains=None):
        self.records = {name: content for name in (domains or [DOMAIN])}
        self.proxied = proxied
        self.calls = []
        self.partial = False

    def open(self, req, timeout):
        self.calls.append(req)
        if req.get_method() == "GET":
            from urllib.parse import parse_qs, urlsplit
            name = parse_qs(urlsplit(req.full_url).query)["name"][0]
            data = [{
                "id": RID, "name": name, "type": "A", "proxied": self.proxied,
                "content": self.records[name], "ttl": 120,
            }]
            return Response({"success": True, "result": data})
        payload = json.loads(req.data)
        if self.partial:
            raise OSError("unknown provider outcome")
        self.records[payload["name"]] = payload["content"]
        return Response({"success": True, "result": {"id": RID}})


def make_cf(provider):
    return ProtectedCloudflareDNS(lambda: {
        "token": "test-only", "zone": ZONE, "public_domain": DOMAIN,
        "tls_passthrough": "0",
    }, opener=provider.open)


class CloudflareUnitTests(unittest.TestCase):
    def test_edge_to_edge_requires_old_provider_source_and_validates_result(self):
        backend = CloudflareFake()
        dns = make_cf(backend)
        dns.switch_edge_to_edge(SRC, TGT)
        dns.assert_target(TGT)
        self.assertEqual(backend.records[DOMAIN], TGT)
        self.assertEqual(len([q for q in backend.calls if q.get_method() == "PUT"]), 1)
        with self.assertRaisesRegex(DnsHold, "CF_SOURCE_RECORD_CAS_LOST"):
            dns.switch_edge_to_edge(SRC, TGT)

    def test_no_core_dns_proxy_or_unknown_provider_success(self):
        for bad in ("10.77.0.1", "127.0.0.1", "invalid", "192.168.0.1"):
            with self.assertRaises(DnsHold):
                make_cf(CloudflareFake()).switch_edge_to_edge(SRC, bad)
        proxied = CloudflareFake(proxied=True)
        with self.assertRaisesRegex(DnsHold, "CF_RECORD_IDENTITY_CHANGED"):
            make_cf(proxied).switch_edge_to_edge(SRC, TGT)
        self.assertFalse(any(q.get_method() == "PUT" for q in proxied.calls))

    def test_provider_uncertain_does_not_claim_success(self):
        back = CloudflareFake()
        back.partial = True
        with self.assertRaisesRegex(DnsHold, "CF_REQUEST_UNCERTAIN"):
            make_cf(back).switch_edge_to_edge(SRC, TGT)


class HostUnitTests(unittest.TestCase):
    def test_inactive_process_snapshot_allows_no_uid_login(self):
        assert_idle_process_snapshot(
            "  1 0 systemd /sbin/init\n  101 0 sshd sshd: /usr/sbin/sshd -D\n"
            " 123 1001 bash -bash\n", "nvl0557", 1644
        )

    def test_exact_root_attested_doh_main_pid_is_only_idle_exemption(self):
        dns = (" 333 1644 python3 "
               "/usr/bin/python3 /opt/nvl-egress/edge_egress_uid_dns.py "
               "serve --username nvl0557 --uid 1644 --priority 20008 --table 20008")
        basic = " 1 0 systemd /sbin/init\\n 2 0 kthreadd [kthreadd]\\n"
        assert_idle_process_snapshot(basic + dns + "\\n", "nvl0557", 1644,
                                     allowed_dns_pid=333)
        for wrong_pid in (None, 332):
            with self.assertRaises(LiveHold):
                assert_idle_process_snapshot(
                    basic + dns + "\\n", "nvl0557", 1644,
                    allowed_dns_pid=wrong_pid,
                )
        with self.assertRaisesRegex(LiveHold, "ACTIVE_PROCESS"):
            assert_idle_process_snapshot(
                basic + dns + "\\n 334 1644 curl curl -4 https://example.net\\n",
                "nvl0557", 1644, allowed_dns_pid=333,
            )

    def test_uid_process_or_root_owned_sshd_session_holds(self):
        for line in (
            " 111 1644 curl curl --silent https://example.net",
            " 112 0 sshd sshd: nvl0557 [priv]",
            " 112 0 sshd-session sshd-session: nvl0557@notty",
        ):
            with self.subTest(line=line), self.assertRaises(LiveHold):
                assert_idle_process_snapshot(
                    "  1 0 systemd /sbin/init\n" + line + "\n",
                    "nvl0557", 1644,
                )
        with self.assertRaises(LiveHold):
            assert_idle_process_snapshot("bad inventory", "nvl0557", 1644)

    def test_remote_stage_path_is_validated_before_network(self):
        remote = RemotePinnedEdge(TGT, 22, "not-key", Path("/tmp/key"),
                                  Path("/root/unsafe path"), "a"*64)
        with self.assertRaisesRegex(LiveHold, "REMOTE_STAGE_PATH_UNSAFE"):
            remote.transport("inspect")
        with self.assertRaisesRegex(LiveHold, "REMOTE_COMMAND_NOT_ALLOWED"):
            remote.transport("delete")

    def test_probe_rearms_uid_reject_even_on_mismatched_public_ip(self):
        # The UID is only unfenced for the isolated, F2-admission-blocked probe.
        driver = object.__new__(ProtectedLiveHostActions)
        driver.run = Mock()
        driver._lease = lambda: None  # Isolate re-arm contract after verified 6G lease.
        driver._req = lambda username, uid: SimpleNamespace(
            spec=SimpleNamespace(edge_public_ipv4=TGT)
        )
        async def idle(*_): return None
        async def frozen(*_): return None
        driver.assert_no_ssh_sessions = idle
        driver.assert_uid_frozen = frozen
        driver.kernel = SimpleNamespace(
            public_ipv4=lambda req: SRC,
            assert_dns_ipv6=lambda req: None,
        )
        driver.clock = lambda: 100.0
        driver._proven = {}
        with patch("edge_egress_v1_live_driver.release_uid_deny") as release, \
             patch("edge_egress_v1_live_driver.arm_uid_deny") as rearm:
            with self.assertRaisesRegex(LiveHold, "UID_EGRESS_PUBLIC_IP_MISMATCH"):
                asyncio.run(driver.prove_uid_ipv4("nvl0557", 1644, TGT))
            release.assert_called_once()
            rearm.assert_called_once()
        self.assertNotIn("nvl0557", driver._proven)


if __name__ == "__main__":
    unittest.main()
