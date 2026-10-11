"""F4 external actual-SSH SOCKS proof with no fallback to Core."""
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from edge_egress_f4_ssh_probe import (
    parse_trace_public_ip, probe_external_ssh_socks, SSHProbeUnsafe,
)


def proc(body,code=0):
    return SimpleNamespace(stdout=body,returncode=code)


class SSHProxyProbeTests(unittest.TestCase):
    def invoke(self,body,rc=0,outage=False):
        calls=[]
        def runner(argv,**kwargs):
            calls.append((argv,kwargs))
            return proc(body,rc)
        result=probe_external_ssh_socks(
            port=31884,expected_edge="216.126.229.12",
            core_ipv4="209.200.246.198",expect_outage=outage,run=runner,
        )
        self.assertEqual(len(calls),1)
        args,opts=calls[0]
        self.assertIn("socks5h://127.0.0.1:31884",args)
        self.assertIn("--noproxy",args)
        self.assertNotIn("http_proxy",opts["env"])
        self.assertNotIn("HTTPS_PROXY",opts["env"])
        self.assertLessEqual(opts["timeout"],16)
        return result

    @patch.dict("os.environ",{"HTTPS_PROXY":"http://proxy.invalid",
                              "http_proxy":"http://proxy.invalid"})
    def test_real_proxy_edge_ip(self):
        x=self.invoke("fl=29f1\nip=216.126.229.12\ncolo=AMS\n")
        self.assertTrue(x.passed)
        self.assertFalse(x.customer_ready)

    def test_core_ip_or_unexpected_public_exposure_fails(self):
        self.assertEqual(
            self.invoke("ip=209.200.246.198\n").code,"CORE_IP_EXPOSED")
        self.assertEqual(
            self.invoke("ip=8.8.8.8\n").code,"UNEXPECTED_PUBLIC_EGRESS")

    def test_edge_down_must_block_internet_entirely(self):
        self.assertTrue(self.invoke("",rc=7,outage=True).passed)
        self.assertFalse(self.invoke("ip=216.126.229.12\n",outage=True).passed)
        self.assertFalse(self.invoke("ip=209.200.246.198\n",outage=True).passed)

    def test_bad_traces_never_succeed(self):
        for value in ("", "ip=bad\n", "ip=127.0.0.1\n",
                      "ip=216.126.229.12\nip=216.126.229.12\n"):
            with self.subTest(value=value):
                self.assertFalse(self.invoke(value).passed)

    def test_no_proxy_fallback_when_curl_or_socket_unavailable(self):
        def fail(*args,**kwargs):
            raise subprocess.TimeoutExpired(args[0],16)
        x=probe_external_ssh_socks(
            port=31884,expected_edge="216.126.229.12",
            core_ipv4="209.200.246.198",run=fail,
        )
        self.assertFalse(x.passed)
        self.assertEqual(x.code,"SSH_SOCKS_UNAVAILABLE")

    def test_input_guards(self):
        with self.assertRaises(SSHProbeUnsafe):
            probe_external_ssh_socks(port=80,expected_edge="216.126.229.12",
                                     core_ipv4="209.200.246.198")
        with self.assertRaises(SSHProbeUnsafe):
            parse_trace_public_ip("ip=192.0.2.1\n")


if __name__=="__main__":
    unittest.main()
