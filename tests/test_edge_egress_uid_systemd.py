"""D1-C3E: no-activation SSH boot dependency verifier and DNS readiness tests."""
import os
import socket
import tempfile
import unittest
from unittest.mock import patch

from edge_egress_uid_systemd import (
    SystemdBootError, SSHSystemdBundle, assess_ssh_host_socket,
    render_ssh_systemd_bundle, verify_bundle,
)
from edge_egress_uid_dns import sd_notify_ready
from edge_egress_uid_boot import BootGuardManifest
from ops.edge_egress_provision import EgressSpec


def manifest():
    spec = dict(edge_id="fra1", edge_public_ipv4="216.126.229.12",
                core_public_ipv4="209.200.246.198",
                tunnel_network="10.78.100.0/30", veth_network="10.78.101.0/30",
                edge_uplink="eth0", edge_listen_port=51832, route_table=1780,
                mode="relay")
    return BootGuardManifest.parse(dict(
        mode="PROTECTED_BOOT_GUARD", username="nvl0557",
        uid=1644, priority=1780, dns_port=10553, spec=spec))


class SystemdBootTests(unittest.TestCase):
    def test_exact_ssh_dependencies_and_notified_dns_ready(self):
        bundle = render_ssh_systemd_bundle(manifest())
        self.assertIn("BindsTo="+bundle.guard_name+" "+bundle.dns_name,
                      bundle.ssh_dropin)
        self.assertIn("After="+bundle.guard_name+" "+bundle.dns_name,
                      bundle.ssh_dropin)
        self.assertIn("Requires="+bundle.guard_name+" "+bundle.dns_name,
                      bundle.ssh_dropin)
        self.assertIn("Type=notify", bundle.dns_unit)
        self.assertIn("NotifyAccess=main", bundle.dns_unit)
        self.assertIn("Before=ssh.service", bundle.guard_unit)
        verify_bundle(bundle)

    def test_reject_dns_not_ready_before_ssh(self):
        good = render_ssh_systemd_bundle(manifest())
        bad = SSHSystemdBundle(
            good.guard_name,good.dns_name,good.guard_unit,
            good.dns_unit.replace("Type=notify","Type=simple"),
            good.ssh_dropin,
        )
        with self.assertRaisesRegex(SystemdBootError,"DNS_NOT_BOOT_BLOCKING"):
            verify_bundle(bad)

    def test_reject_wanted_only_ssh_dependency(self):
        good = render_ssh_systemd_bundle(manifest())
        bad = SSHSystemdBundle(
            good.guard_name,good.dns_name,good.guard_unit,good.dns_unit,
            good.ssh_dropin.replace("BindsTo=","Wants="),
        )
        with self.assertRaisesRegex(SystemdBootError,"SSH_MISSING"):
            verify_bundle(bad)

    def test_socket_activated_ssh_is_not_approved(self):
        assess_ssh_host_socket({"ssh.socket":"disabled",
                                "sshd.socket":"not-found"})
        for state in ("enabled","enabled-runtime","active","static","indirect",""):
            with self.subTest(state=state):
                with self.assertRaisesRegex(SystemdBootError,"SSH_SOCKET"):
                    assess_ssh_host_socket({"ssh.socket":state,
                                            "sshd.socket":"not-found"})

    def test_systemd_ready_datagram_is_emitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=os.path.join(tmp,"notify.sock")
            with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as recv:
                recv.bind(path)
                recv.settimeout(2)
                with patch.dict(os.environ,{"NOTIFY_SOCKET":path}):
                    sd_notify_ready()
                self.assertEqual(recv.recv(256),b"READY=1")

    def test_absent_notify_socket_safe_for_disposable_non_systemd_test(self):
        with patch.dict(os.environ,{"NOTIFY_SOCKET":""}):
            sd_notify_ready()

    def test_disallow_non_socket_notify_destination(self):
        with patch.dict(os.environ,{"NOTIFY_SOCKET":"tcp://127.0.0.1"}):
            with self.assertRaisesRegex(ValueError,"INVALID_NOTIFY_SOCKET"):
                sd_notify_ready()


if __name__=="__main__":
    unittest.main()
