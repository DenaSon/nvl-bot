"""F4 read-only real SSH SOCKS client probe.

Run on an EXTERNAL test workstation after independently establishing a
single-user SSH -D SOCKS session. This module opens NO SSH sessions and
changes NO server settings. curl is forced to the specified loopback SOCKS
proxy, with no direct/Core fallback and proxy environment cleared.

An Edge-only result cannot alone verify DNS/NSS/IPv6/BadVPN no-leak; require
external packet capture and reboot/failure matrix separately.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import os
import re
import subprocess
import socket
from typing import Callable


class SSHProbeUnsafe(ValueError):
    pass


@dataclass(frozen=True)
class SSHProbe:
    passed: bool
    code: str
    observed_ip: str | None
    customer_ready: bool = False


def _public(value):
    if not isinstance(value,str):
        raise SSHProbeUnsafe("IP_NOT_STRING")
    try:
        value_addr=ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise SSHProbeUnsafe("IP_INVALID") from exc
    if str(value_addr)!=value or not value_addr.is_global:
        raise SSHProbeUnsafe("IP_NOT_CANONICAL_PUBLIC")
    return value


def parse_trace_public_ip(body: str) -> str:
    if not isinstance(body,str) or len(body)>8192:
        raise SSHProbeUnsafe("UNTRUSTED_TRACE_BODY")
    matches=re.findall(r"(?m)^ip=([^\r\n]+)\r?$",body)
    if len(matches)!=1:
        raise SSHProbeUnsafe("TRACE_IP_MISSING_OR_DUPLICATED")
    return _public(matches[0])


def probe_external_ssh_socks(*, port: int, expected_edge: str,
                             core_ipv4: str, expect_outage: bool = False,
                             run=subprocess.run,
                             baseline: SSHProbe | None = None,
                             listener_check: Callable[[int], bool] | None = None) -> SSHProbe:
    """A reachable SOCKS tunnel MUST exit by Edge, never Core."""
    if type(port) is not int or not 1024 <= port <= 65535:
        raise SSHProbeUnsafe("INVALID_PROXY_PORT")
    edge=_public(expected_edge)
    core=_public(core_ipv4)
    if edge==core:
        raise SSHProbeUnsafe("EDGE_EQUALS_CORE")
    # A failing curl is NOT, by itself, evidence of fail-closed routing:
    # curl may be missing, TLS may fail, or the local SSH listener may be dead.
    if expect_outage and (
        baseline is None or baseline.passed is not True
        or baseline.observed_ip != edge
        or baseline.code != "EXTERNAL_SOCKS_EDGE_IPV4_CONFIRMED"
    ):
        return SSHProbe(False, "HEALTHY_BASELINE_REQUIRED", None)
    url="https://one.one.one.one/cdn-cgi/trace"
    cmd=[
        "curl","-4","--fail","--silent","--show-error",
        "--proto","=https","--noproxy","",
        "--proxy",f"socks5h://127.0.0.1:{port}",
        "--connect-timeout","5","--max-time","12",url,
    ]
    env=os.environ.copy()
    for name in ("http_proxy","https_proxy","all_proxy","no_proxy"):
        env.pop(name,None)
        env.pop(name.upper(),None)
    try:
        completed=run(cmd,capture_output=True,text=True,timeout=16,
                      check=False,env=env)
    except (OSError,subprocess.TimeoutExpired):
        return SSHProbe(False, "CURL_OR_PROBE_NOT_EXECUTED", None)
    if completed.returncode != 0:
        if not expect_outage:
            return SSHProbe(False, "SSH_SOCKS_UNAVAILABLE", None)
        # Only connection/transfer failures, NOT HTTP, TLS or invalid
        # client configuration, can corroborate an induced Edge outage.
        if completed.returncode not in (7, 28, 52, 55, 56):
            return SSHProbe(False, "NON_NETWORK_CURL_FAILURE", None)
        if listener_check is None:
            def listener_check(p):
                try:
                    with socket.create_connection(("127.0.0.1", p), timeout=2):
                        return True
                except OSError:
                    return False
        if not listener_check(port):
            return SSHProbe(False, "SSH_SOCKS_LISTENER_MISSING", None)
        return SSHProbe(True, "OUTAGE_PROXY_ALIVE_NETWORK_DENIED", None)
    try:
        observed=parse_trace_public_ip(completed.stdout)
    except SSHProbeUnsafe:
        return SSHProbe(False,"UNTRUSTED_OR_MISSING_EXIT_PROOF",None)
    if expect_outage:
        return SSHProbe(False,"OUTAGE_STILL_REACHES_INTERNET",observed)
    if observed!=edge:
        return SSHProbe(False,"CORE_IP_EXPOSED" if observed==core
                        else "UNEXPECTED_PUBLIC_EGRESS",observed)
    return SSHProbe(True,"EXTERNAL_SOCKS_EDGE_IPV4_CONFIRMED",observed)


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description="F4 off-host SOCKS proof (read-only)")
    parser.add_argument("--socks-port",type=int,required=True)
    parser.add_argument("--edge-ip",required=True)
    parser.add_argument("--core-ip",required=True)
    parser.add_argument("--expect-outage",action="store_true")
    parser.add_argument("--disposable-vps", action="store_true",
                        help="Explicitly attest that the disconnected Edge is disposable")
    args=parser.parse_args(argv)
    try:
        baseline = None
        if args.expect_outage:
            if not args.disposable_vps:
                print("REFUSED:OUTAGE_REQUIRES_DISPOSABLE_VPS")
                return 2
            baseline=probe_external_ssh_socks(
                port=args.socks_port, expected_edge=args.edge_ip,
                core_ipv4=args.core_ip,
            )
            if not baseline.passed:
                print("BLOCKED:NO_HEALTHY_BASELINE", baseline.code)
                return 1
            print("BASELINE: verified expected Edge public IP.")
            print("On the DISPOSABLE VPS ONLY, stop the dedicated Egress peer.")
            if input("After failure injection, type EDGE DOWN: ").strip() != "EDGE DOWN":
                print("REFUSED:NO_EXPLICIT_FAILURE_CONFIRMATION")
                return 2
        result=probe_external_ssh_socks(
            port=args.socks_port,expected_edge=args.edge_ip,
            core_ipv4=args.core_ip,expect_outage=args.expect_outage,
            baseline=baseline,
        )
    except SSHProbeUnsafe:
        print("REFUSED:INVALID_ARGS")
        return 2
    print("PASS" if result.passed else "FAIL",result.code,
          "observed="+(result.observed_ip or "NONE"))
    return 0 if result.passed else 1


if __name__=="__main__":
    raise SystemExit(main())
