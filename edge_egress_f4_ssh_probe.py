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
                             run=subprocess.run) -> SSHProbe:
    """A reachable SOCKS tunnel MUST exit by Edge, never Core."""
    if type(port) is not int or not 1024 <= port <= 65535:
        raise SSHProbeUnsafe("INVALID_PROXY_PORT")
    edge=_public(expected_edge)
    core=_public(core_ipv4)
    if edge==core:
        raise SSHProbeUnsafe("EDGE_EQUALS_CORE")
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
        completed=None
    if completed is None or completed.returncode!=0:
        return SSHProbe(expect_outage,
                        "EDGE_OUTAGE_FAIL_CLOSED_OBSERVED" if expect_outage
                        else "SSH_SOCKS_UNAVAILABLE",None)
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
    args=parser.parse_args(argv)
    try:
        result=probe_external_ssh_socks(
            port=args.socks_port,expected_edge=args.edge_ip,
            core_ipv4=args.core_ip,expect_outage=args.expect_outage,
        )
    except SSHProbeUnsafe:
        print("REFUSED:INVALID_ARGS")
        return 2
    print("PASS" if result.passed else "FAIL",result.code,
          "observed="+(result.observed_ip or "NONE"))
    return 0 if result.passed else 1


if __name__=="__main__":
    raise SystemExit(main())
