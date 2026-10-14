"""M2: root-only, read-only authenticated SSH ingress/wg0 identity witness.

Historical ssh_accounts.host, host_pool default and public DNS are NOT
identities. This adapter can only report a *current* PAM account transaction,
not an offline customer's former Edge. The ephemeral result is not a durable
6G ticket, accepted F4 packet proof or production attribution history.
"""
from __future__ import annotations

import ipaddress
import os
import pwd
import subprocess
import time
from typing import Callable, Mapping

from edge_egress_k2_migration_inventory import LiveIngressWitness
from edge_egress_v1_ingress import (
    NET, IngressPeer, IngressHold, _networks, load_registry,
)

class PAMIngressHold(ValueError):
    pass


def observe_pam_ingress(*, username: str, uid: int,
                        pam_env: Mapping[str, str],
                        peers: tuple[IngressPeer, ...],
                        allowed_ips: str, now: int,
                        geteuid: Callable[[], int] = os.geteuid,
                        resolve_uid: Callable[[str], int] =
                            lambda n: pwd.getpwnam(n).pw_uid) -> LiveIngressWitness:
    """A live authenticated PAM account peer + pinned root-only WG registry.

    Call only inside trusted sshd PAM account context. The current caller's
    privilege and per-login source, not arbitrary supplied username/host
    metadata, are the basis for source identity.
    """
    if (not callable(geteuid) or geteuid() != 0
            or not isinstance(pam_env, Mapping)
            or pam_env.get("PAM_SERVICE") != "sshd"
            or pam_env.get("PAM_TYPE") != "account"
            or pam_env.get("PAM_USER") != username
            or not isinstance(username, str)
            or type(uid) is not int or not 1000 <= uid < 60000
            or type(now) is not int or now <= 0):
        raise PAMIngressHold("ROOT_AUTHENTICATED_PAM_CONTEXT_REQUIRED")
    try:
        if resolve_uid(username) != uid:
            raise PAMIngressHold("LINUX_IDENTITY_CHANGED")
        rhost = pam_env.get("PAM_RHOST", "")
        src = ipaddress.IPv4Address(rhost)
        if str(src) != rhost or src not in NET:
            raise PAMIngressHold("UNKNOWN_OR_FOREIGN_PAM_PEER")
        matches = [x for x in peers if x.ingress_ipv4 == rhost]
        if len(matches) != 1:
            raise PAMIngressHold("AMBIGUOUS_OR_MISSING_INGRESS_PEER")
        peer = matches[0]
        networks = _networks(allowed_ips)
        exact = ipaddress.ip_network(rhost+"/32")
        if exact not in networks.get(peer.wg_public_key, ()):
            raise PAMIngressHold("WG_INGRESS_KEY_OR_IP_NOT_PINNED")
        if any(src in n for key,ranges in networks.items()
               if key != peer.wg_public_key for n in ranges):
            raise PAMIngressHold("WG_INGRESS_PEER_OVERLAP")
        if (peer.edge_id == "" or
                not ipaddress.IPv4Address(peer.edge_ipv4).is_global):
            raise PAMIngressHold("UNTRUSTED_EDGE_PUBLIC_IDENTITY")
        return LiveIngressWitness(
            username,peer.edge_id,peer.edge_ipv4,now,"INDEPENDENT_LIVE")
    except PAMIngressHold:
        raise
    except (IngressHold, ValueError, TypeError, KeyError, OSError) as exc:
        raise PAMIngressHold("WG_OR_PAM_INGRESS_NOT_ATTESTED") from exc


def observe_current_pam_ingress(
        *, now: int | None = None, run: Callable = subprocess.run,
        geteuid: Callable[[], int] = os.geteuid) -> LiveIngressWitness:
    """Concrete observation *without* shell mutation or operator CLI.

    Only an independently reviewed PAM integration can invoke this inside
    actual sshd authorization; it is NOT registered during M2 source work.
    """
    if geteuid() != 0:
        raise PAMIngressHold("ROOT_REQUIRED")
    username = os.environ.get("PAM_USER","")
    try:
        uid = pwd.getpwnam(username).pw_uid
        peer_registry = load_registry()
        result = run(
            ["wg","show","wg0","allowed-ips"],
            capture_output=True,text=True,timeout=3,check=False)
        if result.returncode != 0:
            raise PAMIngressHold("WG_INVENTORY_UNAVAILABLE")
        return observe_pam_ingress(
            username=username,uid=uid,pam_env=os.environ,
            peers=peer_registry,allowed_ips=result.stdout,
            now=int(time.time()) if now is None else now, geteuid=geteuid,
        )
    except (PAMIngressHold, OSError, ValueError, TypeError, KeyError,
            subprocess.TimeoutExpired) as exc:
        raise PAMIngressHold("LIVE_PAM_INGRESS_UNAVAILABLE") from exc
