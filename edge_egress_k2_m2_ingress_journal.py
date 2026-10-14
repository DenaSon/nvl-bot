"""M2 durable SSH ingress observation for later read-only SINGLE/BATCH preview.

An entry is born only during a privileged PAM account transaction backed by
the pinned root WireGuard peer registry. A root-owned journal is *not* a F4
packet witness or customer transfer ticket. Records expire within 300 seconds.
The live WG allowed-ips must still match when an offline preview reads them.
No ssh_accounts.host, DNS/default, or user-supplied source fields are used.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import pwd
import stat
import tempfile
from typing import Callable, Mapping

from edge_egress_k2_m2_ingress_observer import observe_pam_ingress, PAMIngressHold
from edge_egress_k2_migration_inventory import LiveIngressWitness
from edge_egress_v1_ingress import IngressPeer, _networks

VERSION = 1
MAX_RECORDS = 2000
MAX_BYTES = 512000
TTL_SECONDS = 300
JOURNAL = Path("/etc/nvl-egress/m2-pam-ingress.json")


class DurableIngressHold(ValueError):
    pass


@dataclass(frozen=True)
class IngressRecord:
    username: str
    uid: int
    edge_id: str
    edge_ipv4: str
    ingress_ipv4: str
    wg_public_key: str
    observed_at: int


def _validated(raw: bytes) -> dict[str, IngressRecord]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_BYTES:
        raise DurableIngressHold("INGRESS_JOURNAL_INVALID_SIZE")
    try:
        obj = json.loads(raw)
        if not isinstance(obj, dict) or set(obj) != {"version", "records"} or (
            type(obj["version"]) is not int or obj["version"] != VERSION
        ) or not isinstance(obj["records"], list) or len(obj["records"]) > MAX_RECORDS:
            raise ValueError()
        results = {}
        for row in obj["records"]:
            if not isinstance(row, dict) or set(row) != set(IngressRecord.__dataclass_fields__):
                raise ValueError()
            record = IngressRecord(**row)
            if (type(record.uid) is not int or not 1000 <= record.uid < 60000
                or type(record.observed_at) is not int or record.observed_at <= 0
                or not isinstance(record.username,str)
                or record.username in results):
                raise ValueError()
            results[record.username] = record
        return results
    except (ValueError, UnicodeError, TypeError, KeyError) as exc:
        raise DurableIngressHold("INGRESS_JOURNAL_UNTRUSTED") from exc


def encode_records(records: dict[str, IngressRecord]) -> bytes:
    if not isinstance(records, dict) or len(records) > MAX_RECORDS or any(
        not isinstance(name,str) or not isinstance(row,IngressRecord)
        or name != row.username for name,row in records.items()
    ):
        raise DurableIngressHold("INGRESS_RECORD_SET_INVALID")
    output = (json.dumps({"version":VERSION,"records":[
        asdict(records[n]) for n in sorted(records)]},
        sort_keys=True,separators=(",",":"))+"\n").encode()
    _validated(output)
    return output


def add_authenticated_observation(
    before: bytes, *, username: str, uid: int, pam_env: Mapping[str,str],
    peers: tuple[IngressPeer,...], allowed_ips: str, now: int,
    geteuid: Callable[[],int], resolve_uid: Callable[[str],int],
) -> bytes:
    """PAM-bound only; caller persists by exact root-owned CAS.

    Before must be the pinned journal, never an empty fallback after corruption.
    """
    records=_validated(before)
    try:
        proof=observe_pam_ingress(
            username=username,uid=uid,pam_env=pam_env,peers=peers,
            allowed_ips=allowed_ips,now=now,geteuid=geteuid,
            resolve_uid=resolve_uid)
    except (PAMIngressHold,ValueError,TypeError) as exc:
        raise DurableIngressHold("CURRENT_PAM_WG_NOT_ATTESTED") from exc
    peer=next((p for p in peers if p.edge_id==proof.edge_id
               and p.edge_ipv4==proof.edge_ipv4
               and p.ingress_ipv4==pam_env.get("PAM_RHOST")),None)
    if peer is None:
        raise DurableIngressHold("PAM_INGRESS_PEER_CHANGED")
    prev=records.get(username)
    if prev is not None and prev.observed_at > now:
        raise DurableIngressHold("TIME_REWIND_UNSAFE")
    records[username]=IngressRecord(username,uid,peer.edge_id,
        peer.edge_ipv4,peer.ingress_ipv4,peer.wg_public_key,now)
    return encode_records(records)


def verified_recent_observation(raw: bytes, *, username: str, uid: int,
                                peers: tuple[IngressPeer,...], allowed_ips: str,
                                now: int, resolve_uid: Callable[[str],int]
                                ) -> LiveIngressWitness:
    """Offline-preview provider, still re-verifies CURRENT WG key ownership."""
    records=_validated(raw)
    item=records.get(username)
    if (item is None or type(now) is not int or now < item.observed_at
        or now-item.observed_at > TTL_SECONDS
        or item.uid != uid or type(uid) is not int
        or resolve_uid(username) != uid):
        raise DurableIngressHold("SOURCE_PROOF_MISSING_STALE_OR_UID_CHANGED")
    if not any((peer.edge_id,peer.edge_ipv4,peer.ingress_ipv4,peer.wg_public_key)
               == (item.edge_id,item.edge_ipv4,item.ingress_ipv4,item.wg_public_key)
               for peer in peers):
        raise DurableIngressHold("SOURCE_REGISTRY_DRIFT")
    try:
        from ipaddress import IPv4Address, ip_network
        src=IPv4Address(item.ingress_ipv4)
        allowed=_networks(allowed_ips)
        if ip_network(str(src)+"/32") not in allowed.get(item.wg_public_key,()):
            raise DurableIngressHold("SOURCE_WG_KEY_LOST")
        if any(src in net for key,ranges in allowed.items()
               if key != item.wg_public_key for net in ranges):
            raise DurableIngressHold("SOURCE_WG_OVERLAP")
    except (ValueError,TypeError,KeyError) as exc:
        raise DurableIngressHold("SOURCE_WG_NOT_VERIFIED") from exc
    return LiveIngressWitness(username,item.edge_id,item.edge_ipv4,
                              item.observed_at,"INDEPENDENT_LIVE")


def _root_owned_file(path: Path, *, allow_missing=False) -> bytes | None:
    """Follow no symlinks. Refuse shared/group-write directories and files."""
    if path != JOURNAL:
        raise DurableIngressHold("INGRESS_JOURNAL_PATH_NOT_FIXED")
    try:
        st=path.parent.lstat()
        if st.st_uid!=0 or not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o022:
            raise DurableIngressHold("INGRESS_DIRECTORY_NOT_ROOT_TRUSTED")
        st=path.lstat()
        if st.st_uid!=0 or not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
            raise DurableIngressHold("INGRESS_JOURNAL_FILE_NOT_ROOT_TRUSTED")
        fd=os.open(path, os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
        try:
            fs=os.fstat(fd)
            if fs.st_dev!=st.st_dev or fs.st_ino!=st.st_ino:
                raise DurableIngressHold("INGRESS_JOURNAL_SWAP")
            raw=os.read(fd,MAX_BYTES+1)
        finally:
            os.close(fd)
        _validated(raw)
        return raw
    except FileNotFoundError as exc:
        if allow_missing:
            return None
        raise DurableIngressHold("INGRESS_JOURNAL_ABSENT") from exc


def read_root_journal() -> bytes:
    return _root_owned_file(JOURNAL)


def create_root_journal_if_absent(*, geteuid=os.geteuid) -> bytes:
    """Trusted worker bootstrap only. Never reinterpret corrupt as missing."""
    if geteuid()!=0:
        raise DurableIngressHold("ROOT_REQUIRED")
    before=_root_owned_file(JOURNAL,allow_missing=True)
    if before is not None:
        return before
    raw=encode_records({})
    fd=os.open(JOURNAL,os.O_WRONLY|os.O_CREAT|os.O_EXCL|
               getattr(os,"O_NOFOLLOW",0),0o600)
    try:
        with os.fdopen(fd,"wb") as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        raise
    return read_root_journal()


def compare_and_swap_root_journal(before: bytes, after: bytes, *,
                                  geteuid=os.geteuid) -> None:
    """Caller MUST hold the original 6G / PAM serialized root-worker lease.

    Atomic replace is a file CAS against the currently pinned bytes; this is
    NOT a substitute for an exclusive lock against other writers.
    """
    if geteuid()!=0:
        raise DurableIngressHold("ROOT_REQUIRED")
    _validated(before)
    _validated(after)
    if read_root_journal()!=before:
        raise DurableIngressHold("INGRESS_JOURNAL_CAS_LOST")
    fd,p=tempfile.mkstemp(prefix=".m2-pam-ingress-",dir=JOURNAL.parent)
    temp=Path(p)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"wb") as out:
            out.write(after)
            out.flush()
            os.fsync(out.fileno())
        if read_root_journal()!=before:
            raise DurableIngressHold("INGRESS_JOURNAL_CAS_LOST")
        os.replace(temp,JOURNAL)
        parent_fd=os.open(JOURNAL.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(parent_fd)
        finally:os.close(parent_fd)
    finally:
        if temp.exists():
            temp.unlink()
