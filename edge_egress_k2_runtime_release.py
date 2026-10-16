"""One root-owned release profile shared by the Core bot and PAM interpreter.

Importing this module never enables execution. Missing profile means OFF;
an enabled profile pins the installed PAM source as part of the reviewed
release. This avoids editing Python flags for every login or new UID.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import pwd
import subprocess

CORE_PROFILE = Path("/etc/nvl-egress/k2-m4/core-runtime.json")
INSTALLED_PAM = Path("/opt/nvl-egress/edge_egress_v1_admission.py")
LAB_CORE = '144.172.84.127'
LAB_EDGE = '144.172.84.112'
LAB_USERS = {'nvltest1': 1636, 'nvltest2': 1637, 'nvltest3': 1638}


class CoreReleaseHold(ValueError):
    pass


def _root_bytes(path: Path, maximum: int, *, private=False) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_nlink != 1 or info.st_mode & 0o022
            or private and info.st_mode & 0o077
            or not 0 < info.st_size <= maximum):
            raise CoreReleaseHold("CORE_RELEASE_FILE_UNTRUSTED")
        return os.read(fd, maximum + 1)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class CoreReleaseProfile:
    enabled: bool
    pam_module_sha256: str
    operations_enabled: bool = False
    batch_enabled: bool = False
    field_acceptance_sha256: str = ""
    lab_trial: dict | None = None
    lab_trial_sha256: str = ""


def load_core_profile() -> CoreReleaseProfile:
    try:
        if not CORE_PROFILE.exists() and not CORE_PROFILE.is_symlink():
            return CoreReleaseProfile(False, "")
        parent = CORE_PROFILE.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
            or parent.st_mode & 0o077):
            raise CoreReleaseHold("CORE_PROFILE_DIRECTORY_UNTRUSTED")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise CoreReleaseHold("CORE_PROFILE_DUPLICATE_FIELD")
                result[key] = value
            return result
        raw = _root_bytes(CORE_PROFILE, 2048, private=True)
        data = json.loads(raw, object_pairs_hook=unique)
        version=data.get('version') if type(data) is dict else None
        keys={"version", "single_enabled", "pam_module_sha256"}
        if version==2:
            keys|={'operations_enabled','batch_enabled','field_acceptance_sha256'}
        if version==3:
            keys|={'operations_enabled','batch_enabled','lab_trial'}
        if (type(data) is not dict
            or set(data) != keys
            or type(version) is not int or version not in (1,2,3)
            or type(data["single_enabled"]) is not bool
            or type(data["pam_module_sha256"]) is not str
            or not re.fullmatch(r"[a-f0-9]{64}", data["pam_module_sha256"])):
            raise CoreReleaseHold("CORE_PROFILE_INVALID")
        if version==2 and (
            type(data['operations_enabled']) is not bool
            or type(data['batch_enabled']) is not bool
            or data['batch_enabled'] and not data['operations_enabled']
            or data['operations_enabled'] and not data['single_enabled']
            or type(data['field_acceptance_sha256']) is not str
            or not re.fullmatch(r'[a-f0-9]{64}',data['field_acceptance_sha256'])
        ):
            raise CoreReleaseHold('CORE_PROFILE_OPERATIONS_INVALID')
        if version==3:
            trial=data['lab_trial']
            if (data['single_enabled'] is not True
                or data['operations_enabled'] is not True
                or type(data['batch_enabled']) is not bool
                or type(trial) is not dict
                or set(trial)!={'purpose','release_sha','core_ipv4','edge_id','edge_ipv4',
                               'machine_sha256','rescue_sha256','rescue_observed_at'}
                or trial['purpose']!='ISOLATED_LAB_TRIAL'
                or trial['core_ipv4']!=LAB_CORE or trial['edge_ipv4']!=LAB_EDGE
                or trial['edge_id']!='e2'
                or type(trial['rescue_observed_at']) is not int
                or trial['rescue_observed_at']<=0
                or any(type(trial[k]) is not str or not re.fullmatch(pattern,trial[k])
                       for k,pattern in (('release_sha',r'[a-f0-9]{40}'),
                                         ('machine_sha256',r'[a-f0-9]{64}'),
                                         ('rescue_sha256',r'[a-f0-9]{64}')))):
                raise CoreReleaseHold('CORE_LAB_TRIAL_PROFILE_INVALID')
        return CoreReleaseProfile(data["single_enabled"], data["pam_module_sha256"],
            data.get('operations_enabled',False),data.get('batch_enabled',False),
            data.get('field_acceptance_sha256',''),data.get('lab_trial'),
            sha256(raw).hexdigest() if version==3 else '')
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise CoreReleaseHold("CORE_PROFILE_UNAVAILABLE_OR_INVALID") from exc


def lab_rescue_digest() -> str:
    """Bind the independently tested recovery login to its current identity."""
    account=pwd.getpwnam('nvlrescue')
    if account.pw_uid<1000 or account.pw_uid in LAB_USERS.values():
        raise CoreReleaseHold('LAB_RESCUE_IDENTITY_CHANGED')
    rows=[line for line in _root_bytes(Path('/etc/shadow'),131072).splitlines()
          if line.startswith(b'nvlrescue:')]
    if len(rows)!=1:
        raise CoreReleaseHold('LAB_RESCUE_IDENTITY_CHANGED')
    return sha256(repr(tuple(account)).encode()+b'\n'+rows[0]).hexdigest()


def validate_lab_trial(db_conn, *, release_sha, digest, core_ipv4=LAB_CORE,
                       edge_id='e2', usernames=()):
    """Authorize only this disposable installation, never assert field acceptance.

    Every native review/action rechecks the profile, local address, machine,
    rescue identity and the *entire* account population. There is no generic
    skip-F4 flag, wildcard account, alternate executor or Production grant.
    """
    import time
    profile=load_core_profile()
    trial=profile.lab_trial
    if (os.geteuid()!=0 or not profile.enabled or not profile.operations_enabled
        or trial is None or profile.lab_trial_sha256!=digest
        or trial['release_sha']!=release_sha or core_ipv4!=LAB_CORE or edge_id!='e2'
        or any(n not in LAB_USERS for n in usernames)
        or trial['rescue_observed_at']>int(time.time())
        or sha256(_root_bytes(Path('/etc/machine-id'),256)).hexdigest()!=trial['machine_sha256']
        or lab_rescue_digest()!=trial['rescue_sha256']):
        raise CoreReleaseHold('LAB_TRIAL_AUTHORITY_CHANGED')
    result=subprocess.run(['ip','-j','-4','addr','show'],capture_output=True,text=True,
                          timeout=5,check=False)
    addresses={a.get('local') for row in json.loads(result.stdout)
               for a in row.get('addr_info',()) if a.get('family')=='inet'}
    if result.returncode or LAB_CORE not in addresses or '209.200.246.198' in addresses:
        raise CoreReleaseHold('LAB_TRIAL_WRONG_HOST')
    with db_conn() as db:
        for key,value in (('brand','NVL-LAB'),('core_wg_public_ip',LAB_CORE),
                          ('edge_egress_protected_mode','0'),('auto_failover_mode','0'),
                          ('phase6h_auto_failover_enabled','0')):
            if db.execute('SELECT value FROM settings WHERE key=?',(key,)).fetchall()!=[(value,)]:
                raise CoreReleaseHold('LAB_TRIAL_DATABASE_IDENTITY_CHANGED')
        accounts=db.execute('SELECT username,service_type FROM ssh_accounts ORDER BY username').fetchall()
        if accounts!=[(n,'ssh') for n in sorted(LAB_USERS)]:
            raise CoreReleaseHold('LAB_TRIAL_FOREIGN_CUSTOMER')
        if any(pwd.getpwnam(n).pw_uid!=uid for n,uid in LAB_USERS.items()):
            raise CoreReleaseHold('LAB_TRIAL_OS_UID_CHANGED')
        for table in ('edge_egress_uid_runtime','edge_egress_uid_bindings'):
            rows=db.execute('SELECT username,uid,edge_id,edge_ipv4 FROM '+table).fetchall()
            if any(n not in LAB_USERS or LAB_USERS[n]!=uid or e!='e2' or ip!=LAB_EDGE
                   for n,uid,e,ip in rows):
                raise CoreReleaseHold('LAB_TRIAL_FOREIGN_PROTECTED_ACCOUNT')
    return profile


def pam_cross_edge_released() -> bool:
    """The separate PAM Python process rechecks the real release each login."""
    try:
        profile = load_core_profile()
        if not profile.enabled or os.geteuid() != 0:
            return False
        if profile.lab_trial is not None:
            import sqlite3
            release=json.loads(_root_bytes(CORE_PROFILE.parent/'release.json',16384,private=True))
            validate_lab_trial(lambda:sqlite3.connect('file:/root/master_bot.db?mode=ro',uri=True),
                release_sha=release['git_sha'],digest=profile.lab_trial_sha256)
        return sha256(_root_bytes(INSTALLED_PAM, 2_000_000)).hexdigest() == (
            profile.pam_module_sha256
        )
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return False


def lab_trial_pam_target(conn, row) -> bool:
    """Admit this trial's measured F2 UID, without promoting its Edge to READY.

    The separate PAM interpreter cannot use the bot's in-memory collector.
    It rechecks the same private, installation-bound grant plus the exact
    original Single receipt. Kernel, DNS, UID denial and ingress checks still
    run normally in probe_local_guards/check_account.
    """
    try:
        from edge_egress_f3_readiness import read_readiness
        from edge_egress_p3_executor import ExecutionScope,_scope_digest,INTENT_PHASE
        profile=load_core_profile()
        if (profile.lab_trial is None or LAB_USERS.get(row.username)!=row.uid
            or row.edge_id!='e2' or row.edge_ipv4!=LAB_EDGE or row.state!='PROTECTED'
            or not pam_cross_edge_released()):
            return False
        ready=read_readiness(conn,row.edge_id)
        if ready is None or ready.state!='STAGED' or ready.edge_ipv4!=LAB_EDGE:
            return False
        receipt=conn.execute('SELECT status,source_host,target_host,detail_json '
                            'FROM failover_operations WHERE id=?',(row.last_operation_id,)).fetchone()
        if receipt is None:
            return False
        status,source,target,raw=receipt
        detail=json.loads(raw)
        scope=ExecutionScope('UID_ENROLL_SOURCE','e2',LAB_EDGE,LAB_EDGE,row.username,row.uid)
        if (source!=LAB_EDGE or target!=LAB_EDGE or detail.get('kind')!='K2_P3A'
            or detail.get('single_uid') is not True or detail.get('username')!=row.username
            or detail.get('uid')!=row.uid or detail.get('edge_id')!='e2'
            or detail.get('action')!=scope.action or detail.get('scope_digest')!=_scope_digest(scope)
            or type(detail.get('nonce_hash')) is not str
            or not re.fullmatch('[a-f0-9]{64}',detail['nonce_hash'])):
            return False
        return bool(status=='SUCCEEDED' and detail.get('phase')=='EGRESS_P3_VERIFIED'
                    or status=='RUNNING' and detail.get('phase')==INTENT_PHASE
                    and detail.get('probe_only') is True and core_single_busy_admission(conn,row))
    except (OSError,ValueError,KeyError,TypeError,AttributeError):
        return False


def core_single_busy_admission(conn, row) -> bool:
    """Scope original 6G admission to this release's single-UID operation.

    Other protected UIDs keep their independently checked guards. The
    selected UID is admitted only for its post-commit client probe, after
    F2 PROTECTED and under the exact original journal/operation identity.
    Unknown/legacy/global/recovery operations retain the old deny behavior.
    """
    try:
        import sqlite3
        from edge_egress_p3_executor import ExecutionScope, _scope_digest, INTENT_PHASE, RECOVERY_PHASE
        if not pam_cross_edge_released():
            return False
        rows = conn.execute(
            "SELECT id,source_host,target_host,detail_json FROM failover_operations "
            "WHERE status='RUNNING'"
        ).fetchall()
        if len(rows) != 1:
            return False
        op, source, target, raw = rows[0]
        detail = json.loads(raw)
        if (type(detail) is not dict or detail.get("kind") != "K2_P3A"
            or detail.get("single_uid") is not True
            or detail.get("phase") not in (INTENT_PHASE, RECOVERY_PHASE)
            or detail.get("action") not in ("UID_ATTACH", "UID_ENROLL_SOURCE")
            or type(detail.get("nonce_hash")) is not str
            or not re.fullmatch(r"[a-f0-9]{64}", detail["nonce_hash"])):
            return False
        scope = ExecutionScope(detail["action"], detail["edge_id"], source, target,
                               username=detail["username"], uid=detail["uid"])
        if detail.get("scope_digest") != _scope_digest(scope):
            return False
        if row.username != scope.username and row.uid != scope.uid:
            return True
        return bool(
            row.username == scope.username and row.uid == scope.uid
            and row.state == "PROTECTED" and row.last_operation_id == op
            and row.edge_id == scope.edge_id and row.edge_ipv4 == scope.target_host
            and detail["phase"] == INTENT_PHASE and detail.get("probe_only") is True
        )
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.Error):
        return False
