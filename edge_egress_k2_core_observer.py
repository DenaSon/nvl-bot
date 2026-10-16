"""On-demand observations in the existing root bot; no per-UID JSON workflow.

Local UID probes inspect the real kernel and capture the physical uplink.
The real customer SSH forwarding probe runs on an existing pinned Edge via
its authenticated SSH channel. Fault/reboot/rescue qualification must already
be accepted at release time; this module never invents that evidence or F4.
"""
from __future__ import annotations

from dataclasses import asdict, replace
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time

from edge_egress_k2_m42_evidence import (
    SignedExternalEvidence,WitnessAccount,PRE_ATTACH_CHECKS,
    UID_ROUTE_CHECKS,POST_ATTACH_CHECKS,
)
from edge_egress_p3_executor import assert_guarded_6g_intent,_scope_digest
from edge_egress_uid_runtime_store import read_binding
from edge_egress_f3_readiness import read_readiness
from edge_egress_k2_m4_cross_edge_port import root_fresh_source_evidence
from edge_egress_k2_runtime_release import _root_bytes

QUALIFICATION=Path("/etc/nvl-egress/k2-m4/field-acceptance.json")
CORE_PRE_CHECKS=(PRE_ATTACH_CHECKS-{'f4_accepted'})|{'release_qualified'}
LAB_PRE_CHECKS=frozenset(('lab_trial_authorized','ssh_sessions','operator_rescue',
                          'neighbour_isolation'))
PROBE_ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'}


class CoreObservationHold(ValueError):
    pass


class CorePreAttachEvidence(SignedExternalEvidence):
    """Live native measurements; never represented as an off-Core signature.

    Release-time fault/reboot qualification plus a fresh pinned transport
    permits a guarded UID trial. Only later UID_ROUTE/POST_ATTACH can prove
    that UID; no F4 readiness row is manufactured for a new Edge.
    """
    def verify_pre_attach(self):
        if self.phase!='PRE_ATTACH' or self.checks not in (CORE_PRE_CHECKS,LAB_PRE_CHECKS):
            raise CoreObservationHold('NATIVE_PRE_ATTACH_MEASUREMENTS_REQUIRED')


def checked(argv, *, timeout=12, **kwargs):
    kwargs.setdefault('env',PROBE_ENV)
    result=subprocess.run(argv,capture_output=True,text=True,timeout=timeout,
                          check=False,**kwargs)
    if result.returncode!=0:
        raise CoreObservationHold("AUTOMATIC_MEASUREMENT_FAILED")
    return result.stdout


# Executed with runuser as the selected real Linux UID, never root/NSS cache
# approximations. Distinct UDP/TCP transactions and a real AF_INET6 attempt.
_UID_DNS_PROBE=r'''
import errno,json,os,secrets,socket,struct
q=secrets.token_bytes(2)+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b'\x07example\x03com\x00\x00\x01\x00\x01'
def answer(raw):
    if len(raw)<12 or raw[:2]!=q[:2] or not raw[2]&128 or raw[3]&15 or raw[6:8]==b'\0\0':
        raise RuntimeError('dns response invalid')
for kind in (socket.SOCK_DGRAM,socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET,kind) as s:
        s.settimeout(5); s.connect(('1.1.1.1',53))
        if kind==socket.SOCK_DGRAM:
            s.send(q); raw=s.recv(4096)
        else:
            s.sendall(struct.pack('!H',len(q))+q)
            def exact(n):
                out=b''
                while len(out)<n:
                    part=s.recv(n-len(out))
                    if not part: raise RuntimeError('dns truncated')
                    out+=part
                return out
            size=struct.unpack('!H',exact(2))[0]
            if not 12<=size<=4096: raise RuntimeError('dns length')
            raw=exact(size)
        answer(raw)
try:
    socket.getaddrinfo(secrets.token_hex(16)+'.example.com',443,socket.AF_INET,socket.SOCK_STREAM)
except socket.gaierror as exc:
    if exc.errno not in (socket.EAI_NONAME,getattr(socket,'EAI_NODATA',socket.EAI_NONAME)):
        raise RuntimeError('nss resolution unavailable') from None
with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as s:
    s.settimeout(3)
    try:
        s.connect(('2606:4700:4700::1111',443))
    except OSError as exc:
        if exc.errno not in (errno.EPERM,errno.EACCES,errno.ENETUNREACH,errno.EHOSTUNREACH,errno.ECONNREFUSED):
            raise RuntimeError('ipv6 denial unproven') from None
    else:
        raise RuntimeError('ipv6 unexpectedly connected')
print(json.dumps({'dns_udp':True,'dns_tcp':True,'nss':True,'ipv6':True}))
'''


# This runs on an existing Edge. Only stdin carries the password, inside the
# pinned encrypted SSH channel. Temporary owner-only askpass/known_hosts are
# removed even on failure; no sshpass dependency, shell account or daemon.
_REMOTE_CLIENT=r'''
import ipaddress,json,os,pathlib,re,socket,subprocess,tempfile,time
r=REQUEST
for name in ('http_proxy','https_proxy','all_proxy','no_proxy'):
    os.environ.pop(name,None);os.environ.pop(name.upper(),None)
with tempfile.TemporaryDirectory(prefix='nvl-client-proof-') as folder:
    root=pathlib.Path(folder)
    known=root/'known_hosts'
    lookup=r['source_ipv4'] if r['port']==22 else '['+r['source_ipv4']+']:'+str(r['port'])
    known.write_text(lookup+' '+r['core_host_key']+'\n')
    os.chmod(known,0o600)
    ask=root/'askpass'
    ask.write_text('#!/usr/bin/python3\nimport os\nprint(os.environ["NVL_PROBE_PASSWORD"])\n')
    os.chmod(ask,0o700)
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
    env=os.environ.copy()
    env.update(SSH_ASKPASS=str(ask),SSH_ASKPASS_REQUIRE='force',DISPLAY='nvl-probe:0',NVL_PROBE_PASSWORD=r['password'])
    proc=subprocess.Popen(['ssh','-F','/dev/null','-N','-T','-D','127.0.0.1:'+str(port),
        '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(known),
        '-o','GlobalKnownHostsFile=/dev/null','-o','IdentitiesOnly=yes','-o','IdentityFile=none',
        '-o','PreferredAuthentications=password','-o','PubkeyAuthentication=no',
        '-o','NumberOfPasswordPrompts=1','-o','ConnectTimeout=8',
        '-o','ExitOnForwardFailure=yes','-p',str(r['port']),r['username']+'@'+r['source_ipv4']],
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
        env=env,start_new_session=True)
    try:
        deadline=time.monotonic()+12
        while True:
            if proc.poll() is not None: raise RuntimeError('ssh login failed')
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.2): pass
                break
            except OSError:
                if time.monotonic()>=deadline: raise RuntimeError('ssh not ready')
                time.sleep(.05)
        result=subprocess.run(['curl','-4','-fsS','--proto','=https','--noproxy','',
            '--proxy','socks5h://127.0.0.1:'+str(port),'--connect-timeout','5','--max-time','12',
            'https://one.one.one.one/cdn-cgi/trace'],capture_output=True,text=True,
            check=False,timeout=16)
        ips=re.findall(r'(?m)^ip=([^\r\n]+)\r?$',result.stdout)
        if result.returncode or len(ips)!=1 or not ipaddress.IPv4Address(ips[0]).is_global:
            raise RuntimeError('client measurement failed')
        if r['mode']=='POST_ATTACH' and ips!=[r['target_ipv4']]:
            raise RuntimeError('wrong client ip')
        print(json.dumps({'challenge':r['challenge'],'scope_digest':r['scope_digest'],
            'operation_id':r['operation_id'],'observed_ipv4':ips[0]}))
    finally:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill();proc.wait(timeout=3)
'''


class PinnedEdgeClientProbe:
    def __init__(self,db_conn):
        self.db_conn=db_conn

    def _legacy_candidate(self, username, uid, hint):
        """Discover a candidate, never source evidence, from the live peer.

        The historical account host must still be an active known listener.
        Successful pinned SSH authentication AND a new trusted Core sshd
        acceptance record are required before this identity can be published.
        """
        import ipaddress
        import pwd
        from edge_egress_v1_ingress import NET, _networks
        from edge_egress_v1_onboarding import planned_peer, assert_live_ingress
        if os.geteuid()!=0 or pwd.getpwnam(username).pw_uid!=uid:
            raise CoreObservationHold('SOURCE_PROBE_ROOT_UID_REQUIRED')
        with self.db_conn() as db:
            account=db.execute("SELECT host FROM ssh_accounts WHERE username=? "
                "AND service_type='ssh' AND status LIKE '%فعال%' "
                "AND status NOT LIKE '%غیر%'",(username,)).fetchall()
            if 'service_port' not in {row[1] for row in db.execute('PRAGMA table_info(host_pool)')}:
                raise CoreObservationHold('SOURCE_PROBE_RECONNECT_TO_KNOWN_EDGE')
            listener=db.execute('SELECT active,service_port FROM host_pool WHERE host=?',
                                (hint,)).fetchall()
        if (account!=[(hint,)] or len(listener)!=1 or listener[0][0]!=1
            or type(listener[0][1]) is not int or not 1<=listener[0][1]<=65535):
            raise CoreObservationHold('SOURCE_PROBE_RECONNECT_TO_KNOWN_EDGE')
        try:
            if str(ipaddress.IPv4Address(hint))!=hint or not ipaddress.IPv4Address(hint).is_global:
                raise ValueError()
            endpoints=checked(['wg','show','wg0','endpoints'])
            keys=[parts[0] for line in endpoints.splitlines()
                if len(parts:=line.split())==2
                and re.fullmatch(re.escape(hint)+r':[0-9]{1,5}',parts[1])]
            allowed=checked(['wg','show','wg0','allowed-ips'])
            networks=_networks(allowed)
            if len(keys)!=1:
                raise ValueError()
            sources=[str(n.network_address) for n in networks.get(keys[0],())
                if n.version==4 and n.prefixlen==32 and n.network_address in NET
                and str(n.network_address)!='10.77.0.1']
            if len(sources)!=1:
                raise ValueError()
            peer=planned_peer(sources[0],hint,keys[0])
            assert_live_ingress(peer,allowed)
        except (ValueError,TypeError) as exc:
            raise CoreObservationHold('SOURCE_PROBE_LEGACY_PEER_UNVERIFIED') from exc
        with self.db_conn() as db:
            identities=db.execute('SELECT edge_id FROM edge_egress_allocations WHERE edge_public_ipv4=?',
                                  (hint,)).fetchall()
            if len(identities)>1:
                raise CoreObservationHold('SOURCE_PROBE_LEGACY_IDENTITY_CONFLICT')
            if identities:
                # Preserve an already allocated identity (older installations
                # need not have used the wizard's eN naming convention).
                peer=replace(peer,edge_id=identities[0][0])
                from edge_egress_v1_ingress import render_registry
                render_registry([peer])
            rows=db.execute('SELECT edge_public_ipv4 FROM edge_egress_allocations WHERE edge_id=?',
                            (peer.edge_id,)).fetchall()
        if any(row!=(hint,) for row in rows):
            raise CoreObservationHold('SOURCE_PROBE_LEGACY_IDENTITY_CONFLICT')
        from edge_egress_k2_p1_worker import PIN_ROOT, load_stage_pin
        pin_path=PIN_ROOT/(peer.edge_id+'.json')
        if pin_path.exists() or pin_path.is_symlink():
            try:
                pin=load_stage_pin(peer.edge_id)
                if pin.edge_ipv4!=hint or pin.ingress_ipv4!=peer.ingress_ipv4:
                    raise ValueError()
            except (ValueError,OSError) as exc:
                raise CoreObservationHold('SOURCE_PROBE_LEGACY_IDENTITY_CONFLICT') from exc
        return peer

    @staticmethod
    def _ssh_cursor():
        try:
            raw=checked(['journalctl','-b','-n','1','--no-pager','-o','json',
                         '--output-fields=__CURSOR,_BOOT_ID'])
            rows=[json.loads(line) for line in raw.splitlines() if line.strip()]
            if len(rows)!=1:
                raise ValueError()
            cursor,boot=rows[0]['__CURSOR'],rows[0]['_BOOT_ID']
            if (type(cursor) is not str or not re.fullmatch(r'[A-Za-z0-9;=._-]{1,1024}',cursor)
                or type(boot) is not str or not re.fullmatch(r'[a-f0-9]{32}',boot)):
                raise ValueError()
            return cursor,boot
        except (ValueError,TypeError,KeyError,OSError,subprocess.SubprocessError) as exc:
            raise CoreObservationHold('SOURCE_PROBE_SSH_JOURNAL_REQUIRED') from exc

    @staticmethod
    def _accepted_legacy_source(cursor, username, expected_rhost):
        """Read Core's actual SSH peer, never an Edge-reported PAM address."""
        cursor,boot=cursor
        deadline=time.monotonic()+2
        pattern=re.compile(r'Accepted password for '+re.escape(username)+
                           r' from ([0-9.]+) port ([0-9]{1,5}) ssh2')
        while True:
            try:
                raw=checked(['journalctl','-b','--after-cursor',cursor,'-n','257',
                    '--no-pager','-o','json','--output-fields=MESSAGE,_UID,_EXE,_PID,_BOOT_ID',
                    'SYSLOG_IDENTIFIER=sshd','_UID=0'])
            except (ValueError,OSError,subprocess.SubprocessError) as exc:
                raise CoreObservationHold('SOURCE_PROBE_SSH_JOURNAL_REQUIRED') from exc
            try:
                if len(raw)>262144:
                    raise ValueError()
                entries=[json.loads(line) for line in raw.splitlines() if line.strip()]
                if len(entries)>256:
                    raise ValueError()
                accepted=[]
                for entry in entries:
                    message=entry.get('MESSAGE')
                    match=pattern.fullmatch(message) if type(message) is str else None
                    if match:
                        if (entry.get('_UID')!='0' or entry.get('_BOOT_ID')!=boot
                            or entry.get('_EXE') not in ('/usr/sbin/sshd','/usr/lib/openssh/sshd-session')
                            or type(entry.get('_PID')) is not str or not entry['_PID'].isdecimal()
                            or int(entry['_PID'])<=1 or not 1<=int(match[2])<=65535):
                            raise ValueError()
                        accepted.append(match[1])
                if accepted:
                    if accepted!=[expected_rhost]:
                        raise ValueError()
                    return
            except (ValueError,TypeError,KeyError,AttributeError) as exc:
                raise CoreObservationHold('SOURCE_PROBE_SSH_INGRESS_AMBIGUOUS') from exc
            if time.monotonic()>=deadline:
                raise CoreObservationHold('SOURCE_PROBE_SSH_INGRESS_NOT_OBSERVED')
            time.sleep(.1)

    def _request(self,username,source):
        import secrets
        from edge_egress_k2_p1_worker import load_stage_pin as source_pin
        try:
            port=source_pin(source.edge_id).customer_port
        except (ValueError,OSError):
            with self.db_conn() as db:
                rows=db.execute("SELECT service_port FROM host_pool WHERE host=?",
                            (source.edge_ipv4,)).fetchall()
            if len(rows)!=1:
                raise CoreObservationHold("CLIENT_PROBE_SOURCE_PORT_UNVERIFIED")
            port=rows[0][0]
        if type(port) is not int or not 1<=port<=65535:
            raise CoreObservationHold("CLIENT_PROBE_SOURCE_PORT_INVALID")
        with self.db_conn() as db:
            rows=db.execute("SELECT password FROM ssh_accounts WHERE username=? "
                            "AND service_type='ssh' AND status LIKE '%فعال%' "
                            "AND status NOT LIKE '%غیر%'",(username,)).fetchall()
        if (len(rows)!=1 or type(rows[0][0]) is not str
            or not 1<=len(rows[0][0])<=512 or '\n' in rows[0][0]):
            raise CoreObservationHold("CLIENT_PROBE_CREDENTIAL_UNAVAILABLE")
        key=checked(['ssh-keygen','-y','-f','/etc/ssh/ssh_host_ed25519_key']).strip()
        if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\n]*)?',key):
            raise CoreObservationHold("CLIENT_PROBE_CORE_HOST_KEY_INVALID")
        return dict(username=username,password=rows[0][0],
            source_ipv4=source.edge_ipv4,port=port,
            core_host_key=' '.join(key.split()[:2]),challenge=secrets.token_hex(32))

    def _run(self,edge_id,request):
        from edge_egress_k2_p1_worker import load_stage_pin,SSH_KEY,STAGE_ROOT
        from edge_egress_v1_live_driver import RemotePinnedEdge
        pin=load_stage_pin(edge_id)
        if request['source_ipv4']==pin.edge_ipv4:
            # A locally originated connection on the relay does not traverse
            # its PREROUTING DNAT. Use the full Core->PUBLIC Edge->Core SSH
            # path instead of mistaking that hairpin failure for a UID error.
            # Independent external-device acceptance is still a release gate.
            try:
                proc=subprocess.run(['python3','-'],
                    input='REQUEST='+repr(request)+'\n'+_REMOTE_CLIENT,
                    capture_output=True,text=True,timeout=45,check=False,env=PROBE_ENV)
                if proc.returncode or len(proc.stdout)>8192:
                    raise CoreObservationHold('PUBLIC_RELAY_CLIENT_MEASUREMENT_FAILED')
                return self._result(request,proc.stdout)
            finally:
                request.clear()
        remote=RemotePinnedEdge(pin.edge_ipv4,pin.ssh_port,pin.ssh_host_key,
                               SSH_KEY,STAGE_ROOT/('edge-'+pin.edge_id),pin.edge_sha)
        ssh=remote._ssh()
        try:
            stdin,stdout,stderr=ssh.exec_command('python3 -',timeout=40,get_pty=False)
            stdout.channel.settimeout(40)
            stdin.write('REQUEST='+repr(request)+'\n'+_REMOTE_CLIENT)
            stdin.flush();stdout.channel.shutdown_write()
            raw=stdout.read(8193)
            if len(raw)>8192 or stdout.channel.recv_exit_status()!=0:
                raise CoreObservationHold("EXTERNAL_CLIENT_MEASUREMENT_FAILED")
            observed=self._result(request,raw)
        except (ValueError,OSError,TypeError) as exc:
            raise CoreObservationHold("EXTERNAL_CLIENT_MEASUREMENT_UNAVAILABLE") from exc
        finally:
            ssh.close()
            request.clear()
        return observed

    @staticmethod
    def _result(request,raw):
        from ipaddress import IPv4Address
        result=json.loads(raw)
        if type(result) is not dict:
            raise CoreObservationHold('CLIENT_MEASUREMENT_FORMAT_INVALID')
        expected={key:request[key] for key in ('challenge','scope_digest','operation_id')}
        observed=result.get('observed_ipv4')
        if (type(observed) is not str or str(IPv4Address(observed))!=observed
            or not IPv4Address(observed).is_global
            or result!={**expected,'observed_ipv4':observed}
            or request['mode']=='POST_ATTACH' and observed!=request['target_ipv4']):
            raise CoreObservationHold('CLIENT_MEASUREMENT_SCOPE_DRIFT')
        return observed

    def __call__(self,scope,ticket):
        source=root_fresh_source_evidence()(scope.username)
        if source.edge_ipv4!=scope.source_host:
            raise CoreObservationHold("CLIENT_PROBE_INGRESS_CHANGED")
        request=self._request(scope.username,source)
        request.update(mode='POST_ATTACH',target_ipv4=scope.target_host,
            scope_digest=_scope_digest(scope),
            operation_id=assert_guarded_6g_intent(self.db_conn,scope,ticket))
        result=self._run(scope.edge_id,request)
        assert_guarded_6g_intent(self.db_conn,scope,ticket)
        return result

    def refresh_source(self,username,target_edge_id):
        """Actually authenticate through a candidate ingress; never infer it.

        Historical host is only a connection hint. A pinned external Edge
        must open real customer SSH/SOCKS to the exact Core host key. A
        failed login, unobserved Core SSH peer or changed WG owner cannot
        publish source evidence. A legacy peer can be registered automatically
        only after that actual authenticated Core observation.
        """
        from edge_egress_v1_ingress import load_registry,_networks
        from edge_egress_k2_m2_ingress_journal import (
            create_root_journal_if_absent,serialized_root_journal,
            compare_and_swap_root_journal,encode_records,_validated,IngressRecord,
            verified_recent_observation,
        )
        import pwd
        from ipaddress import ip_address,ip_network
        uid=pwd.getpwnam(username).pw_uid
        with self.db_conn() as db:
            hints=db.execute("SELECT host FROM ssh_accounts WHERE username=? AND service_type='ssh'",
                             (username,)).fetchall()
        if len(hints)!=1:
            raise CoreObservationHold('SOURCE_PROBE_ACCOUNT_AMBIGUOUS')
        peers=load_registry()
        with serialized_root_journal():
            before=create_root_journal_if_absent()
        records=_validated(before)
        old=records.get(username)
        hint=old.edge_ipv4 if old is not None and old.uid==uid else hints[0][0]
        candidates=[p for p in peers if p.edge_ipv4==hint]
        legacy=not candidates
        if legacy:
            peer=self._legacy_candidate(username,uid,hint)
            # Full registry validation rejects reused IDs, addresses or keys.
            from edge_egress_v1_ingress import render_registry
            try:
                render_registry(list(peers)+[peer])
            except ValueError as exc:
                raise CoreObservationHold('SOURCE_PROBE_LEGACY_IDENTITY_CONFLICT') from exc
        elif len(candidates)==1:
            peer=candidates[0]
        else:
            raise CoreObservationHold('SOURCE_PROBE_RECONNECT_TO_KNOWN_EDGE')
        def ownership():
            current=load_registry()
            allowed=checked(['wg','show','wg0','allowed-ips'])
            try:
                ranges=_networks(allowed)
            except ValueError as exc:
                raise CoreObservationHold('SOURCE_PROBE_WG_OWNERSHIP_CHANGED') from exc
            src=ip_address(peer.ingress_ipv4)
            if ((peer not in current and not legacy)
                or ip_network(peer.ingress_ipv4+'/32') not in ranges.get(peer.wg_public_key,())
                or any(src in n for k,ns in ranges.items() if k!=peer.wg_public_key for n in ns)
                or pwd.getpwnam(username).pw_uid!=uid):
                raise CoreObservationHold('SOURCE_PROBE_WG_OWNERSHIP_CHANGED')
            if legacy:
                if self._legacy_candidate(username,uid,hint)!=peer:
                    raise CoreObservationHold('SOURCE_PROBE_LEGACY_PEER_CHANGED')
                # An exact concurrent authenticated registration is harmless;
                # any conflicting identity must remain a hold.
                from edge_egress_v1_ingress import render_registry
                try:
                    render_registry(list(current) if peer in current else list(current)+[peer])
                except ValueError as exc:
                    raise CoreObservationHold('SOURCE_PROBE_LEGACY_IDENTITY_CONFLICT') from exc
            return current,allowed
        ownership()
        cursor=self._ssh_cursor() if legacy else None
        started=int(time.time())
        request=self._request(username,peer)
        request.update(mode='SOURCE',target_ipv4='',operation_id=None,
            scope_digest=sha256((username+str(uid)+peer.edge_id+peer.wg_public_key).encode()).hexdigest())
        self._run(target_edge_id,request)
        if legacy:
            self._accepted_legacy_source(cursor,username,peer.ingress_ipv4)
            ownership()
            from edge_egress_v1_onboarding import _publish_registry
            _publish_registry(peer,guard=ownership,allow_existing=True)
        current,allowed=ownership()
        now=int(time.time())
        # Persist only after the authenticated forwarding transaction. The
        # caller waits for its temporary session to close before UID work.
        with serialized_root_journal():
            before=create_root_journal_if_absent()
            records=_validated(before)
            newest=records.get(username)
            if newest!=old and not (newest is not None
                and (newest.username,newest.uid,newest.edge_id,newest.edge_ipv4,
                     newest.ingress_ipv4,newest.wg_public_key)==(
                         username,uid,peer.edge_id,peer.edge_ipv4,peer.ingress_ipv4,peer.wg_public_key)
                and started<=newest.observed_at<=now):
                raise CoreObservationHold('SOURCE_PROBE_CONCURRENT_LOGIN_REVIEW_AGAIN')
            records[username]=IngressRecord(username,uid,peer.edge_id,peer.edge_ipv4,
                peer.ingress_ipv4,peer.wg_public_key,now)
            raw=encode_records(records)
            result=verified_recent_observation(raw,username=username,uid=uid,
                peers=current,allowed_ips=allowed,now=now,
                resolve_uid=lambda n:pwd.getpwnam(n).pw_uid)
            compare_and_swap_root_journal(before,raw)
        return result


class CorePhysicalObservations:
    """Concrete root-only collector, composed once at existing bot startup."""
    def __init__(self,*,db_conn,host,qualification_sha256,release_sha,lab_trial=False):
        self.db_conn,self.host=db_conn,host
        self.qualification_sha256=qualification_sha256
        self.release_sha=release_sha
        self.lab_trial=lab_trial is True
        self.client= PinnedEdgeClientProbe(db_conn)
        self._current=None
        self._transport_cache=None
        self.uid_intent=None

    def _qualification(self,core_ip):
        if self.lab_trial:
            from edge_egress_k2_runtime_release import validate_lab_trial
            validate_lab_trial(self.db_conn,release_sha=self.release_sha,
                               digest=self.qualification_sha256,core_ipv4=core_ip)
            return
        from edge_egress_f4_release import parse_evidence_json,check_release_evidence
        raw=_root_bytes(QUALIFICATION,16384,private=True)
        if sha256(raw).hexdigest()!=self.qualification_sha256:
            raise CoreObservationHold("RELEASE_FIELD_QUALIFICATION_DIGEST_CHANGED")
        wrapper=json.loads(raw)
        if (type(wrapper) is not dict or set(wrapper)!={'release_sha','evidence'}
            or wrapper['release_sha']!=self.release_sha):
            raise CoreObservationHold('FIELD_QUALIFICATION_RELEASE_MISMATCH')
        payload=parse_evidence_json(json.dumps(wrapper['evidence']).encode())
        # Acceptance remains a real, separately performed field stage. A
        # successful namespace probe cannot mint rescue/reboot/WG-loss proof.
        stamp=payload.get('observed_at')
        if type(stamp) is not int or stamp>self.host.now():
            raise CoreObservationHold('FIELD_QUALIFICATION_TIME_INVALID')
        # A pinned qualification records release-time fault/reboot tests;
        # it is not passed off as a new measurement on every transfer.
        environment=payload.get('environment')
        if environment not in ('disposable-vps','controlled-core'):
            raise CoreObservationHold('FIELD_QUALIFICATION_ENVIRONMENT_INVALID')
        result=check_release_evidence(payload,expected_core_ipv4=core_ip,now=stamp,
                                      expected_environment=environment)
        if not result.accepted:
            raise CoreObservationHold("RELEASE_FIELD_QUALIFICATION_REQUIRED")

    def qualify_target(self,edge_id):
        from edge_egress_k2_p1_worker import load_stage_pin,probe_phase1
        from edge_egress_k2_runtime_release import load_core_profile
        profile=load_core_profile()
        if (not profile.enabled or not profile.operations_enabled
            or (profile.field_acceptance_sha256 if not self.lab_trial else
                profile.lab_trial_sha256)!=self.qualification_sha256):
            raise CoreObservationHold('CORE_OPERATIONS_RELEASE_REVOKED_OR_CHANGED')
        pin=load_stage_pin(edge_id)
        if self.lab_trial and (pin.edge_id!='e2' or pin.edge_ipv4!='144.172.84.112'):
            raise CoreObservationHold('LAB_TRIAL_TARGET_NOT_AUTHORIZED')
        self._qualification(pin.core_ipv4)
        with self.db_conn() as db:
            ready=read_readiness(db,edge_id)
            rows=db.execute('SELECT edge_public_ipv4,status FROM edge_egress_allocations '
                            'WHERE edge_id=?',(edge_id,)).fetchall()
        if (rows!=[(pin.edge_ipv4,'STAGED')] or ready is None
            or ready.edge_ipv4!=pin.edge_ipv4 or ready.state in ('HOLD','REVOKED')):
            raise CoreObservationHold("EDGE_STAGE_OR_READINESS_REQUIRES_REPAIR")
        cache=self._transport_cache
        identity=(pin.edge_id,pin.core_sha,pin.edge_sha,pin.ssh_host_key)
        if cache is not None and cache[0]==identity and 0<=self.host.now()-cache[1]<5:
            result=cache[2]
        else:
            kwargs={'uid_intent':self.uid_intent} if self.uid_intent is not None else {}
            result=probe_phase1(edge_id,db_conn=self.db_conn,**kwargs)
            self._transport_cache=(identity,self.host.now(),result)
        if result.get('observed_ipv4')!=pin.edge_ipv4:
            raise CoreObservationHold("AUTOMATIC_EDGE_IP_MISMATCH")
        return pin,sha256(json.dumps((pin.edge_id,pin.edge_ipv4,pin.core_sha,
            pin.edge_sha,pin.ssh_host_key,self.release_sha,self.qualification_sha256),
            separators=(',',':')).encode()).hexdigest()

    def target_qualified(self,req):
        if self.lab_trial:
            self._trial_scope(req.spec.edge_id,(req.username,))
        pin,_=self.qualify_target(req.spec.edge_id)
        return req.spec.edge_public_ipv4==pin.edge_ipv4

    def pre(self,selection):
        if self.lab_trial:
            self._trial_scope(selection.target_edge_id,selection.usernames)
        neighbours=self._neighbours('')
        pin,digest=self.qualify_target(selection.target_edge_id)
        from edge_egress_k2_m2_ingress_journal import (
            serialized_root_journal,create_root_journal_if_absent,
        )
        with serialized_root_journal():
            create_root_journal_if_absent()
        observed=root_fresh_source_evidence()
        accounts=[]
        for name in selection.usernames:
            uid=self.host.os_uid(name)
            if not self.host.local_idle(name,uid):
                raise CoreObservationHold("SELECTED_USER_HAS_ACTIVE_SESSIONS")
            try:
                w=observed(name)
            except (ValueError,OSError,KeyError):
                self.client.refresh_source(name,selection.target_edge_id)
                w=root_fresh_source_evidence()(name)
                deadline=time.monotonic()+3
                while not self.host.local_idle(name,uid):
                    if time.monotonic()>=deadline:
                        raise CoreObservationHold('SOURCE_PROBE_SESSION_NOT_DRAINED')
                    time.sleep(.1)
            accounts.append(WitnessAccount(name,uid,w.edge_id,w.edge_ipv4,0))
        if self._neighbours('')!=neighbours:
            raise CoreObservationHold('PRE_ATTACH_NEIGHBOUR_STATE_CHANGED')
        now=self.host.now()
        generation=sha256(json.dumps((pin.core_sha,pin.edge_sha,
            self.qualification_sha256,[asdict(a) for a in accounts]),
            sort_keys=True,separators=(',',':')).encode()).hexdigest()
        self._current=CorePreAttachEvidence(generation,now,now+30,
            selection.target_edge_id,pin.edge_ipv4,
            LAB_PRE_CHECKS if self.lab_trial else CORE_PRE_CHECKS,tuple(accounts),
            phase='PRE_ATTACH')
        self.target_digest=digest
        return self._current

    def _trial_scope(self,edge_id,names):
        from edge_egress_k2_runtime_release import validate_lab_trial
        validate_lab_trial(self.db_conn,release_sha=self.release_sha,
            digest=self.qualification_sha256,edge_id=edge_id,usernames=names)

    def current(self):
        if self._current is None:
            raise CoreObservationHold("AUTOMATIC_PRE_ATTACH_NOT_REQUESTED")
        return self._current

    def _neighbours(self,username):
        from edge_egress_v1_admission import load_roster,ROSTER
        with self.db_conn() as db:
            rr=db.execute('SELECT * FROM edge_egress_uid_runtime WHERE username<>? ORDER BY username',
                          (username,)).fetchall()
            bb=db.execute('SELECT * FROM edge_egress_uid_bindings WHERE username<>? ORDER BY username',
                          (username,)).fetchall()
        if not ROSTER.exists() and not ROSTER.is_symlink():
            if rr or bb:
                raise CoreObservationHold('PROTECTED_ROSTER_MISSING')
            roster=()
        else:
            roster=tuple(sorted((n,m.uid,m.guard_sha256) for n,m in load_roster().items() if n!=username))
        return rr,bb,roster

    def post(self,scope,ticket,*,phase):
        if self.lab_trial:
            self._trial_scope(scope.edge_id,(scope.username,))
        if phase not in ('UID_ROUTE','POST_ATTACH'):
            raise CoreObservationHold('AUTOMATIC_OBSERVATION_PHASE_INVALID')
        op=assert_guarded_6g_intent(self.db_conn,scope,ticket)
        def state():
            with self.db_conn() as db:
                row=read_binding(db,scope.username)
            if (row is None or row.uid!=scope.uid or row.edge_id!=scope.edge_id
                or row.edge_ipv4!=scope.target_host or row.last_operation_id!=op
                or row.state!=('ROUTED_UNVERIFIED' if phase=='UID_ROUTE' else 'PROTECTED')):
                raise CoreObservationHold('AUTOMATIC_OBSERVATION_RUNTIME_DRIFT')
            return row
        before=state()
        neighbours=self._neighbours(scope.username)
        from edge_egress_v1_admission import load_roster,checked_guard
        from edge_egress_uid_runtime_kernel import LocalLinuxProtectedRuntimeKernel
        manifest=checked_guard(load_roster()[scope.username])
        req=manifest.request
        if (req.username!=scope.username or req.uid!=scope.uid
            or req.spec.edge_id!=scope.edge_id
            or req.spec.edge_public_ipv4!=scope.target_host
            or req.spec.route_table!=before.route_table
            or req.priority!=before.priority or manifest.dns_port!=before.dns_port):
            raise CoreObservationHold('AUTOMATIC_GUARD_RUNTIME_IDENTITY_MISMATCH')
        nss=_root_bytes(Path('/etc/nsswitch.conf'),16384).decode('utf-8')
        from edge_egress_uid_dns import validate_nss_hosts
        validate_nss_hosts(nss)
        kernel=LocalLinuxProtectedRuntimeKernel(explicitly_enabled=True)
        kernel.assert_dns_ipv6(req)
        # Capture only the physical uplink, never wg/veth plaintext. False
        # positives from another user stop this transfer; they cannot PASS it.
        routes=json.loads(checked(['ip','-j','-4','route','show','default']))
        devices={r.get('dev') for r in routes if r.get('dev')}
        if len(devices)!=1 or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',next(iter(devices))):
            raise CoreObservationHold('CORE_PHYSICAL_UPLINK_AMBIGUOUS')
        device=next(iter(devices))
        with tempfile.TemporaryDirectory(prefix='nvl-uid-observation-') as folder:
            capture=Path(folder)/'uplink.pcap'
            proc=subprocess.Popen(['tcpdump','-U','-n','-Q','out','-i',device,'-w',str(capture),
                '(dst port 53 or dst port 853) or ((dst host 1.1.1.1 or dst host 1.0.0.1) and dst port 443) or (ip6 and dst host 2606:4700:4700::1111)'],
                stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True,env=PROBE_ENV)
            try:
                # tcpdump's ready message proves the capture is attached
                # before any probe. A missing tool/permission is a HOLD.
                import select
                deadline=time.monotonic()+3
                while True:
                    if time.monotonic()>=deadline or not select.select(
                        [proc.stderr],[],[],max(0,deadline-time.monotonic()))[0]:
                        raise CoreObservationHold('CORE_PACKET_CAPTURE_NOT_READY')
                    line=proc.stderr.readline()
                    if 'listening on' in line:
                        break
                    if not line or proc.poll() is not None:
                        raise CoreObservationHold('CORE_PACKET_CAPTURE_NOT_READY')
                if kernel.public_ipv4(req)!=scope.target_host:
                    raise CoreObservationHold('AUTOMATIC_UID_PUBLIC_IP_MISMATCH')
                raw=checked(['runuser','-u',scope.username,'--','python3','-c',_UID_DNS_PROBE],timeout=20)
                if json.loads(raw)!={c:True for c in ('dns_udp','dns_tcp','nss','ipv6')}:
                    raise CoreObservationHold('AUTOMATIC_DNS_IPV6_PROBE_FAILED')
                if phase=='POST_ATTACH' and self.client(scope,ticket)!=scope.target_host:
                    raise CoreObservationHold('AUTOMATIC_CLIENT_PUBLIC_IP_MISMATCH')
            finally:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)
                try: _,stats=proc.communicate(timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill();_,stats=proc.communicate(timeout=3)
            if (proc.returncode!=0 or not capture.is_file()
                or re.findall(r'(?m)^(\d+) packets dropped by kernel\s*$',stats)!=['0']):
                raise CoreObservationHold('CORE_PACKET_CAPTURE_FAILED')
            output=checked(['tcpdump','-nn','-r',str(capture)],timeout=5)
            if output.strip():
                raise CoreObservationHold('CORE_UPLINK_PACKET_LEAK_OBSERVED')
        if state()!=before or self._neighbours(scope.username)!=neighbours:
            raise CoreObservationHold('AUTOMATIC_RUNTIME_OR_NEIGHBOUR_CHANGED')
        assert_guarded_6g_intent(self.db_conn,scope,ticket)
        source=root_fresh_source_evidence()(scope.username)
        now=self.host.now()
        proof=SignedExternalEvidence(
            sha256((phase+_scope_digest(scope)+str(op)).encode()).hexdigest(),
            now,now+30,scope.edge_id,scope.target_host,
            UID_ROUTE_CHECKS if phase=='UID_ROUTE' else POST_ATTACH_CHECKS,
            (WitnessAccount(scope.username,scope.uid,source.edge_id,source.edge_ipv4,0),),
            phase=phase,scope_digest=_scope_digest(scope),
            nonce_hash=sha256(ticket.nonce.encode()).hexdigest(),operation_id=op,
            observed_public_ipv4=scope.target_host)
        proof.verify_post_attach(scope,ticket,operation_id=op,now=now,phase=phase)
        return proof
