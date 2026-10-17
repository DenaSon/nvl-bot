"""Owner-run, pinned Lab code publication and bounded Telegram trial release.

Run the controller on the original Core. Only 144.172.84.127 is changed.
The real P3/F2/6G engine installs first/Nth UID guards from Telegram; this
helper neither migrates a user nor manufactures F4/customer acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

from ops import k2_core_code_publish_febcc as publisher
from ops.k2_lab_core_copy import LAB_IP, local_ipv4s

CONFIG=Path('/etc/nvl-egress/k2-m4')
OLD_RELEASE='7376742013018b25171ed848464fe1947dc67527c91025d11efe161e512cfa14'
OLD_BOT='502504367bdc01ef34efca70b6949ff3c03a74d3997e24ccf1478b1b945ce09b'
DELTA=frozenset(('edge_egress_k2_runtime_release.py','edge_egress_k2_core_runtime.py',
                 'edge_egress_k2_core_observer.py','edge_egress_uid_admission.py',
                 'edge_egress_uid_dns.py'))


def require(ok,message):
    if not ok:
        raise RuntimeError(message)


def db_conn():
    return sqlite3.connect('/root/master_bot.db',timeout=5)


def lab_identity():
    # Wrong-host refusal comes before *any* profile/service/file mutation.
    require(os.geteuid()==0 and LAB_IP in local_ipv4s()
            and '209.200.246.198' not in local_ipv4s(),'WRONG_LAB_HOST')
    with sqlite3.connect('file:/root/master_bot.db?mode=ro',uri=True) as db:
        for key,value in (('brand','NVL-LAB'),('core_wg_public_ip',LAB_IP)):
            require(db.execute('SELECT value FROM settings WHERE key=?',(key,)).fetchall()
                    ==[(value,)],'LAB_IDENTITY_CHANGED')


def rescue_info():
    lab_identity()
    from edge_egress_k2_runtime_release import lab_rescue_digest
    env=dict(line.split('=',1) for line in Path('/etc/nvlbot/nvlbot.env').read_text().splitlines()
             if '=' in line)
    require(env.get('MASTER_USER')=='labadmin' and env.get('MASTER_PASS'),
            'LAB_RECOVERY_CREDENTIAL_MISSING')
    # This output is captured privately by the controller, never a log/argv.
    return {'password':env['MASTER_PASS'],'rescue_sha256':lab_rescue_digest(),
            'rescue_observed_at':int(time.time())}


def verify_rescue(info):
    """Fresh independent TCP login from original Core, followed by real sudo."""
    import paramiko
    client=paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(LAB_IP,port=22,username='nvlrescue',password=info['password'],
            look_for_keys=False,allow_agent=False,timeout=15,auth_timeout=15,banner_timeout=15)
        stdin,stdout,stderr=client.exec_command("sudo -S -p '' id -u",timeout=15)
        stdin.write(info['password']+'\n');stdin.flush();stdin.channel.shutdown_write()
        require(stdout.read(128).strip()==b'0' and stdout.channel.recv_exit_status()==0,
                'LAB_RESCUE_SSH_SUDO_FAILED')
    finally:
        client.close()
    info.pop('password',None)
    return info


def preflight_trial():
    lab_identity()
    publisher.off()
    publisher.db_check()
    from edge_egress_k2_runtime_release import LAB_USERS,LAB_EDGE
    import pwd
    with db_conn() as db:
        require(db.execute('SELECT username,service_type FROM ssh_accounts ORDER BY username').fetchall()
                ==[(n,'ssh') for n in sorted(LAB_USERS)],'LAB_TRIAL_FOREIGN_CUSTOMER')
        for name,uid in LAB_USERS.items():
            require(pwd.getpwnam(name).pw_uid==uid,'LAB_TRIAL_UID_CHANGED')
        for table in ('edge_egress_uid_runtime','edge_egress_uid_bindings'):
            require(db.execute('SELECT COUNT(*) FROM '+table).fetchone()==(0,),
                    'LAB_TRIAL_ALREADY_STARTED')
        require(db.execute('SELECT edge_id,edge_public_ipv4,status FROM edge_egress_allocations').fetchall()
                ==[('e2',LAB_EDGE,'STAGED')],'LAB_ALLOCATION_CHANGED')
    for path in ('/etc/nvl-egress/v1-protected-users.json','/opt/nvl-egress'):
        p=Path(path)
        require(not p.exists() and not p.is_symlink(),'LAB_GUARD_SETUP_ALREADY_STARTED')
    from edge_egress_k2_p1_worker import load_stage_pin,probe_phase1
    pin=load_stage_pin('e2')
    require(pin.core_ipv4==LAB_IP and pin.edge_ipv4==LAB_EDGE,'LAB_STAGE_IDENTITY_CHANGED')
    require(probe_phase1('e2',db_conn=db_conn)['observed_ipv4']==LAB_EDGE,
            'LAB_TRANSPORT_NOT_PROVEN')
    subprocess.run(['sshd','-t'],check=True,timeout=10)
    for name in LAB_USERS:
        text=subprocess.check_output(['sshd','-T','-C',
            f'user={name},host=lab,addr=10.77.0.2,laddr=10.77.0.1,lport=2252'],text=True,timeout=10)
        require({'usepam yes','passwordauthentication yes','allowtcpforwarding yes'}
                <=set(text.splitlines()),'LAB_CUSTOMER_SSH_POLICY_CHANGED')


def trial_profile(release,proof):
    from edge_egress_k2_runtime_release import _root_bytes,lab_rescue_digest,LAB_EDGE
    require(set(proof)=={'rescue_sha256','rescue_observed_at'}
            and proof['rescue_sha256']==lab_rescue_digest()
            and type(proof['rescue_observed_at']) is int
            and 0<=int(time.time())-proof['rescue_observed_at']<600,
            'FRESH_INDEPENDENT_RESCUE_PROOF_REQUIRED')
    return {'version':3,'single_enabled':True,'operations_enabled':True,'batch_enabled':True,
        'pam_module_sha256':release['files']['edge_egress_v1_admission.py'],
        'lab_trial':{'purpose':'ISOLATED_LAB_TRIAL','release_sha':release['git_sha'],
            'core_ipv4':LAB_IP,'edge_id':'e2','edge_ipv4':LAB_EDGE,
            'machine_sha256':hashlib.sha256(_root_bytes(Path('/etc/machine-id'),256)).hexdigest(),
            **proof}}


def activate(proof):
    preflight_trial()
    release=json.loads((CONFIG/'release.json').read_bytes())
    profile=trial_profile(release,proof)
    raw=(json.dumps(profile,sort_keys=True)+'\n').encode()
    profile_path=CONFIG/'core-runtime.json'
    nss=Path('/etc/nsswitch.conf')
    previous=publisher.snapshot(nss)
    require(previous is not None,'LAB_NSS_MISSING')
    lines=previous[1].decode().splitlines(keepends=True)
    require(sum(line.lstrip().startswith('hosts:') for line in lines)==1,'LAB_NSS_AMBIGUOUS')
    after=''.join('hosts: files dns\n' if line.lstrip().startswith('hosts:') else line
                  for line in lines).encode()
    # This host-wide NSS change is restricted to the empty-customer Lab and
    # saved before replacement. It is never part of per-user bot behavior.
    backup=Path(tempfile.mkdtemp(prefix='nvl-lab-trial-backup-',dir='/root'))
    (backup/'nsswitch.conf').write_bytes(previous[1])
    print('LAB_SETUP_BACKUP='+str(backup),flush=True)
    require(publisher.snapshot(nss)==previous,'LAB_NSS_CHANGED')
    publisher.unit('stop')
    try:
        require(publisher.prop('MainPID')=='0','LAB_BOT_NOT_STOPPED')
        publisher.db_check()
        publisher.replace(nss,after,previous[0]['mode'],previous[0]['uid'],previous[0]['gid'])
        # No existing profile is replaced; interrupted trials require review.
        with profile_path.open('xb') as f:
            f.write(raw);f.flush();os.fsync(f.fileno())
        profile_path.chmod(0o600)
        from edge_egress_k2_core_runtime import start_core_single_runtime
        from edge_egress_k2_root_direct import bound_root_client
        from edge_egress_k2_core_edge_operations import prepare_edge
        app=SimpleNamespace(bot_data={})
        result=start_core_single_runtime(app,db_conn=db_conn,source_root=Path('/root'))
        require(result.state=='SINGLE_REGISTERED','LAB_NATIVE_RUNTIME_NOT_REGISTERED')
        root=bound_root_client(app).portal.execute_single.__self__
        actor,chat=sorted(root.policy.principals)[0]
        # Reuse the original native P1/6G operation to persist this *existing*
        # allocation. No direct unit hack, duplicate allocation or lock clear.
        prepared=prepare_edge(root,'e2',actor_id=actor,chat_id=chat)
        require(prepared.get('transport_up') is True and prepared.get('observed_ipv4')=='144.172.84.112',
                'LAB_TRANSPORT_PERSISTENCE_FAILED')
        publisher.unit('start')
        pid=publisher.stable()
        invocation=publisher.prop('InvocationID')
        log=subprocess.check_output(['journalctl','_SYSTEMD_INVOCATION_ID='+invocation,
                                     '--no-pager','-o','cat','-n','600'],text=True,timeout=10)
        require('K2 Single startup: SINGLE_REGISTERED' in log,'LAB_BOT_NATIVE_STARTUP_NOT_CONFIRMED')
        publisher.db_check()
        print(json.dumps({'status':'LAB_TELEGRAM_TRIAL_ENABLED','single':True,'batch':True,
            'edge_id':'e2','users':['nvltest1','nvltest2','nvltest3'],'pid':int(pid),
            'customers_moved':0,'field_accepted':False}),flush=True)
    except BaseException:
        # Disable only our exact grant. Preserve any 6G RECOVERY/guards/routes;
        # never auto-restore old SQLite or remove a protection artifact.
        publisher.unit('stop')
        if profile_path.exists() and profile_path.read_bytes()==raw:
            profile_path.unlink()
        publisher.unit('start')
        print('LAB_TRIAL_ENABLE_FAILED_RUNTIME_OFF: preserve operation and inspect',flush=True)
        raise


def publish(stage,commit,package):
    preflight_trial()
    publisher.STAGE=stage
    publisher.SHA=commit
    publisher.PACKAGE_SHA=package
    publisher.OLD_RELEASE_SHA=OLD_RELEASE
    publisher.OLD_BOT_SHA=OLD_BOT
    publisher.EXPECTED_CHANGED=DELTA
    publisher.deploy()


def controller(commit,bundle,package):
    require(os.geteuid()==0 and '209.200.246.198' in local_ipv4s() and LAB_IP not in local_ipv4s(),
            'RUN_CONTROLLER_ON_ORIGINAL_CORE')
    pid=publisher.prop('MainPID')
    require(pid.isdecimal() and int(pid)>0,'ORIGINAL_CORE_BOT_NOT_RUNNING')
    repo=Path('/root/nvl-release')
    subprocess.run(['git','-C',str(repo),'fetch','--quiet','origin',commit],check=True)
    require(subprocess.check_output(['git','-C',str(repo),'rev-parse','FETCH_HEAD'],text=True).strip()
            ==commit,'COMMIT_MISMATCH')
    folder=Path(tempfile.mkdtemp(prefix='nvl-lab-trial-export-',dir='/root'))
    source=folder/'source'
    source.mkdir(mode=0o700)
    archive=subprocess.check_output(['git','-C',str(repo),'archive',commit])
    subprocess.run(['tar','-x','-C',str(source)],input=archive,check=True)
    del archive
    subprocess.run([sys.executable,'-B','-m','ops.k2_release_bundle','build','--repo',str(repo),
                    '--commit',commit,'--output',str(folder/'source.tar')],cwd=source,check=True)
    require(publisher.digest((folder/'source.tar').read_bytes())==bundle,'BUNDLE_SHA_MISMATCH')
    control=str(folder/'ssh')
    connection=['-o','ControlMaster=auto','-o','ControlPersist=600','-o','ControlPath='+control,
                '-o','ServerAliveInterval=15','-o','ServerAliveCountMax=3','root@'+LAB_IP]
    def remote(cmd,**kwargs):
        return subprocess.check_output(['ssh',*connection,cmd],**kwargs)
    try:
        stage=remote('umask 077; mktemp -d /root/nvl-lab-trial-XXXXXXXX',text=True).strip()
        require(re.fullmatch('/root/nvl-lab-trial-[A-Za-z0-9]{8}',stage) is not None,'LAB_STAGE_INVALID')
        print('LAB_STAGE='+stage,flush=True)
        subprocess.run(['scp','-o','ControlPath='+control,str(folder/'source.tar'),
                        'root@'+LAB_IP+':'+stage+'/source.tar'],check=True)
        # Pinned package verification precedes importing any staged helper.
        command=('set -Eeuo pipefail\numask 077\ncd '+shlex.quote(stage)+'\n'+
            "printf '%s  source.tar\\n' "+shlex.quote(bundle)+" | sha256sum -c -\n"+
            'mkdir source\ntar -xf source.tar -C source\ncd source\n'+
            '/root/venv/bin/python3 -B -m ops.k2_release_bundle verify --directory . --commit '+
            commit+' --package-sha256 '+package+'\n'+
            '/root/venv/bin/python3 -B -m unittest tests.test_k2_lab_trial '
            'tests.test_edge_egress_core_pam_qualification tests.test_edge_egress_uid_dns '
            'tests.test_edge_egress_k2_core_runtime tests.test_edge_egress_k2_runtime_release -q\n'+
            'printf "%s\\n" '+commit+' > ../STAGING_OK\n'+
            'nohup flock -n ../publish.lock /root/venv/bin/python3 -B -m ops.k2_lab_trial '
            '--publish '+shlex.quote(stage)+' --commit '+commit+' --package-sha256 '+package+
            ' > ../deploy.log 2>&1 < /dev/null &\nNVL_JOB=$!\n'+
            'if wait "$NVL_JOB"; then cat ../deploy.log; else cat ../deploy.log; exit 1; fi\n')
        sys.stdout.buffer.write(remote('bash -s',input=command.encode()));sys.stdout.flush()
        # Read only this Lab's temporary recovery password into memory, then
        # erase it immediately after actual independent SSH/sudo verification.
        cmd='cd '+shlex.quote(stage+'/source')+' && /root/venv/bin/python3 -B -m ops.k2_lab_trial '
        proof=verify_rescue(json.loads(remote(cmd+'--rescue-info')))
        print('LAB_INDEPENDENT_RESCUE_SSH_SUDO=PASS',flush=True)
        sys.stdout.buffer.write(remote(cmd+'--activate',input=json.dumps(proof).encode()))
        sys.stdout.flush()
    finally:
        subprocess.run(['ssh','-O','exit',*connection],capture_output=True)
        require(publisher.prop('MainPID')==pid,'ORIGINAL_CORE_PID_CHANGED')
        require(publisher.prop('ActiveState')=='active','ORIGINAL_CORE_NOT_ACTIVE')
        print('PRODUCTION_SERVICE_UNCHANGED=YES',flush=True)


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commit')
    parser.add_argument('--bundle-sha256')
    parser.add_argument('--package-sha256')
    modes=parser.add_mutually_exclusive_group()
    modes.add_argument('--publish',type=Path)
    modes.add_argument('--rescue-info',action='store_true')
    modes.add_argument('--activate',action='store_true')
    args=parser.parse_args()
    if args.rescue_info:
        print(json.dumps(rescue_info()))
    elif args.activate:
        activate(json.loads(sys.stdin.buffer.read(2049)))
    else:
        require(type(args.commit) is str and re.fullmatch('[a-f0-9]{40}',args.commit)
                and type(args.package_sha256) is str
                and re.fullmatch('[a-f0-9]{64}',args.package_sha256),'EXACT_RELEASE_PINS_REQUIRED')
        if args.publish:
            require(args.publish.parent==Path('/root') and not args.publish.is_symlink()
                and re.fullmatch('nvl-lab-trial-[A-Za-z0-9]{8}',args.publish.name)
                and Path(__file__).resolve().parents[1]==args.publish/'source','INVALID_LAB_STAGE')
            publish(args.publish,args.commit,args.package_sha256)
        else:
            require(type(args.bundle_sha256) is str and re.fullmatch('[a-f0-9]{64}',args.bundle_sha256),
                    'BUNDLE_PIN_REQUIRED')
            controller(args.commit,args.bundle_sha256,args.package_sha256)


if __name__=='__main__':
    main()
