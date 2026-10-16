"""One-time isolated lab copy. Run export on the existing Core, never migrate it.

Only committed application bytes and installed Python packages leave the Core.
No customer DB, login persistence, production token, SSH/WG key or peer is copied.
The lab has fresh identities; customer execution/field acceptance remain OFF.
"""
from __future__ import annotations

import argparse
from datetime import date, timedelta
import getpass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import secrets
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

APP = 'febcc45c505e5bdc6a712745651dd8f87c2e1f91'
LAB_IP = '144.172.84.127'
EDGE_IP = '144.172.84.112'
SOURCE_SHA = '3381ed21691fe2fd0406d27fc0f51fe45b7a83d4fca94370afcd2752b8ca88cf'
PACKAGE_SHA = '3af297eab2f087128cd7bc8b32d456dab91d0a5a61df534eb77ec3606722154d'
RELEASE_SHA = 'e7e1324646d60bd7a9d533b4a28313bc03c319c9e2a64c6accfd0052ba80c297'
ROOT = Path('/root')
SOURCE = ROOT / 'nvl-k2-febcc45c505e/source.tar'


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def read(args):
    return subprocess.check_output(args, text=True).strip()


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def write_new(path, data, mode=0o600):
    path = Path(path)
    with path.open('xb') as stream:
        stream.write(data if isinstance(data, bytes) else data.encode())
    path.chmod(mode)


def install_lab_egress_schema(db_path, *, python, source_root):
    """Use the shipped canonical migrations before starting the fresh lab bot."""
    run([python, '-B', '-c', '''
import sqlite3, sys
from edge_egress_inventory import ensure_schema
from edge_egress_f3_readiness import install_readiness_schema
from edge_egress_protected_mapping import install_protected_mapping_schema
from edge_egress_uid_runtime_store import install_runtime_schema
with sqlite3.connect(sys.argv[1]) as db:
    ensure_schema(db)
    install_readiness_schema(db)
    install_protected_mapping_schema(db)
    install_runtime_schema(db)
print('LAB_EGRESS_SCHEMAS=OK')
''', str(db_path)], cwd=source_root)


def local_ipv4s():
    return {a['local'] for row in json.loads(read(['ip', '-j', '-4', 'addr', 'show']))
            for a in row.get('addr_info', ()) if a.get('family') == 'inet'}


def preflight_lab():
    require(os.geteuid() == 0 and LAB_IP in local_ipv4s(), 'WRONG_LAB_HOST')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines()
                   if '=' in line)
    require(release.get('ID', '').strip('"') == 'ubuntu'
            and release.get('VERSION_ID', '').strip('"') == '24.04'
            and read(['dpkg', '--print-architecture']) == 'amd64', 'LAB_OS_MISMATCH')
    for path in ('/root/master_bot.db', '/root/bot_final_v49-2.py',
                 '/root/bot_persistence.pickle', '/etc/wireguard/wg0.conf',
                 '/etc/nvl-egress', '/opt/nvl-egress',
                 '/etc/systemd/system/nvlbot.service',
                 '/etc/ssh/sshd_config.d/00-nvl-lab.conf',
                 '/etc/systemd/system/ssh.service.d/00-nvl-lab.conf'):
        p = Path(path)
        require(not p.exists() and not p.is_symlink(), 'LAB_NOT_FRESH: ' + path)
    unit = subprocess.run(['systemctl', 'show', 'nvlbot', '-p', 'LoadState', '--value'],
                          capture_output=True, text=True)
    require(unit.stdout.strip() == 'not-found',
            'LAB_BOT_UNIT_ALREADY_EXISTS')
    for username, uid in (('nvlrescue', None), ('nvltest1', 1636),
                          ('nvltest2', 1637), ('nvltest3', 1638)):
        try:
            pwd.getpwnam(username)
        except KeyError:
            pass
        else:
            raise RuntimeError('LAB_ACCOUNT_ALREADY_EXISTS')
        if uid is not None:
            try:
                pwd.getpwuid(uid)
            except KeyError:
                pass
            else:
                raise RuntimeError('LAB_TEST_UID_ALREADY_EXISTS')


def safe_extract(archive, target, prefix=None):
    """Our payloads contain only regular files/directories, never links/devices."""
    with tarfile.open(archive) as source:
        members = source.getmembers()
        seen = set()
        for member in members:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and '..' not in name.parts
                    and name.parts and member.name not in seen
                    and (member.isfile() or member.isdir()), 'UNSAFE_ARCHIVE_MEMBER')
            require(prefix is None or name.parts[0] == prefix, 'ARCHIVE_SCOPE_CHANGED')
            seen.add(member.name)
        for member in members:
            member.uid = member.gid = 0
            member.uname = member.gname = ''
            member.mode = 0o700 if member.isdir() else 0o600
        source.extractall(target, members=members, filter='data')


def bot_api(token, method):
    try:
        with urllib.request.urlopen('https://api.telegram.org/bot' + token + '/' + method,
                                    timeout=20) as response:
            payload = json.load(response)
        require(payload.get('ok') is True, 'TEST_BOT_API_REJECTED')
        return payload['result']
    except Exception:
        raise RuntimeError('TEST_BOT_API_UNAVAILABLE_OR_TOKEN_INVALID') from None


def check_test_token(token, production_token):
    require(bool(re.fullmatch(r'[0-9]{6,20}:[A-Za-z0-9_-]{20,100}', token)),
            'INVALID_TEST_BOT_TOKEN')
    require(int(token.split(':')[0]) != int(production_token.split(':')[0]),
            'PRODUCTION_BOT_TOKEN_FORBIDDEN')


def ssh_ports(output):
    ports = sorted({int(line.split()[1]) for line in output.splitlines()
                    if line.startswith('port ') and line.split()[1].isdigit()})
    require(22 in ports and all(1 <= p <= 65535 for p in ports),
            'LAB_ADMIN_SSH_PORT_REQUIRES_REVIEW')
    return sorted(set(ports) | {2252})


def render_lab_sshd(ports):
    return (''.join('Port %s\n' % p for p in ports) +
            'Match LocalPort 2252\n'
            '    PasswordAuthentication yes\n    KbdInteractiveAuthentication no\n'
            '    PermitRootLogin no\n    AllowTcpForwarding yes\nMatch all\n'
            'Match User nvlrescue LocalPort 22\n'
            '    PasswordAuthentication yes\nMatch all\n')


def configure_ssh(stage):
    context = 'user=root,host=lab,addr=127.0.0.1,laddr=127.0.0.1,lport=22'
    before = read(['/usr/sbin/sshd', '-T', '-C', context])
    require('usepam yes' in before.splitlines(), 'LAB_USEPAM_NOT_ENABLED')
    ports = ssh_ports(before)
    config = Path('/etc/ssh/sshd_config.d/00-nvl-lab.conf')
    unit = Path('/etc/systemd/system/ssh.service.d/00-nvl-lab.conf')
    unit.parent.mkdir(parents=True, exist_ok=True)
    write_new(config, render_lab_sshd(ports))
    write_new(unit, '[Service]\nKillMode=process\n')
    socket_state = read(['systemctl', 'is-enabled', 'ssh.socket']) if subprocess.run(
        ['systemctl', 'is-enabled', 'ssh.socket'], capture_output=True).returncode == 0 else 'disabled'
    try:
        run(['/usr/sbin/sshd', '-t'])
        effective = read(['/usr/sbin/sshd', '-T', '-C',
            'user=nvltest1,host=lab,addr=10.77.0.2,laddr=10.77.0.1,lport=2252'])
        require({'usepam yes', 'passwordauthentication yes', 'allowtcpforwarding yes',
                 'permitrootlogin no'} <= set(effective.splitlines()), 'LAB_CUSTOMER_SSH_POLICY_FAILED')
        run(['systemctl', 'daemon-reload'])
        # Lab only. Disable socket bypass before the later PAM/boot trial.
        run(['systemctl', 'disable', '--now', 'ssh.socket'])
        run(['systemctl', 'mask', 'ssh.socket'])
        run(['systemctl', 'stop', 'ssh.service'])
        run(['systemctl', 'enable', 'ssh.service'])
        run(['systemctl', 'start', 'ssh.service'])
        run(['systemctl', 'is-active', '--quiet', 'ssh.service'])
        require(':2252 ' in read(['ss', '-H', '-lnt']), 'LAB_CUSTOMER_LISTENER_MISSING')
    except BaseException:
        config.unlink(missing_ok=True)
        unit.unlink(missing_ok=True)
        subprocess.run(['systemctl', 'daemon-reload'])
        subprocess.run(['systemctl', 'unmask', 'ssh.socket'])
        if socket_state == 'enabled':
            subprocess.run(['systemctl', 'enable', '--now', 'ssh.socket'])
        subprocess.run(['systemctl', 'restart', 'ssh.service'])
        raise


def install_lab(stage):
    preflight_lab()
    metadata = json.loads((stage / 'metadata.json').read_text())
    require(metadata['app'] == APP and metadata['destination'] == LAB_IP,
            'LAB_PAYLOAD_IDENTITY_CHANGED')
    require(set(metadata['files']) == {'source.tar', 'packages.tar.gz', 'lab.env', 'setup.py'},
            'LAB_PAYLOAD_FILES_CHANGED')
    for name, expected in metadata['files'].items():
        require(digest(stage / name) == expected, 'LAB_PAYLOAD_HASH_FAILED: ' + name)
    require(digest(stage / 'source.tar') == SOURCE_SHA, 'LAB_SOURCE_HASH_FAILED')
    require(list(sys.version_info[:3]) == metadata['python'], 'LAB_PYTHON_VERSION_MISMATCH')
    env = dict(line.split('=', 1) for line in (stage / 'lab.env').read_text().splitlines())
    require(set(env) == {'BOT_TOKEN', 'MASTER_USER', 'MASTER_PASS', 'RB_CONFIRM_PASS',
                       'BOT_DB_PATH', 'BOT_PERSISTENCE_PATH', 'PYTHONDONTWRITEBYTECODE'},
            'LAB_ENV_SCOPE_CHANGED')
    test_bot = bot_api(env['BOT_TOKEN'], 'getMe')
    require(test_bot['id'] == metadata['test_bot_id'], 'LAB_TEST_BOT_ID_CHANGED')
    print('LAB_INSTALL=PACKAGES', flush=True)
    run(['apt-get', 'update', '-qq'])
    run(['apt-get', 'install', '-y', '-qq', 'python3-venv', 'openssh-server',
         'wireguard-tools', 'iproute2', 'iptables', 'curl', 'sqlite3', 'tcpdump',
         'dnsutils', 'jq', 'procps', 'util-linux', 'iputils-ping', 'sudo', 'libstdc++6'],
        env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive', 'NEEDRESTART_MODE': 'l'})
    source = stage / 'source'
    source.mkdir(mode=0o700)
    safe_extract(stage / 'source.tar', source)
    run([sys.executable, '-B', '-m', 'ops.k2_release_bundle', 'verify',
         '--directory', str(source), '--commit', APP, '--package-sha256', PACKAGE_SHA], cwd=source)
    venv = ROOT / 'venv'
    require(not venv.is_symlink(), 'LAB_VENV_SYMLINK')
    if venv.exists():
        require(read([str(venv/'bin/python3'), '-c', 'import sys;print(sys.prefix)']) == str(venv),
                'LAB_VENV_PATH_CHANGED')
        installed = json.loads(read([str(venv/'bin/python3'), '-m', 'pip', 'list', '--format=json']))
        require({p['name'].lower() for p in installed} <= {'pip', 'setuptools', 'wheel'},
                'LAB_VENV_NOT_EMPTY')
    else:
        run([sys.executable, '-m', 'venv', str(venv)])
    packages = stage / 'packages'
    packages.mkdir(mode=0o700)
    safe_extract(stage / 'packages.tar.gz', packages, prefix='site-packages')
    target = venv / 'lib/python3.12/site-packages'
    require(target.is_dir() and not target.is_symlink(), 'LAB_SITE_PATH_CHANGED')
    target.rename(stage / 'previous-site-packages')
    (packages / 'site-packages').rename(target)
    py = str(venv / 'bin/python3')
    run([py, '-m', 'pip', 'check'])
    run([py, '-B', '-c', 'import telegram,aiohttp,paramiko,qrcode,cryptography,nacl,sqlite3;'
         'print("LAB_PYTHON_IMPORTS=OK")'])
    package = json.loads((source / 'package.json').read_text())
    for name in package['files']:
        p = PurePosixPath(name)
        if (len(p.parts) == 1 and p.suffix in ('.py', '.sh')) or p.parts[0] in ('ops', 'server_migration'):
            destination = ROOT / name
            require(not destination.exists() and not destination.is_symlink(), 'LAB_CODE_TARGET_EXISTS')
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            write_new(destination, (source/name).read_bytes(), 0o700 if p.suffix == '.sh' else 0o600)
    config = Path('/etc/nvl-egress/k2-m4')
    config.mkdir(parents=True, mode=0o700)
    config.parent.chmod(0o700)
    write_new(config/'release.json', (source/'release.json').read_bytes())
    for name, expected in json.loads((config/'release.json').read_text())['files'].items():
        require(digest(ROOT/name) == expected, 'LAB_INSTALLED_RELEASE_MISMATCH')
    Path('/etc/nvlbot').mkdir(mode=0o700)
    write_new('/etc/nvlbot/nvlbot.env', (stage/'lab.env').read_bytes())
    os.environ.update(env)
    with sqlite3.connect(ROOT/'master_bot.db') as db:
        db.execute('CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)')
        db.executemany('INSERT INTO settings VALUES (?,?)', [
            ('brand', 'NVL-LAB'), ('counter', '0000'), ('hosts', LAB_IP), ('port', '2252'),
            ('core_wg_public_ip', LAB_IP), ('tls_domain', ''), ('public_domain', ''),
            ('marzban_url', ''), ('marzban_username', ''), ('marzban_password', ''),
            ('auto_failover_mode', '0'), ('phase6h_auto_failover_enabled', '0'),
            ('edge_egress_protected_mode', '0'), ('k2_p1_transport_activation_enabled', '1')])
    # Native schema only; __main__/polling/background jobs do not run here.
    run([py, '-B', '-c', 'import runpy; b=runpy.run_path("/root/bot_final_v49-2.py",'
         'run_name="nvl_lab_schema"); b["init_db"](); print("LAB_SCHEMA=OK")'], cwd=ROOT)
    install_lab_egress_schema(ROOT/'master_bot.db', python=py, source_root=ROOT)
    access = ['TEST BOT: @' + test_bot['username'], 'BOT LOGIN: labadmin',
              'BOT PASSWORD: ' + env['MASTER_PASS'],
              'SSH RECOVERY: nvlrescue@' + LAB_IP + ':22',
              'RECOVERY PASSWORD: ' + env['MASTER_PASS'],
              'Accounts below become usable through the Edge after its lab onboarding.']
    run(['useradd', '-m', '-s', '/bin/bash', '-G', 'sudo', 'nvlrescue'])
    run(['chpasswd'], input='nvlrescue:' + env['MASTER_PASS'] + '\n', text=True)
    today = date.today()
    with sqlite3.connect(ROOT/'master_bot.db') as db:
        for n in range(1, 4):
            username, uid, password = 'nvltest'+str(n), 1635+n, secrets.token_urlsafe(18)
            run(['useradd', '-M', '-u', str(uid), '-s', '/usr/sbin/nologin', username])
            run(['chpasswd'], input=username+':'+password+'\n', text=True)
            db.execute('INSERT INTO ssh_accounts (username,password,expire_date,creation_date,'
                       'users_limit,status,agent_id,host,service_type,conn_mode) '
                       'VALUES (?,?,?,?,?,?,?,?,?,?)',
                       (username,password,str(today+timedelta(days=30)),str(today),1,
                        '🟢 فعال',0,EDGE_IP,'ssh','direct'))
            access.append(username + ' / ' + password + ' / UID=' + str(uid))
        require(db.execute('PRAGMA quick_check').fetchall() == [('ok',)], 'LAB_DB_CHECK_FAILED')
    write_new(ROOT/'nvl-lab-access.txt', '\n'.join(access)+'\n')
    # New empty ingress identity, with NO production peers or private keys.
    wg = Path('/etc/wireguard')
    wg.mkdir(mode=0o700, exist_ok=True)
    private = read(['wg', 'genkey'])
    public = subprocess.check_output(['wg', 'pubkey'], input=private+'\n', text=True).strip()
    write_new(wg/'core_private.key', private+'\n')
    write_new(wg/'core_public.key', public+'\n')
    write_new(wg/'wg0.conf', '[Interface]\nAddress = 10.77.0.1/24\n'
              'ListenPort = 51820\nPrivateKey = '+private+'\n')
    write_new('/etc/sysctl.d/90-nvl-lab.conf', 'net.ipv4.ip_forward=1\n')
    run(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
    run(['systemctl', 'enable', '--now', 'wg-quick@wg0'])
    if shutil.which('ufw') and 'Status: active' in read(['ufw', 'status']):
        run(['ufw', 'allow', '51820/udp'])
        run(['ufw', 'allow', '2252/tcp'])
    print('LAB_INSTALL=SSH_LISTENERS', flush=True)
    configure_ssh(stage)
    write_new('/etc/systemd/system/nvlbot.service',
        '[Unit]\nDescription=NVL isolated test bot\nAfter=network-online.target\n'
        '[Service]\nType=simple\nUser=root\nWorkingDirectory=/root\nUMask=0077\n'
        'EnvironmentFile=/etc/nvlbot/nvlbot.env\n'
        'ExecStart=/root/venv/bin/python3 -B /root/bot_final_v49-2.py\n'
        'Restart=on-failure\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\n')
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', 'nvlbot'])
    pid = read(['systemctl', 'show', 'nvlbot', '-p', 'MainPID', '--value'])
    require(pid.isdigit() and int(pid)>0, 'LAB_BOT_PID_MISSING')
    for _ in range(10):
        time.sleep(2)
        run(['systemctl', 'is-active', '--quiet', 'nvlbot'])
        require(read(['systemctl', 'show', 'nvlbot', '-p', 'MainPID', '--value']) == pid,
                'LAB_BOT_UNSTABLE')
    require(not (config/'core-runtime.json').exists()
            and not (config/'field-acceptance.json').exists(), 'LAB_EXECUTION_MUST_REMAIN_OFF')
    return {'status':'LAB_CORE_INSTALLED', 'app':APP, 'ip':LAB_IP,
            'bot':'@'+test_bot['username'], 'pid':int(pid), 'runtime':'OFF',
            'edge_connected':False, 'field_accepted':False,
            'credentials':'/root/nvl-lab-access.txt'}


def copy_from_core(port):
    require(os.geteuid() == 0 and LAB_IP not in local_ipv4s(), 'RUN_ON_ORIGINAL_CORE')
    release = Path('/etc/nvl-egress/k2-m4/release.json')
    require(digest(release) == RELEASE_SHA and digest(SOURCE) == SOURCE_SHA,
            'EXPECTED_PRODUCTION_RELEASE_NOT_PRESENT')
    for name, expected in json.loads(release.read_text())['files'].items():
        require(digest(ROOT/name) == expected, 'PRODUCTION_SOURCE_CHANGED: '+name)
    pid = int(read(['systemctl', 'show', 'nvlbot', '-p', 'MainPID', '--value']))
    require(pid > 0, 'ORIGINAL_BOT_NOT_RUNNING')
    environment = dict(x.split(b'=',1) for x in (Path('/proc')/str(pid)/'environ').read_bytes().split(b'\0') if b'=' in x)
    production_token = environment[b'BOT_TOKEN'].decode()
    require(read([str(ROOT/'venv/bin/python3'), '-c', 'import sys;print(sys.prefix)']) == '/root/venv',
            'PRODUCTION_VENV_PATH_CHANGED')
    token = getpass.getpass('Temporary TEST bot token (not production): ').strip()
    check_test_token(token, production_token)
    test_bot = bot_api(token, 'getMe')
    require(not bot_api(token, 'getWebhookInfo').get('url'), 'USE_A_FRESH_POLLING_TEST_BOT')
    stage = Path(tempfile.mkdtemp(prefix='nvl-lab-export-', dir=ROOT))
    control = str(stage/'ssh.sock')
    connection = ['-p',str(port),'-o','ControlPath='+control,'-o','ServerAliveInterval=10',
                  '-o','ServerAliveCountMax=3','root@'+LAB_IP]
    ssh = lambda command: read(['ssh',*connection,command])
    try:
        run(['ssh','-M','-N','-f','-o','ControlPersist=600',*connection])
        remote = '/root/nvl-lab-import-'+secrets.token_hex(6)
        # Copying into an empty private staging directory cannot start services.
        ssh('umask 077; mkdir -m 700 '+shlex.quote(remote))
        shutil.copyfile(SOURCE,stage/'source.tar')
        shutil.copyfile(Path(__file__).resolve(),stage/'setup.py')
        password = secrets.token_urlsafe(24)
        write_new(stage/'lab.env', 'BOT_TOKEN='+token+'\nMASTER_USER=labadmin\nMASTER_PASS='+password+
                  '\nRB_CONFIRM_PASS='+secrets.token_urlsafe(24)+
                  '\nBOT_DB_PATH=/root/master_bot.db\nBOT_PERSISTENCE_PATH=/root/bot_persistence.pickle\n'
                  'PYTHONDONTWRITEBYTECODE=1\n')
        print('EXPORT=INSTALLED_PYTHON_PACKAGES (no customer data)',flush=True)
        run(['nice','-n','15','tar','-C','/root/venv/lib/python3.12',
             '--exclude=__pycache__','--exclude=*.pyc','-czf',str(stage/'packages.tar.gz'),'site-packages'])
        metadata={'app':APP,'destination':LAB_IP,'test_bot_id':test_bot['id'],
                  'python':json.loads(read([str(ROOT/'venv/bin/python3'),'-c',
                    'import sys,json; print(json.dumps(list(sys.version_info[:3])))'])),
                  'files':{p:digest(stage/p) for p in ('source.tar','packages.tar.gz','lab.env','setup.py')}}
        write_new(stage/'metadata.json',json.dumps(metadata))
        run(['scp','-P',str(port),'-o','ControlPath='+control,
             *[str(stage/p) for p in (*metadata['files'],'metadata.json')],
             'root@'+LAB_IP+':'+remote+'/'])
        # Detached: the lab's deliberate SSH listener restart cannot kill setup.
        ssh('nohup /usr/bin/python3 -B '+shlex.quote(remote+'/setup.py')+' --install '+
            shlex.quote(remote)+' > '+shlex.quote(remote+'/install.log')+' 2>&1 < /dev/null &')
        print('LAB_STAGE='+remote,flush=True)
        for attempt in range(180):
            raw = ssh('if test -f '+shlex.quote(remote+'/result.json')+'; then cat '+
                      shlex.quote(remote+'/result.json')+'; fi')
            if raw:
                result=json.loads(raw)
                print(json.dumps(result,ensure_ascii=False),flush=True)
                require(result.get('status') == 'LAB_CORE_INSTALLED', 'LAB_INSTALL_FAILED; inspect '+remote+'/install.log')
                # Fresh independent TCP/SSH authentication, not the old root master.
                import paramiko
                client=paramiko.SSHClient();client.load_system_host_keys()
                try:
                    client.connect(LAB_IP,port=port,username='nvlrescue',password=password,
                                   look_for_keys=False,allow_agent=False,timeout=15)
                    stdin,stdout,stderr=client.exec_command("sudo -S -p '' true",timeout=15)
                    stdin.write(password+'\n');stdin.flush();stdin.channel.shutdown_write()
                    require(stdout.channel.recv_exit_status()==0,'LAB_RESCUE_SUDO_FAILED')
                finally:
                    client.close()
                require(read(['systemctl','show','nvlbot','-p','MainPID','--value'])==str(pid),
                        'PRODUCTION_BOT_PID_CHANGED_DURING_COPY')
                run(['systemctl','is-active','--quiet','nvlbot'])
                print('LAB_RESCUE_SSH_AND_SUDO=PASS\nPRODUCTION_SERVICE_UNCHANGED=YES\n'
                      'CUSTOMER_TRANSFER_ENABLED=NO',flush=True)
                return
            if attempt % 6 == 0:
                print('LAB_INSTALL_RUNNING: '+str(attempt*5)+'s',flush=True)
            time.sleep(5)
        raise RuntimeError('LAB_INSTALL_STILL_RUNNING: '+remote+'/install.log')
    finally:
        subprocess.run(['ssh','-O','exit',*connection],capture_output=True)


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=22)
    parser.add_argument('--install',type=Path)
    args=parser.parse_args()
    if args.install:
        stage=args.install.resolve()
        require(stage.parent==ROOT and stage.name.startswith('nvl-lab-import-'), 'LAB_STAGE_PATH_INVALID')
        # Never enter even failure cleanup on a wrong/nonfresh machine.
        try:
            preflight_lab()
        except BaseException as error:
            (stage/'result.json').write_text(json.dumps(
                {'status':'LAB_PREFLIGHT_FAILED','error':str(error)})+'\n')
            raise
        try:
            result=install_lab(stage)
        except BaseException as error:
            subprocess.run(['systemctl','stop','nvlbot'],capture_output=True)
            result={'status':'LAB_INSTALL_FAILED','error':str(error)}
            (stage/'result.json').write_text(json.dumps(result)+'\n')
            raise
        (stage/'result.json').write_text(json.dumps(result)+'\n')
    else:
        require(1 <= args.port <= 65535, 'INVALID_LAB_SSH_PORT')
        copy_from_core(args.port)


if __name__=='__main__':
    main()
