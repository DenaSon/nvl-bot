"""Owner-run fresh Core preparation: interactive destination, password and TEST token.

Export committed code and installed packages only. Reuse the canonical fresh-Lab
installer; never export Production databases, credentials, persistence or peers.
"""
from __future__ import annotations
import argparse
import base64
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sys
import sysconfig
import tempfile
import time
from ops import k2_lab_core_copy as lab
from ops.k2_release_bundle import build

REPO = Path('/root/nvl-release')


def destination_ipv4(value, local):
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        raise RuntimeError('INVALID_LAB_IPV4') from None
    lab.require(address.version == 4 and address.is_global and not address.is_multicast,
                'PUBLIC_LAB_IPV4_REQUIRED')
    lab.require(str(address) not in set(local) | {'209.200.246.198'},
                'PRODUCTION_OR_LOCAL_DESTINATION_FORBIDDEN')
    return str(address)


def tty_line(prompt):
    # A bash heredoc consumes stdin; interactive input must use the terminal.
    with open('/dev/tty', 'r+') as tty:
        tty.write(prompt)
        tty.flush()
        value = tty.readline()
    lab.require(bool(value), 'CLI_INPUT_REQUIRED')
    return value.strip()


def export_environment(pid):
    raw = (Path('/proc')/str(pid)/'environ').read_bytes()
    env = dict(x.split(b'=', 1) for x in raw.split(b'\0') if b'=' in x)
    lab.require(b'BOT_TOKEN' in env, 'SOURCE_BOT_TOKEN_UNAVAILABLE')
    return env[b'BOT_TOKEN'].decode()


def source_identity():
    lab.require(os.geteuid() == 0, 'RUN_AS_ROOT_ON_ORIGINAL_CORE')
    pid = lab.read(['systemctl', 'show', 'nvlbot', '-p', 'MainPID', '--value'])
    lab.require(pid.isdecimal() and int(pid) > 0, 'PRODUCTION_BOT_NOT_RUNNING')
    lab.run(['systemctl', 'is-active', '--quiet', 'nvlbot'])
    lab.require(sys.version_info[:2] == (3, 12)
                and Path(sys.prefix).resolve() == Path('/root/venv'),
                'RUN_WITH_ROOT_VENV_PYTHON312')
    local = lab.local_ipv4s()
    lab.require('209.200.246.198' in local, 'RUN_ON_ORIGINAL_CORE')
    return pid, local


def ssh_client(ip, port, username, password, known_hosts):
    import paramiko

    class RecordNewHost(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            fingerprint = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
            print('LAB_SSH_HOST_KEY=SHA256:'+fingerprint, flush=True)
            client.get_host_keys().add(hostname, key.get_name(), key)
            client.save_host_keys(str(known_hosts))
            known_hosts.chmod(0o600)

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    lab.require(not known_hosts.is_symlink(), 'LAB_KNOWN_HOSTS_NOT_PRIVATE')
    if known_hosts.exists():
        lab.require(known_hosts.is_file() and known_hosts.stat().st_uid == 0
                    and known_hosts.stat().st_mode & 0o077 == 0, 'LAB_KNOWN_HOSTS_NOT_PRIVATE')
        client.load_host_keys(str(known_hosts))
    client.set_missing_host_key_policy(RecordNewHost())
    try:
        client.connect(ip, port=port, username=username, password=password,
                       look_for_keys=False, allow_agent=False,
                       timeout=20, auth_timeout=20, banner_timeout=20)
    except paramiko.BadHostKeyException:
        client.close()
        raise RuntimeError('LAB_SSH_HOST_KEY_CHANGED: verify the replacement VPS key') from None
    except paramiko.AuthenticationException:
        client.close()
        raise RuntimeError('LAB_SSH_AUTHENTICATION_FAILED') from None
    except BaseException:
        client.close()
        raise
    client.get_transport().set_keepalive(15)
    return client


def remote(client, command, timeout=30):
    _, stdout, stderr = client.exec_command(command, timeout=timeout)
    data = stdout.read()
    stderr.read()
    code = stdout.channel.recv_exit_status()
    if code:
        raise RuntimeError('LAB_REMOTE_COMMAND_FAILED exit='+str(code))
    return data


def payload(stage, commit, ip, token, bot, source_hash, package_hash):
    password = secrets.token_urlsafe(24)
    lab.write_new(stage/'lab.env',
        'BOT_TOKEN='+token+'\nMASTER_USER=labadmin\nMASTER_PASS='+password+
        '\nRB_CONFIRM_PASS='+secrets.token_urlsafe(24)+
        '\nBOT_DB_PATH=/root/master_bot.db\nBOT_PERSISTENCE_PATH=/root/bot_persistence.pickle\n'
        'PYTHONDONTWRITEBYTECODE=1\n')
    lab.write_new(stage/'setup.py', Path(lab.__file__).read_bytes())
    lab.run(['nice', '-n', '15', 'tar', '-C', '/root/venv/lib/python3.12',
             '--exclude=__pycache__', '--exclude=*.pyc',
             '-czf', str(stage/'packages.tar.gz'), 'site-packages'])
    names = ('source.tar', 'packages.tar.gz', 'lab.env', 'setup.py')
    metadata = {'app':commit, 'destination':ip, 'test_bot_id':bot['id'],
        'python':list(sys.version_info[:3]), 'soabi':sysconfig.get_config_var('SOABI'),
        'files':{name:lab.digest(stage/name) for name in names},
        'configuration':{'app':commit, 'destination':ip,
                         'source_sha256':source_hash, 'package_sha256':package_hash}}
    lab.write_new(stage/'metadata.json', json.dumps(metadata))
    return password, metadata


def wait_for_install(connect, client, remote_stage, *, timeout=1800):
    deadline = time.monotonic() + timeout
    next_progress = 0
    command = ('if test -f '+shlex.quote(remote_stage+'/result.json')+
               '; then cat '+shlex.quote(remote_stage+'/result.json')+'; fi')
    while time.monotonic() < deadline:
        try:
            if client is None or not client.get_transport() or not client.get_transport().is_active():
                if client is not None:
                    client.close()
                client = connect()
            raw = remote(client, command)
        except (OSError, EOFError):
            if client is not None:
                client.close()
            client = None
            time.sleep(5)
            continue
        except Exception as error:
            import paramiko
            if not isinstance(error, paramiko.SSHException) or isinstance(
                    error, (paramiko.BadHostKeyException, paramiko.AuthenticationException)):
                raise
            if client is not None:
                client.close()
            client = None
            time.sleep(5)
            continue
        if raw:
            result = json.loads(raw)
            print(json.dumps(result, ensure_ascii=False), flush=True)
            lab.require(result.get('status') == 'LAB_CORE_INSTALLED',
                        'LAB_SETUP_STOPPED: '+remote_stage+'/install.log')
            return client, result
        now = time.monotonic()
        if now >= next_progress:
            print('LAB_INSTALL_RUNNING stage='+remote_stage, flush=True)
            next_progress = now + 30
        time.sleep(5)
    raise RuntimeError('LAB_INSTALL_STILL_RUNNING: '+remote_stage+'/install.log')


def prepare(commit, port):
    pid, local = source_identity()
    ip = destination_ipv4(tty_line('New test Core IPv4: '), local)
    ssh_password = getpass.getpass('New test Core root SSH password: ')
    lab.require(bool(ssh_password), 'SSH_PASSWORD_REQUIRED')
    token = getpass.getpass('TEST Telegram bot token (not production): ').strip()
    lab.check_test_token(token, export_environment(pid))
    bot = lab.bot_api(token, 'getMe')
    lab.require(not lab.bot_api(token, 'getWebhookInfo').get('url'), 'TEST_BOT_MUST_USE_POLLING')
    stage = Path(tempfile.mkdtemp(prefix='nvl-fresh-core-', dir='/root'))
    known_hosts = Path('/root/.ssh/nvl-lab-known_hosts')
    known_hosts.parent.mkdir(mode=0o700, exist_ok=True)
    client = None
    try:
        connect = lambda: ssh_client(ip, port, 'root', ssh_password, known_hosts)
        client = connect()
        lab.run(['git', '-C', str(REPO), 'fetch', '--quiet', 'origin', commit])
        lab.require(lab.read(['git', '-C', str(REPO), 'rev-parse', 'FETCH_HEAD']) == commit,
                    'COMMIT_MISMATCH')
        source_hash, package_hash = build(REPO, commit, stage/'source.tar')
        print('SOURCE_COMMIT='+commit, flush=True)
        print('BUNDLE_SHA256='+source_hash, flush=True)
        print('EXPORT=SOURCE_AND_INSTALLED_PACKAGES', flush=True)
        rescue_password, metadata = payload(stage, commit, ip, token, bot, source_hash, package_hash)
        token = ''
        remote_stage = '/root/nvl-lab-import-'+secrets.token_hex(6)
        remote(client, 'umask 077; mkdir -m 700 '+shlex.quote(remote_stage))
        with client.open_sftp() as sftp:
            for name in (*metadata['files'], 'metadata.json'):
                sftp.put(str(stage/name), remote_stage+'/'+name)
                sftp.chmod(remote_stage+'/'+name, 0o600)
        check = ("printf '%s  %s\\n' "+shlex.quote(metadata['files']['setup.py'])+
                 ' '+shlex.quote(remote_stage+'/setup.py')+' | sha256sum -c -')
        remote(client, check)
        print('LAB_STAGE='+remote_stage, flush=True)
        remote(client, 'nohup /usr/bin/python3 -B '+shlex.quote(remote_stage+'/setup.py')+
               ' --fresh-install '+shlex.quote(remote_stage)+
               ' > '+shlex.quote(remote_stage+'/install.log')+' 2>&1 < /dev/null &')
        client, result = wait_for_install(connect, client, remote_stage)
        # Independent TCP login followed by real sudo, not the existing root channel.
        with ssh_client(ip, 22, 'nvlrescue', rescue_password, known_hosts) as rescue:
            stdin, stdout, stderr = rescue.exec_command("sudo -S -p '' id -u", timeout=20)
            stdin.write(rescue_password+'\n')
            stdin.flush()
            stdin.channel.shutdown_write()
            lab.require(stdout.read(128).strip() == b'0'
                        and stdout.channel.recv_exit_status() == 0, 'LAB_RESCUE_SUDO_FAILED')
        rescue_password = ''
        access = stage/'lab-access.txt'
        with client.open_sftp() as sftp:
            sftp.get('/root/nvl-lab-access.txt', str(access))
        access.chmod(0o600)
        print('LAB_RESCUE_SSH_AND_SUDO=PASS', flush=True)
        print('LAB_ACCESS_FILE='+str(access), flush=True)
        print('TEST_BOT=@'+bot['username'], flush=True)
        print('NEXT=ADD_NEW_EDGE_IN_TEST_BOT_WIZARD', flush=True)
    finally:
        if client is not None:
            client.close()
        ssh_password = ''
        (stage/'lab.env').unlink(missing_ok=True)
        lab.require(lab.read(['systemctl', 'show', 'nvlbot', '-p', 'MainPID', '--value']) == pid,
                    'PRODUCTION_BOT_PID_CHANGED')
        lab.run(['systemctl', 'is-active', '--quiet', 'nvlbot'])
        print('PRODUCTION_SERVICE_UNCHANGED=YES', flush=True)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--port', type=int, default=22)
    args = parser.parse_args()
    lab.require(re.fullmatch('[a-f0-9]{40}', args.commit) is not None
                and 1 <= args.port <= 65535, 'EXACT_COMMIT_AND_VALID_PORT_REQUIRED')
    prepare(args.commit, args.port)


if __name__ == '__main__':
    main()
