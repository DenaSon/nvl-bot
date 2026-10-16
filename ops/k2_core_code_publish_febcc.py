"""One-shot df52 to febcc code upgrade; profiles remain OFF, network unchanged."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

SHA = 'febcc45c505e5bdc6a712745651dd8f87c2e1f91'
PACKAGE_SHA = '3af297eab2f087128cd7bc8b32d456dab91d0a5a61df534eb77ec3606722154d'
OLD_BOT_SHA = 'f8c9c5be5271a1c9e7492a655b813488ce3d2ea0a81f730fcb3c47659bb923a5'
OLD_RELEASE_SHA = '72152f907b05ecc21f2010249498095ce16b36c2a82d1f81cd9dd87230ff90fa'
EXPECTED_CHANGED = frozenset(('bot_final_v49-2.py', 'edge_egress_k2_core_observer.py',
    'edge_egress_k2_m4_telegram.py', 'edge_egress_v1_onboarding.py'))
STAGE = Path('/root/nvl-k2-febcc45c505e')
ROOT = Path('/root')
CONFIG = Path('/etc/nvl-egress/k2-m4')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unit(action):
    subprocess.run(['systemctl', action, 'nvlbot'], check=True)


def prop(name):
    return subprocess.check_output(
        ['systemctl', 'show', 'nvlbot', '-p', name, '--value'], text=True).strip()


def off():
    for name in ('core-runtime.json', 'field-acceptance.json'):
        p = CONFIG / name
        require(not p.exists() and not p.is_symlink(), 'RUNTIME_PROFILE_CHANGED')


def db_check():
    with sqlite3.connect((ROOT/'master_bot.db').as_uri()+'?mode=ro', uri=True, timeout=5) as db:
        require(db.execute('PRAGMA quick_check').fetchall() == [('ok',)], 'DB_CHECK_FAILED')
        count = db.execute("SELECT COUNT(*) FROM failover_operations WHERE status IN ('RUNNING','RECOVERY')").fetchone()[0]
        require(count == 0, 'RUNNING_OR_RECOVERY_OPERATION')


def identity():
    require(prop('ActiveState') == 'active', 'BOT_NOT_ACTIVE')
    pid = int(prop('MainPID'))
    require(pid > 0, 'BOT_PID_MISSING')
    proc = Path('/proc') / str(pid)
    require((proc/'cwd').resolve() == ROOT, 'BOT_WORKING_DIRECTORY_CHANGED')
    argv = (proc/'cmdline').read_bytes().split(b'\0')
    require(os.fsencode(str(ROOT/'bot_final_v49-2.py')) in argv, 'BOT_ENTRY_CHANGED')
    require(os.path.realpath(os.fsdecode(argv[0])) == os.path.realpath(sys.executable), 'BOT_INTERPRETER_CHANGED')
    env = dict(x.split(b'=', 1) for x in (proc/'environ').read_bytes().split(b'\0') if b'=' in x)
    path = Path(os.fsdecode(env.get(b'BOT_DB_PATH', os.fsencode(str(ROOT/'master_bot.db')))))
    require((ROOT/path).resolve() == ROOT/'master_bot.db', 'BOT_DB_PATH_CHANGED')


def snapshot(path):
    if not path.exists() and not path.is_symlink():
        return None
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1, 'UNSAFE_TARGET: '+str(path))
    data = path.read_bytes()
    after = path.lstat()
    require((st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns) ==
            (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'TARGET_CHANGED_DURING_READ')
    return {'sha256': digest(data), 'mode': stat.S_IMODE(st.st_mode),
            'uid': st.st_uid, 'gid': st.st_gid}, data


def parents(path, create=False):
    missing = []
    cur = path.parent
    while not cur.exists() and not cur.is_symlink():
        missing.append(cur)
        cur = cur.parent
    while True:
        st = cur.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022, 'UNSAFE_PARENT: '+str(cur))
        if cur == Path('/'):
            break
        cur = cur.parent
    if create:
        for p in reversed(missing):
            p.mkdir(mode=0o700)


def replace(path, data, mode, uid=0, gid=0):
    parents(path, create=True)
    fd, name = tempfile.mkstemp(prefix='.nvl-code-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
            f.flush()
            os.fchown(f.fileno(), uid, gid)
            os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def stable():
    pid = prop('MainPID')
    require(pid.isdigit() and int(pid) > 0, 'NEW_BOT_PID_MISSING')
    for _ in range(10):
        time.sleep(2)
        require(prop('ActiveState') == 'active' and prop('MainPID') == pid, 'BOT_UNSTABLE')
    return pid


def restore(plan, automatic=False):
    off()
    if not automatic:
        db_check()
    payloads = []
    for item in plan['files']:
        path = Path(item['path'])
        current = snapshot(path)
        allowed = {item['sha256']}
        if item['old']:
            allowed.add(item['old']['sha256'])
            data = Path(item['backup']).read_bytes()
            require(digest(data) == item['old']['sha256'], 'CODE_BACKUP_CHANGED')
        else:
            data = None
        require(current is None or current[0]['sha256'] in allowed, 'ROLLBACK_TARGET_CHANGED: '+str(path))
        payloads.append((item, data))
    unit('stop')
    for item, data in reversed(payloads):
        path = Path(item['path'])
        if item['old'] is None:
            if path.exists():
                require(digest(path.read_bytes()) == item['sha256'], 'NEW_FILE_CHANGED')
                path.unlink()
        else:
            old = item['old']
            replace(path, data, old['mode'], old['uid'], old['gid'])
    unit('start')
    pid = stable()
    db_check()
    print('CODE_ROLLBACK_OK PID='+pid, flush=True)


def deploy():
    source = STAGE/'source'
    plan_file = STAGE/'deployment-plan.json'
    require(not plan_file.exists(), 'PUBLISH_ALREADY_STARTED: use saved plan; do not rerun')
    require((STAGE/'STAGING_OK').read_text().strip() == SHA, 'STAGING_NOT_ACCEPTED')
    subprocess.run([sys.executable, '-B', '-m', 'ops.k2_release_bundle', 'verify',
                    '--directory', str(source), '--commit', SHA, '--package-sha256', PACKAGE_SHA], cwd=source, check=True)
    off()
    prior = snapshot(CONFIG/'release.json')
    require(prior is not None and prior[0]['sha256'] == OLD_RELEASE_SHA, 'INSTALLED_RELEASE_CHANGED')
    old_release = json.loads(prior[1])
    for name, expected in old_release['files'].items():
        current = snapshot(ROOT/name)
        require(current is not None and current[0]['sha256'] == expected, 'INSTALLED_SOURCE_CHANGED: '+name)
    identity()
    db_check()
    require(digest((ROOT/'bot_final_v49-2.py').read_bytes()) == OLD_BOT_SHA, 'LIVE_BOT_CHANGED')
    package = json.loads((source/'package.json').read_bytes())
    release = json.loads((source/'release.json').read_bytes())
    names = set(release['files'])
    require(names == set(old_release['files']), 'CRITICAL_SOURCE_SET_CHANGED')
    require({n for n in names if release['files'][n] != old_release['files'][n]} ==
            EXPECTED_CHANGED, 'UNREVIEWED_CODE_DELTA')
    payloads = {str(ROOT/n): (source/n).read_bytes() for n in sorted(names)}
    payloads[str(CONFIG/'release.json')] = (source/'release.json').read_bytes()
    for name in names:
        require(digest(payloads[str(ROOT/name)]) == package['files'][name], 'SOURCE_CHANGED')
        if name.endswith('.py'):
            compile(payloads[str(ROOT/name)], name, 'exec')
    backup = Path(tempfile.mkdtemp(prefix='nvl-k2-predeploy-febcc-', dir=ROOT))
    items = []
    for pathstr, data in payloads.items():
        path = Path(pathstr)
        parents(path)
        old = snapshot(path)
        if old and old[0]['sha256'] == digest(data) and not old[0]['mode'] & 0o022:
            continue
        saved = backup/str(len(items))
        if old:
            saved.write_bytes(old[1])
        items.append({'path': pathstr, 'sha256': digest(data),
                      'mode': 0o700 if path.suffix == '.sh' else 0o600,
                      'old': old[0] if old else None, 'backup': str(saved)})
    plan = {'git_sha': SHA, 'backup_dir': str(backup), 'files': items}
    plan_file.write_text(json.dumps(plan, sort_keys=True, indent=2)+'\n')
    (backup/'deployment-plan.json').write_bytes(plan_file.read_bytes())
    print('CODE_BACKUP='+str(backup), flush=True)
    print('REPLACE='+str(sum(i['old'] is not None for i in items))+' ADD='+str(sum(i['old'] is None for i in items)), flush=True)
    stopped = False
    try:
        off()
        db_check()
        stopped = True
        unit('stop')
        require(prop('MainPID') == '0', 'BOT_NOT_STOPPED')
        db_check()
        for name in ('master_bot.db', 'accounting.db'):
            path = ROOT/name
            if path.is_file():
                src = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, timeout=5)
                dst = sqlite3.connect(backup/(name+'.sqlite3'))
                try:
                    src.backup(dst)
                    require(dst.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'DATABASE_BACKUP_FAILED')
                finally:
                    dst.close()
                    src.close()
        off()
        for item in items:
            now = snapshot(Path(item['path']))
            require((now[0] if now else None) == item['old'], 'LIVE_FILE_CHANGED')
        for item in items:
            replace(Path(item['path']), payloads[item['path']], item['mode'])
        for pathstr, data in payloads.items():
            current = snapshot(Path(pathstr))
            require(current is not None and current[0]['sha256'] == digest(data) and not current[0]['mode'] & 0o022, 'PUBLISHED_HASH_OR_MODE_FAILED')
        off()
        unit('start')
        pid = stable()
        db_check()
        (STAGE/'DEPLOYED').write_text(SHA+'\n')
        print('K2_DEPLOY_SUCCESS='+SHA, flush=True)
        print('MAIN_PID='+pid, flush=True)
        print('CODE_BACKUP='+str(backup), flush=True)
        print('RUNTIME_PROFILE=OFF', flush=True)
    except BaseException:
        if stopped:
            try:
                restore(plan, automatic=True)
            except BaseException as err:
                print('ROLLBACK_REQUIRES_INSPECTION='+type(err).__name__+': '+str(err), flush=True)
        raise


if __name__ == '__main__':
    os.umask(0o077)
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    if sys.argv[1:] == ['rollback']:
        restore(json.loads((STAGE/'deployment-plan.json').read_bytes()))
    elif not sys.argv[1:]:
        deploy()
    else:
        raise SystemExit('Unsupported action')
