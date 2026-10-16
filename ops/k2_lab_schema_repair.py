"""One-shot lab metadata repair for the already-UP e2 transport, operation 1.

No host transport action or lock deletion. Complete the same original 6G row
only after fresh pinned transport/IP proof; atomic DDL + F3 STAGED + final CAS.
The installed application remains 0e06 and customer execution remains OFF.
"""
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile

ROOT = Path('/root')
CONFIG = Path('/etc/nvl-egress/k2-m4')
LAB_IP, EDGE_IP = '144.172.84.127', '144.172.84.112'
APP = '0e06cf767872996cf3c1e93749a93a9646337960'
RELEASE_SHA = '7376742013018b25171ed848464fe1947dc67527c91025d11efe161e512cfa14'
TABLES = frozenset(('edge_egress_allocations', 'edge_egress_readiness',
                   'edge_egress_uid_bindings', 'edge_egress_uid_runtime'))


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def profiles_off():
    require(all(not (CONFIG/name).exists() and not (CONFIG/name).is_symlink()
                for name in ('core-runtime.json', 'field-acceptance.json')),
            'CUSTOMER_PROFILE_CHANGED')


def checked(path):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0
            and st.st_nlink == 1 and not st.st_mode & 0o077, 'UNTRUSTED_SOURCE_FILE')
    return path.read_bytes()


def preflight():
    require(os.geteuid() == 0, 'ROOT_REQUIRED')
    result = subprocess.run(['ip', '-j', '-4', 'addr', 'show'],
                            capture_output=True, text=True, timeout=8, check=True)
    addresses = {a.get('local') for row in json.loads(result.stdout)
                 for a in row.get('addr_info', [])}
    require(LAB_IP in addresses, 'WRONG_LAB_HOST')
    profiles_off()
    raw = checked(CONFIG/'release.json')
    require(hashlib.sha256(raw).hexdigest() == RELEASE_SHA, 'INSTALLED_RELEASE_CHANGED')
    release = json.loads(raw)
    require(release['git_sha'] == APP, 'INSTALLED_APP_CHANGED')
    for name, digest in release['files'].items():
        path = Path(name)
        require(not path.is_absolute() and '..' not in path.parts, 'INVALID_SOURCE_PATH')
        require(hashlib.sha256(checked(ROOT/path)).hexdigest() == digest,
                'INSTALLED_SOURCE_CHANGED: '+name)


def canonical_schemas():
    from edge_egress_inventory import SCHEMA
    from edge_egress_f3_readiness import READINESS_SCHEMA
    from edge_egress_protected_mapping import MAPPING_SCHEMA
    from edge_egress_uid_runtime_store import RUNTIME_SCHEMA
    return (SCHEMA, READINESS_SCHEMA, MAPPING_SCHEMA, RUNTIME_SCHEMA)


def execute_schema(db, script):
    # executescript would implicitly COMMIT and break the original 6G fence.
    pending = ''
    for line in script.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            db.execute(pending)
            pending = ''
    require(not pending.strip(), 'INCOMPLETE_CANONICAL_SCHEMA')


def reconcile(db_conn, pin, *, prove, recheck):
    from edge_egress_k2_p1_worker import RECOVERY, _check_source
    from edge_egress_f3_readiness import _shared_lock, stage_in_existing_6g_transaction
    from edge_egress_inventory import reserve_allocation, mark_stage_only
    require(pin.edge_id == 'e2' and pin.core_ipv4 == LAB_IP and pin.edge_ipv4 == EDGE_IP,
            'WRONG_REPAIR_TARGET')
    spec, peer, observed = prove(pin)
    require(observed == EDGE_IP and peer == pin.edge_wg_pub and pin.core_wg_pub
            and spec.edge_id == pin.edge_id and spec.core_public_ipv4 == LAB_IP
            and spec.edge_public_ipv4 == EDGE_IP, 'FRESH_TRANSPORT_PROOF_REQUIRED')
    with db_conn() as db:
        db.execute('BEGIN IMMEDIATE')
        _shared_lock(db, 1, LAB_IP, EDGE_IP)
        for key, value in (('brand', 'NVL-LAB'), ('core_wg_public_ip', LAB_IP)):
            require(db.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchall()
                    == [(value,)], 'LAB_DATABASE_IDENTITY_CHANGED')
        raw = db.execute('SELECT detail_json FROM failover_operations WHERE id=1').fetchone()[0]
        intent = json.loads(raw)
        require(isinstance(intent, dict) and intent.get('kind') == 'K2_P1'
                and intent.get('phase') == RECOVERY and intent.get('edge_id') == 'e2'
                and intent.get('core_sha') == pin.core_sha and intent.get('edge_sha') == pin.edge_sha
                and type(intent.get('customers_moved')) is int and intent['customers_moved'] == 0
                and intent.get('manual_recovery') is True
                and intent.get('source_mode') == 'INITIAL_CORE'
                and intent.get('source_pool') == [[LAB_IP, 1, 0]], 'EXACT_RECOVERY_INTENT_REQUIRED')
        _check_source(db, LAB_IP, pin, intent, 'INITIAL_CORE_BASELINE_CHANGED')
        names = {r[0] for r in db.execute('SELECT name FROM sqlite_master')}
        require(not TABLES & names, 'REPAIR_REQUIRES_ORIGINAL_MISSING_SCHEMAS')
        profiles_off()
        for schema in canonical_schemas():
            execute_schema(db, schema)
        reservation = reserve_allocation(db, spec, core_public_key=pin.core_wg_pub,
                                         edge_public_key=peer)
        require(reservation.created and reservation.status == 'RESERVED', 'ALLOCATION_NOT_NEW')
        mark_stage_only(db, 'e2')
        stage_in_existing_6g_transaction(db, 1, source=LAB_IP, edge_id='e2', target=EDGE_IP)
        # Stage/pin/ingress drift rolls back DDL, F3 and the journal together.
        recheck(pin, spec, peer)
        profiles_off()
        _shared_lock(db, 1, LAB_IP, EDGE_IP)
        detail = {key: value for key, value in intent.items() if key != 'manual_recovery'}
        detail.update(phase='EGRESS_P1_TRANSPORT_PROVEN', observed_ipv4=observed,
                      f3_stage='STAGED', customer_ready=False, recovered_from=RECOVERY)
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        changed = db.execute("UPDATE failover_operations SET status='SUCCEEDED',detail_json=?,"
            "updated_at=?,finished_at=? WHERE id=1 AND status='RUNNING' AND source_host=? "
            "AND target_host=? AND detail_json=?",
            (json.dumps(detail), now, now, LAB_IP, EDGE_IP, raw)).rowcount
        require(changed == 1, 'ORIGINAL_6G_CAS_LOST')
    return {'operation_id': 1, 'status': 'SUCCEEDED', 'edge_id': 'e2',
            'allocation': 'STAGED', 'readiness': 'STAGED',
            'observed_ipv4': observed, 'customers_moved': 0, 'customer_ready': False}


def main():
    os.umask(0o077)
    preflight()
    sys.path.insert(0, str(ROOT))
    from edge_egress_k2_p1_worker import load_stage_pin, _check_stage, _remote_transport, _prove_ipv4
    from ops.edge_egress_v1_transport import observe
    pin = load_stage_pin('e2')

    @contextmanager
    def connection():
        db = sqlite3.connect('file:'+str(ROOT/'master_bot.db')+'?mode=rw', uri=True, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    backup = Path(tempfile.mkdtemp(prefix='nvl-lab-schema-backup-', dir=ROOT))
    with sqlite3.connect('file:'+str(ROOT/'master_bot.db')+'?mode=ro', uri=True, timeout=5) as source:
        with sqlite3.connect(backup/'master_bot.sqlite3') as target:
            source.backup(target)
            require(target.execute('PRAGMA integrity_check').fetchall() == [('ok',)],
                    'DATABASE_BACKUP_FAILED')
    print('DATABASE_BACKUP='+str(backup), flush=True)

    def recheck(current, spec, peer):
        require(load_stage_pin('e2') == current, 'STAGE_PIN_CHANGED')
        actual, actual_peer, _ = _check_stage(current)
        require((actual, actual_peer) == (spec, peer), 'STAGE_OR_INGRESS_CHANGED')

    def prove(current):
        spec, peer, _ = _check_stage(current)
        require(observe(spec, 'core', peer) == 'UP'
                and _remote_transport(current, 'inspect') == 'UP', 'TRANSPORT_NOT_UP')
        observed = _prove_ipv4(spec)
        recheck(current, spec, peer)
        return spec, peer, observed

    print(json.dumps(reconcile(connection, pin, prove=prove, recheck=recheck)), flush=True)
    print('CUSTOMER_RUNTIME=OFF', flush=True)


if __name__ == '__main__':
    main()
