"""Bot-requested reconciliation of settled cohort projections.

Never clears/replays a RUNNING original 6G operation or changes a UID's host
state. Only a fully settled original journal plus matching guards can retire
an interrupted/stopped projection and permit a new explicit selection.
"""
from __future__ import annotations

import json

from edge_egress_uid_runtime_store import read_binding
from edge_egress_k2_core_operations import CoreOperationalBindings


class CoreRecoveryHold(ValueError):
    pass


def reconcile_settled_cohorts(root,selection,*,actor_id,chat_id):
    if type(root) is not CoreOperationalBindings or not root.admin(actor_id,chat_id):
        raise CoreRecoveryHold('RECOVERY_CURRENT_ROOT_ADMIN_REQUIRED')
    from edge_egress_v1_admission import load_roster,checked_guard
    from edge_egress_uid_boot import BootGuardApplier
    expected_names=list(selection.usernames)
    with root.ports.db_conn() as db:
        db.execute('BEGIN IMMEDIATE')
        if db.execute("SELECT 1 FROM failover_operations WHERE status='RUNNING'").fetchone():
            raise CoreRecoveryHold('RECOVERY_ORIGINAL_6G_STILL_RUNNING')
        roster=load_roster()
        rows=db.execute("SELECT approval_hash,usernames_json,progress_json FROM k2_m4_wave_checkpoints "
            "WHERE edge_id=? AND actor_id=? AND chat_id=? AND state IN ('HOLD','RUNNING')",
            (selection.target_edge_id,actor_id,chat_id)).fetchall()
        changed=0
        for key,names_raw,progress_raw in rows:
            names=json.loads(names_raw)
            if names!=expected_names:
                continue
            progress=json.loads(progress_raw)
            if type(progress) is not list or len(progress)>len(names):
                raise CoreRecoveryHold('RECOVERY_PROGRESS_UNTRUSTED')
            for name in names:
                uid=root.ports.os_uid(name)
                row=read_binding(db,name)
                mapped=db.execute('SELECT uid,edge_id,edge_ipv4,status FROM edge_egress_uid_bindings WHERE username=?',
                                  (name,)).fetchone()
                if row is None:
                    if mapped is not None or name in roster:
                        raise CoreRecoveryHold('RECOVERY_PARTIAL_UID_REQUIRES_REPAIR')
                    continue
                if (row.uid!=uid or row.state!='PROTECTED'
                    or mapped!=(uid,row.edge_id,row.edge_ipv4,'PROTECTED')):
                    raise CoreRecoveryHold('RECOVERY_UID_NOT_SETTLED')
                member=roster.get(name)
                if member is None or member.uid!=uid:
                    raise CoreRecoveryHold('RECOVERY_GUARD_IDENTITY_CHANGED')
                man=checked_guard(member)
                if (man.request.spec.edge_id!=row.edge_id
                    or man.request.spec.edge_public_ipv4!=row.edge_ipv4):
                    raise CoreRecoveryHold('RECOVERY_GUARD_TARGET_DRIFT')
                BootGuardApplier().verify(man)
                op=db.execute('SELECT status,detail_json FROM failover_operations WHERE id=?',
                              (row.last_operation_id,)).fetchone()
                detail=json.loads(op[1]) if op else {}
                if (not op or op[0]!='SUCCEEDED' or detail.get('phase')!='EGRESS_P3_VERIFIED'
                    or detail.get('username')!=name or detail.get('uid')!=uid
                    or detail.get('edge_id')!=row.edge_id):
                    raise CoreRecoveryHold('RECOVERY_ORIGINAL_RECEIPT_NOT_VERIFIED')
            for item in progress:
                if (not isinstance(item,list) or len(item)!=3 or item[0] not in names
                    or item[1] not in ('VERIFIED','HOLD','DEFERRED')):
                    raise CoreRecoveryHold('RECOVERY_PROGRESS_CORRUPT')
                if item[1]=='VERIFIED':
                    op=db.execute('SELECT status,detail_json FROM failover_operations WHERE id=?',
                                  (item[2],)).fetchone()
                    detail=json.loads(op[1]) if op else {}
                    if (not op or op[0]!='SUCCEEDED' or detail.get('username')!=item[0]
                        or detail.get('phase')!='EGRESS_P3_VERIFIED'
                        or detail.get('edge_id')!=selection.target_edge_id):
                        raise CoreRecoveryHold('RECOVERY_RECORDED_RECEIPT_CHANGED')
            # EXPIRED is rendered as reconciled/closed, never SUCCEEDED.
            # Original progress and original 6G receipts remain immutable.
            changed+=db.execute("UPDATE k2_m4_wave_checkpoints SET state='PREPARED',expires_at=?,"
                "reason='RECONCILED_SETTLED_NO_REPLAY',updated_at=? WHERE approval_hash=? "
                "AND state IN ('HOLD','RUNNING')",
                (root.ports.now()-1,root.ports.now(),key)).rowcount
        return {'state':'RECONCILED','closed':changed,'replayed':False}
