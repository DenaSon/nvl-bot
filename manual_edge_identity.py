"""Provider-neutral pinned Edge identity; never forges Cloudzy ownership.

CZ04B/CZ07 retain their historical provider_id journal column; for manual
Edges this contains an explicit *internal* manual:<operation-id> reference,
NOT a Cloudzy provider server ID or purchase receipt.
"""
from __future__ import annotations


class EdgeIdentityHold(RuntimeError):
    pass


def resolve(db, host, *, require_standby=False, require_default=False):
    row=db.execute(
        "SELECT provider,provider_instance_id,active,is_default,is_standby,"
        "service_port,admin_ssh_port FROM host_pool WHERE host=?",(host,),
    ).fetchone()
    if not row:
        raise EdgeIdentityHold("EDGE_NOT_REGISTERED")
    provider,pid,active,default,standby,service_port,admin_port=row
    if not active or (require_standby and (not standby or default)) or (
            require_default and (not default or standby)):
        raise EdgeIdentityHold("EDGE_ROLE_NOT_READY")
    if provider=="cloudzy":
        if not pid:
            raise EdgeIdentityHold("CLOUDZY_ID_MISSING")
        receipts=db.execute(
            "SELECT host_key_type,host_key_base64 FROM cloudzy_edge_operations "
            "WHERE status='EDGE_READY' AND public_ipv4=? AND provider_server_id=?",
            (host,pid),
        ).fetchall()
        if len(receipts)!=1 or not all(receipts[0]):
            raise EdgeIdentityHold("CLOUDZY_RECEIPT_NOT_VERIFIED")
        ref=str(pid); pinned=tuple(receipts[0])
    elif provider=="manual":
        if pid is not None:
            raise EdgeIdentityHold("MANUAL_HAS_FORGED_PROVIDER_ID")
        records=db.execute(
            "SELECT id,pin_type,pin_base64 FROM manual_edge_operations "
            "WHERE ip=? AND status IN ('STANDBY','ROUTING','MIGRATING','ACTIVE')",
            (host,),
        ).fetchall()
        if len(records)!=1 or not all(records[0]):
            raise EdgeIdentityHold("MANUAL_RECEIPT_NOT_VERIFIED")
        op,key_type,key_base64=records[0]
        ref="manual:"+str(op)
        pinned=(key_type,key_base64)
    else:
        raise EdgeIdentityHold("EDGE_PROVIDER_UNSUPPORTED")
    if not (1<=int(service_port or 0)<=65535 and
            1<=int(admin_port or 0)<=65535):
        raise EdgeIdentityHold("EDGE_PORT_INVALID")
    return {
        "host":host,"provider":provider,"identity_ref":ref,
        "pinned_key":pinned,"customer_port":int(service_port),
        "admin_port":int(admin_port),
    }


def assert_ref(db,host,ref,*,require_standby=False,require_default=False):
    obj=resolve(db,host,require_standby=require_standby,
                require_default=require_default)
    if obj["identity_ref"]!=ref:
        raise EdgeIdentityHold("EDGE_IDENTITY_CHANGED")
    return obj


def assert_role_ref(db,host,ref,*,require_standby=False,require_default=False):
    """Backwards-compatible CZ07 role fence for legacy Cloudzy receipts.

    CZ07's historical recovery journal stores provider identity and role, but
    some old database schemas did not yet have the 6A service/admin port pair.
    Read only those columns for a Cloudzy role fence; the CZ04B admission/
    active network verification separately requires the full pinned receipt.
    Manual edges always need complete independent proof.
    """
    if ref.startswith("manual:"):
        return assert_ref(db,host,ref,require_standby=require_standby,
                          require_default=require_default)
    row=db.execute(
        "SELECT provider,provider_instance_id,active,is_default,is_standby "
        "FROM host_pool WHERE host=?",(host,),
    ).fetchone()
    if (not row or tuple(row[:2])!=("cloudzy",ref)
            or row[2]!=1
            or (require_standby and tuple(row[3:])!=(0,1))
            or (require_default and tuple(row[3:])!=(1,0))):
        raise EdgeIdentityHold("CLOUDZY_ROLE_CHANGED")
    return {"host":host,"provider":"cloudzy","identity_ref":ref}
