"""Authorization policy for reducing time-based account subscriptions."""


def can_reduce_renewal(
    role,
    actor_agent_id,
    owner_agent_id,
    service_type,
    *,
    connection_mode=None,
    volumetric=False,
):
    role = str(role or "").strip().lower()
    service_type = str(service_type or "").strip().lower()
    connection_mode = str(connection_mode or "").strip().lower()

    if role not in {"admin", "super_admin", "agent"}:
        return False
    if service_type not in {"ssh", "v2ray"} or volumetric:
        return False
    if connection_mode == "tls":
        return False
    if role in {"admin", "super_admin"}:
        return True

    try:
        actor = int(actor_agent_id or 0)
        owner = int(owner_agent_id or 0)
    except (TypeError, ValueError):
        return False
    return actor > 0 and actor == owner
