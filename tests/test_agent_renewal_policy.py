from agent_renewal_policy import can_reduce_renewal


def test_admin_can_reduce_supported_non_volumetric_accounts():
    assert can_reduce_renewal("admin", 0, 42, "ssh")
    assert can_reduce_renewal("admin", 0, 42, "v2ray")


def test_agent_can_reduce_only_own_supported_accounts():
    assert can_reduce_renewal("agent", 42, 42, "ssh")
    assert can_reduce_renewal("agent", 42, 42, "v2ray")
    assert not can_reduce_renewal("agent", 42, 43, "ssh")
    assert not can_reduce_renewal("agent", 0, 42, "v2ray")


def test_reduction_rejects_unsupported_roles_and_service_types():
    assert not can_reduce_renewal("accountant", 42, 42, "ssh")
    assert not can_reduce_renewal("agent", 42, 42, "v2ray_vol")
    assert not can_reduce_renewal("agent", 42, 42, "v2ray", volumetric=True)
    assert not can_reduce_renewal("agent", 42, 42, "ssh", connection_mode="tls")
