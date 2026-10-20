from ops.testing import Relation, State, SubordinateRelation
from scenario import BlockedStatus


def test_same_app_related_via_juju_info_and_cos_agent_blocks(ctx):
    # GIVEN the same principal app is related via both juju-info and cos-agent
    juju_info_relation = SubordinateRelation(
        "juju-info", remote_app_name="ubuntu", remote_unit_id=0
    )
    cos_agent_relation = SubordinateRelation(
        "cos-agent", remote_app_name="ubuntu", remote_unit_id=0
    )
    sink_relation = Relation("send-remote-write")
    state = State(
        leader=True,
        relations=[juju_info_relation, cos_agent_relation, sink_relation],
    )
    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.update_status(), state)
    # THEN the charm enters BlockedStatus
    assert isinstance(state_out.unit_status, BlockedStatus)
    # AND the status message mentions the duplicated app
    assert "ubuntu" in state_out.unit_status.message


def test_different_apps_related_via_juju_info_and_cos_agent_does_not_block(ctx):
    # GIVEN different principal apps are related via juju-info and cos-agent
    juju_info_relation = SubordinateRelation(
        "juju-info", remote_app_name="ubuntu", remote_unit_id=0
    )
    cos_agent_relation = SubordinateRelation(
        "cos-agent", remote_app_name="zookeeper", remote_unit_id=0
    )
    sink_relation = Relation("send-remote-write")
    state = State(
        leader=True,
        relations=[juju_info_relation, cos_agent_relation, sink_relation],
    )
    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.update_status(), state)
    # THEN the charm does not enter BlockedStatus due to duplicated relations
    assert not (
        isinstance(state_out.unit_status, BlockedStatus)
        and "ubuntu" in state_out.unit_status.message
        and "zookeeper" in state_out.unit_status.message
    )
