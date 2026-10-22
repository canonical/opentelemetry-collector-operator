import logging

from ops.testing import Relation, State, SubordinateRelation
from scenario import BlockedStatus

MUTUALLY_EXCLUSIVE_MESSAGE = "Mutually exclusive integrations found; see debug-log"


def test_same_app_related_via_juju_info_and_cos_agent_blocks(ctx, caplog):
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
    with caplog.at_level(logging.WARNING):
        state_out = ctx.run(ctx.on.update_status(), state)
    # THEN the charm enters BlockedStatus
    assert isinstance(state_out.unit_status, BlockedStatus)
    assert state_out.unit_status.message == MUTUALLY_EXCLUSIVE_MESSAGE
    # AND the debug-log mentions the duplicated app
    assert "ubuntu" in caplog.text


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
    with caplog.at_level(logging.WARNING):
        state_out = ctx.run(ctx.on.update_status(), state)
    # THEN the charm does not enter BlockedStatus due to duplicated relations
    assert not isinstance(state_out.unit_status, BlockedStatus)
    # AND the debug-log does not mention a duplicated app
    assert state_out.unit_status.message != MUTUALLY_EXCLUSIVE_MESSAGE
    assert "ubuntu" not in caplog.text
    assert "zookeeper" not in caplog.text
