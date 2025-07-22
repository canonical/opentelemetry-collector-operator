from ops.testing import Relation, State
from scenario import ActiveStatus, BlockedStatus


def test_missing_relation_pair_status(ctx):
    source_relation = Relation("cos-agent")
    # GIVEN the charm has no relations
    state = State(
        leader=True,
        relations=[source_relation],  # source_relation must exist in state for relation_joined
    )
    # WHEN a source is related to opentelemetry-collector
    state_out = ctx.run(ctx.on.relation_joined(source_relation), state)
    # THEN the charm enters BlockedStatus
    assert isinstance(state_out.unit_status, BlockedStatus)
    # AND the status message warns of the missing sink relations
    assert "] for cos-agent" in state_out.unit_status.message


def test_valid_relation_pair_status(ctx):
    source_relation = Relation("cos-agent")
    sink_relation = Relation("send-remote-write")
    # GIVEN the charm has a source and no sink relation
    state = State(
        leader=True,
        relations=[
            source_relation,
            sink_relation,
        ],  # sink_relation must exist in state for relation_joined
    )
    # WHEN a sink is related to opentelemetry-collector
    state_out = ctx.run(ctx.on.relation_joined(sink_relation), state)
    # THEN the charm enters ActiveStatus
    assert isinstance(state_out.unit_status, ActiveStatus)
