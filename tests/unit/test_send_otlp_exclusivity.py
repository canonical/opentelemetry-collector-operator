# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: send-otlp must be mutually exclusive with other telemetry relations per remote app."""

import logging

import pytest
from ops.testing import Relation, State
from scenario import BlockedStatus

MUTUALLY_EXCLUSIVE_MESSAGE = "Mutually exclusive integrations found; see debug-log"


@pytest.mark.parametrize(
    "other_relation_name",
    ["send-remote-write", "send-loki-logs", "send-traces", "send-charm-traces"],
)
def test_send_otlp_and_other_telemetry_to_same_app_blocks(ctx, other_relation_name, caplog):
    # GIVEN the same remote app is related via send-otlp and another telemetry relation
    otlp_relation = Relation(
        "send-otlp", remote_app_name="mimir", remote_app_data={"endpoints": "[]"}
    )
    other_relation = Relation(other_relation_name, remote_app_name="mimir")
    state = State(
        leader=True,
        relations=[otlp_relation, other_relation],
    )
    # WHEN the charm reconciles
    with caplog.at_level(logging.WARNING):
        state_out = ctx.run(ctx.on.update_status(), state)
    # THEN the charm enters BlockedStatus
    assert isinstance(state_out.unit_status, BlockedStatus)
    assert state_out.unit_status.message == MUTUALLY_EXCLUSIVE_MESSAGE
    # AND the debug-log mentions the duplicated app
    assert "mimir" in caplog.text


def test_send_otlp_and_other_telemetry_to_different_apps_does_not_block(ctx, caplog):
    # GIVEN different remote apps related via send-otlp and send-remote-write
    otlp_relation = Relation(
        "send-otlp", remote_app_name="mimir", remote_app_data={"endpoints": "[]"}
    )
    other_relation = Relation("send-remote-write", remote_app_name="prometheus")
    state = State(
        leader=True,
        relations=[otlp_relation, other_relation],
    )
    # WHEN the charm reconciles
    with caplog.at_level(logging.WARNING):
        state_out = ctx.run(ctx.on.update_status(), state)
    # THEN the charm does not enter BlockedStatus due to the send-otlp exclusivity check
    assert not isinstance(state_out.unit_status, BlockedStatus)
    assert state_out.unit_status.message != MUTUALLY_EXCLUSIVE_MESSAGE
    # AND the debug-log does not mention the remote apps
    assert "mimir" not in caplog.text
    assert "prometheus" not in caplog.text
