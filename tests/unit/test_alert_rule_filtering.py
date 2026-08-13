# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests for blocking on invalid alert rules from prometheus_scrape and loki_push_api."""

import json

from ops.testing import Relation, State
from scenario import BlockedStatus


def _metrics_endpoint_relation(*, event_data: dict) -> Relation:
    """Build a metrics-endpoint Relation with the given app-level event data."""
    return Relation(
        endpoint="metrics-endpoint",
        local_app_data={"event": json.dumps(event_data)},
    )


def _receive_loki_logs_relation(*, event_data: dict) -> Relation:
    """Build a receive-loki-logs Relation with the given app-level event data."""
    return Relation(
        endpoint="receive-loki-logs",
        local_app_data={"event": json.dumps(event_data)},
    )


# --- Prometheus alert rule tests ---


def test_valid_alert_rules_active(ctx):
    """Scenario: valid alert rules over metrics-endpoint → ActiveStatus."""
    # GIVEN a metrics-endpoint relation with no errors in app data
    relation = _metrics_endpoint_relation(event_data={})
    state = State(leader=True, relations=[relation])

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm is not blocked
    assert not isinstance(state_out.unit_status, BlockedStatus)


def test_invalid_alert_rules_blocked(ctx):
    """Scenario: invalid alert rules over metrics-endpoint → BlockedStatus."""
    # GIVEN a metrics-endpoint relation with alert rule validation errors in app data
    error_msg = "error validating rule: parse error: unexpected token"
    relation = _metrics_endpoint_relation(event_data={"errors": error_msg})
    state = State(leader=True, relations=[relation])

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm enters BlockedStatus
    assert isinstance(state_out.unit_status, BlockedStatus)
    # AND the status message points to the debug-log
    assert state_out.unit_status.message == "Invalid Prometheus alerts. See debug-log"


def test_non_leader_ignores_invalid_alert_rules(ctx):
    """Scenario: non-leader units do not block on invalid alert rules."""
    # GIVEN a metrics-endpoint relation with errors, but this unit is NOT the leader
    error_msg = "error validating rule: parse error: unexpected token"
    relation = _metrics_endpoint_relation(event_data={"errors": error_msg})
    state = State(leader=False, relations=[relation])

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm is not blocked (non-leaders skip alert rule error detection)
    assert not isinstance(state_out.unit_status, BlockedStatus)


def test_alert_rule_errors_cleared_after_fix(ctx):
    """Scenario: after errors are cleared from relation data, charm recovers to ActiveStatus."""
    # GIVEN a metrics-endpoint relation with no errors (errors were previously present and fixed)
    relation = _metrics_endpoint_relation(event_data={})
    state = State(leader=True, relations=[relation])

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm is not blocked
    assert not isinstance(state_out.unit_status, BlockedStatus)


def test_multiple_relations_one_invalid_blocks(ctx):
    """Scenario: one invalid relation among multiple blocks the charm."""
    # GIVEN one valid and one invalid metrics-endpoint relation
    valid_relation = _metrics_endpoint_relation(event_data={})
    invalid_relation = _metrics_endpoint_relation(
        event_data={"errors": "parse error: invalid PromQL expression"}
    )
    state = State(leader=True, relations=[valid_relation, invalid_relation])

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm enters BlockedStatus
    assert isinstance(state_out.unit_status, BlockedStatus)
    assert state_out.unit_status.message == "Invalid Prometheus alerts. See debug-log"


# --- Loki alert rule tests ---


def test_valid_loki_alert_rules_active(ctx):
    """Scenario: valid alert rules over receive-loki-logs → ActiveStatus."""
    # GIVEN a receive-loki-logs relation with no errors in app data
    relation = _receive_loki_logs_relation(event_data={})
    state = State(leader=True, relations=[relation])

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm is not blocked
    assert not isinstance(state_out.unit_status, BlockedStatus)


def test_invalid_loki_alert_rules_blocked(ctx):
    """Scenario: invalid alert rules over receive-loki-logs → BlockedStatus."""
    # GIVEN a receive-loki-logs relation with alert rule validation errors in app data
    error_msg = "error validating rule: parse error: unexpected token"
    relation = _receive_loki_logs_relation(event_data={"errors": error_msg})
    state = State(leader=True, relations=[relation])

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm enters BlockedStatus
    assert isinstance(state_out.unit_status, BlockedStatus)
    # AND the status message points to the debug-log
    assert state_out.unit_status.message == "Invalid Loki alerts. See debug-log"


def test_non_leader_ignores_invalid_loki_alert_rules(ctx):
    """Scenario: non-leader units do not block on invalid Loki alert rules."""
    # GIVEN a receive-loki-logs relation with errors, but this unit is NOT the leader
    error_msg = "error validating rule: parse error: unexpected token"
    relation = _receive_loki_logs_relation(event_data={"errors": error_msg})
    state = State(leader=False, relations=[relation])

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm is not blocked (non-leaders skip alert rule error detection)
    assert not isinstance(state_out.unit_status, BlockedStatus)


def test_loki_alert_rule_errors_cleared_after_fix(ctx):
    """Scenario: after errors are cleared from relation data, charm recovers to ActiveStatus."""
    # GIVEN a receive-loki-logs relation with no errors (errors were previously present and fixed)
    relation = _receive_loki_logs_relation(event_data={})
    state = State(leader=True, relations=[relation])

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm is not blocked
    assert not isinstance(state_out.unit_status, BlockedStatus)


def test_multiple_loki_relations_one_invalid_blocks(ctx):
    """Scenario: one invalid relation among multiple receive-loki-logs relations blocks the charm."""
    # GIVEN one valid and one invalid receive-loki-logs relation
    valid_relation = _receive_loki_logs_relation(event_data={})
    invalid_relation = _receive_loki_logs_relation(
        event_data={"errors": "parse error: invalid LogQL expression"}
    )
    state = State(leader=True, relations=[valid_relation, invalid_relation])

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm enters BlockedStatus
    assert isinstance(state_out.unit_status, BlockedStatus)
    assert state_out.unit_status.message == "Invalid Loki alerts. See debug-log"
