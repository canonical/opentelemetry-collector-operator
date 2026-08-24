# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: node-exporter package-type config option."""

from ops.testing import State


def test_default_package_type_is_apt(ctx):
    """The option defaults to apt and the charm does not block over it."""
    # GIVEN no explicit package-type config
    # WHEN any hook runs the reconciler
    state_out = ctx.run(ctx.on.update_status(), State())
    # THEN the unit is not blocked over package-type
    assert "package-type" not in getattr(state_out.unit_status, "message", "")


def test_invalid_package_type_blocks(ctx):
    # GIVEN an invalid package-type value
    state = State(config={"package-type": "flatpak"})
    # WHEN the reconciler runs
    state_out = ctx.run(ctx.on.config_changed(), state)
    # THEN the unit is blocked with an actionable message
    assert state_out.unit_status.name == "blocked"
    assert state_out.unit_status.message == "Invalid package-type config: must be 'snap' or 'apt'"


def test_valid_package_type_values_do_not_block(ctx):
    for value in ("snap", "apt"):
        # GIVEN a valid package-type value
        state = State(config={"package-type": value})
        # WHEN the reconciler runs
        state_out = ctx.run(ctx.on.config_changed(), state)
        # THEN the unit is not blocked over package-type
        assert "package-type" not in getattr(state_out.unit_status, "message", "")


def test_node_exporter_port_override_blocks_in_apt_mode(ctx):
    # GIVEN apt mode (default) with a node_exporter port override
    state = State(config={"ports": "node_exporter=9200"})
    # WHEN the reconciler runs
    state_out = ctx.run(ctx.on.config_changed(), state)
    # THEN the unit is blocked: the charm does not configure the stock deb
    assert state_out.unit_status.name == "blocked"
    assert state_out.unit_status.message == "node_exporter port override requires package-type=snap"


def test_node_exporter_port_override_allowed_in_snap_mode(ctx):
    # GIVEN snap mode with a node_exporter port override
    state = State(config={"package-type": "snap", "ports": "node_exporter=9200"})
    # WHEN the reconciler runs
    state_out = ctx.run(ctx.on.config_changed(), state)
    # THEN the unit is not blocked over the port override
    assert "port override" not in getattr(state_out.unit_status, "message", "")
