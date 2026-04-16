# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: User memory limit config is safely written to config."""

from ops.testing import State

from helpers import get_otelcol_config_file


def test_incorrect_config_defaults(ctx, unit_name, config_folder):
    # GIVEN a user provides an invalid value for the soft_memory_limit_percentage config option
    state = State(leader=True, config={"soft_memory_limit_percentage": "invalid"})

    # WHEN any event executes the reconciler
    ctx.run(ctx.on.update_status(), state=state)

    cfg = get_otelcol_config_file(unit_name, config_folder)
    processor = cfg.get("processors", {}).get("memory_limiter", {})

    # THEN the default value is used in the config and no error is raised
    assert processor.get("spike_limit_percentage") == 15
    assert processor.get("limit_percentage") == 65
