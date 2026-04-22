# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: User memory limit config is safely written to config."""

from unittest.mock import patch
from ops.testing import State
from scenario import ActiveStatus, BlockedStatus
from helpers import get_otelcol_config_file
import dataclasses

@patch("config_manager._total_memory_mib", return_value=1024)
def test_default_config_hard_limit_is_100_percent(mock_mem, ctx, unit_name, config_folder):
    # GIVEN a user provides no value for the memory_limit_percentage config option
    state = State(leader=True)

    # WHEN any event executes the reconciler
    ctx.run(ctx.on.update_status(), state=state)

    cfg = get_otelcol_config_file(unit_name, config_folder)
    processor = cfg.get("processors", {}).get("memory_limiter", {})

    # THEN the default hard limit is 100% of total memory
    # * the spike limit is 20% of the hard limit
    assert processor["limit_mib"] == 1024
    assert processor["spike_limit_mib"] == 1024 * 20 // 100


@patch("config_manager._total_memory_mib", return_value=1024)
def test_incorrect_config_defaults_hard_limit_is_100_percent(
    mock_mem, ctx, unit_name, config_folder
):
    # GIVEN a user provides an invalid value for the memory_limit_percentage config option
    state = State(leader=True, config={"memory_limit_percentage": "invalid"})

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)
    cfg = get_otelcol_config_file(unit_name, config_folder)
    processor = cfg.get("processors", {}).get("memory_limiter", {})

    # THEN the default hard limit (100%) is used and no error is raised
    # * the spike limit is 20% of the hard limit
    assert processor["limit_mib"] == 1024
    assert processor["spike_limit_mib"] == 1024 * 20 // 100

    # AND the charm is in BlockedStatus due to invalid config value
    assert isinstance(state_out.unit_status, BlockedStatus)


def test_memorylimiterprocessor_is_first_in_pipeline(ctx, unit_name, config_folder):
    # GIVEN no config options are set
    state = State(leader=True)

    # WHEN any event executes the reconciler
    ctx.run(ctx.on.update_status(), state=state)
    cfg = get_otelcol_config_file(unit_name, config_folder)
    pipelines = cfg.get("service", {}).get("pipelines", {})
    assert pipelines, "No pipelines found in config"
    for pipeline in pipelines.values():
        processors = pipeline.get("processors", [])
        assert processors, "No processors found in pipeline"

        # THEN memory_limiter is the first processor in all pipelines to ensure that backpressure
        # can be sent to applicable receivers and minimize the likelihood of dropped data when the
        # memory_limiter gets triggered"
        assert processors[0] == "memory_limiter"


def test_blocked_status_on_invalid_memory_limit(ctx):
    # GIVEN no config options are set
    state = State(leader=True, config={"memory_limit_percentage": "-10"})

    # WHEN an value is set below 0 for the memory_limit_percentage config option
    # * any event executes the reconciler
    state_new = dataclasses.replace(state, config={"memory_limit_percentage": "-10"})
    state_out = ctx.run(ctx.on.update_status(), state=state_new)

    # THEN the charm enters BlockedStatus due to invalid config value
    assert isinstance(state_out.unit_status, BlockedStatus)

    # WHEN an value is set above 100 for the memory_limit_percentage config option
    # * any event executes the reconciler
    state_new = dataclasses.replace(state, config={"memory_limit_percentage": "110"})
    state_out = ctx.run(ctx.on.update_status(), state=state_new)

    # THEN the charm enters BlockedStatus due to invalid config value
    assert isinstance(state_out.unit_status, BlockedStatus)
