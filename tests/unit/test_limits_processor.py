# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: User memory limit config is safely written to config."""

from unittest.mock import patch

from helpers import get_otelcol_config_file
from ops.testing import State


@patch("config_manager._total_memory_mib", return_value=1024)
def test_default_config_hard_limit_is_100(mock_mem, ctx, unit_name, config_folder):
    # GIVEN a user provides no value for the soft_memory_limit_percentage config option
    state = State(leader=True)

    # WHEN any event executes the reconciler
    ctx.run(ctx.on.update_status(), state=state)

    cfg = get_otelcol_config_file(unit_name, config_folder)
    processor = cfg.get("processors", {}).get("memory_limiter", {})

    # THEN the default value is used in the config
    assert processor.get("spike_limit_mib") is not None
    assert processor.get("limit_mib") is not None
    assert processor["limit_mib"] == 1024
    assert processor["spike_limit_mib"] == 153  # 15% of 1024


@patch("config_manager._total_memory_mib", return_value=1024)
def test_incorrect_config_defaults_hard_limit_is_100(mock_mem, ctx, unit_name, config_folder):
    # GIVEN a user provides an invalid value for the soft_memory_limit_percentage config option
    state = State(leader=True, config={"soft_memory_limit_percentage": "invalid"})

    # WHEN any event executes the reconciler
    ctx.run(ctx.on.update_status(), state=state)

    cfg = get_otelcol_config_file(unit_name, config_folder)
    processor = cfg.get("processors", {}).get("memory_limiter", {})

    # THEN the default value is used in the config and no error is raised
    assert processor.get("spike_limit_mib") is not None
    assert processor.get("limit_mib") is not None
    assert processor["limit_mib"] == 1024
    assert processor["spike_limit_mib"] == 153  # 15% of 1024
