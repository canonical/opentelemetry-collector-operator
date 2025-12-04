# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol enables log rotation on internal logs."""

import yaml
from helpers import get_otelcol_config_file, get_otelcol_file
from ops.testing import State

from constants import LOGROTATE_SRC_PATH


def test_logrotate_config_exists(tmp_path, ctx, unit_name, config_folder, logrotate_file):
    """Scenario: Otelcol deployed in isolation."""
    # GIVEN otelcol deployed in isolation
    ctx.run(ctx.on.update_status(), State())

    # WHEN `output_paths` is configured in the internal logging config
    cfg = get_otelcol_config_file(unit_name, config_folder)
    assert cfg.get("service", {}).get("telemetry", {}).get("logs", {}).get("output_paths")

    # THEN the logrotate.d file is created with the expected content
    with open(tmp_path / LOGROTATE_SRC_PATH, "r") as f:
        assert yaml.safe_load(f.read()) == get_otelcol_file(logrotate_file)
