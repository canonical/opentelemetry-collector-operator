# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Node exporter configuration."""

from unittest.mock import patch

import pytest
from ops.testing import State

from charm import OpenTelemetryCollectorCharm
from config_builder import Port, build_port_map


def test_node_exporter_default_port():
    """Node exporter has a well-known default port in the Port enum."""
    # GIVEN no port overrides
    # WHEN building the default port map
    port_map = build_port_map("")
    # THEN the node_exporter port is the well-known default
    assert port_map[Port.node_exporter.name] == 9100


def test_node_exporter_port_override():
    """Node exporter port can be overridden like any other port."""
    # GIVEN an override for the node_exporter port
    overrides = "node_exporter=9200"
    # WHEN building the port map
    port_map = build_port_map(overrides)
    # THEN the node_exporter port reflects the override
    assert port_map[Port.node_exporter.name] == 9200
    # AND all other ports keep their defaults
    for port in Port:
        if port.name != "node_exporter":
            assert port_map[port.name] == port.value


@pytest.mark.parametrize(
    "config,enabled",
    [
        ({}, set()),
        ({"enable_logind_collector": True}, {"logind"}),
        ({"enable_systemd_collector": True}, {"systemd"}),
        (
            {"enable_logind_collector": True, "enable_systemd_collector": True},
            {"logind", "systemd"},
        ),
    ],
)
def test_high_cardinality_collectors_are_opt_in(ctx, config, enabled):
    with patch.object(OpenTelemetryCollectorCharm, "_set_snap_configs_with_retry") as set_config:
        ctx.run(ctx.on.update_status(), State(config=config))

    node_exporter = [
        call.args[1] for call in set_config.call_args_list if "collectors" in call.args[1]
    ]
    assert len(node_exporter) == 1
    configured = node_exporter[0]
    high_cardinality_collectors = {"logind", "systemd"}
    assert set(configured["collectors"].split()) & high_cardinality_collectors == enabled
    assert set(configured["no-collectors"].split()) == high_cardinality_collectors - enabled
    assert not (set(configured["collectors"].split()) & set(configured["no-collectors"].split()))
