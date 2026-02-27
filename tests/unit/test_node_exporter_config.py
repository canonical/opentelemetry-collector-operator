# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Node exporter port configuration."""

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
