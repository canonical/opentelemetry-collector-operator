# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Node exporter port configuration."""

import pytest

from constants import NODE_EXPORTER_DEFAULT_PORT
from utils import find_available_port


@pytest.mark.parametrize(
    "occupied_ports,expected_port",
    [
        ([], NODE_EXPORTER_DEFAULT_PORT),  # Default port is free, use 9100
        ([NODE_EXPORTER_DEFAULT_PORT], NODE_EXPORTER_DEFAULT_PORT + 1),  # Port 9100 occupied, use 9101
        ([NODE_EXPORTER_DEFAULT_PORT, NODE_EXPORTER_DEFAULT_PORT + 1], NODE_EXPORTER_DEFAULT_PORT + 2),  # Multiple occupied
    ],
)
def test_node_exporter_port_selection(occupied_ports, expected_port, monkeypatch, mock_socket_with_occupied_ports):
    """Scenario: Port selection function finds available port correctly."""
    # GIVEN some ports are occupied
    mock_socket_class = mock_socket_with_occupied_ports(occupied_ports)
    monkeypatch.setattr("utils.socket.socket", mock_socket_class)

    # WHEN we search for an available port
    port = find_available_port(start_port=NODE_EXPORTER_DEFAULT_PORT)

    # THEN it returns the first available port
    assert port == expected_port
