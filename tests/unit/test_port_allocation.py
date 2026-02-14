# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Port allocation for OpenTelemetry Collector."""

import logging

import pytest

from config_builder import Port
from utils import allocate_ports, find_available_port


@pytest.mark.parametrize(
    "occupied_ports,expected_ports",
    [
        # All default ports are free
        (
            [],
            {
                Port.loki_http: 3500,
                Port.otlp_grpc: 4317,
                Port.otlp_http: 4318,
                Port.metrics: 8888,
                Port.health: 13133,
                Port.jaeger_grpc: 14250,
                Port.jaeger_thrift_http: 14268,
                Port.zipkin: 9411,
            },
        ),
        # One port is occupied
        (
            [4317],
            {
                Port.loki_http: 3500,
                Port.otlp_grpc: 50000,
                Port.otlp_http: 4318,
                Port.metrics: 8888,
                Port.health: 13133,
                Port.jaeger_grpc: 14250,
                Port.jaeger_thrift_http: 14268,
                Port.zipkin: 9411,
            },
        ),
        # Multiple ports occupied
        (
            [4317, 4318, 14268],
            {
                Port.loki_http: 3500,
                Port.otlp_grpc: 50000,
                Port.otlp_http: 50001,
                Port.metrics: 8888,
                Port.health: 13133,
                Port.jaeger_grpc: 14250,
                Port.jaeger_thrift_http: 50002,
                Port.zipkin: 9411,
            },
        ),
    ],
)
def test_allocate_ports(occupied_ports, expected_ports, monkeypatch, mock_socket_with_occupied_ports):
    """Scenario: Port allocation function finds available ports correctly."""
    # GIVEN some ports are occupied
    mock_socket_class = mock_socket_with_occupied_ports(occupied_ports)
    monkeypatch.setattr("utils.socket.socket", mock_socket_class)

    # WHEN we allocate ports passing the Port enum class
    allocated_ports = allocate_ports(Port)

    # THEN it returns the correct port mapping
    assert allocated_ports == expected_ports


def test_find_available_port_without_exclude_ports(monkeypatch, mock_socket_with_occupied_ports):
    """Scenario: find_available_port works when exclude_ports is None (line 44)."""
    # GIVEN some ports are occupied, and we don't pass exclude_ports
    occupied_ports = [50000, 50001]
    mock_socket_class = mock_socket_with_occupied_ports(occupied_ports)
    monkeypatch.setattr("utils.socket.socket", mock_socket_class)

    # WHEN we call find_available_port without exclude_ports parameter
    port = find_available_port(start_port=50000)

    # THEN it should find the first available port (50002)
    assert port == 50002


def test_find_available_port_no_ports_available(monkeypatch):
    """Scenario: find_available_port raises RuntimeError when no ports are available (line 52)."""
    # GIVEN all ports are occupied (mock always returns OSError)
    class AlwaysOccupiedSocket:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def bind(self, address):
            raise OSError("Port is occupied")

    monkeypatch.setattr("utils.socket.socket", AlwaysOccupiedSocket)

    # WHEN we try to find an available port starting from a high port number
    # THEN it should raise RuntimeError
    with pytest.raises(RuntimeError, match="no available port found in range"):
        find_available_port(start_port=50000)


@pytest.mark.parametrize(
    "start_port,expected_error_msg",
    [
        (-1, "Invalid start_port: -1"),
        (-100, "Invalid start_port: -100"),
        (70000, "Invalid start_port: 70000"),
        (99999, "Invalid start_port: 99999"),
    ],
)
def test_find_available_port_invalid_range(start_port, expected_error_msg):
    """Scenario: Invalid start_port values raise ValueError with clear message."""
    # GIVEN an invalid port number (negative or > 65535)
    # WHEN we try to find an available port
    # THEN it should raise ValueError with descriptive message
    with pytest.raises(ValueError, match=expected_error_msg):
        find_available_port(start_port=start_port)


def test_find_available_port_privileged_port_warning(monkeypatch, mock_socket_with_occupied_ports, caplog):
    """Scenario: Starting from privileged port (<1024) logs a warning."""
    # GIVEN we start from a privileged port
    occupied_ports = []
    mock_socket_class = mock_socket_with_occupied_ports(occupied_ports)
    monkeypatch.setattr("utils.socket.socket", mock_socket_class)

    # WHEN we call find_available_port with a privileged port
    with caplog.at_level(logging.WARNING):
        port = find_available_port(start_port=80)

    # THEN it should log a warning about privileged ports
    assert "privileged port 80" in caplog.text.lower()
    assert "root" in caplog.text.lower() or "administrator" in caplog.text.lower()
    # AND it should still find an available port
    assert port == 80


@pytest.mark.parametrize(
    "start_port",
    [65535],
)
def test_find_available_port_edge_cases(start_port, monkeypatch, mock_socket_with_occupied_ports):
    """Scenario: Edge case port 65535 is valid and handled correctly."""
    # GIVEN an edge case port (65535) and no occupied ports
    occupied_ports = []
    mock_socket_class = mock_socket_with_occupied_ports(occupied_ports)
    monkeypatch.setattr("utils.socket.socket", mock_socket_class)

    # WHEN we try to find an available port
    port = find_available_port(start_port=start_port)

    # THEN it should return the requested port within the valid range
    assert port == start_port
    assert 0 <= port <= 65535
