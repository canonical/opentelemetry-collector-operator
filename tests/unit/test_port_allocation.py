# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Port allocation for OpenTelemetry Collector."""

import json
import logging
from unittest.mock import mock_open, patch

import pytest
from filelock import Timeout

from config_builder import Port
from utils import (
    allocate_ports,
    find_available_port,
    get_or_allocate_ports,
    load_port_map,
    save_port_map,
)


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
                Port.otlp_grpc: 50000,  # Should get first available from DEFAULT_PORT_SEARCH_START
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
        (0, "Invalid start_port: 0"),
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


def test_save_and_load_port_map(tmp_path, monkeypatch):
    """Scenario: Port map can be saved and loaded from disk."""
    # GIVEN a temporary port map file
    test_port_map_file = tmp_path / "port_map.json"
    monkeypatch.setattr("utils.PORT_MAP_FILE", str(test_port_map_file))

    # AND a port map to save
    otelcol_port_map = {
        Port.otlp_grpc: 4317,
        Port.otlp_http: 4318,
        Port.loki_http: 3500,
    }
    node_exporter_port = 9100

    # WHEN we save the port map
    save_port_map(otelcol_port_map, node_exporter_port)

    # THEN the file should exist
    assert test_port_map_file.exists()

    # AND we can load it back
    loaded_map = load_port_map()
    assert loaded_map is not None
    assert loaded_map["node_exporter"] == 9100
    assert loaded_map["otlp_grpc"] == 4317
    assert loaded_map["otlp_http"] == 4318
    assert loaded_map["loki_http"] == 3500


@pytest.mark.parametrize(
    "scenario,setup_file",
    [
        ("no_file", lambda tmp_path: None),  # Don't create file
        ("permission_error", lambda tmp_path: _create_unreadable_file(tmp_path)),
        ("corrupted_json", lambda tmp_path: _create_corrupted_json_file(tmp_path)),
    ],
)
def test_load_port_map_error_cases(tmp_path, monkeypatch, scenario, setup_file):
    """Scenario: load_port_map returns None when encountering various error conditions."""
    # GIVEN a problematic port map file situation
    test_port_map_file = tmp_path / "port_map.json"
    monkeypatch.setattr("utils.PORT_MAP_FILE", str(test_port_map_file))

    if setup_file:
        setup_file(test_port_map_file)

    # WHEN we try to load the port map
    loaded_map = load_port_map()

    # THEN it should return None
    assert loaded_map is None

    # Cleanup: restore permissions if needed
    if scenario == "permission_error" and test_port_map_file.exists():
        test_port_map_file.chmod(0o644)


def _create_unreadable_file(file_path):
    """Helper: Create a file without read permissions."""
    file_path.write_text('{"node_exporter": 9100}')
    file_path.chmod(0o000)


def _create_corrupted_json_file(file_path):
    """Helper: Create a file with invalid JSON."""
    file_path.write_text('{"node_exporter": 9100, invalid json')


@pytest.mark.parametrize(
    "persisted_ports,expected_node_exporter,expected_otlp_grpc,expected_otlp_http,should_persist",
    [
        # No persisted map - allocate new ports
        (None, 9100, 4317, 4318, True),
        # Persisted map with alternative ports - reuse them
        (
            {
                Port.otlp_grpc: 50000,
                Port.otlp_http: 50001,
                Port.loki_http: 3500,
                Port.metrics: 8888,
                Port.health: 13133,
                Port.jaeger_grpc: 14250,
                Port.jaeger_thrift_http: 14268,
                Port.zipkin: 9411,
            },
            50010,
            50000,
            50001,
            False,
        ),
    ],
)
def test_get_or_allocate_ports_scenarios(
    tmp_path,
    monkeypatch,
    mock_socket_with_occupied_ports,
    persisted_ports,
    expected_node_exporter,
    expected_otlp_grpc,
    expected_otlp_http,
    should_persist,
):
    """Scenario: get_or_allocate_ports handles both new allocation and persisted reuse."""
    # GIVEN a test port map file
    test_port_map_file = tmp_path / "port_map.json"
    monkeypatch.setattr("utils.PORT_MAP_FILE", str(test_port_map_file))

    # AND optionally a persisted port map
    if persisted_ports:
        save_port_map(persisted_ports, expected_node_exporter)
    else:
        # Mock available ports for allocation
        mock_socket_class = mock_socket_with_occupied_ports([])
        monkeypatch.setattr("utils.socket.socket", mock_socket_class)

    # WHEN we call get_or_allocate_ports
    otelcol_port_map, node_exporter_port = get_or_allocate_ports(Port, 9100)

    # THEN it should use the expected ports
    assert node_exporter_port == expected_node_exporter
    assert otelcol_port_map[Port.otlp_grpc] == expected_otlp_grpc
    assert otelcol_port_map[Port.otlp_http] == expected_otlp_http

    # AND the port map should be persisted
    if should_persist:
        assert test_port_map_file.exists()
        loaded_map = load_port_map()
        assert loaded_map is not None
        assert loaded_map["node_exporter"] == expected_node_exporter
        assert loaded_map["otlp_grpc"] == expected_otlp_grpc


def test_get_or_allocate_ports_with_occupied_default(tmp_path, monkeypatch, caplog, mock_socket_with_occupied_ports):
    """Scenario: get_or_allocate_ports allocates alternative when default port is occupied."""
    # GIVEN no persisted ports and node_exporter default port (9100) is occupied
    test_port_map_file = tmp_path / "port_map.json"
    monkeypatch.setattr("utils.PORT_MAP_FILE", str(test_port_map_file))

    # Mock socket to make port 9100 occupied
    mock_socket_class = mock_socket_with_occupied_ports([9100])
    monkeypatch.setattr("utils.socket.socket", mock_socket_class)

    # WHEN we call get_or_allocate_ports with caplog to capture warnings
    with caplog.at_level(logging.WARNING):
        otelcol_port_map, node_exporter_port = get_or_allocate_ports(Port, 9100)

    # THEN node_exporter should get an alternative port (50000)
    assert node_exporter_port == 50000

    # AND we should see warning log about alternative port assignment
    assert "assigned alternative port 50000" in caplog.text
    assert "default 9100 unavailable" in caplog.text


def test_reconstruct_otelcol_map_with_missing_ports(tmp_path, monkeypatch, caplog):
    """Scenario: reconstruct_otelcol_map uses defaults when ports are missing in persisted data."""
    # GIVEN a persisted port map with only some ports (missing zipkin and jaeger_thrift_http)
    test_port_map_file = tmp_path / "port_map.json"
    monkeypatch.setattr("utils.PORT_MAP_FILE", str(test_port_map_file))

    # Create a partial port map (missing some ports)
    partial_persisted_data = {
        "node_exporter": 9100,
        "otlp_grpc": 50000,
        "otlp_http": 50001,
        "loki_http": 3500,
        "metrics": 8888,
        "health": 13133,
        "jaeger_grpc": 14250,
        # Missing: zipkin and jaeger_thrift_http
    }

    test_port_map_file.parent.mkdir(parents=True, exist_ok=True)
    test_port_map_file.write_text(json.dumps(partial_persisted_data))

    # WHEN we call get_or_allocate_ports with caplog to capture warnings
    with caplog.at_level(logging.WARNING):
        otelcol_port_map, node_exporter_port = get_or_allocate_ports(Port, 9100)

    # THEN it should use persisted ports for available ones
    assert otelcol_port_map[Port.otlp_grpc] == 50000
    assert otelcol_port_map[Port.otlp_http] == 50001

    # AND it should use default values for missing ports
    assert otelcol_port_map[Port.zipkin] == Port.zipkin.value
    assert otelcol_port_map[Port.jaeger_thrift_http] == Port.jaeger_thrift_http.value

    # AND it should log warnings for missing ports
    assert "Port zipkin not found, using default" in caplog.text
    assert "Port jaeger_thrift_http not found, using default" in caplog.text


def test_save_port_map_permission_error(tmp_path, monkeypatch, caplog):
    """Scenario: save_port_map handles PermissionError gracefully."""
    # GIVEN a test environment
    test_port_map_file = tmp_path / "port_map.json"
    monkeypatch.setattr("utils.PORT_MAP_FILE", str(test_port_map_file))

    otelcol_ports = {Port.otlp_grpc: 4317, Port.otlp_http: 4318}
    node_exporter_port = 9100

    # WHEN save fails due to permission error
    with patch("builtins.open", mock_open()) as mock_file:
        mock_file.side_effect = PermissionError("Permission denied")
        with caplog.at_level(logging.WARNING):
            save_port_map(otelcol_ports, node_exporter_port)

    # THEN it should log appropriate warnings
    assert "failed to save port map" in caplog.text
    assert "Permission denied" in caplog.text
    assert "Ports will be re-allocated" in caplog.text


def test_save_port_map_timeout(tmp_path, monkeypatch, caplog):
    """Scenario: save_port_map handles FileLock timeout gracefully."""
    # GIVEN a test environment
    test_port_map_file = tmp_path / "port_map.json"
    monkeypatch.setattr("utils.PORT_MAP_FILE", str(test_port_map_file))

    # WHEN save fails due to lock timeout
    with patch("utils.FileLock") as mock_filelock:
        mock_filelock.return_value.__enter__.side_effect = Timeout("lock_file")
        with caplog.at_level(logging.WARNING):
            save_port_map({Port.otlp_grpc: 4317}, 9100)

    # THEN it should log appropriate warnings
    assert "timeout acquiring lock" in caplog.text
    assert "Another process may be saving ports" in caplog.text
    assert "Ports will be re-allocated" in caplog.text


def test_load_port_map_timeout(tmp_path, monkeypatch, caplog):
    """Scenario: load_port_map handles FileLock timeout gracefully."""
    # GIVEN a test environment with a valid port map file
    test_port_map_file = _setup_load_timeout_test(tmp_path)
    monkeypatch.setattr("utils.PORT_MAP_FILE", str(test_port_map_file))

    # WHEN load fails due to lock timeout
    with patch("utils.FileLock") as mock_filelock:
        mock_filelock.return_value.__enter__.side_effect = Timeout("lock_file")
        with caplog.at_level(logging.WARNING):
            result = load_port_map()

    # THEN it should return None
    assert result is None

    # AND it should log appropriate warnings
    assert "timeout acquiring lock" in caplog.text
    assert "Another process may be allocating ports" in caplog.text


def _setup_load_timeout_test(tmp_path):
    """Helper: Setup for load_port_map timeout test."""
    test_file = tmp_path / "port_map.json"
    test_file.write_text('{"node_exporter": 9100, "otlp_grpc": 4317}')
    return test_file
