# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utils module."""

import json
import logging
import socket
from pathlib import Path
from typing import Dict, Optional, Set, Tuple, Type

from filelock import FileLock, Timeout

from config_builder import Port
from constants import DEFAULT_PORT_SEARCH_START, PORT_MAP_FILE, PORT_MAP_LOCK_TIMEOUT

logger = logging.getLogger(__name__)


def is_port_available(port: int) -> bool:
    """Check if a port is available for binding.

    Args:
        port: The port number to check

    Returns:
        True if the port is available, False otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("", port))
            return True
    except OSError:
        return False


def load_port_map() -> Optional[Dict[str, int]]:
    """Load the persisted port map from disk.

    Returns:
        Dictionary mapping port names to port numbers, or None if no file exists
        or if loading fails. Uses both 'node_exporter' key and Port enum member names.
    """
    if not Path(PORT_MAP_FILE).exists():
        logger.debug(f"port map file does not exist: {PORT_MAP_FILE}")
        return None

    lock_file = f"{PORT_MAP_FILE}.lock"
    try:
        with FileLock(lock_file, timeout=PORT_MAP_LOCK_TIMEOUT), open(PORT_MAP_FILE, "r") as f:
            port_map = json.load(f)
            logger.info(f"loaded port map from {PORT_MAP_FILE}: {port_map}")
            return port_map
    except Timeout:
        logger.warning(f"timeout acquiring lock for {PORT_MAP_FILE}. "
                      f"Another process may be allocating ports.")
        return None
    except (OSError, PermissionError) as e:
        logger.warning(f"failed to load port map from {PORT_MAP_FILE}: {e}")
        return None
    except json.JSONDecodeError as e:
        logger.warning(f"port map file is corrupted at {PORT_MAP_FILE}: {e}. "
                      f"Will allocate new ports.")
        return None


def save_port_map(otelcol_port_map: Dict[Port, int], node_exporter_port: int) -> None:
    """Save the port map to disk for persistence across reconciliations.

    Args:
        otelcol_port_map: Dictionary mapping Port enum members to port numbers
        node_exporter_port: Port number for node-exporter

    The saved format uses string keys for JSON compatibility:
    {
        "node_exporter": 9100,
        "otlp_grpc": 4317,
        "otlp_http": 4318,
        ...
    }
    """
    # Ensure parent directory exists
    Path(PORT_MAP_FILE).parent.mkdir(parents=True, exist_ok=True)

    port_map = {
        "node_exporter": node_exporter_port,
        **{port_enum.name: port_num for port_enum, port_num in otelcol_port_map.items()}
    }

    lock_file = f"{PORT_MAP_FILE}.lock"
    try:
        with FileLock(lock_file, timeout=PORT_MAP_LOCK_TIMEOUT), open(PORT_MAP_FILE, "w") as f:
            json.dump(port_map, f, indent=2)
            logger.info(f"saved port map to {PORT_MAP_FILE}: {port_map}")
    except Timeout:
        logger.warning(f"timeout acquiring lock for {PORT_MAP_FILE}. "
                      f"Another process may be saving ports. Ports will be re-allocated on next reconciliation.")
    except (OSError, PermissionError) as e:
        logger.warning(f"failed to save port map to {PORT_MAP_FILE}: {e}. "
                      f"Ports will be re-allocated on next reconciliation.")


def find_available_port(start_port: int = DEFAULT_PORT_SEARCH_START, exclude_ports: Optional[set] = None) -> int:
    """Find an available port starting from the given port.

    Args:
        start_port: The port to start checking from (must be between 1 and 65535)
        exclude_ports: Optional set of ports to exclude from the search

    Returns:
        The first available port found

    Raises:
        ValueError: If start_port is not in the valid range (1-65535)
        RuntimeError: If no available port is found up to port 65535.
    """
    # Validate port range (port 0 is special and should not be used)
    if not 1 <= start_port <= 65535:
        error_msg = (
            f"Invalid start_port: {start_port}. "
            f"Port must be between 1 and 65535"
        )
        logger.error(error_msg)
        raise ValueError(error_msg)

    # Warn about privileged ports
    if start_port < 1024:
        logger.warning(
            f"Starting port search from privileged port {start_port}. "
            f"Binding may require root/administrator privileges"
        )

    if exclude_ports is None:
        exclude_ports = set()

    logger.debug(f"searching for available port starting from {start_port}")
    port = start_port
    # Port numbers must be in the range 0–65535; avoid an unbounded search.
    while port <= 65535:
        if port not in exclude_ports and is_port_available(port):
            logger.debug(f"Found available port: {port}")
            return port
        port += 1

    error_msg = f"no available port found in range [{start_port}, 65535]"
    logger.error(error_msg)
    raise RuntimeError(error_msg)


def allocate_ports(port_enum_class: Type[Port]) -> Dict[Port, int]:
    """Allocate available ports for all members of the Port enum.

    For each port in the enum, check if its default port value is available.
    If available, use it. If not, search for an available port starting from
    DEFAULT_PORT_SEARCH_START, ensuring no port is allocated twice.

    .. deprecated::
        Use :func:`get_or_allocate_ports` instead for persistent port allocation
        that avoids port churn across reconciliations.

    Args:
        port_enum_class: The Port enum class (e.g., Port)

    Returns:
        Dictionary mapping each Port enum member to its allocated port number

    Raises:
        RuntimeError: If no available port is found for any protocol
    """
    logger.info("starting port allocation for OpenTelemetry Collector protocols")
    allocated_ports: Dict[Port, int] = {}
    used_ports: set = set()

    for port_enum in port_enum_class:
        desired_port = port_enum.value
        # Try the desired port first (only if not already used)
        if desired_port not in used_ports and is_port_available(desired_port):
            logger.info(f"using default port {desired_port} for {port_enum.name}")
            allocated_ports[port_enum] = desired_port
            used_ports.add(desired_port)
        else:
            # Desired port is occupied or already used, find an alternative
            alternative_port = find_available_port(
                start_port=DEFAULT_PORT_SEARCH_START,
                exclude_ports=used_ports
            )
            logger.warning(
                f"assigned alternative port {alternative_port} for {port_enum.name} "
                f"(default port {desired_port} was not available)"
            )
            allocated_ports[port_enum] = alternative_port
            used_ports.add(alternative_port)

    logger.info(
        f"port allocation complete. allocated {len(allocated_ports)} ports: "
        f"{', '.join(f'{p.name}={port}' for p, port in allocated_ports.items())}"
    )
    return allocated_ports


def reconstruct_otelcol_map(persisted: Dict[str, int], port_enum_class: Type[Port]) -> Dict[Port, int]:
    """Reconstruct otelcol port map from persisted JSON data.

    Args:
        persisted: Dictionary mapping port names to port numbers
        port_enum_class: The Port enum class

    Returns:
        Dictionary mapping Port enum members to port numbers
    """
    otelcol_port_map = {}
    for port_enum in port_enum_class:
        if port_enum.name in persisted:
            otelcol_port_map[port_enum] = persisted[port_enum.name]
        else:
            logger.warning(f"Port {port_enum.name} not found, using default {port_enum.value}")
            otelcol_port_map[port_enum] = port_enum.value
    return otelcol_port_map


def allocate_single_port(default_port: int, exclude_ports: Set[int]) -> int:
    """Allocate a single port, checking availability and finding alternatives if needed.

    First attempts to use the default port if available and not excluded.
    If unavailable, searches for an alternative starting from DEFAULT_PORT_SEARCH_START.

    Args:
        default_port: Desired default port number
        exclude_ports: Set of ports to exclude from the search

    Returns:
        Allocated port number (either default or alternative)

    Raises:
        RuntimeError: If no available port is found in the range [DEFAULT_PORT_SEARCH_START, 65535]
    """
    if default_port not in exclude_ports and is_port_available(default_port):
        logger.info(f"using default port {default_port}")
        return default_port

    alternative = find_available_port(start_port=DEFAULT_PORT_SEARCH_START, exclude_ports=exclude_ports)
    logger.warning(f"assigned alternative port {alternative} (default {default_port} unavailable)")
    return alternative


def allocate_port_map(port_enum_class: Type[Port], exclude_ports: Set[int]) -> Dict[Port, int]:
    """Allocate ports for all members of the Port enum.

    Iterates through all Port enum members and allocates a port for each,
    ensuring no two protocols share the same port.

    Args:
        port_enum_class: The Port enum class (e.g., Port)
        exclude_ports: Set of ports to exclude from allocation (e.g., node-exporter port)

    Returns:
        Dictionary mapping Port enum members to allocated port numbers

    Raises:
        RuntimeError: If no available ports are found for any protocol
    """
    otelcol_port_map = {}
    used_ports = exclude_ports.copy()

    for port_enum in port_enum_class:
        port = allocate_single_port(port_enum.value, used_ports)
        otelcol_port_map[port_enum] = port
        used_ports.add(port)

    return otelcol_port_map


def get_or_allocate_ports(
    port_enum_class: Type[Port],
    node_exporter_default_port: int
) -> Tuple[Dict[Port, int], int]:
    """Get persisted ports or allocate new ones if needed.

    This function implements persistent port allocation to avoid "port churn"
    where ports change on every reconciliation. It:
    1. Tries to load persisted port assignments from disk
    2. If found, reuses them (avoiding restarts)
    3. If not found, allocates new ports and persists them

    Args:
        port_enum_class: The Port enum class (e.g., Port)
        node_exporter_default_port: Default port for node-exporter

    Returns:
        Tuple of (otelcol_port_map, node_exporter_port)

    Raises:
        RuntimeError: If no available ports are found
    """
    if persisted := load_port_map():
        logger.info("reusing persisted port assignments")
        otelcol_port_map = reconstruct_otelcol_map(persisted, port_enum_class)
        node_exporter_port = persisted.get("node_exporter", node_exporter_default_port)
        return otelcol_port_map, node_exporter_port

    logger.info("no persisted port map found, allocating new ports")
    node_exporter_port = allocate_single_port(node_exporter_default_port, set())
    otelcol_port_map = allocate_port_map(port_enum_class, {node_exporter_port})
    save_port_map(otelcol_port_map, node_exporter_port)
    return otelcol_port_map, node_exporter_port
