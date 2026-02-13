# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utils module."""

import logging
import socket
from typing import Dict, Optional, Type

from config_builder import Port
from constants import DEFAULT_PORT_SEARCH_START

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


def find_available_port(start_port: int = DEFAULT_PORT_SEARCH_START, exclude_ports: Optional[set] = None) -> int:
    """Find an available port starting from the given port.

    Args:
        start_port: The port to start checking from (must be between 0 and 65535)
        exclude_ports: Optional set of ports to exclude from the search

    Returns:
        The first available port found

    Raises:
        ValueError: If start_port is not in the valid range (0-65535)
        RuntimeError: If no available port is found up to port 65535.
    """
    # Validate port range
    if not 0 <= start_port <= 65535:
        error_msg = (
            f"Invalid start_port: {start_port}. "
            f"Port must be between 0 and 65535"
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

    Args:
        port_enum_class: The Port enum class (e.g., Port).

    Returns:
        A dictionary mapping each Port enum member to its allocated port number.

    Raises:
        RuntimeError: If no available port is found for any protocol.
    """
    logger.info("Starting port allocation for OpenTelemetry Collector protocols")
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
                f"(default port {desired_port} was no available)"
            )
            allocated_ports[port_enum] = alternative_port
            used_ports.add(alternative_port)

    logger.info(
        f"port allocation complete. Allocated {len(allocated_ports)} ports: "
        f"{', '.join(f'{p.name}={port}' for p, port in allocated_ports.items())}"
    )
    return allocated_ports
