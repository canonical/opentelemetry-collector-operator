# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utils module."""

import socket
from constants import DEFAULT_PORT_SEARCH_START


def find_available_port(start_port: int = DEFAULT_PORT_SEARCH_START) -> int:
    """Find an available port starting from the given port.

    Args:
        start_port: The port to start checking from

    Returns:
        The first available port found

    Raises:
        RuntimeError: If no available port is found up to port 65535.
    """
    port = start_port
    # Port numbers must be in the range 0–65535; avoid an unbounded search.
    while port <= 65535:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("", port))
                return port
        except OSError:
            port += 1
    raise RuntimeError(
        f"No available port found in range [{start_port}, 65535]"
    )
