"""Node exporter helpers."""

import logging
from typing import Set

logger = logging.getLogger(__name__)

class NodeExporterCollectorError(ValueError):
    """Custom exception for node-exporter collector errors."""


def validate_node_exporter_collectors(valid_collectors: Set, collectors: Set) -> None:
    """Validate the node-exporter collectors configuration."""
    diff = collectors - valid_collectors

    if diff:
        msg = f"Invalid node-exporter collectors: {', '.join(diff)}"
        logger.error(msg)
        raise NodeExporterCollectorError(msg)
