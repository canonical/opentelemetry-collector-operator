# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utils module."""

import logging
import os

from constants import CGROUP_MEMORY_MAX

logger = logging.getLogger(__name__)


def total_memory_mib() -> int:
    """Return the total memory available to this process in MiB.

    Reads the cgroup memory limit, which reflects container/LXD limits.
    Falls back to physical RAM when the cgroup file is absent or reads "max"
    (meaning no limit is set).

    We need this function until this issue is closed:
        - https://github.com/canonical/opentelemetry-collector-operator/issues/256
    """
    try:
        raw = open(CGROUP_MEMORY_MAX).read().strip()
        if raw != "max":
            return int(raw) // (1024 * 1024)
    except (OSError, ValueError):
        pass
    return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // (1024 * 1024)


def parse_memory_limit(config_value: str) -> int:
    """Parse the memory limit percentage from config and validate it."""
    try:
        limit = int(config_value)
        if limit < 0 or limit > 100:
            raise ValueError("memory_limit_percentage value must be [0, 100]")
        return limit
    except ValueError:
        logger.warning(
            "Invalid memory_limit_percentage config value, defaulting to 100. "
            "Valid values are [0, 100]"
        )
        raise
