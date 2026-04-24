# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Utils module."""

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def _get_cgroup_memory_max_path() -> Path:
    # TODO: this should accept a snap name or PID as an arg
    return Path("/sys/fs/cgroup/memory.max")


def total_memory_mib() -> int:
    """Return the total memory available to this process in MiB.

    Reads the cgroup memory limit, which reflects container/LXD limits.
    Falls back to physical RAM when the cgroup file is absent or reads "max"
    (meaning no limit is set).

    We need this function until this issue is closed:
        - https://github.com/canonical/opentelemetry-collector-operator/issues/256
    """
    try:
        raw = _get_cgroup_memory_max_path().read_text().strip()
        if raw != "max":
            return int(raw) // (1024 * 1024)
    except (OSError, ValueError):
        pass
    return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") // (1024 * 1024)


def parse_memory_limit(config_value: int) -> int:
    """Parse the memory limit percentage from config and validate it."""
    if config_value < 0 or config_value > 100:
        logger.warning(
            "Invalid memory_limit_percentage config value. Valid values are [0, 100]"
        )
        raise ValueError
    return config_value
