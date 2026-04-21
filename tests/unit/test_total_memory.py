# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for _total_memory_mib()."""

from unittest.mock import mock_open, patch

import pytest

from config_manager import _total_memory_mib


@pytest.mark.parametrize(
    "cgroup_content, expected_mib",
    [
        # K8s container with 1 GiB limit
        ("1073741824\n", 1024),
        # LXD container with 2 GiB limit
        ("2147483648\n", 2048),
        # 512 MiB limit
        ("536870912\n", 512),
    ],
)
def test_cgroup_limit_is_respected(cgroup_content, expected_mib):
    """When cgroup memory.max is a number, use it as the memory limit."""
    with patch("builtins.open", mock_open(read_data=cgroup_content)):
        assert _total_memory_mib() == expected_mib


def test_cgroup_max_falls_back_to_physical_ram():
    """When cgroup memory.max reads 'max', fall back to physical RAM."""
    fake_physical_mib = 88128
    with (
        patch("builtins.open", mock_open(read_data="max\n")),
        patch("config_manager.os.sysconf", side_effect=lambda key: {
            "SC_PAGE_SIZE": 4096,
            "SC_PHYS_PAGES": fake_physical_mib * 1024 * 1024 // 4096,
        }[key]),
    ):
        assert _total_memory_mib() == fake_physical_mib


def test_missing_cgroup_file_falls_back_to_physical_ram():
    """When the cgroup file doesn't exist, fall back to physical RAM."""
    fake_physical_mib = 16384
    with (
        patch("builtins.open", side_effect=OSError("No such file")),
        patch("config_manager.os.sysconf", side_effect=lambda key: {
            "SC_PAGE_SIZE": 4096,
            "SC_PHYS_PAGES": fake_physical_mib * 1024 * 1024 // 4096,
        }[key]),
    ):
        assert _total_memory_mib() == fake_physical_mib


def test_invalid_cgroup_content_falls_back_to_physical_ram():
    """When the cgroup file has unexpected content, fall back to physical RAM."""
    fake_physical_mib = 4096
    with (
        patch("builtins.open", mock_open(read_data="not_a_number\n")),
        patch("config_manager.os.sysconf", side_effect=lambda key: {
            "SC_PAGE_SIZE": 4096,
            "SC_PHYS_PAGES": fake_physical_mib * 1024 * 1024 // 4096,
        }[key]),
    ):
        assert _total_memory_mib() == fake_physical_mib
