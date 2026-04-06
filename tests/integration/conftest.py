#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Conftest file for integration tests."""

import subprocess
from pytest import fixture
from pytest_jubilant import pack
import logging

import os
from collections import defaultdict
from pathlib import Path

import pytest
import jubilant

logger = logging.getLogger(__name__)

store = defaultdict(str)

CONFIG_BUILDER_PATH = Path(__file__).parent.parent.parent / "src" / "config_builder.py"
REPO_ROOT = Path(__file__).resolve().parents[2]


def charm_and_channel(charm_path_key: str, charm_channel_key: str) -> tuple[str, str | None]:
    """Opentelemetry-collector charm used for integration testing.

    Build once per session and reuse in all integration tests.
    """
    if channel_from_env := os.getenv(charm_channel_key):
        charm = "opentelemetry-collector"
        logger.info("Using published %s charm from %s", charm, channel_from_env)
        return charm, channel_from_env
    if path_from_env := os.getenv(charm_path_key):
        charm_path = str(Path(path_from_env).absolute())
        logger.info("Using local charm: %s", charm_path)
        return charm_path, None
    for _ in range(3):
        logger.info("packing Opentelemetry-collector charm ...")
        try:
            pth = str(pack(REPO_ROOT, platform="ubuntu@22.04:amd64"))
        except subprocess.CalledProcessError:
            logger.warning("Failed to build Opentelemetry-collector charm. Trying again!")
            continue
        os.environ[charm_path_key] = pth
        return pth, None
    raise subprocess.CalledProcessError(1, "pack charm")


@fixture(scope="session")
def charm():
    """Opentelemetry-collector coordinator used for integration testing."""
    return charm_and_channel("CHARM_PATH", "CHARM_CHANNEL")[0]


@pytest.fixture(scope="module")
def charm_22_04(charm) -> str:
    """Charm (platform = ubuntu@22.04) used for integration testing."""
    # Note: Use '22.04' in integration tests with Zookeeper, because that's Zookeeper's base
    return charm.replace("24.04", "22.04")


@pytest.fixture(scope="module")
def juju():
    keep_models: bool = os.environ.get("KEEP_MODELS") is not None
    with jubilant.temp_model(keep=keep_models) as juju:
        yield juju
