#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Conftest file for integration tests."""

import functools
from typing import Literal
import subprocess
from pytest import fixture
from pytest_jubilant import get_resources, pack
import logging

import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import pytest
import jubilant

logger = logging.getLogger(__name__)

store = defaultdict(str)

CONFIG_BUILDER_PATH = Path(__file__).parent.parent.parent / "src" / "config_builder.py"
REPO_ROOT = Path(__file__).resolve().parents[2]


def charm_and_channel_and_resources(charm_path_key: str, charm_channel_key: str):
    """Opentelemetry-collector charm used for integration testing.

    Build once per session and reuse in all integration tests.
    """
    if channel_from_env := os.getenv(charm_channel_key):
        charm = "opentelemetry-collector"
        logger.info("Using published %s charm from %s", charm, channel_from_env)
        return charm, channel_from_env, None
    if path_from_env := os.getenv(charm_path_key):
        charm_path = Path(path_from_env).absolute()
        logger.info("Using local charm: %s", charm_path)
        return charm_path, None, get_resources(REPO_ROOT)
    for _ in range(3):
        logger.info("packing Opentelemetry-collector charm ...")
        try:
            pth = pack(REPO_ROOT, platform="ubuntu@22.04:amd64")
        except subprocess.CalledProcessError:
            logger.warning("Failed to build Opentelemetry-collector charm. Trying again!")
            continue
        os.environ[charm_path_key] = str(pth)
        return pth, None, get_resources(REPO_ROOT)
    raise subprocess.CalledProcessError(1, "pack charm")


@fixture(scope="session")
def otelcol_charm():
    """Opentelemetry-collector coordinator used for integration testing."""
    # TODO: otelcol_charm.replace("24.04", "22.04")
    return charm_and_channel_and_resources("CHARM_PATH", "CHARM_CHANNEL")


@pytest.fixture(scope="module")
def charm_22_04(otelcol_charm) -> str:
    """Charm (platform = ubuntu@22.04) used for integration testing."""
    # Note: Use '22.04' in integration tests with Zookeeper, because that's Zookeeper's base
    return otelcol_charm[0].replace("24.04", "22.04")


@pytest.fixture(scope="module")
def juju():
    keep_models: bool = os.environ.get("KEEP_MODELS") is not None
    with jubilant.temp_model(keep=keep_models) as juju:
        yield juju
