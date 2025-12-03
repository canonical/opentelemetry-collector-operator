#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Conftest file for integration tests."""

import functools
import logging

import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import pytest
from pytest_operator.plugin import OpsTest
import jubilant

logger = logging.getLogger(__name__)

store = defaultdict(str)

CONFIG_BUILDER_PATH = Path(__file__).parent.parent.parent / "src" / "config_builder.py"


def timed_memoizer(func):
    """Cache the result of a function."""

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        fname = func.__qualname__
        logger.info("Started: %s" % fname)
        start_time = datetime.now()
        if fname in store.keys():
            ret = store[fname]
        else:
            logger.info("Return for {} not cached".format(fname))
            ret = await func(*args, **kwargs)
            store[fname] = ret
        logger.info("Finished: {} in: {} seconds".format(fname, datetime.now() - start_time))
        return ret

    return wrapper


@pytest.fixture(scope="module")
@timed_memoizer
async def charm(ops_test: OpsTest) -> str:
    """Charm used for integration testing.

    When multiple charm files (i.e., for different bases) are produced by a `charmcraft pack`,
    our CI will currently set the variable to the highest-base one.
    """
    # FIXME: Avoid passing the charm file path as an environment variable,
    #        so every time a test is executed a new charm is packed with the modification
    #        in the internal telemetry level. This comment should be removed when then itest
    #        are improved to not use internal telemetry to verify if otelcol is receiving logs and metrics
    # if charm_file := os.environ.get("CHARM_PATH"):
    #     return charm_file

    charm = await ops_test.build_charm(".")
    charm = str(charm).replace("24.04", "22.04")
    assert charm
    return charm


@pytest.fixture(scope="module")
@timed_memoizer
async def charm_22_04(charm) -> str:
    """Charm (platform = ubuntu@22.04) used for integration testing."""
    # Note: Use '22.04' in integration tests with Zookeeper, because that's Zookeeper's base
    return charm.replace("24.04", "22.04")


@pytest.fixture(scope="module")
def juju():
    keep_models: bool = os.environ.get("KEEP_MODELS") is not None
    with jubilant.temp_model(keep=keep_models) as juju:
        yield juju
