# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Ingested traces are pushed to Tempo via COS Agent."""

import pathlib
import jubilant
from helpers import PATH_EXCLUDE, is_pattern_in_debug_logs

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


async def test_deploy(juju: jubilant.Juju, charm_22_04: str):
    # GIVEN an OpenTelemetry Collector charm and a principal
    juju.deploy(
        charm_22_04,
        app="otelcol",
        config={"path_exclude": PATH_EXCLUDE},
    )
    juju.deploy("postgresql", channel="14/stable")
    # WHEN they are related
    juju.integrate("otelcol:cos-agent", "postgresql:cos-agent")
    # THEN all units are active/blocked
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        error=jubilant.any_error,
        timeout=420,
    )
    juju.wait(
        lambda status: jubilant.all_active(status, "postgresql"),
        error=jubilant.any_error,
        timeout=420,
    )


async def test_traces_are_scraped(juju: jubilant.Juju):
    grep_filters = ["ScopeTraces", "postgresql-charm"]
    result = await is_pattern_in_debug_logs(juju, grep_filters)
    assert result
