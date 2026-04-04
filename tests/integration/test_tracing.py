# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Ingested traces are pushed to Tempo via COS Agent."""

import pathlib
import jubilant
from helpers import PATH_EXCLUDE, is_pattern_in_debug_logs

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


def test_deploy(juju: jubilant.Juju, otelcol_charm: tuple[str, str, dict]):
    # GIVEN an OpenTelemetry Collector charm and a principal
    charm, _, _ = otelcol_charm
    juju.deploy(
        charm,
        app="otelcol",
        config={"path_exclude": PATH_EXCLUDE, "debug_exporter_for_traces": "true"},
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


def test_traces_are_scraped(juju: jubilant.Juju):
    grep_filters = ["ScopeTraces", "postgresql-charm"]
    result = is_pattern_in_debug_logs(juju, grep_filters)
    assert result
