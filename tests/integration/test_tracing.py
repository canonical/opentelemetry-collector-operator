# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: COS Agent integration works as expected."""

import pathlib
import jubilant
from tenacity import retry, stop_after_attempt, wait_fixed
from helpers import is_pattern_in_snap_logs

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


async def test_deploy(juju: jubilant.Juju, charm_22_04: str):
    # GIVEN an OpenTelemetry Collector charm and a principal
    juju.deploy(charm_22_04, app="otelcol")
    juju.deploy("postgresql", channel="14/stable")
    # WHEN they are related
    juju.integrate("otelcol:cos-agent", "postgresql:cos-agent")
    # THEN all units are active/blocked
    assert False  # FIXME: trigger debug test in CI, remove this from PR
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        error=jubilant.any_error,
        timeout=360,
    )
    juju.wait(
        lambda status: jubilant.all_active(status, "postgresql"),
        error=jubilant.any_error,
        timeout=600,
    )


async def test_metrics_are_scraped(juju: jubilant.Juju):
    grep_filters = ["juju_application=postgresql", f"juju_model={juju.model}"]
    result = await is_pattern_in_snap_logs(juju, grep_filters)
    assert result


# async def test_logs_are_scraped(juju: jubilant.Juju):
#     grep_filters = ["log.file.name=zookeeper.log", "log.file.path=/snap/opentelemetry-collector"]
#     result = await is_pattern_in_snap_logs(juju, grep_filters)
#     assert result


@retry(stop=stop_after_attempt(25), wait=wait_fixed(10))
def test_alerts_are_aggregated(juju: jubilant.Juju):
    alert_files = juju.ssh(
        "otelcol/0",
        command="find /var/lib/juju/agents/unit-otelcol-0/charm/prometheus_alert_rules -type f",
    )
    assert "postgresql" in alert_files


async def test_traces_are_scraped(juju: jubilant.Juju):
    grep_filters = ["service.name=postgresql-charm"]
    result = await is_pattern_in_snap_logs(juju, grep_filters)
    assert result


# @retry(stop=stop_after_attempt(25), wait=wait_fixed(10))
# def test_dashboards_are_aggregated(juju: jubilant.Juju):
#     dashboard_files = juju.ssh(
#         "otelcol/0",
#         command="find /var/lib/juju/agents/unit-otelcol-0/charm/grafana_dashboards -type f",
#     )
#     assert "postgresql" in dashboard_files
