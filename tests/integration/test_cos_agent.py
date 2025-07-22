# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: COS Agent integration works as expected."""

import pathlib

import jubilant
from helpers import is_pattern_in_logs
from tenacity import retry, stop_after_attempt, wait_exponential

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


async def test_deploy(juju: jubilant.Juju, charm_22_04: str):
    # GIVEN an OpenTelemetry Collector charm and a principal
    juju.deploy(charm_22_04, app="otelcol")
    juju.deploy("zookeeper", channel="3/stable")
    # WHEN they are related
    juju.integrate("otelcol:cos-agent", "zookeeper:cos-agent")
    # THEN all units are active
    juju.wait(
        lambda status: jubilant.all_active(status, "zookeeper"),
        error=jubilant.any_error,
        timeout=300,
    )
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        error=jubilant.any_error,
        timeout=300,
    )


async def test_metrics_are_scraped(juju: jubilant.Juju):
    metrics_pattern = rf".+{{.*juju_application=zookeeper,.*juju_model={juju.model}.*}}"
    result = await is_pattern_in_logs(juju, metrics_pattern)
    assert result


async def test_logs_are_scraped(juju: jubilant.Juju):
    zookeeper_logs_pattern = r".+log.file.name=zookeeper.log.+log.file.path=/snap/opentelemetry-collector/\d+/shared-logs/zookeeper"
    result = await is_pattern_in_logs(juju, zookeeper_logs_pattern)
    assert result


@retry(stop=stop_after_attempt(5), wait=wait_exponential(max=10))
def test_alerts_are_aggregated(juju: jubilant.Juju):
    alert_files = juju.ssh(
        "otelcol/0",
        command="find /var/lib/juju/agents/unit-otelcol-0/charm/prometheus_alert_rules -type f",
    )
    assert "zookeeper" in alert_files


def test_dashboards_are_aggregated(juju: jubilant.Juju):
    dashboard_files = juju.ssh(
        "otelcol/0",
        command="find /var/lib/juju/agents/unit-otelcol-0/charm/grafana_dashboards -type f",
    )
    assert "zookeeper" in dashboard_files
