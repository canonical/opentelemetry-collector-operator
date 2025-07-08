# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: COS Agent integration works as expected."""

import pathlib
import re
from tenacity import retry, wait_exponential

import jubilant

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


@retry(wait=wait_exponential(multiplier=1, min=4, max=10))
async def is_pattern_in_logs(juju: jubilant.Juju, pattern: str):
    otelcol_logs = juju.ssh("otelcol/0", command="sudo snap logs opentelemetry-collector -n=all")
    if not re.search(pattern, otelcol_logs):
        raise Exception(f"Pattern {pattern} not found in the otelcol logs")
    return True


async def test_deploy(juju: jubilant.Juju, charm: str):
    # GIVEN an OpenTelemetry Collector charm and a principal
    juju.deploy(charm, app="otelcol")
    juju.deploy("zookeeper", channel="3/stable")
    # WHEN they are related
    juju.integrate("otelcol:cos-agent", "zookeeper:cos-agent")
    # THEN all units are active
    # FIXME: after we add blocked status on missing relations (mandatory pairs), change this
    juju.wait(jubilant.all_active, timeout=300)


async def test_metrics_are_scraped(juju: jubilant.Juju):
    metrics_pattern = rf".+{{.*juju_application=zookeeper,.*juju_model={juju.model}.*}}"
    result = await is_pattern_in_logs(juju, metrics_pattern)
    assert result


async def test_logs_are_scraped(juju: jubilant.Juju):
    zookeeper_logs_pattern = r".+log.file.name=zookeeper.log.+log.file.path=/snap/opentelemetry-collector/\d+/shared-logs/zookeeper"
    result = await is_pattern_in_logs(juju, zookeeper_logs_pattern)
    assert result


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
