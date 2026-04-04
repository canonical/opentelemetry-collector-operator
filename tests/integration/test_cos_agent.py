# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: COS Agent integration works as expected."""

import pathlib
import jubilant
from tenacity import retry, stop_after_attempt, wait_fixed
from helpers import ENABLE_BASIC_DEBUG_EXPORTERS, PATH_EXCLUDE, is_pattern_in_debug_logs

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


def test_deploy(juju: jubilant.Juju, otelcol_charm: tuple[str, str, dict]):
    # GIVEN an OpenTelemetry Collector charm and a principal
    charm, _, _ = otelcol_charm
    juju.deploy(
        charm,
        app="otelcol",
        config={"path_exclude": PATH_EXCLUDE, **ENABLE_BASIC_DEBUG_EXPORTERS},
    )
    juju.deploy("zookeeper", channel="3/stable")
    # WHEN they are related
    juju.integrate("otelcol:cos-agent", "zookeeper:cos-agent")
    # THEN all units are active/blocked
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        error=jubilant.any_error,
        timeout=420,
    )
    juju.wait(
        lambda status: jubilant.all_active(status, "zookeeper"),
        error=jubilant.any_error,
        timeout=420,
    )


def test_metrics_are_scraped(juju: jubilant.Juju):
    grep_filters = ["juju_application=zookeeper", f"juju_model={juju.model}"]
    result = is_pattern_in_debug_logs(juju, grep_filters)
    assert result


def test_logs_are_scraped(juju: jubilant.Juju):
    grep_filters = ["log.file.name=zookeeper.log", "log.file.path=/snap/opentelemetry-collector"]
    result = is_pattern_in_debug_logs(juju, grep_filters)
    assert result


@retry(stop=stop_after_attempt(25), wait=wait_fixed(10))
def test_alerts_are_aggregated(juju: jubilant.Juju):
    alert_files = juju.ssh(
        "otelcol/0",
        command="find /var/lib/juju/agents/unit-otelcol-0/charm/prometheus_alert_rules -type f",
    )
    assert "zookeeper" in alert_files


@retry(stop=stop_after_attempt(25), wait=wait_fixed(10))
def test_dashboards_are_aggregated(juju: jubilant.Juju):
    dashboard_files = juju.ssh(
        "otelcol/0",
        command="find /var/lib/juju/agents/unit-otelcol-0/charm/grafana_dashboards -type f",
    )
    assert "zookeeper" in dashboard_files
