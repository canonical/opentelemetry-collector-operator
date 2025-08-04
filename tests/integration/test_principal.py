# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: COS Agent integration works as expected."""

import pathlib
import re

import jubilant
from tenacity import retry, stop_after_attempt, wait_fixed

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


# FIXME: Reduce retry count once fixed
# https://github.com/canonical/opentelemetry-collector-operator/issues/32
@retry(stop=stop_after_attempt(25), wait=wait_fixed(10))
async def is_pattern_in_logs(juju: jubilant.Juju, pattern: str):
    otelcol_logs = juju.ssh("otelcol/0", command="sudo snap logs opentelemetry-collector -n=all")
    if not re.search(pattern, otelcol_logs):
        raise Exception(f"Pattern {pattern} not found in the otelcol logs")
    return True


@retry(stop=stop_after_attempt(25), wait=wait_fixed(10))
async def is_pattern_not_in_logs(juju: jubilant.Juju, pattern: str):
    otelcol_logs = juju.ssh("otelcol/0", command="sudo snap logs opentelemetry-collector -n=all")
    if re.search(pattern, otelcol_logs):
        raise Exception(f"Pattern {pattern} found in the otelcol logs")
    return True

async def is_node_exporter_running_with_collectors(juju: jubilant.Juju, pattern: str):
    output_ps = juju.ssh("otelcol/0", command="ps ax | grep node-exporter | egrep -v 'grep|snapfuse'")
    if not re.search(pattern, output_ps):
        raise Exception(f"Pattern {pattern} not found in the node-exporter process output")
    return True

async def test_deploy(juju: jubilant.Juju, charm_22_04: str):
    # GIVEN an OpenTelemetry Collector charm and a principal
    ## NOTE: /var/log/cloud-init.log and /var/log/cloud-init-output.log are always present
    juju.deploy(
        charm_22_04, app="otelcol", config={"path_exclude": "/var/log/cloud-init-output.log"}
    )
    juju.deploy("zookeeper", channel="3/stable")
    # WHEN they are related
    juju.integrate("otelcol:juju-info", "zookeeper:juju-info")
    # THEN all units are active
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        error=jubilant.any_error,
        timeout=300,
    )
    juju.wait(
        lambda status: jubilant.all_active(status, "zookeeper"),
        error=jubilant.any_error,
        timeout=600,
    )


async def test_var_log_is_scraped(juju: jubilant.Juju):
    var_log_pattern = r".+log.file.path=/var/log"
    is_var_log_scraped = await is_pattern_in_logs(juju, var_log_pattern)
    assert is_var_log_scraped


async def test_path_exclude(juju: jubilant.Juju):
    included_log_pattern = r".+log.file.name=cloud-init.log"
    excluded_log_pattern = r".+log.file.name=cloud-init-output.log"
    is_included = await is_pattern_in_logs(juju, included_log_pattern)
    assert is_included
    is_excluded = await is_pattern_not_in_logs(juju, excluded_log_pattern)
    assert is_excluded


async def test_node_metrics(juju: jubilant.Juju):
    node_metric = r"node_scrape_collector_success"
    is_included = await is_pattern_in_logs(juju, node_metric)
    assert is_included

async def test_node_exporter_collectors(juju: jubilant.Juju):
    node_exporter_collectors = r"collector.drm"
    is_included = await is_node_exporter_running_with_collectors(juju, node_exporter_collectors)
    assert is_included
