# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: COS Agent integration works as expected."""

import pathlib
import re
from tenacity import retry, stop_after_attempt, wait_fixed

import jubilant

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


@retry(stop=stop_after_attempt(60), wait=wait_fixed(10))
async def is_pattern_in_logs(juju: jubilant.Juju, pattern: str):
    otelcol_logs = juju.ssh("otelcol/0", command="sudo snap logs opentelemetry-collector -n=1000")
    match = re.search(pattern, otelcol_logs)
    return match is not None


async def test_deploy(juju: jubilant.Juju, charm: str):
    # GIVEN an OpenTelemetry Collector charm and a principal
    juju.deploy(charm, app="otelcol")
    juju.deploy("zookeeper", channel="3/stable")
    # WHEN they are related
    juju.integrate("otelcol:cos-agent", "zookeeper:cos-agent")
    # THEN all units are active
    # FIXME: after we add blocked status on missing relations (mandatory pairs), change this
    juju.wait(jubilant.all_active, timeout=300)


async def test_metrics(juju: jubilant.Juju):
    metrics_pattern = rf".+{{.*juju_application=zookeeper,.*juju_model={juju.model}.*}}"
    result = await is_pattern_in_logs(juju, metrics_pattern)
    return result


async def test_logs(juju: jubilant.Juju):
    logs_pattern = r".+log.file.name=zookeeper.log.+log.file.path=/snap/opentelemetry-collector/\d+/shared-logs/zookeeper"
    result = await is_pattern_in_logs(juju, logs_pattern)
    return result
