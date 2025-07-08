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


@retry(wait=wait_exponential(multiplier=1, min=4, max=10))
async def is_pattern_not_in_logs(juju: jubilant.Juju, pattern: str):
    otelcol_logs = juju.ssh("otelcol/0", command="sudo snap logs opentelemetry-collector -n=all")
    if re.search(pattern, otelcol_logs):
        raise Exception(f"Pattern {pattern} found in the otelcol logs")
    return True


async def test_deploy(juju: jubilant.Juju, charm: str):
    # GIVEN an OpenTelemetry Collector charm and a principal
    ## NOTE: /var/log/cloud-init.log and /var/log/cloud-init-output.log are always present
    juju.deploy(charm, app="otelcol", config={"path_exclude": "/var/log/cloud-init-output.log"})
    juju.deploy("zookeeper", channel="3/stable")
    # WHEN they are related
    juju.integrate("otelcol:cos-agent", "zookeeper:cos-agent")
    # THEN all units are active
    # FIXME: after we add blocked status on missing relations (mandatory pairs), change this
    juju.wait(jubilant.all_active, timeout=300)


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
