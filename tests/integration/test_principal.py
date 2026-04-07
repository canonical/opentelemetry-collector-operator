# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: COS Agent integration works as expected."""

import pathlib
import re

import jubilant
from helpers import ENABLE_BASIC_DEBUG_EXPORTERS, PATH_EXCLUDE, is_pattern_in_debug_logs, is_pattern_not_in_debug_logs

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


def is_node_exporter_running_with_collectors(juju: jubilant.Juju, pattern: str):
    output_ps = juju.ssh(
        "otelcol/0", command="ps ax | grep node-exporter | egrep -v 'grep|snapfuse'"
    )
    if not re.search(pattern, output_ps):
        raise Exception(f"Pattern {pattern} not found in the node-exporter process output")
    return True


def test_deploy(juju: jubilant.Juju, charm: str):
    # GIVEN an OpenTelemetry Collector charm and a principal
    ## NOTE: /var/log/cloud-init.log and /var/log/cloud-init-output.log are always present
    juju.deploy(
        charm,
        app="otelcol",
        config={"path_exclude": PATH_EXCLUDE, **ENABLE_BASIC_DEBUG_EXPORTERS},
    )
    juju.deploy("ubuntu", channel="latest/stable", base="ubuntu@24.04")
    # WHEN they are related
    juju.integrate("otelcol:juju-info", "ubuntu:juju-info")
    # THEN all units are active
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        error=jubilant.any_error,
        timeout=420,
    )
    juju.wait(
        lambda status: jubilant.all_active(status, "ubuntu"),
        error=jubilant.any_error,
        timeout=420,
    )


def test_var_log_is_scraped(juju: jubilant.Juju):
    var_log_pattern = ["log.file.path=/var/log"]
    is_var_log_scraped = is_pattern_in_debug_logs(juju, var_log_pattern)
    assert is_var_log_scraped


def test_path_exclude(juju: jubilant.Juju):
    included_log_pattern = ["log.file.name=cloud-init.log"]
    excluded_log_pattern = r".+log.file.name=cloud-init-output.log"

    is_included = is_pattern_in_debug_logs(juju, included_log_pattern)
    assert is_included

    is_excluded = is_pattern_not_in_debug_logs(juju, excluded_log_pattern)
    assert is_excluded


def test_node_metrics(juju: jubilant.Juju):
    node_metric = ["node_scrape_collector_success"]
    is_included = is_pattern_in_debug_logs(juju, node_metric)
    assert is_included


def test_node_exporter_collectors(juju: jubilant.Juju):
    node_exporter_collectors = r"collector.drm"
    is_included = is_node_exporter_running_with_collectors(juju, node_exporter_collectors)
    assert is_included
