# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: node-exporter package-type switching between apt and snap."""

import jubilant
from helpers import ENABLE_BASIC_DEBUG_EXPORTERS, PATH_EXCLUDE, RETRY


def deb_installed(juju: jubilant.Juju) -> bool:
    output = juju.ssh(
        "otelcol/0",
        command="dpkg-query -W -f '${Status}' prometheus-node-exporter 2>/dev/null || true",
    )
    return "install ok installed" in output


def snap_installed(juju: jubilant.Juju) -> bool:
    output = juju.ssh("otelcol/0", command="snap list 2>/dev/null || true")
    # NOTE: match the exact snap name; 'opentelemetry-collector' must not count
    return any(
        line.split()[0] == "node-exporter" for line in output.splitlines()[1:] if line.split()
    )


def node_exporter_serving_metrics(juju: jubilant.Juju) -> bool:
    output = juju.ssh("otelcol/0", command="curl -s http://localhost:9100/metrics | head -5")
    return "node_" in output or "# HELP" in output


def settle(juju: jubilant.Juju):
    # otelcol is expected to be blocked on missing mandatory outgoing relations,
    # like in test_principal.py; agents must be idle either way.
    juju.wait(jubilant.all_agents_idle, error=jubilant.any_error, timeout=420)


def test_deploy(juju: jubilant.Juju, charm: str):
    # GIVEN an OpenTelemetry Collector charm with default config and a principal
    juju.deploy(
        charm,
        app="otelcol",
        config={"path_exclude": PATH_EXCLUDE, **ENABLE_BASIC_DEBUG_EXPORTERS},
    )
    juju.deploy("ubuntu", channel="latest/stable", base="ubuntu@24.04")
    # WHEN they are related
    juju.integrate("otelcol:juju-info", "ubuntu:juju-info")
    # THEN the model settles
    settle(juju)


@RETRY
def test_default_package_type_is_apt(juju: jubilant.Juju):
    # THEN the deb is installed and the snap is not
    assert deb_installed(juju)
    assert not snap_installed(juju)
    # AND node-exporter serves metrics on the stock port with stock config
    assert node_exporter_serving_metrics(juju)


@RETRY
def test_info_metric_scraped_from_stock_textfile_dir(juju: jubilant.Juju):
    # THEN the per-unit info metric written to /var/lib/prometheus/node-exporter is served
    # (validates the assumption that the stock deb scrapes that directory)
    output = juju.ssh(
        "otelcol/0",
        command="curl -s http://localhost:9100/metrics | grep otelcol_subordinate_charm_info || true",
    )
    assert "otelcol_subordinate_charm_info" in output


def test_switch_to_snap(juju: jubilant.Juju):
    # WHEN switching to the snap flavor
    juju.config("otelcol", {"package-type": "snap"})
    settle(juju)
    # THEN the deb is uninstalled and the snap installed
    _assert_snap_flavor(juju)


@RETRY
def _assert_snap_flavor(juju: jubilant.Juju):
    assert snap_installed(juju)
    assert not deb_installed(juju)
    assert node_exporter_serving_metrics(juju)


def test_switch_back_to_apt(juju: jubilant.Juju):
    # WHEN switching back to the apt flavor
    juju.config("otelcol", {"package-type": "apt"})
    settle(juju)
    # THEN the snap is uninstalled and the deb installed
    _assert_apt_flavor(juju)


@RETRY
def _assert_apt_flavor(juju: jubilant.Juju):
    assert deb_installed(juju)
    assert not snap_installed(juju)
    assert node_exporter_serving_metrics(juju)
