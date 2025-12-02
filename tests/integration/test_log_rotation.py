# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Logs are rotated via logrotate.d configuration."""

import pathlib

import jubilant
from helpers import PATH_EXCLUDE

from constants import INTERNAL_TELEMETRY_LOG_FILE

LOG_DIR = str(pathlib.Path(INTERNAL_TELEMETRY_LOG_FILE).parent)


async def test_deploy(juju: jubilant.Juju, charm: str):
    # GIVEN an OpenTelemetry Collector charm and a principal
    ## NOTE: /var/log/cloud-init.log and /var/log/cloud-init-output.log are always present
    juju.deploy(charm, app="otelcol", config={"path_exclude": PATH_EXCLUDE})
    juju.deploy("ubuntu", base="ubuntu@22.04", channel="latest/stable")
    # WHEN they are related
    juju.integrate("otelcol:juju-info", "ubuntu:juju-info")
    # THEN all units are settled
    juju.wait(
        lambda status: jubilant.all_active(status, "ubuntu"),
        error=jubilant.any_error,
        timeout=420,
    )
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        error=jubilant.any_error,
        timeout=420,
    )


async def test_log_rotation(juju: jubilant.Juju):
    # GIVEN the log file is present on disk
    files = juju.ssh("otelcol/0", f"ls {LOG_DIR}").strip().split("  ")
    assert files == ["otelcol.log"]

    # WHEN the log rotation is run manually
    juju.ssh("otelcol/0", "sudo logrotate -f /etc/logrotate.d/otelcol").strip()

    # THEN the log file is rotated
    files = juju.ssh("otelcol/0", f"ls {LOG_DIR}").strip().split("  ")
    assert files == ["otelcol.log", "otelcol.log.1"]
