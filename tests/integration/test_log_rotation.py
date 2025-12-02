# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Logs are rotated via logrotate.d configuration."""

import pathlib

import jubilant

from constants import INTERNAL_TELEMETRY_LOG_FILE

LOG_DIR = str(pathlib.Path(INTERNAL_TELEMETRY_LOG_FILE).parent)


async def test_deploy(juju: jubilant.Juju, charm: str):
    # GIVEN an OpenTelemetry Collector charm and a principal
    juju.deploy(charm, app="otelcol")
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
    # GIVEN the log file is present and is configured for log rotation
    logrotate_config = juju.ssh(
        "otelcol/0",
        f'sudo logrotate --verbose /etc/logrotate.conf 2>&1 | grep "{INTERNAL_TELEMETRY_LOG_FILE}"',
    ).strip()
    assert f"considering log {INTERNAL_TELEMETRY_LOG_FILE}" in logrotate_config
    files = juju.ssh("otelcol/0", f"ls {INTERNAL_TELEMETRY_LOG_FILE}*").strip().split("  ")
    assert files == [INTERNAL_TELEMETRY_LOG_FILE]

    # WHEN the log rotation is run manually
    juju.ssh("otelcol/0", "sudo logrotate -f /etc/logrotate.d/otelcol").strip()

    # THEN the log file is rotated
    files = juju.ssh("otelcol/0", f"ls {INTERNAL_TELEMETRY_LOG_FILE}*").strip().split("  ")
    assert files == [INTERNAL_TELEMETRY_LOG_FILE, f"{INTERNAL_TELEMETRY_LOG_FILE}.1"]
