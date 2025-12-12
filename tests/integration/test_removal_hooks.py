# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: COS Agent integration works as expected."""

import pathlib

import jubilant

from constants import CONFIG_FOLDER
from singleton_snap import SnapRegistrationFile
import os

from helpers import PATH_EXCLUDE, is_snap_active, ssh_and_execute_command_in_machine

SNAP_STATUS_COMMAND = "sudo snap services opentelemetry-collector"

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()

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

    juju.wait(lambda status: jubilant.all_agents_idle(status, "ubuntu", "otelcol"))

    snap_status = ssh_and_execute_command_in_machine(juju, "ubuntu/0", SNAP_STATUS_COMMAND)
    assert is_snap_active(snap_status)


async def test_remove_one_subordinate_one_machine(juju: jubilant.Juju):
    # GIVEN only 1 unit of the otelcol charm
    assert juju.status().get_units("otelcol").keys() == {"otelcol/0"}
    # WHEN the relation is removed
    juju.remove_relation("otelcol:juju-info", "ubuntu:juju-info")
    juju.wait(
        lambda status: jubilant.all_active(status, "ubuntu"),
        error=jubilant.any_error,
        timeout=240,
    )
    # THEN Otelcol has "unknown" status and a scale of 0
    juju.wait(
        lambda status: status.apps["otelcol"].app_status.current == "unknown",
        error=jubilant.any_error,
        timeout=240,
    )
    assert juju.status().get_units("otelcol") == {}
    # AND the otelcol config directory is removed from disk
    otelcol_config_dir = juju.ssh(
        "ubuntu/0", command=f'test -e {CONFIG_FOLDER} || echo "does not exist"'
    )
    assert otelcol_config_dir.strip() == "does not exist"


async def test_remove_two_subordinates_one_machine(juju: jubilant.Juju):
    # GIVEN otelcol has 2 subordinate units on the same machine
    juju.integrate("otelcol:juju-info", "ubuntu:juju-info")
    juju.add_unit("ubuntu", to="0")
    juju.wait(
        lambda status: jubilant.all_active(status, "ubuntu"),
        error=jubilant.any_error,
        timeout=240,
    )
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        error=jubilant.any_error,
        timeout=240,
    )

    # The snap must be active (meaning it has successfully started, showing the configs are valid)
    snap_status = ssh_and_execute_command_in_machine(juju, "ubuntu/0", SNAP_STATUS_COMMAND)
    assert is_snap_active(snap_status)

    # WHEN the relation is removed
    juju.remove_unit("ubuntu/1")
    juju.wait(
        lambda status: jubilant.all_active(status, "ubuntu"),
        error=jubilant.any_error,
        timeout=240,
    )
    # THEN Otelcol is in "Blocked" status with agent idle status
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        error=jubilant.any_error,
        timeout=240,
    )
    juju.wait(
        lambda status: jubilant.all_agents_idle(status, "otelcol"),
        error=jubilant.any_error,
        timeout=240,
    )
    # AND otelcol has a scale of 1
    assert juju.status().get_units("otelcol").keys() == {"otelcol/1"}

    # AND the otelcol config file for the second otelcol unit is now removed from disk
    config_filename = f"{SnapRegistrationFile._normalize_name('otelcol/2')}.yaml"
    otelcol_config = juju.ssh(
        "ubuntu/0",
        command=f'test -e {os.path.join(CONFIG_FOLDER, config_filename)} || echo "does not exist"',
    )
    assert otelcol_config.strip() == "does not exist"
    # AND the otelcol config directory remains on disk
    otelcol_config_dir = juju.ssh(
        "ubuntu/0", command=f'test -e {CONFIG_FOLDER} || echo "does not exist"'
    )
    assert otelcol_config_dir.strip() != "does not exist"

    # AND the snap is still active in the machine
    snap_status = ssh_and_execute_command_in_machine(juju, "ubuntu/0", SNAP_STATUS_COMMAND)
    assert is_snap_active(snap_status)

async def test_remove_two_subordinate_two_machines(juju: jubilant.Juju):
    # GIVEN otelcol has 2 subordinate units on different machines
    juju.add_unit("ubuntu")
    juju.wait(
        lambda status: jubilant.all_active(status, "ubuntu"),
        error=jubilant.any_error,
        timeout=240,
    )
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        error=jubilant.any_error,
        timeout=240,
    )
    # WHEN the relation is removed
    juju.remove_relation("otelcol:juju-info", "ubuntu:juju-info")
    juju.wait(
        lambda status: jubilant.all_active(status, "ubuntu"),
        error=jubilant.any_error,
        timeout=240,
    )
    # THEN Otelcol has "unknown" status and a scale of 0
    juju.wait(
        lambda status: status.apps["otelcol"].app_status.current == "unknown",
        error=jubilant.any_error,
        timeout=240,
    )
    assert juju.status().get_units("otelcol") == {}
    # AND there are no otelcol config files on disk
    otelcol_config_0 = juju.ssh(
        "ubuntu/0", command=f'test -e {CONFIG_FOLDER} || echo "does not exist"'
    )
    otelcol_config_1 = juju.ssh(
        "ubuntu/2", command=f'test -e {CONFIG_FOLDER} || echo "does not exist"'
    )
    assert otelcol_config_0.strip() == "does not exist"
    assert otelcol_config_1.strip() == "does not exist"

