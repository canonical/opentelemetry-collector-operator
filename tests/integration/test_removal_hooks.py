# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: COS Agent integration works as expected."""

import pathlib

import jubilant
from constants import CONFIG_PATH

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


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


async def test_remove_one_principal_one_machine(juju: jubilant.Juju):
    # GIVEN only 1 unit of the otelcol charm
    assert juju.status().get_units("otelcol").keys() == {"otelcol/0"}
    # WHEN the relation is removed
    juju.remove_relation("otelcol:juju-info", "zookeeper:juju-info")
    juju.wait(
        lambda status: jubilant.all_active(status, "zookeeper"),
        error=jubilant.any_error,
        timeout=120,
    )

    # THEN Otelcol has "unknown" status and a scale of 0
    juju.wait(
        lambda status: status.apps["otelcol"].app_status.current == "unknown",
        error=jubilant.any_error,
        timeout=120,
    )
    assert juju.status().get_units("otelcol") == {}

    # AND there is no otelcol config file on disk
    otelcol_config = juju.ssh(
        "zookeeper/0", command=f'test -e {CONFIG_PATH} || echo "does not exist"'
    )
    assert otelcol_config.strip() == "does not exist"


async def test_remove_two_principals_one_machine(juju: jubilant.Juju):
    # GIVEN otelcol has 2 subordinate units on the same machine
    juju.deploy("ubuntu", base="ubuntu@22.04", to="0")
    juju.integrate("otelcol:juju-info", "zookeeper:juju-info")
    # FIXME port registration conflict
    # juju.integrate("otelcol:juju-info", "ubuntu:juju-info")
    # juju.wait(
    #     lambda status: jubilant.all_blocked(status, "otelcol"),
    #     error=jubilant.any_error,
    #     timeout=120,
    # )
    # juju.wait(
    #     lambda status: jubilant.all_active(status, "ubuntu"),
    #     error=jubilant.any_error,
    #     timeout=120,
    # )

    # # WHEN the relation is removed
    # juju.remove_relation("otelcol:juju-info", "ubuntu:juju-info")
    # juju.wait(
    #     lambda status: jubilant.all_active(status, "ubuntu"),
    #     error=jubilant.any_error,
    #     timeout=120,
    # )

    # # THEN Otelcol has "unknown" status and a scale of 0
    # juju.wait(
    #     lambda status: status.apps["otelcol"].app_status.current == "unknown",
    #     error=jubilant.any_error,
    #     timeout=120,
    # )
    # assert juju.status().get_units("otelcol") == {}

    # # AND the otelcol config file remains on disk
    # otelcol_config = juju.ssh(
    #     "zookeeper/0", command=f'test -e {CONFIG_PATH} || echo "does not exist"'
    # )
    # assert otelcol_config.strip() != "does not exist"


async def test_remove_two_principals_two_machines(juju: jubilant.Juju):
    # GIVEN otelcol has 2 subordinate units on different machines
    juju.add_unit("zookeeper", num_units=1)
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        error=jubilant.any_error,
        timeout=480,
    )
    juju.wait(
        lambda status: jubilant.all_active(status, "zookeeper"),
        error=jubilant.any_error,
        timeout=480,
    )

    # WHEN the relation is removed
    juju.remove_relation("otelcol:juju-info", "zookeeper:juju-info")
    juju.wait(
        lambda status: jubilant.all_active(status, "zookeeper"),
        error=jubilant.any_error,
        timeout=120,
    )

    # THEN Otelcol has "unknown" status and a scale of 0
    juju.wait(
        lambda status: status.apps["otelcol"].app_status.current == "unknown",
        error=jubilant.any_error,
        timeout=120,
    )
    assert juju.status().get_units("otelcol") == {}

    # AND there are no otelcol config files on disk
    otelcol_config_0 = juju.ssh(
        "zookeeper/0", command=f'test -e {CONFIG_PATH} || echo "does not exist"'
    )
    otelcol_config_1 = juju.ssh(
        "zookeeper/1", command=f'test -e {CONFIG_PATH} || echo "does not exist"'
    )
    assert otelcol_config_0.strip() == "does not exist"
    assert otelcol_config_1.strip() == "does not exist"
