# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: traces are forwarded to multiple Tempo backends simultaneously."""

import os

import jubilant

from constants import CONFIG_FOLDER
from helpers import PATH_EXCLUDE, get_otelcol_config
from singleton_snap import SnapRegistrationFile

OTELCOL_CONFIG_FILE = os.path.join(
    CONFIG_FOLDER, f"{SnapRegistrationFile._normalize_name('otelcol/0')}.yaml"
)


async def test_deploy(juju: jubilant.Juju, charm_22_04: str):
    """Deploy otelcol and two backend otelcol apps, wire both as send-traces targets."""
    # GIVEN an otelcol and two backends — each as a subordinate to its own ubuntu principal
    juju.deploy("ubuntu", app="ubuntu-main", base="ubuntu@22.04", channel="latest/stable")
    juju.deploy("ubuntu", app="ubuntu-b1", base="ubuntu@22.04", channel="latest/stable")
    juju.deploy("ubuntu", app="ubuntu-b2", base="ubuntu@22.04", channel="latest/stable")

    juju.deploy(
        charm_22_04,
        app="otelcol",
        config={"path_exclude": PATH_EXCLUDE, "debug_exporter_for_traces": "true"},
    )
    juju.deploy(charm_22_04, app="otelcol-b1", config={"path_exclude": PATH_EXCLUDE})
    juju.deploy(charm_22_04, app="otelcol-b2", config={"path_exclude": PATH_EXCLUDE})

    juju.integrate("otelcol:juju-info", "ubuntu-main:juju-info")
    juju.integrate("otelcol-b1:juju-info", "ubuntu-b1:juju-info")
    juju.integrate("otelcol-b2:juju-info", "ubuntu-b2:juju-info")

    # WHEN both backends are wired to otelcol via send-traces
    juju.integrate("otelcol:send-traces", "otelcol-b1:receive-traces")
    juju.integrate("otelcol:send-traces", "otelcol-b2:receive-traces")

    # THEN all units settle — blocked is expected (no data sink configured)
    # Only check ubuntu apps for errors here; otelcol errors are caught in the next wait.
    juju.wait(
        lambda status: jubilant.all_active(status, "ubuntu-main", "ubuntu-b1", "ubuntu-b2"),
        error=lambda status: jubilant.any_error(status, "ubuntu-main", "ubuntu-b1", "ubuntu-b2"),
        timeout=420,
    )
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol", "otelcol-b1", "otelcol-b2"),
        error=jubilant.any_error,
        timeout=420,
    )
    juju.wait(
        lambda status: jubilant.all_agents_idle(
            status, "otelcol", "otelcol-b1", "otelcol-b2", "ubuntu-main", "ubuntu-b1", "ubuntu-b2"
        ),
        timeout=120,
    )


async def test_two_exporters_in_config(juju: jubilant.Juju):
    """Both send-traces relations produce distinct exporters wired into the traces pipeline."""
    # GIVEN otelcol settled with two send-traces relations
    cfg = get_otelcol_config(juju, "ubuntu-main/0", OTELCOL_CONFIG_FILE)

    # THEN two otlphttp/send-traces-* exporters exist — one per backend
    send_traces_exporters = [k for k in cfg["exporters"] if k.startswith("otlphttp/send-traces-")]
    assert len(send_traces_exporters) == 2, (
        f"Expected 2 send-traces exporters, got {send_traces_exporters}"
    )

    # AND both are wired into the traces pipeline
    pipeline_exporters = cfg["service"]["pipelines"]["traces/otelcol/0"]["exporters"]
    for exporter_name in send_traces_exporters:
        assert exporter_name in pipeline_exporters, (
            f"{exporter_name} not found in traces pipeline: {pipeline_exporters}"
        )


async def test_no_ambiguous_relation_error(juju: jubilant.Juju):
    """No unit enters error state, which is what AmbiguousRelationUsageError would cause."""
    # An unhandled AmbiguousRelationUsageError in a charm hook drives the unit into
    # error state. Asserting clean status is more reliable than grepping log output,
    # which is subject to timing and buffering.
    assert not jubilant.any_error(juju.status())


async def test_relation_removal_reconfigures_cleanly(juju: jubilant.Juju):
    """Removing one send-traces relation drops its exporter and leaves the other intact."""
    # WHEN one backend relation is removed
    juju.remove_relation("otelcol:send-traces", "otelcol-b2:receive-traces")
    juju.wait(
        lambda status: jubilant.all_agents_idle(status, "otelcol"),
        timeout=120,
    )

    # THEN exactly one send-traces exporter remains in the config
    cfg = get_otelcol_config(juju, "ubuntu-main/0", OTELCOL_CONFIG_FILE)
    send_traces_exporters = [k for k in cfg["exporters"] if k.startswith("otlphttp/send-traces-")]
    assert len(send_traces_exporters) == 1, (
        f"Expected 1 send-traces exporter after removal, got {send_traces_exporters}"
    )

    # AND no unit entered error state during reconfiguration
    assert not jubilant.any_error(juju.status())
