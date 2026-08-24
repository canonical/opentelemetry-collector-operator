# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: switching node-exporter between snap and apt package sources."""

from unittest.mock import patch

from ops.testing import State

from constants import NODE_EXPORTER_APT_PACKAGE
from singleton_snap import SingletonSnapManager


def test_apt_mode_registers_deb_not_snap(ctx):
    # GIVEN the default (apt) package-type
    with patch("charm.event", return_value="install"), patch("charm.install_snap"):
        # WHEN the install hook runs
        ctx.run(ctx.on.install(), State())
    # THEN the unit is registered for the deb, not the node-exporter snap
    assert SingletonSnapManager.get_units(NODE_EXPORTER_APT_PACKAGE) == {"otelcol_0"}
    assert SingletonSnapManager.get_units("node-exporter") == set()
    # AND the otelcol snap is still registered
    assert SingletonSnapManager.get_units("opentelemetry-collector") == {"otelcol_0"}


def test_snap_mode_registers_snap_not_deb(ctx):
    # GIVEN package-type=snap
    with patch("charm.event", return_value="install"), patch("charm.install_snap"):
        # WHEN the install hook runs
        ctx.run(ctx.on.install(), State(config={"package-type": "snap"}))
    # THEN the unit is registered for the snap, not the deb
    assert SingletonSnapManager.get_units("node-exporter") == {"otelcol_0"}
    assert SingletonSnapManager.get_units(NODE_EXPORTER_APT_PACKAGE) == set()


def test_install_hook_does_not_install_node_exporter_snap_in_apt_mode(ctx):
    # GIVEN the default (apt) package-type
    with (
        patch("charm.event", return_value="install"),
        patch("charm.install_snap") as mock_install,
    ):
        # WHEN the install hook runs
        ctx.run(ctx.on.install(), State())
    # THEN only the otelcol snap is installed by the snap path
    installed = {call.args[0] for call in mock_install.call_args_list}
    assert "opentelemetry-collector" in installed
    assert "node-exporter" not in installed


def test_install_hook_installs_node_exporter_snap_in_snap_mode(ctx):
    # GIVEN package-type=snap
    with (
        patch("charm.event", return_value="install"),
        patch("charm.install_snap") as mock_install,
    ):
        # WHEN the install hook runs
        ctx.run(ctx.on.install(), State(config={"package-type": "snap"}))
    # THEN both snaps are installed
    installed = {call.args[0] for call in mock_install.call_args_list}
    assert installed == {"opentelemetry-collector", "node-exporter"}
