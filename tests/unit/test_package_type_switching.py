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


def test_apt_mode_installs_deb(ctx, mock_apt_operations):
    # GIVEN apt mode and the deb not yet installed
    with (
        patch("apt_management.install_package") as mock_install,
        patch("apt_management.ensure_service_running") as mock_ensure,
    ):
        # WHEN the reconciler runs
        ctx.run(ctx.on.config_changed(), State())
    # THEN the deb is installed with its stock configuration (no config calls exist)
    mock_install.assert_called_once_with(NODE_EXPORTER_APT_PACKAGE)
    # AND the service is kept running
    mock_ensure.assert_called_once_with("prometheus-node-exporter")


def test_apt_mode_skips_install_when_already_installed(ctx, mock_apt_operations):
    # GIVEN apt mode with the deb already installed
    mock_apt_operations["is_installed"].return_value = True
    with patch("apt_management.install_package") as mock_install:
        # WHEN the reconciler runs
        ctx.run(ctx.on.config_changed(), State())
    # THEN no reinstall happens
    mock_install.assert_not_called()


def test_apt_mode_does_not_configure_node_exporter(ctx, mock_apt_operations):
    # GIVEN apt mode
    with (
        patch("apt_management.install_package"),
        patch("charm.OpenTelemetryCollectorCharm._configure_node_exporter") as mock_cfg,
    ):
        # WHEN the reconciler runs
        ctx.run(ctx.on.config_changed(), State())
    # THEN the snap-flavor configuration path is never invoked (deb keeps stock config)
    mock_cfg.assert_not_called()


def test_switch_snap_to_apt_removes_snap(ctx, mock_apt_operations, mock_snap_operations):
    # GIVEN this unit previously registered the node-exporter snap (was in snap mode)
    # and the snap is present on the machine
    SingletonSnapManager("otelcol/0").register("node-exporter", 2)
    mock_snap_operations.present = True
    with (
        patch("charm.OpenTelemetryCollectorCharm._remove_snap") as mock_remove,
        patch("apt_management.install_package"),
    ):
        # WHEN the reconciler runs with package-type=apt
        ctx.run(ctx.on.config_changed(), State(config={"package-type": "apt"}))
    # THEN the snap is removed and the snap registration dropped
    mock_remove.assert_called_once_with("node-exporter")
    assert SingletonSnapManager.get_units("node-exporter") == set()
    assert SingletonSnapManager.get_units(NODE_EXPORTER_APT_PACKAGE) == {"otelcol_0"}


def test_switch_snap_to_apt_keeps_snap_used_by_other_unit(
    ctx, mock_apt_operations, mock_snap_operations
):
    # GIVEN another co-located unit still uses the node-exporter snap, which is present
    SingletonSnapManager("otelcol/0").register("node-exporter", 2)
    SingletonSnapManager("other/0").register("node-exporter", 2)
    mock_snap_operations.present = True
    with (
        patch("charm.OpenTelemetryCollectorCharm._remove_snap") as mock_remove,
        patch("apt_management.install_package"),
    ):
        # WHEN this unit switches to apt
        ctx.run(ctx.on.config_changed(), State(config={"package-type": "apt"}))
    # THEN the snap is NOT removed (still referenced by other/0)
    mock_remove.assert_not_called()
    # AND only this unit's snap registration is dropped
    assert SingletonSnapManager.get_units("node-exporter") == {"other_0"}


def test_switch_apt_to_snap_removes_deb_and_installs_snap(ctx, mock_apt_operations):
    # GIVEN this unit previously registered the deb (was in apt mode) and the deb is installed
    SingletonSnapManager("otelcol/0").register(NODE_EXPORTER_APT_PACKAGE, 0)
    mock_apt_operations["is_installed"].return_value = True
    with (
        patch("apt_management.remove_package") as mock_remove_deb,
        patch("charm.install_snap") as mock_install_snap,
    ):
        # WHEN the reconciler runs with package-type=snap
        ctx.run(ctx.on.config_changed(), State(config={"package-type": "snap"}))
    # THEN the deb is removed and its registration dropped
    mock_remove_deb.assert_called_once_with(NODE_EXPORTER_APT_PACKAGE)
    assert SingletonSnapManager.get_units(NODE_EXPORTER_APT_PACKAGE) == set()
    # AND the node-exporter snap is installed (snap.present is mocked False)
    assert "node-exporter" in {call.args[0] for call in mock_install_snap.call_args_list}
    assert SingletonSnapManager.get_units("node-exporter") == {"otelcol_0"}


def test_switch_apt_to_snap_keeps_deb_used_by_other_unit(ctx, mock_apt_operations):
    # GIVEN another co-located unit still uses the deb
    SingletonSnapManager("otelcol/0").register(NODE_EXPORTER_APT_PACKAGE, 0)
    SingletonSnapManager("other/0").register(NODE_EXPORTER_APT_PACKAGE, 0)
    mock_apt_operations["is_installed"].return_value = True
    with (
        patch("apt_management.remove_package") as mock_remove_deb,
        patch("charm.install_snap"),
    ):
        # WHEN this unit switches to snap
        ctx.run(ctx.on.config_changed(), State(config={"package-type": "snap"}))
    # THEN the deb is NOT removed
    mock_remove_deb.assert_not_called()
    assert SingletonSnapManager.get_units(NODE_EXPORTER_APT_PACKAGE) == {"other_0"}


def test_remove_hook_removes_deb_in_apt_mode(ctx, mock_apt_operations):
    # GIVEN apt mode with the deb installed and registered
    SingletonSnapManager("otelcol/0").register(NODE_EXPORTER_APT_PACKAGE, 0)
    mock_apt_operations["is_installed"].return_value = True
    with (
        patch("charm.event", return_value="remove"),
        patch("apt_management.remove_package") as mock_remove_deb,
    ):
        # WHEN the remove hook runs
        ctx.run(ctx.on.remove(), State())
    # THEN the deb is removed and unregistered
    mock_remove_deb.assert_called_once_with(NODE_EXPORTER_APT_PACKAGE)
    assert SingletonSnapManager.get_units(NODE_EXPORTER_APT_PACKAGE) == set()


def test_remove_hook_keeps_deb_used_by_other_unit(ctx, mock_apt_operations):
    # GIVEN the deb is also registered by another co-located unit
    SingletonSnapManager("otelcol/0").register(NODE_EXPORTER_APT_PACKAGE, 0)
    SingletonSnapManager("other/0").register(NODE_EXPORTER_APT_PACKAGE, 0)
    mock_apt_operations["is_installed"].return_value = True
    with (
        patch("charm.event", return_value="remove"),
        patch("apt_management.remove_package") as mock_remove_deb,
    ):
        # WHEN the remove hook runs
        ctx.run(ctx.on.remove(), State())
    # THEN the deb is kept for the other unit
    mock_remove_deb.assert_not_called()
    assert SingletonSnapManager.get_units(NODE_EXPORTER_APT_PACKAGE) == {"other_0"}
