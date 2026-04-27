# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Regression tests for charm lifecycle hooks (install, upgrade-charm, remove)."""

from unittest.mock import patch

from ops.testing import State

from charm import OpenTelemetryCollectorCharm


def test_install_snaps_called_on_upgrade_charm(ctx):
    """_install_snaps is called on upgrade-charm."""
    with (
        patch("charm.event", return_value="upgrade-charm"),
        patch.object(OpenTelemetryCollectorCharm, "_install_snaps") as mock_install,
    ):
        ctx.run(ctx.on.upgrade_charm(), State())
    mock_install.assert_called_once()


def test_install_snaps_called_on_install(ctx):
    """Check: _install_snaps must be called on the install hook."""
    with (
        patch("charm.event", return_value="install"),
        patch.object(OpenTelemetryCollectorCharm, "_install_snaps") as mock_install,
    ):
        ctx.run(ctx.on.install(), State())
    mock_install.assert_called_once()


def test_install_snaps_not_called_on_other_hooks(ctx):
    """_install_snaps must NOT be called on regular hooks like update-status."""
    with (
        patch("charm.event", return_value="update-status"),
        patch.object(OpenTelemetryCollectorCharm, "_install_snaps") as mock_install,
    ):
        ctx.run(ctx.on.update_status(), State())
    mock_install.assert_not_called()
