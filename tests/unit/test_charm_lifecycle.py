# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Regression tests for charm lifecycle hooks (install, upgrade-charm, remove)."""

from unittest.mock import patch

from ops.testing import State

from charm import OpenTelemetryCollectorCharm
from singleton_snap import SingletonSnapManager, SnapRegistrationFile


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


def test_deleted_lockfile_is_recreated_on_any_hook(ctx, mock_lock_dir):
    """Refs https://github.com/canonical/opentelemetry-collector-operator/issues/208.

    Registering only on install/upgrade-charm meant a lockfile deleted out of band stayed
    missing, which in turn wedged the unit in BlockedStatus until the next `juju refresh`.
    """
    # GIVEN no lockfiles exist, i.e. they were deleted out of band
    # WHEN an ordinary hook executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), State())
    # THEN this unit is registered again for every managed snap
    assert SingletonSnapManager.get_units("opentelemetry-collector") == {"otelcol_0"}
    assert SingletonSnapManager.get_units("node-exporter") == {"otelcol_0"}
    # AND the unit is not blocked on a bogus revision mismatch
    assert state_out.unit_status.name == "active"


def test_registration_does_not_hide_a_co_located_revision_mismatch(ctx, mock_lock_dir):
    """Re-registering must not neuter the co-tenancy check.

    The snap is shared by every collector unit on a machine, so a unit pinning an older
    revision than a co-located one must still block.
    """
    # GIVEN a co-located unit registered for a newer node-exporter revision than this unit
    # pins (mocked to 2)
    mock_lock_dir.mkdir(parents=True, exist_ok=True)
    other_unit = SnapRegistrationFile(
        unit_name="otelcol/1", snap_name="node-exporter", snap_revision=99
    )
    (mock_lock_dir / other_unit.filename).touch()
    # WHEN the reconciler runs
    state_out = ctx.run(ctx.on.update_status(), State())
    # THEN this unit still blocks on the mismatch
    assert state_out.unit_status.name == "blocked"
    assert "Mismatching snap revisions for node-exporter" in state_out.unit_status.message
    # AND the co-located unit's registration was left untouched
    assert SingletonSnapManager.get_units("node-exporter") == {"otelcol_0", "otelcol_1"}
