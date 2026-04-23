# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Regression test: charm refresh correctly updates snaps and lockfiles.

This test verifies the fix for the bug where `juju refresh` failed to update
the installed snaps. The root cause was that charm.py checked for
event() == "upgrade" instead of the correct "upgrade-charm", so _install_snaps()
was never called during a charm refresh. The result was a BlockedStatus with
"Mismatching snap revisions" on subsequent refreshes.
"""

import subprocess
from pathlib import Path

import jubilant
import pytest
from pytest_jubilant import pack

from helpers import PATH_EXCLUDE
from singleton_snap import SnapRegistrationFile

LOCK_DIR = "/opt/singleton_snaps"
REPO_ROOT = Path(__file__).resolve().parents[2]

# Old charm revision to deploy initially, before refreshing to the current build.
OLD_CHARM_REVISION = 149
OLD_CHARM_CHANNEL = "2/stable"

# Snaps managed by this charm whose lockfiles we verify.
MANAGED_SNAPS = ("node-exporter", "opentelemetry-collector")


@pytest.fixture(scope="module")
def refreshed_charm() -> str:
    """Always pack the charm from current source, bypassing any cached CHARM_PATH.

    This regression test must validate the actual current source code, not a
    pre-built artifact that may predate the fix.
    """
    for _ in range(3):
        try:
            return str(pack(REPO_ROOT, platform="ubuntu@22.04:amd64"))
        except subprocess.CalledProcessError:
            continue
    raise subprocess.CalledProcessError(1, "charmcraft pack")


def _get_lockfile_revision(juju: jubilant.Juju, snap_name: str) -> int | None:
    """Return the snap revision recorded in the lockfile for snap_name, or None if absent."""
    raw = juju.ssh("ubuntu/0", command=f"ls {LOCK_DIR} 2>/dev/null || true").strip()
    for filename in raw.split():
        try:
            reg = SnapRegistrationFile.from_filename(filename)
        except (ValueError, IndexError):
            continue
        if reg.snap_name == snap_name:
            return reg.snap_revision
    return None


def _get_all_lockfiles(juju: jubilant.Juju) -> str:
    """Return the contents of the singleton snap lock directory for diagnostics."""
    return juju.ssh("ubuntu/0", command=f"ls -1 {LOCK_DIR} 2>/dev/null || echo '(empty)'")


def _get_installed_snap_revision(juju: jubilant.Juju, snap_name: str, unit: str) -> int:
    """Return the revision of the currently installed snap on ubuntu/0.

    Parses the output of `snap list <snap_name>`:
      Name           Version  Rev   Tracking  Publisher  Notes
      node-exporter  1.9.0    1904  ...
    """
    output = juju.ssh(unit, command=f"snap list {snap_name} --unicode=never")
    parts = output.strip().splitlines()[1].split()
    return int(parts[2])


def test_deploy_old_charm_revision(juju: jubilant.Juju):
    """Deploy ubuntu and otelcol at an old charm revision to establish a baseline."""
    # GIVEN a fresh Juju model
    # WHEN ubuntu and otelcol (old revision) are deployed and integrated
    juju.deploy("ubuntu", channel="latest/stable", base="ubuntu@22.04")
    juju.deploy(
        "opentelemetry-collector",
        app="otelcol",
        channel=OLD_CHARM_CHANNEL,
        revision=OLD_CHARM_REVISION,
        base="ubuntu@22.04",
        config={"path_exclude": PATH_EXCLUDE},
    )
    juju.integrate("otelcol:juju-info", "ubuntu:juju-info")
    # THEN ubuntu becomes active and all agents settle to idle
    juju.wait(
        lambda status: jubilant.all_active(status, "ubuntu"),
        error=jubilant.any_error,
        timeout=600,
    )
    juju.wait(
        lambda status: jubilant.all_agents_idle(status, "ubuntu", "otelcol"),
        timeout=600,
    )


def test_lockfile_matches_installed_snap_before_refresh(juju: jubilant.Juju):
    """Check: the lockfile revision must match the installed snap revision after deploy."""
    # GIVEN otelcol deployed at the old charm revision
    # WHEN we inspect the singleton snap lockfiles and the installed snap revisions
    for snap_name in MANAGED_SNAPS:
        lockfile_rev = _get_lockfile_revision(juju, snap_name)
        installed_rev = _get_installed_snap_revision(juju, snap_name, "ubuntu/0")

        # THEN each lockfile exists and its revision matches the installed snap
        assert lockfile_rev is not None, f"No {snap_name} lockfile found in {LOCK_DIR}"
        assert lockfile_rev == installed_rev, (
            f"{snap_name}: lockfile points to rev{lockfile_rev} "
            f"but snap rev{installed_rev} is installed"
        )


def test_refresh_to_current_charm(juju: jubilant.Juju, refreshed_charm: str):
    """Refresh otelcol to the locally built charm and wait for it to settle.

    After the fix, the upgrade-charm hook correctly calls _install_snaps(),
    which installs the new snap revision and updates the lockfile.
    """
    # GIVEN otelcol running at the old charm revision with its lockfiles in place
    # WHEN the charm is refreshed to the locally built version (containing the fix)
    juju.refresh("otelcol", path=refreshed_charm)
    # THEN ubuntu stays active and all agents settle to idle (no hook errors)
    juju.wait(
        lambda status: jubilant.all_active(status, "ubuntu"),
        error=jubilant.any_error,
        timeout=600,
    )
    juju.wait(
        lambda status: jubilant.all_agents_idle(status, "ubuntu", "otelcol"),
        timeout=600,
    )


def test_lockfile_matches_installed_snap_after_refresh(juju: jubilant.Juju):
    """After refresh, lockfiles and snaps must be consistent and the charm must not be blocked.

    PRIMARY regression check: otelcol units must not report "Mismatching snap revisions".
    Before the fix, upgrade-charm never called _install_snaps(), so the old lockfile
    (rev X) remained on disk while the new charm tried to register rev Y, triggering
    that blocked message on every subsequent hook.

    SECONDARY check: each lockfile revision must equal the installed snap revision,
    confirming the charm registered and installed consistently.
    """
    # GIVEN otelcol has been refreshed to the locally built charm
    # WHEN we inspect the unit workload status and the singleton snap lockfiles
    status = juju.status()
    lockfiles = _get_all_lockfiles(juju)

    # THEN no otelcol unit reports "Mismatching snap revisions" (primary regression check)
    for unit_name, unit in status.apps["otelcol"].units.items():
        msg = unit.workload_status.message
        assert "Mismatching snap revisions" not in msg, (
            f"After refresh, {unit_name!r} is blocked: {msg!r}\n"
            f"This indicates upgrade-charm did not call _install_snaps().\n"
            f"Lock dir contents:\n{lockfiles}"
        )

    # AND each lockfile revision matches the installed snap revision
    for snap_name in MANAGED_SNAPS:
        lockfile_rev = _get_lockfile_revision(juju, snap_name)
        installed_rev = _get_installed_snap_revision(juju, snap_name, "ubuntu/0")

        assert lockfile_rev is not None, (
            f"No {snap_name} lockfile found in {LOCK_DIR} after refresh.\n"
            f"Lock dir contents:\n{lockfiles}"
        )
        assert lockfile_rev == installed_rev, (
            f"After refresh: {snap_name} lockfile at rev{lockfile_rev} "
            f"but snap rev{installed_rev} is installed.\n"
            f"Lock dir contents:\n{lockfiles}"
        )

    # AND ubuntu remains active and idle
    assert jubilant.all_active(status, "ubuntu")
    assert jubilant.all_agents_idle(status, "ubuntu")
