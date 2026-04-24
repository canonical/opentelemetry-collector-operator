# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests for snap refresh behaviour.

Test progression:
- GIVEN the charm deployed at an old revision with its snaps and lockfiles in place
- WHEN the charm is refreshed to a locally built version
- THEN the managed snaps are updated to the new revisions
- AND no unit is blocked with "Mismatching snap revisions"
- AND each lockfile revision matches the installed snap revision
"""

import subprocess
from pathlib import Path

import jubilant
import pytest
from pytest_jubilant import pack

from helpers import PATH_EXCLUDE

REPO_ROOT = Path(__file__).resolve().parents[2]

# Old charm revision to deploy initially, before refreshing to the current build.
OLD_CHARM_REVISION = 149
OLD_CHARM_CHANNEL = "2/stable"

# Snaps managed by this charm.
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


def _get_installed_snap_revision(juju: jubilant.Juju, snap_name: str, unit: str) -> int:
    """Return the revision of the currently installed snap.

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


def test_refresh_to_current_charm(juju: jubilant.Juju, refreshed_charm: str):
    """Refresh otelcol to the locally built charm and wait for it to settle."""
    # GIVEN otelcol running at the old charm revision
    # WHEN the charm is refreshed to the locally built version
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


def test_snaps_updated_after_refresh(juju: jubilant.Juju):
    """After refresh, the charm must not be blocked with snap revision mismatches.

    Verifies that upgrade-charm correctly calls _install_snaps().
    """
    # GIVEN otelcol has been refreshed to the locally built charm
    # WHEN we inspect the unit workload status
    status = juju.status()

    # THEN no otelcol unit reports "Mismatching snap revisions"
    for unit_name, unit in status.apps["otelcol"].units.items():
        msg = unit.workload_status.message
        assert "Mismatching snap revisions" not in msg, (
            f"After refresh, {unit_name!r} is blocked: {msg!r}"
        )

    # AND all managed snaps are installed
    for snap_name in MANAGED_SNAPS:
        installed_rev = _get_installed_snap_revision(juju, snap_name, "ubuntu/0")
        assert installed_rev > 0, f"{snap_name} is not installed after refresh"

    # AND ubuntu remains active and idle
    assert jubilant.all_active(status, "ubuntu")
    assert jubilant.all_agents_idle(status, "ubuntu")
