#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on machines."""

import logging
import ops
import os
from charms.operator_libs_linux.v2 import snap  # type: ignore
from ops.model import ActiveStatus, MaintenanceStatus
from snap_management import (
    SnapSpecError,
    SnapInstallError,
    SnapServiceError,
    install_snap,
    SnapMap,
)
from singleton_snap import SingletonSnapManager

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)
VALID_LOG_LEVELS = ["info", "debug", "warning", "error", "critical"]


def hook() -> str:
    """Return Juju hook name."""
    return os.environ["JUJU_HOOK_NAME"]


class OpentelemetryCollectorOperatorCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        if hook() == "install":
            self._install()
        if hook() == "stop":
            self._stop()
        self._reconcile()

    def _reconcile(self):
        # TODO: when removing the locking mechanism, change manager.get_revisions
        # to a free function, and use it to set to BlockedStatus on update-status
        # if the installed snap revision (max(get_revisions())) doesn't match the
        # one required by the charm.
        self.unit.status = ActiveStatus()

    def _install(self) -> None:
        manager = SingletonSnapManager(self.unit.name)

        for snap_name in SnapMap.snaps():
            snap_revision = SnapMap.get_revision(snap_name)
            manager.register(snap_name, snap_revision)
            if snap_revision > max(manager.get_revisions(snap_name)):
                # Install the snap
                self.unit.status = MaintenanceStatus(f"Installing {snap_name} snap")
                install_snap(snap_name)
                # Start the snap
                self.unit.status = MaintenanceStatus(f"Starting {snap_name} snap")
                try:
                    self.snap(snap_name).start(enable=True)
                except snap.SnapError as e:
                    raise SnapServiceError(f"Failed to start {snap_name}") from e

            # Merge configurations under a directory into one,
            # and write it to the default otelcol config file.
            # This is a placeholder for actual configuration merging logic.
            # For example:
            #
            # content = merge_config()
            # with open('etc/otelcol/config.yaml', 'w') as f:
            #     f.write(content)
            #     f.flush()
            pass

    def _stop(self) -> None:
        manager = SingletonSnapManager(self.unit.name)
        for snap_name in SnapMap.snaps():
            snap_revision = SnapMap.get_revision(snap_name)
            manager.unregister(snap_name, snap_revision)
            if not manager.is_used_by_other_units(snap_name):
                # Remove the snap
                self.unit.status = MaintenanceStatus(f"Uninstalling {snap_name} snap")
                try:
                    self.snap(snap_name).ensure(state=snap.SnapState.Absent)
                except (snap.SnapError, SnapSpecError) as e:
                    raise SnapInstallError(f"Failed to uninstall {snap_name}") from e

    def snap(self, snap_name: str) -> snap.Snap:
        """Return the snap object for the given snap.

        This method provides lazy initialization of snap objects, avoiding unnecessary
        calls to snapd until they're actually needed.
        """
        return snap.SnapCache()[snap_name]


if __name__ == "__main__":  # pragma: nocover
    ops.main(OpentelemetryCollectorOperatorCharm)
