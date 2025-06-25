#!/usr/bin/env python3
# Copyright 2025 jose
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk
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
    get_system_arch,
    install_snap,
    node_exporter_snap_name,
    opentelemetry_collector_snap_name,
    snap_maps,
)
from singleton_snap import SingletonSnapManager

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)
VALID_LOG_LEVELS = ["info", "debug", "warning", "error", "critical"]

SNAPS = [opentelemetry_collector_snap_name, node_exporter_snap_name]


class OpentelemetryCollectorOperatorCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self._reconcile()

    def _reconcile(self):
        self._install()
        self._stop()
        self.unit.status = ActiveStatus()

    def _install(self) -> None:
        if self.hook != "install":
            return

        manager = SingletonSnapManager(self.unit.name)
        arch = get_system_arch()

        for snap_package in SNAPS:
            snap_revision = snap_maps[snap_package][("strict", arch)]
            manager.register(snap_package, snap_revision)
            with manager.snap_operation(snap_package):
                if snap_revision > max(manager.get_revisions(snap_package)):
                    self._install_snap(snap_package)
                    self._start_snap(snap_package)

            with manager.config_operation(snap_package):
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
        if self.hook != "stop":
            return

        manager = SingletonSnapManager(self.unit.name)
        for snap_package in SNAPS:
            manager.unregister(snap_package)
            with manager.snap_operation(snap_package):
                if not manager.is_used_by_other_units(snap_package):
                    self._remove_snap(snap_package)

    def _install_snap(self, snap_name: str) -> None:
        self.unit.status = MaintenanceStatus(f"Installing {snap_name} snap")
        try:
            install_snap(snap_name)
        except (snap.SnapError, SnapSpecError) as e:
            raise SnapInstallError(f"Failed to install {snap_name}") from e

    def _remove_snap(self, snap_name: str) -> None:
        self.unit.status = MaintenanceStatus(f"Uninstalling {snap_name} snap")
        try:
            self.snap(snap_name).ensure(state=snap.SnapState.Absent)
        except (snap.SnapError, SnapSpecError) as e:
            raise SnapInstallError(f"Failed to uninstall {snap_name}") from e

    def _start_snap(self, snap_name: str) -> None:
        self.unit.status = MaintenanceStatus(f"Starting {snap_name} snap")

        try:
            self.snap(snap_name).start(enable=True)
        except snap.SnapError as e:
            raise SnapServiceError(f"Failed to start {snap_name}") from e

    def snap(self, snap_name: str):
        """Return the snap object for the given snap."""
        # This is handled in a property to avoid calls to snapd until they're necessary.
        return snap.SnapCache()[snap_name]

    @property
    def hook(self) -> str:
        """Return hook name."""
        return os.environ["JUJU_HOOK_NAME"]


if __name__ == "__main__":  # pragma: nocover
    ops.main(OpentelemetryCollectorOperatorCharm)
