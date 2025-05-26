#!/usr/bin/env python3
# Copyright 2025 jose
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk
"""A Juju charm for OpenTelemetry Collector on machines."""

import logging
import ops
from charms.operator_libs_linux.v2 import snap  # type: ignore
from ops.model import ActiveStatus, MaintenanceStatus
from snap_management import SnapSpecError, SnapInstallError, SnapServiceError, install_snap, node_exporter_snap_name, opentelemetry_collector_snap_name

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)
VALID_LOG_LEVELS = ["info", "debug", "warning", "error", "critical"]


class OpentelemetryCollectorOperatorCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self._reconcile()

    def _reconcile(self):

        for snap_package in [opentelemetry_collector_snap_name, node_exporter_snap_name]:
            self._install_snap(snap_package)
            self._start_snap(snap_package)

        self.unit.status = ActiveStatus()


    def _install_snap(self, snap_name: str) -> None:
        self.unit.status = MaintenanceStatus(f"Installing {snap_name} snap")
        try:
            install_snap(snap_name)
        except (snap.SnapError, SnapSpecError) as e:
            raise SnapInstallError(f"Failed to install {snap_name}") from e


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


if __name__ == "__main__":  # pragma: nocover
    ops.main(OpentelemetryCollectorOperatorCharm)
