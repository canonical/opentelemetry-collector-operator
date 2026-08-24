# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Apt Package Management Module.

Counterpart of snap_management.py for the apt-installed node-exporter
(the `prometheus-node-exporter` deb from the Ubuntu archive).

By design this module only installs/removes the package and keeps its service
running. It never writes the deb's configuration (/etc/default/...): the
package runs with its stock defaults.
"""

import logging

import charms.operator_libs_linux.v0.apt as apt
import charms.operator_libs_linux.v1.systemd as systemd

log = logging.getLogger(__name__)


class AptError(Exception):
    """Base exception for all apt-related errors."""


class AptInstallError(AptError):
    """Raised when there's an error installing a deb package."""


def is_installed(package_name: str) -> bool:
    """Return True if the deb package is installed."""
    try:
        apt.DebianPackage.from_installed_package(package_name)
        return True
    except apt.PackageNotFoundError:
        return False


def install_package(package_name: str) -> None:
    """Install a deb package from the Ubuntu archive with its stock configuration.

    Raises:
        AptInstallError: if the package cannot be found or installed.
    """
    try:
        apt.add_package(package_name, update_cache=True)
        log.info(f"{package_name} deb has been installed")
    except (apt.PackageNotFoundError, apt.PackageError) as e:
        raise AptInstallError(f"Failed to install {package_name} from apt") from e


def remove_package(package_name: str) -> None:
    """Remove a deb package. Missing packages are ignored."""
    try:
        apt.remove_package(package_name)
        log.info(f"{package_name} deb has been removed")
    except apt.PackageNotFoundError:
        log.debug(f"{package_name} deb was not installed; nothing to remove")


def ensure_service_running(service_name: str) -> None:
    """Start the service if it is not running.

    Debs auto-start their service on install, but the service can be down if it
    failed to bind its port while the other node-exporter flavor still held it.
    """
    if not systemd.service_running(service_name):
        systemd.service_restart(service_name)
