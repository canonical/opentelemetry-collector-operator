# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: node-exporter installed from apt (prometheus-node-exporter deb)."""

from unittest.mock import patch

import pytest

import apt_management


def test_is_installed_true_and_false():
    with patch.object(apt_management.apt, "DebianPackage") as pkg:
        # GIVEN the package resolves as installed
        pkg.from_installed_package.return_value = object()
        # THEN is_installed is True
        assert apt_management.is_installed("prometheus-node-exporter") is True
        # GIVEN the package is not installed
        pkg.from_installed_package.side_effect = apt_management.apt.PackageNotFoundError("nope")
        # THEN is_installed is False
        assert apt_management.is_installed("prometheus-node-exporter") is False


def test_install_package_delegates_to_apt_lib():
    with patch.object(apt_management.apt, "add_package") as add:
        apt_management.install_package("prometheus-node-exporter")
    add.assert_called_once_with("prometheus-node-exporter", update_cache=True)


def test_install_package_raises_apt_install_error():
    with patch.object(
        apt_management.apt, "add_package", side_effect=apt_management.apt.PackageError("boom")
    ):
        with pytest.raises(apt_management.AptInstallError):
            apt_management.install_package("prometheus-node-exporter")


def test_remove_package_tolerates_missing_package():
    with patch.object(
        apt_management.apt,
        "remove_package",
        side_effect=apt_management.apt.PackageNotFoundError("nope"),
    ):
        # THEN no exception propagates
        apt_management.remove_package("prometheus-node-exporter")


def test_ensure_service_running_restarts_stopped_service():
    with (
        patch.object(apt_management.systemd, "service_running", return_value=False),
        patch.object(apt_management.systemd, "service_restart") as restart,
    ):
        # WHEN the service is not running
        apt_management.ensure_service_running("prometheus-node-exporter")
    # THEN it is restarted
    restart.assert_called_once_with("prometheus-node-exporter")


def test_ensure_service_running_noop_when_running():
    with (
        patch.object(apt_management.systemd, "service_running", return_value=True),
        patch.object(apt_management.systemd, "service_restart") as restart,
    ):
        # WHEN the service is already running
        apt_management.ensure_service_running("prometheus-node-exporter")
    # THEN nothing is restarted (stock config is never touched either)
    restart.assert_not_called()
