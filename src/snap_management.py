#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# Learn more at: https://juju.is/docs/sdk

"""Snap Installation Module.

Modified from https://github.com/canonical/k8s-operator/blob/main/charms/worker/k8s/src/snap.py
"""

import logging
import platform
from typing import Dict, Optional

import charms.operator_libs_linux.v2.snap as snap_lib
from charms.operator_libs_linux.v2.snap import JSONAble

# Log messages can be retrieved using juju debug-log
log = logging.getLogger(__name__)


opentelemetry_collector_snap_name = "opentelemetry-collector"
node_exporter_snap_name = "node-exporter"

snap_maps = {
    opentelemetry_collector_snap_name: {
        # (confinement, arch): revision
        ("strict", "amd64"): "9",  # 0.119.0
        ("strict", "arm64"): "10",  # 0.119.0
    },
    node_exporter_snap_name: {
        # (confinement, arch): revision
        ("strict", "amd64"): "1904",  # v1.9.1
        ("strict", "arm64"): "1908",  # v1.9.1
    }
}

class SnapSpecError(Exception):
    """Custom exception type for errors related to the snap spec."""
    pass


class SnapError(Exception):
    """Custom exception type for Snaps."""
    pass


class SnapInstallError(SnapError):
    """Custom exception type for install related errors."""
    pass


class SnapServiceError(SnapError):
    """Custom exception type for service related errors."""
    pass


def install_snap(snap: str, classic: bool = False, config: Optional[Dict[str, JSONAble]] = None):
    """Looks up system details and installs the appropriate snap revision."""
    arch = get_system_arch()
    confinement = "classic" if classic else "strict"

    try:
        revision = snap_maps[snap][(confinement, arch)]
    except KeyError as e:
        raise SnapSpecError(
            f"{snap} snap spec not found for arch={arch} and confinement={confinement}"
        ) from e

    _install_snap(name=snap, revision=revision, classic=classic, config=config)


def _install_snap(
    name: str,
    revision: str,
    classic: bool = False,
    config: Optional[Dict[str, JSONAble]] = None,
):
    """Install and pin the given snap revision.

    The revision will be held, i.e. it won't be automatically updated any time a new revision is released.
    """
    cache = snap_lib.SnapCache()
    snap = cache[name]
    log.info(
        f"Ensuring {name} snap is installed at revision={revision}"
        f" with classic confinement={classic}"
    )
    snap.ensure(state=snap_lib.SnapState.Present, revision=revision, classic=classic)
    if config:
        snap.set(config)
    snap.hold()


def get_system_arch() -> str:
    """Returns the architecture of this machine, mapping some values to amd64 or arm64.

    If platform is x86_64 or amd64, it returns amd64.
    If platform is aarch64, arm64, armv8b, or armv8l, it returns arm64.
    """
    arch = platform.processor()
    if arch in ["x86_64", "amd64"]:
        arch = "amd64"
    elif arch in ["aarch64", "arm64", "armv8b", "armv8l"]:
        arch = "arm64"
    # else: keep arch as is
    return arch
