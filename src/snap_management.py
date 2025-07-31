# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Snap Installation Module.

Modified from https://github.com/canonical/k8s-operator/blob/main/charms/worker/k8s/src/snap.py
"""

import logging
import platform
from typing import Dict, Optional, Set

import charms.operator_libs_linux.v2.snap as snap_lib
from charms.operator_libs_linux.v2.snap import JSONAble

log = logging.getLogger(__name__)


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


class SnapMap:
    """Maps snap revisions based on architecture and confinement mode.

    This class maintains a mapping of snap revisions for different combinations
    of architecture and confinement mode. It's used to determine the correct
    revision of a snap to install based on the system's architecture and the
    desired confinement mode.
    """

    snap_maps = {
        "opentelemetry-collector": {
            # (confinement, arch): revision
            ("strict", "amd64"): 18,  # 0.128.0
            ("strict", "arm64"): 10,  # 0.119.0  # FIXME: ARM release is currently failing
        },
        "node-exporter": {
            # (confinement, arch): revision
            ("strict", "amd64"): 1904,  # v1.9.1
            ("strict", "arm64"): 1908,  # v1.9.1
        },
    }

    @staticmethod
    def get_revision(snap_name: str, classic: bool = False, arch: str = get_system_arch()) -> int:
        """Get the target revision of a snap based on confinement and arch."""
        confinement = "classic" if classic else "strict"
        return SnapMap.snap_maps[snap_name][(confinement, arch)]

    @staticmethod
    def snaps() -> Set[str]:
        """Return a Set with all the snap names managed by the map."""
        return set(SnapMap.snap_maps.keys())


class SnapSpecError(Exception):
    """Raised when there's an error with the snap specification.

    This exception is raised when a requested snap or revision is not found
    in the SnapMap for the current system configuration.
    """


class SnapError(Exception):
    """Base exception for all snap-related errors."""


class SnapInstallError(SnapError):
    """Raised when there's an error installing a snap."""


class SnapServiceError(SnapError):
    """Raised when there's an error managing a snap service.

    This exception is raised when there's an error starting, stopping,
    or otherwise managing a snap's service.
    """


def install_snap(
    snap_name: str,
    classic: bool = False,
    config: Optional[Dict[str, JSONAble]] = None,
) -> None:
    """Install a snap and pin it to a specific revision.

    This function installs the specified snap, configures it according to the
    provided parameters, and pins it to prevent automatic updates. The revision
    is determined based on the system architecture and requested confinement mode,
    as defined in the SnapMap.

    Args:
        snap_name: Name of the snap to install (e.g., 'opentelemetry-collector')
        classic: If True, uses classic confinement. Defaults to False for strict confinement.
        config: Optional dictionary of configuration options to apply to the snap.
               The keys should be valid configuration options for the snap.

    Raises:
        SnapSpecError: If the snap or revision is not found in the SnapMap
        SnapInstallError: If there's an error during installation or configuration
        snap.SnapError: For errors from the underlying snap management library
    """
    # Check whether we have a spec in the SnapMap
    try:
        revision = SnapMap.get_revision(snap_name, classic=classic)
    except KeyError as e:
        raise SnapSpecError(
            f"Failed to install snap {snap_name}: "
            f"snap spec not found for arch={get_system_arch()} "
            f"and confinement={'classic' if classic else 'strict'}"
        ) from e
    # Install the Snap
    cache = snap_lib.SnapCache()
    snap = cache[snap_name]
    snap.ensure(state=snap_lib.SnapState.Present, revision=str(revision), classic=classic)
    log.info(
        f"{snap_name} snap has been installed at revision={revision}"
        f" with confinement={'classic' if classic else 'strict'}"
    )
    if config:
        snap.set(config)
    snap.hold()
