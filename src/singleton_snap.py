"""File-based registration for singleton snap operations."""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Set


def normalize_unit_name(name: str) -> str:
    """Normalize a Juju unit name by replacing the '/' separator with '_'.

    Juju uses '<app>/<n>' (e.g. 'otelcol/2') but '/' is not valid in filenames,
    so it is replaced with '_' (e.g. 'otelcol_2').
    """
    return name.replace("/", "_")

def _get_registrations(
    lock_dir: Path, snap_name: str
) -> List["SnapRegistrationFile"]:
    """Return all SnapRegistrationFile objects across all units for well-formed lockfiles matching snap_name.

    Malformed files and files for other snaps are silently skipped.
    """
    result = []
    try:
        filenames = os.listdir(lock_dir)
    except FileNotFoundError:
        return result
    for filename in filenames:
        if not filename.startswith(SnapRegistrationFile.PREFIX):
            continue
        try:
            reg = SnapRegistrationFile.from_filename(filename)
        except (ValueError, IndexError):
            continue
        if reg.snap_name == snap_name:
            result.append(reg)
    return result


@dataclass
class SnapRegistrationFile:
    """Registration file for tracking snap registrations by units.

    The files are stored in the lock directory and follow a specific naming convention.

    The filename format is: LCK..<snap_name>--rev<revision>__<unit_name>
    Example: LCK..opentelemetry-collector--rev10__otelcol_0

    Attributes:
        unit_name: Name of the unit registering the snap (slashes will be replaced with underscores)
        snap_name: Name of the snap being registered
        snap_revision: Revision of the snap being registered
    """

    unit_name: str
    snap_name: str
    snap_revision: int

    PREFIX = "LCK.."
    SEPARATOR_REVISION = "--rev"
    SEPARATOR_UNIT = "__"

    def __post_init__(self):
        """Normalize unit_name on construction."""
        self.unit_name = normalize_unit_name(self.unit_name)

    @property
    def filename(self):
        """Assemble the filename."""
        return (
            f"{self.PREFIX}"
            f"{self.snap_name}"
            f"{self.SEPARATOR_REVISION}"
            f"{str(self.snap_revision)}"
            f"{self.SEPARATOR_UNIT}"
            f"{self.unit_name}"
        )

    @staticmethod
    def from_filename(filename: str):
        """Build a SnapRegistrationFile by parsing its filename."""
        after_prefix = filename.removeprefix(SnapRegistrationFile.PREFIX)
        snap_name, after_snap = after_prefix.split(SnapRegistrationFile.SEPARATOR_REVISION)
        snap_revision, unit_name = after_snap.split(SnapRegistrationFile.SEPARATOR_UNIT)
        return SnapRegistrationFile(
            unit_name=unit_name,
            snap_name=snap_name,
            snap_revision=int(snap_revision),
        )



class SingletonSnapManager:
    """Manages exclusive access to singleton snaps and configuration files using file-based locks.

    Uses a combination of file-based reference counting for unit tracking and
    file locks for exclusive operations.

    manager = SingletonSnapManager("unit-1")

    Usage:

    .. code-block:: python
        # For unit tracking
        manager.register("otelcol")
        # Use the snap...

        # For unregistering
        manager.unregister_all_for_unit("otelcol")

    Raises:
        TimeoutError: If a lock could not be acquired within the specified timeout.
        OSError: on I/O related errors.
    """

    LOCK_DIR: Path = Path("/opt/singleton_snaps")

    def __init__(self, unit_name: str):
        """Initialize the manager with a normalized unit name.

        Args:
            unit_name: Identifier for the current unit
        """
        self.unit_name = normalize_unit_name(unit_name)
        self._ensure_lock_dir_exists()

    @classmethod
    def _ensure_lock_dir_exists(cls) -> None:
        """Ensure the lock directory exists with correct permissions."""
        os.makedirs(cls.LOCK_DIR, exist_ok=True)
        os.chown(cls.LOCK_DIR, os.geteuid(), os.getegid())

    def _remove_unit_lockfiles(self, snap_name: str, exclude_revision: Optional[int] = None) -> None:
        """Remove lockfiles for this unit and snap.

        Args:
            snap_name: Name of the snap.
            exclude_revision: If given, lockfiles with this revision are kept.
        """
        for reg in _get_registrations(self.LOCK_DIR, snap_name):
            if reg.unit_name == self.unit_name and reg.snap_revision != exclude_revision:
                try:
                    os.remove(self.LOCK_DIR / reg.filename)
                except FileNotFoundError:
                    pass

    def register(self, snap_name: str, snap_revision: int) -> None:
        """Register current unit as using the specified snap revision.

        If this unit was previously registered for the same snap with a different
        revision, the old registration is automatically replaced.

        Args:
            snap_name: Name of the snap.
            snap_revision: Revision to register.

        Raises:
            OSError: if there is an I/O related error creating the lock file.
        """
        self._remove_unit_lockfiles(snap_name, exclude_revision=snap_revision)
        registration_file = SnapRegistrationFile(
            unit_name=self.unit_name,
            snap_name=snap_name,
            snap_revision=snap_revision,
        )
        with open(self.LOCK_DIR.joinpath(registration_file.filename), "w") as f:
            f.write("")

    def unregister_all_for_unit(self, snap_name: str) -> None:
        """Remove all lockfiles for this unit and snap, regardless of revision.

        Safe to call even if no lockfiles exist. Use during charm removal to ensure
        cleanup regardless of which revision was last registered.

        Args:
            snap_name: Name of the snap.

        Raises:
            OSError: if there is an I/O related error removing a lock file.
        """
        self._remove_unit_lockfiles(snap_name)

    @classmethod
    def get_revisions(cls, snap_name: str) -> Set[int]:
        """Get all revisions of a snap currently registered with any unit.

        Args:
            snap_name: Name of the snap.

        Returns:
            Set of revision integers registered by units for this snap.

        Raises:
            OSError: If there's an error accessing the lock directory or files.
        """
        cls._ensure_lock_dir_exists()
        return {
            reg.snap_revision
            for reg in _get_registrations(cls.LOCK_DIR, snap_name)
        }

    @classmethod
    def get_units(cls, snap_name: str) -> Set[str]:
        """Get all units currently registered for a snap.

        This method is primarily useful for debugging purposes. In most scenarios, you
        do not need to call this directly. Instead, use
        :meth:`SingletonSnapManager.is_used_by_other_units` to detect if there are other
        units registered with a snap.

        Args:
            snap_name: Name of the snap to get units for

        Returns:
            Set of unit names associated with the snap

        Raises:
            OSError: If there's an error accessing the lock directory
        """
        cls._ensure_lock_dir_exists()
        return {reg.unit_name for reg in _get_registrations(cls.LOCK_DIR, snap_name)}

    def is_used_by_other_units(self, snap_name: str) -> bool:
        """Check if the specified snap is being used by other units."""
        return any(unit != self.unit_name for unit in self.get_units(snap_name))
