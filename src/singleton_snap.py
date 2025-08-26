"""File-based registration for singleton snap operations."""

import errno
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Set


@dataclass
class SnapRegistrationFile:
    """Registration file for tracking snap registrations by units.

    The files are stored in the lock directory and follow a specific naming convention.

    The filename format is: LCK..<snap_name>__<revision>--<unit_name>
    Example: LCK..opentelemetry-collector__10--otelcol-0

    Attributes:
        unit_name: Name of the unit registering the snap
        snap_name: Name of the snap being registered
        snap_revision: Revision of the snap being registered
    """

    unit_name: str
    snap_name: str
    snap_revision: int

    PREFIX = "LCK.."
    SEPARATOR_REVISION = "--rev"
    SEPARATOR_UNIT = "__"

    @property
    def filename(self):
        """Assemble the filename."""
        return (
            f"{self.PREFIX}"
            f"{self.snap_name}"
            f"{self.SEPARATOR_REVISION}"
            f"{str(self.snap_revision)}"
            f"{self.SEPARATOR_UNIT}"
            f"{SnapRegistrationFile._normalize_name(self.unit_name)}"
        )

    @staticmethod
    def from_filename(filename: str):
        """Build a SnapRegistrationFile by parsing its filename."""
        # Remove the PREFIX
        _, filename = filename.split(SnapRegistrationFile.PREFIX)
        # Extract the information one by one
        snap_name, filename = filename.split(SnapRegistrationFile.SEPARATOR_REVISION)
        snap_revision, unit_name = filename.split(SnapRegistrationFile.SEPARATOR_UNIT)
        return SnapRegistrationFile(
            unit_name=unit_name,
            snap_name=snap_name,
            snap_revision=int(snap_revision),
        )

    @classmethod
    def _normalize_name(cls, name: str) -> str:
        """Normalize names to contain only alphanumerics, _ and -."""
        return re.sub(r"[^\w-]", "_", name)


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
        manager.unregister("otelcol")

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
        self.unit_name = unit_name
        self._ensure_lock_dir_exists()

    @classmethod
    def _ensure_lock_dir_exists(cls) -> None:
        """Ensure the lock directory exists with correct permissions."""
        try:
            os.makedirs(cls.LOCK_DIR, exist_ok=True)
            os.chown(cls.LOCK_DIR, os.geteuid(), os.getegid())
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

    def register(self, snap_name: str, snap_revision: int) -> None:
        """Register current unit as using the specified snap and revision.

        Args:
            snap_name: Name of the snap.
            snap_revision: Optional revision to put in the lock file. Defaults to an empty string.

        Raises:
            OSError: if there is an I/O related error creating the lock file.
        """
        registration_file = SnapRegistrationFile(
            unit_name=self.unit_name,
            snap_name=snap_name,
            snap_revision=snap_revision,
        )
        with open(self.LOCK_DIR.joinpath(registration_file.filename), "w") as f:
            f.write("")

    def unregister(self, snap_name: str, snap_revision: int) -> None:
        """Unregister current unit from using the specified snap.

        Raises:
            OSError: if there is an I/O related error removing the lock file.
        """
        registration_file = SnapRegistrationFile(
            unit_name=self.unit_name,
            snap_name=snap_name,
            snap_revision=snap_revision,
        )
        os.remove(self.LOCK_DIR.joinpath(registration_file.filename))

    @classmethod
    def get_revisions(cls, snap_name: str) -> Set[int]:
        """Get all revisions of a snap currently registered with any unit.

        Args:
            snap_name: Name of the snap.

        Returns:
            List of revision integers registered by units for this snap.

        Raises:
            OSError: If there's an error accessing the lock directory or files.
        """
        cls._ensure_lock_dir_exists()
        revisions = set()
        for filename in os.listdir(cls.LOCK_DIR):
            registration_file = SnapRegistrationFile.from_filename(filename)
            if registration_file.snap_name == snap_name:
                path = cls.LOCK_DIR.joinpath(filename)
                if os.path.exists(path):
                    revisions.add(registration_file.snap_revision)
        return revisions

    @classmethod
    def get_units(cls, snap_name: str) -> Set[str]:
        """Get all units currently registered for a snap (atomic with directory lock).

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
        units = set()
        cls._ensure_lock_dir_exists()

        for filename in os.listdir(cls.LOCK_DIR):
            registration_file = SnapRegistrationFile.from_filename(filename)
            if registration_file.snap_name == snap_name:
                units.add(registration_file.unit_name)

        return units

    def is_used_by_other_units(self, snap_name: str) -> bool:
        """Check if the specified snap is being used by other units."""
        return any(unit != self.unit_name for unit in self.get_units(snap_name))
