"""File-based locking and registration for singleton snap operations.

==========================
SingletonSnapManager Class
==========================

This module provides a :class:`SingletonSnapManager` utility to coordinate exclusive
access to snap operations (such as install, remove, or writing configuration
files) across multiple units on the same machine. This is essential to prevent
race conditions and ensure only one unit modifies a snap or its configuration
at a time, and the snap won't be removed if there are still other units using
the snap.

Features
--------

- **Exclusive Locking:** Uses file-based locks with ``fcntl.flock`` to ensure only one process can perform snap operations at a time. Locks are automatically released if the process exits or crashes.
- **Unit Registration:** Each unit registers itself as a user of a snap. Registration is tracked via files in a lock directory, allowing the manager to determine which units are currently using a snap.
- **Concurrent Safety:** Includes context managers for both snap operations and configuration file operations, ensuring safe concurrent access.
- **Automatic Cleanup:** No risk of deadlocks from stale lock files, as ``flock``-based locks are released on process exit.

Usage
-----

.. code-block:: python

    from src.singleton_snap import SingletonSnapManager

    manager = SingletonSnapManager(unit_name="unit-1")

    # Register this unit as using a snap
    manager.register("otelcol")

    # Perform an exclusive snap operation
    with manager.snap_operation("otelcol"):
        # Only one unit can be here at a time
        # Perform install/remove/configure

    # Perform an exclusive config operation
    with manager.config_operation("/etc/otelcol/config.yaml"):
        # Only one unit can modify this config at a time

    # Unregister when the unit is removed
    manager.unregister("otelcol")

Testing
-------

The project includes tests that simulate multiple units/processes attempting
to acquire locks concurrently, ensuring that the locking and registration
mechanisms work as intended. See ``tests/unit/test_singleton_snap.py`` for details.

Configuration
-------------

By default, lock and registration files are stored in ``/run/lock/singleton_snaps``.
For testing, this directory is patched to a temporary location.

.. note::

     If you are running on a platform that does not support ``fcntl.flock``
     (such as Windows), you may need to adapt the locking mechanism.
"""

from dataclasses import dataclass
import os
import re
from typing import Set
import errno


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
    SEPARATOR_REVISION = "__"
    SEPARATOR_UNIT = "--"

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

    @staticmethod
    def _normalize_name(name: str) -> str:
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

    LOCK_DIR = "/run/lock/singleton_snaps"

    def __init__(self, unit_name: str):
        """Initialize the manager with a normalized unit name.

        Args:
            unit_name: Identifier for the current unit
        """
        self.unit_name = unit_name
        self._ensure_lock_dir_exists()

    def _ensure_lock_dir_exists(self) -> None:
        """Ensure the lock directory exists with correct permissions."""
        try:
            os.makedirs(self.LOCK_DIR, exist_ok=True)
            os.chown(self.LOCK_DIR, os.geteuid(), os.getegid())
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
        with open(registration_file.filename, "w") as f:
            f.write(str(snap_revision))

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
        os.remove(registration_file.filename)

    def get_revisions(self, snap_name: str) -> Set[int]:
        """Get all revisions of a snap currently registered with any unit.

        Args:
            snap_name: Name of the snap.

        Returns:
            List of revision integers registered by units for this snap.

        Raises:
            OSError: If there's an error accessing the lock directory or files.
        """
        revisions = set()
        for filename in os.listdir(self.LOCK_DIR):
            registration_file = SnapRegistrationFile.from_filename(filename)
            if registration_file.snap_name == snap_name:
                path = os.path.join(self.LOCK_DIR, filename)
                try:
                    with open(path, "r") as f:
                        revision = f.read().strip()
                        revisions.add(int(revision))
                except OSError:
                    continue
        return revisions

    def get_units(self, snap_name: str) -> Set[str]:
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

        for filename in os.listdir(self.LOCK_DIR):
            registration_file = SnapRegistrationFile.from_filename(filename)
            if registration_file.snap_name == snap_name:
                units.add(registration_file.unit_name)

        return units

    def is_used_by_other_units(self, snap_name: str) -> bool:
        """Check if the specified snap is being used by other units.

        Args:
            snap_name: Name of the snap to check

        Returns:
            bool: True if the snap is used by other units, False otherwise

        Raises:
            OSError: If there's an error accessing the lock directory
        """
        return any(unit != self.unit_name for unit in self.get_units(snap_name))
