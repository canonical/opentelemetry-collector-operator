"""SingletonSnap Module using fcntl.flock and file-based reference counting."""

import fcntl
import os
import re
import time
from contextlib import contextmanager
from typing import Generator, List
import errno


class SingletonSnapError(Exception):
    """Base class for singleton snap error."""

    pass


class SingletonSnapManager:
    """Manages exclusive access to singleton snaps and configuration files using file-based locks.

    Uses a combination of file-based reference counting for unit tracking and
    file locks for exclusive operations.

    manager = SingletonSnapManager("unit-1")

    Usage:

        # For snap operations
        with manager.snap_operation("otelcol", timeout=30):
            # Exclusive snap install/remove operations here.
            pass

        # For configuration changes
        with manager.config_operation("/etc/otelcol/config.yaml"):
            # Safe config file modifications here.
            pass

        # For unit tracking
        manager.register("otelcol")
        # Use the snap...

        # For unregistering
        manager.unregister("otelcol")

    Raises SingletonSnapError on any error.
    """

    LOCK_FILE_PREFIX = 'LCK..'
    SEPARATOR = '--'
    LOCK_DIR = '/run/lock/singleton_snaps'

    def __init__(self, unit_name: str):
        """Initialize the manager with a normalized unit name.

        Args:
            unit_name: Identifier for the current unit
        """
        self.unit_name = self._normalize_name(unit_name)
        self._ensure_lock_dir_exists()

    @staticmethod
    def _normalize_name(name: str) -> str:
        """Normalize names to contain only alphanumerics, _ and -."""
        return re.sub(r'[^\w-]', '_', name)

    def _ensure_lock_dir_exists(self) -> None:
        """Ensure the lock directory exists with correct permissions."""
        try:
            os.makedirs(self.LOCK_DIR, exist_ok=True)
            os.chown(self.LOCK_DIR, os.geteuid(), os.getegid())
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise SingletonSnapError(f'Error creating lock directory: {e}') from e

    def _get_registration_file_path(self, snap_name: str) -> str:
        """Helper method to construct registration file path.

        The registration file name is constructed as:
        LCK..{snap_name}--{unit_name}
        """
        filename = f'{self.LOCK_FILE_PREFIX}{snap_name}{self.SEPARATOR}{self.unit_name}'
        return os.path.join(self.LOCK_DIR, filename)

    def _parse_unit_name_from_file(self, filename: str, snap_name: str) -> str:
        """Helper method to extract unit name from registration filename."""
        prefix = f'{self.LOCK_FILE_PREFIX}{snap_name}{self.SEPARATOR}'
        return filename[len(prefix) :]

    def register(self, snap_name: str) -> None:
        """Register current unit as using the specified snap."""
        self._update_registration(snap_name, create=True)

    def unregister(self, snap_name: str) -> None:
        """Unregister current unit from using the specified snap."""
        self._update_registration(snap_name, create=False)

    @contextmanager
    def _lock_directory(self):
        dir_fd = os.open(self.LOCK_DIR, os.O_RDONLY)
        try:
            fcntl.flock(dir_fd, fcntl.LOCK_SH)
            yield
        finally:
            fcntl.flock(dir_fd, fcntl.LOCK_UN)
            os.close(dir_fd)

    def _update_registration(self, snap_name: str, create: bool) -> None:
        """Internal method to handle registration/unregistration (atomic with directory lock)."""
        lock_path = self._get_registration_file_path(snap_name)
        action = 'registering' if create else 'unregistering'

        try:
            with self._lock_directory():
                if create:
                    open(lock_path, 'w').close()
                else:
                    try:
                        os.remove(lock_path)
                    except FileNotFoundError:
                        pass  # Already unregistered is not an error
        except OSError as e:
            raise SingletonSnapError(f'Error {action} unit: {e}') from e

    def get_units(self, snap_name: str) -> List[str]:
        """Get all units currently registered for a snap (atomic with directory lock).

        Args:
            snap_name: Name of the snap to get units for

        Returns:
            List of unit names associated with the snap

        Raises:
            SingletonSnapError: If there's an error accessing the lock directory
        """
        prefix = f'{self.LOCK_FILE_PREFIX}{self._normalize_name(snap_name)}{self.SEPARATOR}'
        units = []

        try:
            with self._lock_directory():
                for filename in os.listdir(self.LOCK_DIR):
                    if filename.startswith(prefix):
                        units.append(filename[len(prefix) :])
        except OSError as e:
            raise SingletonSnapError(f'Error reading unit list: {e}') from e

        return units

    def is_used_by_other_units(self, snap_name: str) -> bool:
        """Check if snap is being used by other units."""
        return any(unit != self.unit_name for unit in self.get_units(snap_name))

    @contextmanager
    def _acquire_lock(self, lock_name: str, timeout: int) -> Generator[None, None, None]:
        """Internal method to acquire an exclusive lock with timeout.

        Uses fcntl.flock to acquire an exclusive lock on a lock file.
        Retries until the timeout is reached.
        """
        lock_path = os.path.join(self.LOCK_DIR, f'{self.LOCK_FILE_PREFIX}{lock_name}')
        with open(lock_path, 'w') as f:
            deadline = time.time() + timeout
            while True:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.time() > deadline:
                        raise SingletonSnapError(f'Timeout acquiring lock for {lock_name}')
                    time.sleep(0.1)
            try:
                yield
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    @contextmanager
    def snap_operation(self, snap_name: str, timeout: int = 30) -> Generator[None, None, None]:
        """Context manager for exclusive snap operations (install/remove/configure).

        Example:
            with manager.snap_operation('otelcol'):
                # perform privileged snap operations
        """
        with self._acquire_lock(self._normalize_name(snap_name), timeout):
            yield

    @contextmanager
    def config_operation(self, config_path: str, timeout: int = 3) -> Generator[None, None, None]:
        """Context manager for exclusive configuration file operations.

        Example:
            with manager.config_operation('/etc/config.yaml'):
                # safely modify configuration
        """
        normalized = self._normalize_name(config_path.replace('/', '_'))
        with self._acquire_lock(f'config_{normalized}', timeout):
            yield
