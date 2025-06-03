"""Snap Lock Module using fcntl.flock and file-based reference counting."""

import os
import re
import time
from contextlib import contextmanager
from typing import Generator
import errno


class SnapLockError(Exception):
    """Base class for SnapLock error."""

    pass


class SnapLock:
    """SnapLock provides mechanisms for singleton snaps using fcntl.flock and file-based reference counting.

    Raises SnapLockError on any error.
    """

    def __init__(self, instance_name: str, lock_timeout_sec: int = 300):
        # Replace all non-alphanumeric chars (except _-) with _
        self.instance_name = re.sub(r'[^\w-]', '_', instance_name)
        self.lock_timeout = lock_timeout_sec
        self.separator = '--'

        self.lock_dir = os.path.join('/run/lock', 'snap_locks')
        try:
            os.makedirs(self.lock_dir, exist_ok=True)
            os.chown(self.lock_dir, os.geteuid(), os.getegid())
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise SnapLockError(f'Error creating lock directory: {e}') from e

    def _get_lock_file_path(self, resource_name: str) -> str:
        return os.path.join(self.lock_dir, f'{resource_name}.lock')

    def _get_reference_file_path(self, snap_name: str) -> str:
        """Generates the reference file path for a given snap and instance."""
        return os.path.join(self.lock_dir, f'{snap_name}{self.separator}{self.instance_name}')

    def register(self, snap_name: str):
        """Registers an instance using this snap by creating a reference file."""
        reference_file_path = self._get_reference_file_path(snap_name)
        try:
            with open(reference_file_path, 'w') as f:
                f.write('')
        except OSError as e:
            raise SnapLockError(f'Error registering instance: {e}') from e

    def unregister(self, snap_name: str):
        """Unregisters an instance using the snap by removing the reference file."""
        reference_file_path = self._get_reference_file_path(snap_name)
        try:
            os.remove(reference_file_path)
        except FileNotFoundError:
            # It's okay if the file doesn't exist (already unregistered)
            pass
        except OSError as e:
            raise SnapLockError(f'Error unregistering instance: {e}') from e

    def used_by(self, snap_name: str) -> list[str]:
        """Returns a list of instance names that are currently using the specified snap."""
        instances = []
        for filename in os.listdir(self.lock_dir):
            if filename.startswith(snap_name + self.separator):
                instance_name = filename[len(snap_name + self.separator) :]
                instances.append(instance_name)
        return instances

    def used_by_others(self, snap_name: str) -> bool:
        """Returns True if the snap is used by other instances besides the current instance, False otherwise."""
        for filename in os.listdir(self.lock_dir):
            if filename.startswith(snap_name + self.separator):
                instance_name = filename[len(snap_name + self.separator) :]
                if instance_name != self.instance_name:
                    return True
        return False

    @contextmanager
    def lock_snap(self, snap_name: str, timeout: int = 3) -> Generator[None, None, None]:
        """Context manager to acquire a lock on a snap using file creation with timeout.

        Raises SnapLockError if the lock cannot be acquired within the timeout.

        Example usage:

        with lock.lock_snap('otelcol', timeout=5):
            # Perform operations on the snap (lock is guaranteed to be held)
        """
        lock_file_path = self._get_lock_file_path(snap_name)
        fd = None
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                fd = os.open(lock_file_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                time.sleep(1)
                continue
            except OSError as e:
                raise SnapLockError(f'Error creating lock file: {e}') from e
            else:
                break
        else:
            raise SnapLockError(f'Timeout acquiring lock for snap: {snap_name}')

        try:
            yield
        finally:
            try:
                os.close(fd)
                os.remove(lock_file_path)
            except FileNotFoundError:
                pass
            except OSError as e:
                print(f'Error removing lock file: {e}')
