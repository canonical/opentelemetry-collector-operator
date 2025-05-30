"""Snap Lock Module."""

import sqlite3
import time
from contextlib import contextmanager
from typing import Generator


class SnapLockError(Exception):
    """Base class for SnapLock error."""

    pass


class SnapLock:
    """SnapLock provides mechanisms for singleton snaps.

    Raises SnapLockError on any error.
    """

    def __init__(self, instance_id: str, lock_timeout_sec: int = 300):
        self.instance_id = instance_id
        self.db_path = "/tmp/snap_lock.db"
        self.lock_timeout = lock_timeout_sec
        self._init_db()

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS active_instances (
                        instance_id TEXT,
                        snap_name TEXT,
                        PRIMARY KEY (instance_id, snap_name)
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS snap_locks (
                        snap_name TEXT PRIMARY KEY,
                        locked_by TEXT,
                        lock_time TIMESTAMP
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS config_locks (
                        config_path TEXT PRIMARY KEY,
                        locked_by TEXT,
                        lock_time TIMESTAMP
                    )
                """)
                conn.commit()
        except sqlite3.Error as e:
            raise SnapLockError(f"Error initializing database: {e}") from e

    def register(self, snap_name: str):
        """Registers an instance using this snap."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = conn.cursor()

                # Record this instance.
                cursor.execute(
                    "INSERT INTO active_instances VALUES (?, ?)",
                    (
                        self.instance_id,
                        snap_name,
                    ),
                )

                conn.commit()
            except sqlite3.IntegrityError:
                # Instance is already registered with this snap. It's okay.
                # This should not happen, only being defensive here.
                # Rollback the begin immediate, just ignore the error.
                conn.rollback()
                pass
            except Exception as e:
                print(f"Error during registration: {e}")
                conn.rollback()
                raise

    def unregister(self, snap_name: str):
        """Unregisters an instance using the snap."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = conn.cursor()

                # Remove instance record.
                cursor.execute(
                    "DELETE FROM active_instances WHERE instance_id = ? AND snap_name = ?",
                    (self.instance_id, snap_name),
                )

                conn.commit()
            except Exception as e:
                print(f"Error during unregistration: {e}")
                conn.rollback()
                raise

    def used_by(self, snap_name: str) -> list[str]:
        """Returns a list of instance IDs that are currently using the specified snap."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT instance_id FROM active_instances WHERE snap_name = ?
                """,
                (snap_name,),
            )
            instances = [row[0] for row in cursor.fetchall()]
            return instances

    def used_by_others(self, snap_name: str) -> bool:
        """Returns True if the snap is used by other instances besides the current instance, False otherwise."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT instance_id FROM active_instances WHERE snap_name = ? AND instance_id != ?
                """,
                (snap_name, self.instance_id),
            )
            return cursor.fetchone() is not None

    @contextmanager
    def lock_snap(self, snap_name: str, timeout: int = 3) -> Generator[bool, None, None]:
        """Context manager to acquire a lock on a snap for exclusive access.

        Raises SnapLockError.

        Example usage:

        with lock.lock_snap('otelcol') as acquired:
            if acquired:
                # Perform operations on the snap
            else:
                # Handle the case where the snap lock was not acquired
        """
        acquired = False
        try:
            acquired = self._acquire_snap_lock(snap_name, timeout)
            yield acquired
        except SnapLockError:
            raise
        finally:
            if acquired:
                self._release_snap_lock(snap_name)

    def _acquire_snap_lock(self, snap_name: str, timeout: int) -> bool:
        start_time = time.time()
        while time.time() - start_time < timeout:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    cursor = conn.cursor()
                    # Check for existing lock.
                    cursor.execute(
                        """
                        SELECT locked_by, lock_time FROM snap_locks
                        WHERE snap_name = ?
                        """,
                        (snap_name,),
                    )

                    if result := cursor.fetchone():
                        locked_by, lock_time = result
                        # Check if lock is stale.
                        cursor.execute(
                            """
                            SELECT (strftime('%s','now') - strftime('%s',?)) > ?
                            """,
                            (lock_time, self.lock_timeout),
                        )

                        if cursor.fetchone()[0]:  # Stale lock.
                            conn.execute(
                                """
                                DELETE FROM snap_locks
                                WHERE snap_name = ?
                                """,
                                (snap_name,),
                            )
                            conn.commit()
                            continue

                        if locked_by == self.instance_id:  # We already hold it.
                            return True

                        # Active lock held by others.
                        time.sleep(1)
                        continue

                    # Acquire new lock.
                    conn.execute(
                        """
                        INSERT INTO snap_locks 
                        VALUES (?, ?, datetime('now'))
                        """,
                        (snap_name, self.instance_id),
                    )
                    conn.commit()
                    return True
                except sqlite3.IntegrityError:  # Race condition.
                    time.sleep(1)
                    continue
                except sqlite3.Error as e:
                    conn.rollback()  # Rollback on any error.
                    raise SnapLockError(f"Database error acquiring lock: {e}") from e

        return False

    def _release_snap_lock(self, snap_name) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    DELETE FROM snap_locks
                    WHERE snap_name = ? AND locked_by = ?
                    """,
                    (snap_name, self.instance_id),
                )
                conn.commit()
                return cursor.rowcount > 0
            except Exception:
                conn.rollback()
                return False

    @contextmanager
    def lock_config(self, config_path: str, timeout: int = 3) -> Generator[bool, None, None]:
        """Context manager to acquire a lock on a config file for exclusive access.

        Raises SnapLockError.

        Example usage:

        with lock.lock_config('/etc/otelcol/config.yaml') as acquired:
            if acquired:
                # Perform operations on the config
            else:
                # Handle the case where the config lock was not acquired
        """
        acquired = False
        try:
            acquired = self._acquire_config_lock(config_path, timeout)
            yield acquired
        except SnapLockError:
            raise
        finally:
            if acquired:
                self._release_config_lock(config_path)

    def _acquire_config_lock(self, config_path: str, timeout: int) -> bool:
        start_time = time.time()
        while time.time() - start_time < timeout:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    cursor = conn.cursor()
                    # Check for existing lock.
                    cursor.execute(
                        """
                        SELECT locked_by, lock_time FROM config_locks
                        WHERE config_path = ?
                        """,
                        (config_path,),
                    )

                    if result := cursor.fetchone():
                        locked_by, lock_time = result
                        # Check if lock is stale.
                        cursor.execute(
                            """
                            SELECT (strftime('%s','now') - strftime('%s',?)) > ?
                            """,
                            (lock_time, self.lock_timeout),
                        )

                        if cursor.fetchone()[0]:  # Stale lock.
                            conn.execute(
                                """
                                DELETE FROM config_locks
                                WHERE config_path = ?
                                """,
                                (config_path,),
                            )
                            conn.commit()
                            continue

                        if locked_by == self.instance_id:  # We already hold it.
                            return True

                        # Active lock held by others.
                        time.sleep(1)
                        continue

                    # Acquire new lock.
                    conn.execute(
                        """
                        INSERT INTO config_locks
                        VALUES (?, ?, datetime('now'))
                        """,
                        (config_path, self.instance_id),
                    )
                    conn.commit()
                    return True

                except sqlite3.IntegrityError:  # Race condition
                    time.sleep(1)
                    continue
                except sqlite3.Error as e:
                    conn.rollback()  # Rollback on any error.
                    raise SnapLockError(f"Database error acquiring lock: {e}") from e

        return False

    def _release_config_lock(self, config_path) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    DELETE FROM config_locks
                    WHERE config_path = ? AND locked_by = ?
                    """,
                    (config_path, self.instance_id),
                )
                conn.commit()
                return cursor.rowcount > 0
            except Exception:
                conn.rollback()
                return False
