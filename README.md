# opentelemetry-collector-operator

## SingletonSnapManager: Locking and Registration

This project includes a `SingletonSnapManager` utility to coordinate exclusive access to snap operations (such as install, remove, or writing configuration files) across multiple units on the same machine. This is essential to prevent race conditions and ensure only one unit modifies a snap or its configuration at a time, and the snap won't be removed if there are still other units using the snap.

### Features

- **Exclusive Locking:** Uses file-based locks with `fcntl.flock` to ensure only one process can perform snap operations at a time. Locks are automatically released if the process exits or crashes.
- **Unit Registration:** Each unit registers itself as a user of a snap. Registration is tracked via files in a lock directory, allowing the manager to determine which units are currently using a snap.
- **Concurrent Safety:** Includes context managers for both snap operations and configuration file operations, ensuring safe concurrent access.
- **Automatic Cleanup:** No risk of deadlocks from stale lock files, as `flock`-based locks are released on process exit.

### Usage

```python
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
```

### Testing

The project includes tests that simulate multiple units/processes attempting to acquire locks concurrently, ensuring that the locking and registration mechanisms work as intended. See `tests/unit/test_singleton_snap.py` for details.

### Configuration

By default, lock and registration files are stored in `/run/lock/singleton_snaps`. For testing, this directory is patched to a temporary location.

---

**Note:**

If you are running on a platform that does not support `fcntl.flock` (such as Windows), you may need to adapt the locking mechanism.
