import os
import time
import pytest
from multiprocessing import Process, Queue
from src.singleton_snap import SingletonSnapManager, SingletonSnapError


@pytest.fixture
def lock_dir(monkeypatch, tmp_path):
    lock_dir = tmp_path / "lock_dir"
    lock_dir.mkdir()
    monkeypatch.setattr(SingletonSnapManager, "LOCK_DIR", lock_dir)
    yield lock_dir


def test_register_unregister(lock_dir):
    mgr1 = SingletonSnapManager("unit-1")
    mgr1.register("otelcol")
    assert "unit-1" in mgr1.get_units("otelcol")
    mgr2 = SingletonSnapManager("unit-2")
    mgr2.register("otelcol")
    assert "unit-1" in mgr2.get_units("otelcol")
    assert "unit-2" in mgr2.get_units("otelcol")
    mgr1.unregister("otelcol")
    assert "unit-1" not in mgr2.get_units("otelcol")
    mgr2.unregister("otelcol")
    assert "unit-2" not in mgr2.get_units("otelcol")
    # Unregistering a unit that is not registered should raise an error.
    with pytest.raises(SingletonSnapError) as excinfo:
        mgr2.unregister("otelcol")
    assert "Error unregistering unit" in str(excinfo.value)


def test_update_registration(lock_dir):
    mgr = SingletonSnapManager("unit-test")
    snap_name = "test-snap"
    reg_file = lock_dir / f"LCK..{snap_name}--unit-test"

    # Ensure file does not exist
    if reg_file.exists():
        reg_file.unlink()

    # Register (create file)
    mgr._update_registration(snap_name, create=True)
    assert reg_file.exists()

    # Unregister (remove file)
    mgr._update_registration(snap_name, create=False)
    assert not reg_file.exists()


def test_update_registration_nonexistent_file_raises(lock_dir):
    mgr = SingletonSnapManager("unit-test")
    snap_name = "test-snap"
    reg_file = lock_dir / f"LCK..{snap_name}--unit-test"

    # Ensure file does not exist
    if reg_file.exists():
        reg_file.unlink()

    # Unregister should raise SingletonSnapError if file does not exist
    with pytest.raises(SingletonSnapError) as excinfo:
        mgr._update_registration(snap_name, create=False)
    assert "Error unregistering unit" in str(excinfo.value)


def test_update_registration_handles_oserror_on_create(monkeypatch, lock_dir):
    mgr = SingletonSnapManager("unit-test")
    snap_name = "test-snap"

    def raise_oserror(*args, **kwargs):
        raise OSError("test error")

    monkeypatch.setattr("builtins.open", raise_oserror)
    with pytest.raises(SingletonSnapError) as excinfo:
        mgr._update_registration(snap_name, create=True)
    assert "Error registering unit" in str(excinfo.value)


def hold_lock(unit, sleep_time, lock_dir):
    SingletonSnapManager.LOCK_DIR = lock_dir
    mgr = SingletonSnapManager(unit)
    with mgr.snap_operation("otelcol", timeout=2):
        time.sleep(sleep_time)


def test_lock_timeout(lock_dir):
    # Start a process that holds the lock.
    p = Process(target=hold_lock, args=("unit-1", 2, lock_dir))
    p.start()

    # Wait until the lock file appears to ensure the lock is held, up to 1 second.
    lock_file = f"{lock_dir}/LCK..otelcol"
    for _ in range(10):
        if os.path.exists(lock_file):
            break
        time.sleep(0.1)
    else:
        pytest.fail("Lock file was not created in time")

    mgr2 = SingletonSnapManager("unit-2")
    start = time.time()
    with pytest.raises(SingletonSnapError):
        with mgr2.snap_operation("otelcol", timeout=1):
            pass
    assert time.time() - start >= 1, (
        "Second, conflicting lockmgr wrongfully succeeded to grab the lock before it was released by the first lockmgr."
    )

    p.join()


def try_snap_lock(unit, result_queue, lock_dir):
    SingletonSnapManager.LOCK_DIR = lock_dir
    mgr = SingletonSnapManager(unit)
    # The timeout is set to 1 second but the operation sleeps for 2 seconds
    # to ensure that only one process can acquire the lock.
    try:
        with mgr.snap_operation("otelcol", timeout=1):
            result_queue.put(True)
            time.sleep(2)
    except SingletonSnapError:
        result_queue.put(False)


def test_exclusive_snap_operation(lock_dir):
    acquired = Queue()
    num_processes = 20
    processes = [
        Process(target=try_snap_lock, args=(f"unit-{i}", acquired, lock_dir))
        for i in range(num_processes)
    ]

    # Start the first process and wait for the lock to be acquired.
    processes[0].start()
    lock_file = f"{lock_dir}/LCK..otelcol"
    for _ in range(10):
        if os.path.exists(lock_file):
            break
        time.sleep(0.1)
    else:
        pytest.fail("Lock file was not created in time")

    # The rest of the processes.
    for p in processes[1:]:
        p.start()

    for p in processes:
        p.join()

    results = [acquired.get() for _ in range(num_processes)]
    assert results.count(True) == 1
    assert results.count(False) == num_processes - 1


def try_config_lock(unit, result_queue, lock_dir):
    SingletonSnapManager.LOCK_DIR = lock_dir
    mgr = SingletonSnapManager(unit)
    # The timeout is set to 1 second but the operation sleeps for 2 seconds
    # to ensure that only one process can acquire the lock.
    try:
        with mgr.config_operation("/tmp/test.yaml", timeout=1):
            result_queue.put(True)
            time.sleep(2)
    except SingletonSnapError:
        result_queue.put(False)


def test_exclusive_config_operation(lock_dir):
    acquired = Queue()
    num_processes = 20
    processes = [
        Process(target=try_config_lock, args=(f"unit-{i}", acquired, lock_dir))
        for i in range(num_processes)
    ]

    # Start the first process and wait for the lock to be acquired.
    processes[0].start()
    lock_file = f"{lock_dir}/LCK..config__tmp_test_yaml"
    for _ in range(10):
        if os.path.exists(lock_file):
            break
        time.sleep(0.1)
    else:
        pytest.fail("Lock file was not created in time")

    # The rest of the processes.
    for p in processes[1:]:
        p.start()

    for p in processes:
        p.join()

    results = [acquired.get() for _ in range(num_processes)]
    assert results.count(True) == 1
    assert results.count(False) == num_processes - 1
