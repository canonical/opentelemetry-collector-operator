import shutil
import tempfile
import time
import pytest
from multiprocessing import Process, Queue
from src.singleton_snap import SingletonSnapManager, SingletonSnapError


@pytest.fixture
def lock_dir(monkeypatch):
    tmp = tempfile.mkdtemp()
    monkeypatch.setattr(SingletonSnapManager, "LOCK_DIR", tmp)
    yield tmp
    shutil.rmtree(tmp)


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


def hold_lock(unit, sleep_time, lock_dir):
    SingletonSnapManager.LOCK_DIR = lock_dir
    mgr = SingletonSnapManager(unit)
    with mgr.snap_operation("otelcol", timeout=2):
        time.sleep(sleep_time)


def test_lock_timeout(lock_dir):
    # Start a process that holds the lock.
    p = Process(target=hold_lock, args=("unit-1", 2, lock_dir))
    p.start()
    time.sleep(0.2)  # Ensure the lock is held.

    mgr2 = SingletonSnapManager("unit-2")
    start = time.time()
    with pytest.raises(SingletonSnapError):
        with mgr2.snap_operation("otelcol", timeout=1):
            pass
    assert time.time() - start >= 1

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
    p1 = Process(target=try_snap_lock, args=("unit-1", acquired, lock_dir))
    p2 = Process(target=try_snap_lock, args=("unit-2", acquired, lock_dir))

    p1.start()
    time.sleep(0.2)  # Ensure p1 starts first.
    p2.start()
    p1.join()
    p2.join()

    results = [acquired.get(), acquired.get()]
    assert results.count(True) == 1
    assert results.count(False) == 1


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
    p1 = Process(target=try_config_lock, args=("unit-1", acquired, lock_dir))
    p2 = Process(target=try_config_lock, args=("unit-2", acquired, lock_dir))

    p1.start()
    time.sleep(0.2)  # Ensure p1 starts first.
    p2.start()
    p1.join()
    p2.join()

    results = [acquired.get(), acquired.get()]
    assert results.count(True) == 1
    assert results.count(False) == 1
