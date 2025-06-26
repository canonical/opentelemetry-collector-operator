import pytest
from src.singleton_snap import SingletonSnapManager


@pytest.fixture(autouse=True)
def lock_dir(monkeypatch, tmp_path):
    lock_dir = tmp_path / "lock_dir"
    lock_dir.mkdir()
    monkeypatch.setattr(SingletonSnapManager, "LOCK_DIR", lock_dir)
    yield lock_dir


def test_register_unregister():
    unit_name = "unit-0"
    snap_name = "opentelemetry-collector"
    # GIVEN a SingletonSnapManager
    manager = SingletonSnapManager(unit_name)
    # WHEN it registers a snap
    manager.register(snap_name, snap_revision=1)
    # THEN the registration file can be retrieved
    assert unit_name in manager.get_units(snap_name)
    # AND WHEN it unregisters the snap
    manager.unregister(snap_name, snap_revision=1)
    # THEN the registration file is gone
    assert unit_name not in manager.get_units(snap_name)


def test_register_unregister_multiple_units():
    unit_one = "unit-0"
    unit_two = "unit-1"
    snap_name = "opentelemetry-collector"
    # GIVEN two SingletonSnapManager for two different units
    manager_one = SingletonSnapManager(unit_one)
    manager_two = SingletonSnapManager(unit_two)
    # WHEN they both register the same snap with different revision
    manager_one.register(snap_name, snap_revision=1)
    manager_two.register(snap_name, snap_revision=2)
    # THEN both units show up for both managers
    assert unit_one in manager_one.get_units(snap_name)
    assert unit_two in manager_one.get_units(snap_name)
    assert unit_one in manager_two.get_units(snap_name)
    assert unit_two in manager_two.get_units(snap_name)
    # AND WHEN one unregisters the snap
    manager_one.unregister(snap_name, snap_revision=1)
    # THEN its registration file is gone for both managers
    assert unit_one not in manager_one.get_units(snap_name)
    assert unit_one not in manager_two.get_units(snap_name)


def test_unregister_without_register():
    unit_name = "unit-0"
    snap_name = "opentelemetry-collector"
    # GIVEN a SingletonSnapManager
    manager = SingletonSnapManager(unit_name)
    # WHEN it tries to unregister a non-registered snap
    # THEN it raises an Exception
    with pytest.raises(Exception):
        manager.unregister(snap_name, snap_revision=1)


def test_get_revisions():
    snap_name = "opentelemetry-collector"
    # GIVEN multiple SingletonSnapManager
    manager_one = SingletonSnapManager("unit-0")
    manager_two = SingletonSnapManager("unit-1")
    # WHEN they register different revisions for the same snap
    manager_one.register(snap_name, snap_revision=1)
    manager_two.register(snap_name, snap_revision=2)
    # THEN get_revisions displays all the registered revisions
    assert manager_one.get_revisions(snap_name) == {1, 2}
    # AND WHEN one registration is removed
    manager_one.unregister(snap_name, snap_revision=1)
    # THEN only the other revision is left
    assert manager_two.get_revisions(snap_name) == {2}


def test_get_revisions_duplicated():
    snap_name = "opentelemetry-collector"
    # GIVEN multiple SingletonSnapManager
    manager_one = SingletonSnapManager("unit-0")
    manager_two = SingletonSnapManager("unit-1")
    # WHEN they register different revisions for the same snap
    manager_one.register(snap_name, snap_revision=1)
    manager_two.register(snap_name, snap_revision=1)
    # THEN get_revisions displays all the registered revisions
    assert manager_one.get_revisions(snap_name) == {1}
