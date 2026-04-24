import pytest
from src.singleton_snap import SingletonSnapManager, SnapRegistrationFile


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
    manager.unregister_all_for_unit(snap_name)
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
    manager_one.unregister_all_for_unit(snap_name)
    # THEN its registration file is gone for both managers
    assert unit_one not in manager_one.get_units(snap_name)
    assert unit_one not in manager_two.get_units(snap_name)


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
    manager_one.unregister_all_for_unit(snap_name)
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


def test_register_replaces_stale_revision():
    snap_name = "opentelemetry-collector"
    # GIVEN a unit with a Juju-style name (containing a slash) registered with an old revision
    manager = SingletonSnapManager("otelcol/2")
    manager.register(snap_name, snap_revision=1904)
    assert manager.get_revisions(snap_name) == {1904}
    # WHEN it registers a new revision
    manager.register(snap_name, snap_revision=2154)
    # THEN only the new revision remains (old lockfile was cleaned up)
    assert manager.get_revisions(snap_name) == {2154}


def test_register_does_not_affect_other_units():
    snap_name = "opentelemetry-collector"
    manager_one = SingletonSnapManager("unit-0")
    manager_two = SingletonSnapManager("unit-1")
    # GIVEN two units each registered with different old revisions
    manager_one.register(snap_name, snap_revision=1)
    manager_two.register(snap_name, snap_revision=2)
    # WHEN unit-0 upgrades its revision
    manager_one.register(snap_name, snap_revision=3)
    # THEN unit-1's lockfile is untouched
    assert manager_one.get_revisions(snap_name) == {3, 2}


def test_is_used_by_other_units_with_juju_style_names():
    snap_name = "node-exporter"
    # GIVEN units with Juju-style names (slash in unit name)
    manager_a = SingletonSnapManager("otelcol/2")
    manager_b = SingletonSnapManager("otelcol/3")
    # WHEN only this unit is registered
    manager_a.register(snap_name, snap_revision=2154)
    # THEN is_used_by_other_units returns False
    assert not manager_a.is_used_by_other_units(snap_name)
    # WHEN another unit also registers
    manager_b.register(snap_name, snap_revision=2154)
    # THEN both see the other as using the snap
    assert manager_a.is_used_by_other_units(snap_name)
    assert manager_b.is_used_by_other_units(snap_name)


def test_is_used_by_other_units_ignores_revision():
    snap_name = "node-exporter"
    # GIVEN two units registered with different revisions
    manager_a = SingletonSnapManager("otelcol/2")
    manager_b = SingletonSnapManager("otelcol/3")
    manager_a.register(snap_name, snap_revision=1904)
    manager_b.register(snap_name, snap_revision=2154)
    # THEN is_used_by_other_units returns True regardless of revision mismatch
    # (it only checks whether another unit is registered, not whether revisions match)
    assert manager_a.is_used_by_other_units(snap_name)
    assert manager_b.is_used_by_other_units(snap_name)


def test_unregister_all_for_unit_removes_all_revisions(lock_dir):
    snap_name = "node-exporter"
    manager = SingletonSnapManager("unit-0")
    # GIVEN a current lockfile plus a manually-created stale one (simulating pre-fix state)
    manager.register(snap_name, snap_revision=2154)
    stale = SnapRegistrationFile(unit_name="unit-0", snap_name=snap_name, snap_revision=1904)
    (lock_dir / stale.filename).touch()
    assert manager.get_revisions(snap_name) == {1904, 2154}
    # WHEN unregister_all_for_unit is called
    manager.unregister_all_for_unit(snap_name)
    # THEN all lockfiles for this unit are gone
    assert manager.get_revisions(snap_name) == set()


def test_unregister_all_for_unit_does_not_affect_other_units():
    snap_name = "node-exporter"
    manager_a = SingletonSnapManager("unit-0")
    manager_b = SingletonSnapManager("unit-1")
    manager_a.register(snap_name, snap_revision=1)
    manager_b.register(snap_name, snap_revision=1)
    # WHEN unit-0 unregisters all
    manager_a.unregister_all_for_unit(snap_name)
    # THEN unit-1's lockfile is untouched
    assert manager_b.get_revisions(snap_name) == {1}
    assert "unit-1" in manager_b.get_units(snap_name)


def test_unregister_all_for_unit_no_files():
    snap_name = "node-exporter"
    manager = SingletonSnapManager("unit-0")
    # GIVEN no lockfiles exist
    # THEN unregister_all_for_unit does not raise
    manager.unregister_all_for_unit(snap_name)


def test_get_revisions_skips_malformed_files(lock_dir):
    snap_name = "opentelemetry-collector"
    # GIVEN a malformed file alongside a valid lockfile
    (lock_dir / "malformed_file").touch()
    (lock_dir / "LCK..opentelemetry-collector--rev1__unit-0").touch()
    # THEN get_revisions skips the malformed file and returns the valid revision
    assert SingletonSnapManager.get_revisions(snap_name) == {1}


def test_get_units_skips_malformed_files(lock_dir):
    snap_name = "opentelemetry-collector"
    # GIVEN a malformed file alongside a valid lockfile
    (lock_dir / "random_other_file").touch()
    (lock_dir / "LCK..opentelemetry-collector--rev1__unit-0").touch()
    # THEN get_units skips the malformed file and returns only the valid unit
    assert SingletonSnapManager.get_units(snap_name) == {"unit-0"}


def test_register_lockfile_revision_matches_registered_revision(lock_dir):
    snap_name = "node-exporter"
    manager = SingletonSnapManager("otelcol/0")
    # GIVEN a unit registered with an old revision (simulating pre-refresh state)
    manager.register(snap_name, snap_revision=1904)
    # WHEN the charm refreshes and registers a new revision
    manager.register(snap_name, snap_revision=2154)
    # THEN exactly one lockfile exists for this unit and snap
    lockfiles = list(lock_dir.glob(f"LCK..{snap_name}*otelcol_0"))
    assert len(lockfiles) == 1
    # AND that lockfile encodes the new revision
    reg = SnapRegistrationFile.from_filename(lockfiles[0].name)
    assert reg.snap_revision == 2154
