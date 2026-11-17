# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

import pytest
from src.snap_management import SnapMap, get_system_arch


@pytest.mark.parametrize(
    "machine, expected",
    [
        ("x86_64", "amd64"),
        ("amd64", "amd64"),
        ("aarch64", "arm64"),
        ("arm64", "arm64"),
        ("armv8b", "arm64"),
        ("armv8l", "arm64"),
        ("ppc64le", "ppc64el"),
        ("PPC64LE", "ppc64el"),
        ("riscv64", "riscv64"),
    ],
)
def test_get_system_arch(monkeypatch, machine, expected):
    # GIVEN a machine reporting the given architecture
    monkeypatch.setattr("platform.machine", lambda: machine)
    # WHEN the architecture is resolved
    # THEN it is normalized to the name used by the snap map
    assert get_system_arch() == expected


def test_ppc64le_resolves_to_snap_revision(monkeypatch):
    # GIVEN a ppc64le machine
    monkeypatch.setattr("platform.machine", lambda: "ppc64le")
    # WHEN the snap revision is looked up with the detected architecture
    arch = get_system_arch()
    # THEN the lookup succeeds for every managed snap
    for snap_name in SnapMap.snaps():
        assert SnapMap.get_revision(snap_name, arch=arch) > 0
