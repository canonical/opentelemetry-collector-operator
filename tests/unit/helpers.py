# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import yaml
from pathlib import Path

from charmlibs.pathops import LocalPath

from singleton_snap import SnapRegistrationFile


def get_otelcol_file(unit_name: str, config_folder:str) -> dict:
    config_filename = f"{SnapRegistrationFile._normalize_name(unit_name)}.yaml"
    config_path = LocalPath(Path(config_folder)/config_filename)
    assert config_path.exists(), "file does not exist"
    cfg = yaml.safe_load(config_path.read_text())
    return cfg
