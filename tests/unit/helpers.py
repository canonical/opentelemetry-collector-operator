# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

import yaml
from pathlib import Path


def get_otelcol_file(file_path: Path) -> dict:
    assert file_path.exists(), "file does not exist"
    cfg = yaml.safe_load(file_path.read_text())
    return cfg
