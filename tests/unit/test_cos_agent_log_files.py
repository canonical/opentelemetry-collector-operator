# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: COS Agent include_log_files integration."""

import json
import yaml
from pathlib import Path
from charmlibs.pathops import LocalPath
from ops.testing import State, SubordinateRelation

from singleton_snap import SnapRegistrationFile


def test_cos_agent_log_files_are_scraped(ctx, config_folder, unit_name):
    """Test that log files specified via cos-agent are properly configured."""
    # GIVEN a charm with a cos-agent relation that provides include_log_files
    cos_agent_relation = SubordinateRelation(
        "cos-agent",
        remote_unit_data={
            "config": json.dumps({
                "metrics_alert_rules": {},
                "log_alert_rules": {},
                "dashboards": [],
                "metrics_scrape_jobs": [],
                "log_slots": [],
                "include_log_files": ["/var/log/app.log", "/var/log/app-error.log"]
            })
        },
    )

    state = State(
        relations=[cos_agent_relation],
        config={"path_exclude": ""},
    )

    # WHEN the config-changed event is triggered
    with ctx(ctx.on.config_changed(), state=state) as mgr:
        mgr.run()

    # THEN the config should contain filelog receivers for each log file
    config_filename = f"{SnapRegistrationFile._normalize_name(unit_name)}.yaml"
    config_path = LocalPath(Path(config_folder) / config_filename)
    assert config_path.exists(), "config file should exist"

    cfg = yaml.safe_load(config_path.read_text())

    # Check that we have receivers for the log files
    assert "receivers" in cfg

    # Look for the filelog receivers with the expected names
    receiver_names = list(cfg["receivers"].keys())

    # We should have receivers for both log files
    var_log_app_log_receivers = [
        name for name in receiver_names
        if "filelog" in name and "var_log_app_log" in name
    ]
    var_log_app_error_log_receivers = [
        name for name in receiver_names
        if "filelog" in name and "var_log_app-error_log" in name
    ]

    assert len(var_log_app_log_receivers) > 0, "Should have receiver for /var/log/app.log"
    assert len(var_log_app_error_log_receivers) > 0, "Should have receiver for /var/log/app-error.log"

    # Verify the receiver configuration for the first log file
    receiver_name = var_log_app_log_receivers[0]
    receiver_config = cfg["receivers"][receiver_name]

    assert receiver_config["include"] == ["/var/log/app.log"]
    assert "attributes" in receiver_config
    
    # Verify topology labels
    attrs = receiver_config["attributes"]
    assert attrs["job"] == "cos-agent-var_log_app_log"
    assert attrs["juju_application"] == "my-principal-app"
    assert attrs["juju_unit"] == "my-principal-app/0"
    assert "juju_model" in attrs
    assert "juju_model_uuid" in attrs
    assert "juju_charm" in attrs


def test_cos_agent_empty_log_files(ctx, config_folder, unit_name):
    """Test that empty include_log_files list doesn't cause errors."""
    # GIVEN a charm with cos-agent relation but no include_log_files
    cos_agent_relation = SubordinateRelation(
        "cos-agent",
        remote_unit_data={
            "config": json.dumps({
                "metrics_alert_rules": {},
                "log_alert_rules": {},
                "dashboards": [],
                "metrics_scrape_jobs": [],
                "log_slots": [],
                "include_log_files": []
            })
        },
    )

    state = State(
        relations=[cos_agent_relation],
        config={"path_exclude": ""},
    )

    # WHEN the config-changed event is triggered
    with ctx(ctx.on.config_changed(), state=state) as mgr:
        mgr.run()

    # THEN the config should be generated without errors
    config_filename = f"{SnapRegistrationFile._normalize_name(unit_name)}.yaml"
    config_path = LocalPath(Path(config_folder) / config_filename)
    assert config_path.exists(), "config file should exist"

    cfg = yaml.safe_load(config_path.read_text())
    assert "receivers" in cfg


def test_cos_agent_log_files_none(ctx, config_folder, unit_name):
    """Test that missing include_log_files field doesn't cause errors (backward compatibility)."""
    # GIVEN a charm with cos-agent relation without include_log_files field
    cos_agent_relation = SubordinateRelation(
        "cos-agent",
        remote_unit_data={
            "config": json.dumps({
                "metrics_alert_rules": {},
                "log_alert_rules": {},
                "dashboards": [],
                "metrics_scrape_jobs": [],
                "log_slots": []
            })
        },
    )

    state = State(
        relations=[cos_agent_relation],
        config={"path_exclude": ""},
    )

    # WHEN the config-changed event is triggered
    with ctx(ctx.on.config_changed(), state=state) as mgr:
        mgr.run()

    # THEN the config should be generated without errors
    config_filename = f"{SnapRegistrationFile._normalize_name(unit_name)}.yaml"
    config_path = LocalPath(Path(config_folder) / config_filename)
    assert config_path.exists(), "config file should exist"

    cfg = yaml.safe_load(config_path.read_text())
    assert "receivers" in cfg
