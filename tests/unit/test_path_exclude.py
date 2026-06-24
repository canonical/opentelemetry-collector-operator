# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Test that path_exclude config is applied to both var-log and snap fstab log jobs."""

from unittest.mock import patch

from ops.testing import PeerRelation, State, SubordinateRelation

from charms.grafana_agent.v0.cos_agent import CosAgentProviderUnitData
from helpers import get_otelcol_config_file
from snap_fstab import SnapFstab, _SnapFstabEntry


def _mock_fstab_entry() -> _SnapFstabEntry:
    """Create a mock fstab entry for a snap (e.g., postgresql)."""
    return _SnapFstabEntry(
        source="/snap/charmed-postgresql/42/var/log/postgresql",
        target="/snap/grafana-agent/123/shared-logs/charmed-postgresql-logs",
        fstype="none",
        options=["bind", "ro"],
        dump=0,
        fsck=0,
    )


def _mock_fstab(tmp_path):
    """Create a mock SnapFstab with a single entry."""
    fstab_path = tmp_path / "mock.fstab"
    fstab_path.write_text(
        "/snap/charmed-postgresql/42/var/log/postgresql "
        "/snap/grafana-agent/123/shared-logs/charmed-postgresql-logs "
        "none bind,ro 0 0\n"
    )
    return SnapFstab(fstab_path)


def test_path_exclude_applied_to_var_log(ctx, unit_name, config_folder):
    """Scenario: path_exclude config is applied to /var/log scrape job."""
    # GIVEN a charm with path_exclude configured
    state = State(config={"path_exclude": "/var/log/journal/**;/var/log/syslog"})

    # WHEN any event executes the reconciler
    ctx.run(ctx.on.update_status(), state=state)

    # THEN the config file exists
    cfg = get_otelcol_config_file(unit_name, config_folder)
    # AND the filelog/var-log receiver has the exclude patterns
    var_log_receiver = cfg["receivers"]["filelog/var-log"]
    assert "/var/log/journal/**" in var_log_receiver["exclude"]
    assert "/var/log/syslog" in var_log_receiver["exclude"]


def test_path_exclude_applied_to_snap_fstab_logs(ctx, unit_name, config_folder, tmp_path):
    """Scenario: path_exclude config is applied to fstab-based snap log jobs.

    Regression test for https://github.com/canonical/opentelemetry-collector-operator/issues/324
    """
    # GIVEN a charm with path_exclude configured
    # AND a cos-agent relation with a snap that has log_slots
    provider_data = CosAgentProviderUnitData(
        metrics_alert_rules={},
        log_alert_rules={},
        dashboards=[],
        metrics_scrape_jobs=[],
        log_slots=["charmed-postgresql:logs"],
    )
    cos_agent_relation = SubordinateRelation(
        "cos-agent",
        remote_app_name="postgresql",
        remote_unit_id=0,
        remote_unit_data={CosAgentProviderUnitData.KEY: provider_data.json()},
    )
    peers_relation = PeerRelation("peers")
    state = State(
        relations=[cos_agent_relation, peers_relation],
        config={"path_exclude": "/var/log/journal/**;*.gz"},
    )

    # AND a mock fstab with an entry for the snap
    mock_fstab = _mock_fstab(tmp_path)

    # WHEN any event executes the reconciler
    with patch("charm.SnapFstab", return_value=mock_fstab):
        ctx.run(ctx.on.update_status(), state=state)

    # THEN the config file exists
    cfg = get_otelcol_config_file(unit_name, config_folder)

    # AND the snap filelog receiver has the exclude patterns
    snap_receiver_name = [
        k for k in cfg["receivers"] if k.startswith("filelog/charmed-postgresql")
    ]
    assert len(snap_receiver_name) == 1, f"Expected one snap receiver, got: {snap_receiver_name}"

    snap_receiver = cfg["receivers"][snap_receiver_name[0]]
    assert "/var/log/journal/**" in snap_receiver["exclude"]
    assert "*.gz" in snap_receiver["exclude"]


def test_path_exclude_empty_by_default(ctx, unit_name, config_folder):
    """Scenario: When path_exclude is empty, exclude list contains only empty string."""
    # GIVEN a charm with default (empty) path_exclude
    state = State()

    # WHEN any event executes the reconciler
    ctx.run(ctx.on.update_status(), state=state)

    # THEN the config file exists
    cfg = get_otelcol_config_file(unit_name, config_folder)
    # AND the filelog/var-log receiver has an empty exclude pattern
    var_log_receiver = cfg["receivers"]["filelog/var-log"]
    assert var_log_receiver["exclude"] == [""]
