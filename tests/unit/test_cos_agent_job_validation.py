# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: COS Agent metrics jobs are validated with cos-tool."""

import pytest
from charms.grafana_agent.v0.cos_agent import CosAgentProviderUnitData
from ops.model import BlockedStatus
from ops.testing import PeerRelation, Relation, State, SubordinateRelation

from helpers import get_otelcol_config_file

# The fake cos-tool marks a scrape job as invalid when its yaml contains this marker.
INVALID_MARKER = "invalid_probe"

FAKE_COS_TOOL = """#!/bin/sh
if grep -q "{marker}" "$2"; then
    echo "error validating scrape job"
    exit 1
fi
exit 0
""".format(marker=INVALID_MARKER)


def _cos_agent_relation(jobs):
    provider_data = CosAgentProviderUnitData(
        metrics_alert_rules={},
        log_alert_rules={},
        dashboards=[],
        metrics_scrape_jobs=jobs,
        log_slots=[],
    )
    return SubordinateRelation(
        "cos-agent",
        remote_app_name="postgresql",
        remote_unit_id=0,
        remote_unit_data={CosAgentProviderUnitData.KEY: provider_data.json()},
    )


def _valid_job():
    return {"job_name": "valid-job", "metrics_path": "/metrics",
            "static_configs": [{"targets": ["localhost:9090"]}]}


def _invalid_job():
    job = _valid_job()
    job["job_name"] = "invalid-job"
    job["invalid_probe"] = "whatever"
    return job


def _cos_agent_receivers(cfg):
    return [k for k in cfg["receivers"] if k.startswith("prometheus/cos-agent")]


@pytest.fixture
def fake_cos_tool(tmp_path, monkeypatch):
    """Provide a fake executable cos-tool and chdir so the charm can resolve it."""
    tool = tmp_path / "cos-tool-amd64"
    tool.write_text(FAKE_COS_TOOL)
    tool.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    return tool


def test_valid_cos_agent_jobs_are_kept(ctx, unit_name, config_folder, fake_cos_tool):
    """Scenario: valid cos-agent scrape jobs are added to the otelcol config."""
    # GIVEN a cos-agent relation with a valid scrape job
    state = State(
        leader=True,
        relations=[_cos_agent_relation([_valid_job()]), PeerRelation("peers")],
    )

    # WHEN any event executes the reconciler
    ctx.run(ctx.on.update_status(), state=state)

    # THEN only the valid job is present in the prometheus receiver config
    cfg = get_otelcol_config_file(unit_name, config_folder)
    receivers = _cos_agent_receivers(cfg)
    assert len(receivers) == 1
    scrape_configs = cfg["receivers"][receivers[0]]["config"]["scrape_configs"]
    assert {job["job_name"] for job in scrape_configs} == {"valid-job"}


def test_invalid_cos_agent_jobs_are_dropped_and_status_blocked(ctx, unit_name, config_folder, fake_cos_tool):
    """Scenario: an invalid job is dropped, valid ones kept, and the unit is blocked."""
    # GIVEN a cos-agent relation with one valid and one invalid scrape job
    relation = _cos_agent_relation([_valid_job(), _invalid_job()])

    # WHEN the reconciler runs
    out = ctx.run(
        ctx.on.update_status(),
        State(leader=True, relations=[relation, PeerRelation("peers")]),
    )

    # THEN the valid job is kept and the invalid one is dropped
    cfg = get_otelcol_config_file(unit_name, config_folder)
    receivers = _cos_agent_receivers(cfg)
    assert len(receivers) == 1
    scrape_configs = cfg["receivers"][receivers[0]]["config"]["scrape_configs"]
    assert {job["job_name"] for job in scrape_configs} == {"valid-job"}

    # AND the unit is blocked
    assert isinstance(out.unit_status, BlockedStatus)
    assert out.unit_status.message == "Invalid COS Agent metrics jobs. See debug-log"


def test_cos_tool_unavailable_does_not_block(ctx, unit_name, config_folder):
    """Scenario: when cos-tool is unavailable, jobs pass through and the unit is not blocked."""
    # GIVEN a cos-agent relation with jobs, but no cos-tool binary on disk
    relation = _cos_agent_relation([_valid_job()])
    # AND an outgoing remote-write relation so the charm is not blocked on mandatory pairs
    remote_write = Relation("send-remote-write", remote_app_name="prom", remote_app_data={})

    # WHEN the reconciler runs
    out = ctx.run(
        ctx.on.update_status(),
        State(
            leader=True,
            relations=[relation, remote_write, PeerRelation("peers")],
        ),
    )

    # THEN the job is still added and the unit is not blocked with the validation message
    cfg = get_otelcol_config_file(unit_name, config_folder)
    receivers = _cos_agent_receivers(cfg)
    assert len(receivers) == 1
    scrape_configs = cfg["receivers"][receivers[0]]["config"]["scrape_configs"]
    assert {job["job_name"] for job in scrape_configs} == {"valid-job"}
    assert out.unit_status.message != "Invalid COS Agent metrics jobs. See debug-log"
