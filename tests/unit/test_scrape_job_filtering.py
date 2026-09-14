# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: block when a metrics-endpoint relation reports invalid scrape jobs.

The charm consumes scrape jobs over the `metrics-endpoint` relation. The
`prometheus_scrape` lib validates each scrape job with cos-tool and records any
validation failures in the leader's relation app data (under `event.scrape_job_errors`).
An invalid scrape job is excluded from the resulting jobs list, so the only way to
detect it is to inspect that same relation data. The charm should set `blocked` when
any such error is present, and return to `active` once the errors are cleared.
"""

import dataclasses
import json

import pytest
from ops.testing import Relation, State

MODEL_NAME = "test"
MODEL_UUID = "20ce8299-3634-4bef-8bd8-5ace6c8816b4"

# The fake cos-tool marks a scrape job as invalid when its yaml contains this marker.
INVALID_MARKER = "invalid_probe"

FAKE_COS_TOOL = """#!/bin/sh
if grep -q "{marker}" "$2"; then
    echo "error validating scrape job"
    exit 1
fi
exit 0
""".format(marker=INVALID_MARKER)


def _scrape_jobs(job_name: str, valid: bool) -> str:
    job = {
        "job_name": job_name,
        "metrics_path": "/metrics",
        "static_configs": [{"targets": ["localhost:9090"]}],
    }
    if not valid:
        # `sample_limit` must be a number; a dict makes the scrape job invalid. It is also in
        # the lib's ALLOWED_KEYS, so it survives sanitization and reaches the YAML validated
        # by the fake cos-tool (which greps for the marker to decide validity).
        job["sample_limit"] = {INVALID_MARKER: "whatever"}
    return json.dumps([job])


def _scrape_metadata(app_name: str) -> str:
    return json.dumps(
        {
            "model": MODEL_NAME,
            "model_uuid": MODEL_UUID,
            "application": app_name,
            "charm_name": f"{app_name}-charm",
        }
    )


def _metrics_endpoint_relation(app_name: str, job_name: str, valid: bool) -> Relation:
    return Relation(
        "metrics-endpoint",
        remote_app_name=app_name,
        remote_app_data={
            "scrape_jobs": _scrape_jobs(job_name, valid),
            "scrape_metadata": _scrape_metadata(app_name),
        },
    )


VALID_SCRAPE_JOB_RELATION = _metrics_endpoint_relation(
    "scrape-job-valid", "valid-job", valid=True
)
INVALID_SCRAPE_JOB_RELATION = _metrics_endpoint_relation(
    "scrape-job-invalid", "invalid-job", valid=False
)

# `metrics-endpoint` is paired with a metrics sink for realism; on its own it would not
# trigger the missing-mandatory-relations block, since those only cover cos-agent/juju-info.
SEND_REMOTE_WRITE = Relation("send-remote-write", remote_app_name="prometheus")


@pytest.fixture
def fake_cos_tool(tmp_path, monkeypatch):
    """Provide a fake executable cos-tool and chdir so the charm can resolve it."""
    tool = tmp_path / "cos-tool-amd64"
    tool.write_text(FAKE_COS_TOOL)
    tool.chmod(0o755)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    return tool


def test_valid_scrape_job_relation_remains_active(ctx, fake_cos_tool):
    # GIVEN a scrape relation with a valid scrape job
    state = State(
        leader=True,
        relations=[VALID_SCRAPE_JOB_RELATION, SEND_REMOTE_WRITE],
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN the charm stays active
    assert state_out.unit_status.name == "active"


def test_invalid_scrape_job_relation_blocks(ctx, fake_cos_tool):
    # GIVEN a scrape relation with an invalid scrape job
    state = State(
        leader=True,
        relations=[INVALID_SCRAPE_JOB_RELATION, SEND_REMOTE_WRITE],
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN the charm is blocked with a helpful message
    assert state_out.unit_status.name == "blocked"
    assert state_out.unit_status.message == "Invalid scrape jobs. See debug-log"


def test_invalid_scrape_job_relation_broken_recovers_to_active(ctx, fake_cos_tool):
    # GIVEN an invalid scrape relation has already blocked the charm
    state = State(
        leader=True,
        relations=[INVALID_SCRAPE_JOB_RELATION, SEND_REMOTE_WRITE],
    )
    blocked_state = ctx.run(ctx.on.update_status(), state=state)
    assert blocked_state.unit_status.name == "blocked"

    # WHEN the invalid scrape relation is removed
    removed_relation = blocked_state.get_relation(INVALID_SCRAPE_JOB_RELATION.id)
    state_out = ctx.run(ctx.on.relation_broken(removed_relation), blocked_state)

    # THEN the charm is active again
    assert state_out.unit_status.name == "active"


def test_invalid_scrape_job_relation_becoming_valid_recovers_to_active(ctx, fake_cos_tool):
    # GIVEN an invalid scrape relation has already blocked the charm
    state = State(
        leader=True,
        relations=[INVALID_SCRAPE_JOB_RELATION, SEND_REMOTE_WRITE],
    )
    blocked_state = ctx.run(ctx.on.update_status(), state=state)
    assert blocked_state.unit_status.name == "blocked"
    relation_after_invalid = blocked_state.get_relation(INVALID_SCRAPE_JOB_RELATION.id)

    # WHEN the same scrape relation updates its jobs to become valid
    now_valid_relation = dataclasses.replace(
        relation_after_invalid,
        remote_app_data={
            **relation_after_invalid.remote_app_data,
            "scrape_jobs": VALID_SCRAPE_JOB_RELATION.remote_app_data["scrape_jobs"],
        },
    )
    recovered_state = ctx.run(
        ctx.on.relation_changed(now_valid_relation),
        dataclasses.replace(
            blocked_state, relations=[now_valid_relation, SEND_REMOTE_WRITE]
        ),
    )

    # THEN the charm is active again
    assert recovered_state.unit_status.name == "active"
