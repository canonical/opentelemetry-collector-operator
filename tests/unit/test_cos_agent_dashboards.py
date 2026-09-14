# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: cos-agent dashboards are forwarded to Grafana without overwriting each other."""

import json

from charms.grafana_agent.v0.cos_agent import CosAgentProviderUnitData
from cosl.utils import LZMABase64
from integrations import _add_dashboards
from ops.testing import PeerRelation, Relation, State, SubordinateRelation


def encode_as_dashboard(dct: dict) -> str:
    return LZMABase64.compress(json.dumps(dct))


def _cos_agent_state(*dashboard_groups: list[dict]) -> State:
    """Build a State from `juju show-unit`-shaped cos-agent relations.

    Each group is one principal app's dashboards, carried under the ``config``
    key of its own ``cos-agent`` subordinate relation (as a real principal does).
    The reconciler stashes cos-agent data into ``peers`` before forwarding it to
    the ``grafana-dashboards-provider`` relation, where we observe the output.
    """
    relations: list = [
        Relation("grafana-dashboards-provider"),
        PeerRelation(endpoint="peers", interface="otelcol_replica"),
    ]
    for idx, dashboards in enumerate(dashboard_groups):
        config = CosAgentProviderUnitData(
            metrics_alert_rules={},
            log_alert_rules={},
            dashboards=[encode_as_dashboard(d) for d in dashboards],
            metrics_scrape_jobs=[],
            log_slots=[],
        )
        relations.append(
            SubordinateRelation(
                endpoint="cos-agent",
                interface="cos_agent",
                remote_app_name=f"principal_{idx}",
                remote_unit_data={CosAgentProviderUnitData.KEY: config.json()},
            )
        )
    return State(relations=relations, leader=True)


def _forwarded_dashboards(state_out) -> dict:
    for rel in state_out.relations:
        if rel.endpoint == "grafana-dashboards-provider":
            return json.loads(rel.local_app_data["dashboards"])["templates"]
    raise AssertionError("no grafana-dashboards-provider relation found in output state")


def test_titled_dashboards_forwarded(ctx):
    """Titled dashboards are forwarded, keyed by their (lowercased) title."""
    # GIVEN a principal sending two titled dashboards (as postgresql ships)
    state = _cos_agent_state(
        [
            {"title": "pgBackRest", "uid": "uid-pgbackrest", "panels": []},
            {"title": "PostgreSQL Metrics", "uid": "uid-psql-metrics", "panels": []},
        ]
    )

    # WHEN reconciling
    with ctx(ctx.on.update_status(), state=state) as mgr:
        state_out = mgr.run()

    # THEN both dashboards reach Grafana under their titles
    templates = _forwarded_dashboards(state_out)
    assert any("pgbackrest" in k for k in templates), list(templates)
    assert any("postgresql_metrics" in k for k in templates), list(templates)


def test_untitled_dashboards_not_overwritten(ctx):
    """Untitled dashboards get unique filenames instead of clobbering each other."""
    # GIVEN two dashboards with no title
    state = _cos_agent_state([{"uid": f"uid_{i}", "overwrite": True} for i in range(2)])

    # WHEN reconciling
    with ctx(ctx.on.update_status(), state=state) as mgr:
        state_out = mgr.run()

    # THEN both are forwarded under distinct no_title_N keys
    no_title = [k for k in _forwarded_dashboards(state_out) if "no_title" in k]
    assert len(set(no_title)) == 2, no_title


def test_nested_title_extracted(ctx):
    """A title nested under the provisioning envelope is used, not `no_title`."""
    # GIVEN a dashboard with its title inside the nested `dashboard` object
    state = _cos_agent_state(
        [{"dashboard": {"title": "My Nested Dashboard", "uid": "abc123"}, "overwrite": True}]
    )

    # WHEN reconciling
    with ctx(ctx.on.update_status(), state=state) as mgr:
        state_out = mgr.run()

    # THEN the nested title is used
    templates = _forwarded_dashboards(state_out)
    assert any("my_nested_dashboard" in k for k in templates), list(templates)
    assert not any("no_title" in k for k in templates)


def test_same_title_written_to_distinct_files(tmp_path):
    """Same (title, charm, rel_id) but different content -> distinct files."""
    # GIVEN two same-titled dashboards from one charm/relation with different content
    dashboards = [
        {"charm": "c", "relation_id": "17", "title": "dup", "content": {"uid": "uid_a"}},
        {"charm": "c", "relation_id": "17", "title": "dup", "content": {"uid": "uid_b"}},
    ]

    # WHEN writing them to disk
    _add_dashboards(dashboards, dest_path=tmp_path)

    # THEN both survive as separate files
    written = sorted(tmp_path.glob("*.json"))
    assert {json.loads(f.read_text())["uid"] for f in written} == {"uid_a", "uid_b"}


def test_filename_stable_across_calls(tmp_path):
    """Unchanged content yields the same filename (no churn / stale files)."""
    # GIVEN one untitled dashboard (identity must come from content, not title)
    dash = {"charm": "c", "relation_id": "17", "title": "", "content": {"uid": "stable"}}

    # WHEN writing it twice
    _add_dashboards([dash], dest_path=tmp_path)
    _add_dashboards([dash], dest_path=tmp_path)

    # THEN only one file exists
    assert len(list(tmp_path.glob("*.json"))) == 1
