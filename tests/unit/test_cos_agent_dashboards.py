# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: cos-agent dashboards without a title must not overwrite each other.

Regression test for the bug surfaced by cos-proxy
(https://github.com/canonical/cos-proxy-operator/pull/241) and fixed in the
cos_agent charm library (grafana-agent-operator#415, LIBPATCH 26): when a
principal sends multiple dashboards that lack a ``title`` key, they used to all
be assigned the placeholder ``no_title`` and therefore collide on the same
filename on disk, so only the last one survived and was forwarded to Grafana.
"""

import json

from charms.grafana_agent.v0.cos_agent import CosAgentPeersUnitData
from cosl.utils import LZMABase64
from integrations import _add_dashboards
from ops.testing import PeerRelation, Relation, State


def encode_as_dashboard(dct: dict) -> str:
    return LZMABase64.compress(json.dumps(dct))


def _state_with_cos_agent_dashboards(*dashboard_groups) -> State:
    """Build a State whose peer unit databag carries the given dashboard groups.

    Each element of *dashboard_groups* is a list of raw dashboard dicts belonging
    to a single principal app. Synthetic app names "primary_0", "primary_1", ...
    ensure each group is treated as a distinct app by ``_gather_peer_data``.
    A ``grafana-dashboards-provider`` relation is included so the reconciler
    forwards the aggregated dashboards, letting us assert the on-disk outcome.
    """
    peers_data: dict = {}
    for idx, dashboards in enumerate(dashboard_groups):
        app_name = f"primary_{idx}"
        unit_name = f"{app_name}/0"
        peers_data[idx + 1] = {
            f"{CosAgentPeersUnitData.KEY}-{unit_name}": CosAgentPeersUnitData(
                unit_name=unit_name,
                relation_id=str(40 + idx),
                relation_name="cos-agent",
                dashboards=[encode_as_dashboard(d) for d in dashboards],
                metrics_alert_rules={},
                log_alert_rules={},
            ).json()
        }

    peer_relation = PeerRelation(
        endpoint="peers",
        interface="otelcol_replica",
        peers_data=peers_data,
    )
    provider = Relation("grafana-dashboards-provider")
    return State(relations=[peer_relation, provider], leader=True)


def _forwarded_dashboards(state_out) -> dict:
    for rel in state_out.relations:
        if rel.endpoint == "grafana-dashboards-provider":
            return json.loads(rel.local_app_data["dashboards"])["templates"]
    raise AssertionError("no grafana-dashboards-provider relation found in output state")


def test_multiple_no_title_dashboards_are_not_overwritten(ctx):
    """Scenario: seven untitled cos-agent dashboards all survive to Grafana."""
    # GIVEN seven dashboards from the same app, none of which have a title
    # (the root scenario from cos-proxy#241: multiple untitled dashboards that
    # previously all mapped to `juju_no_title-...json` and clobbered one another)
    no_title_dashes = [{"uid": f"uid_{i}", "overwrite": True, "tags": []} for i in range(7)]
    state = _state_with_cos_agent_dashboards(no_title_dashes)

    # WHEN a reconcile runs
    with ctx(ctx.on.update_status(), state=state) as mgr:
        state_out = mgr.run()

    # THEN all seven cos-agent dashboards are forwarded under unique filenames
    templates = _forwarded_dashboards(state_out)
    no_title_keys = [k for k in templates if "no_title" in k]
    assert len(no_title_keys) == 7, (
        f"Expected 7 unique no_title dashboards, got {len(no_title_keys)}: {no_title_keys}"
    )
    assert len(set(no_title_keys)) == 7


def test_nested_provisioning_title_is_extracted(ctx):
    """Scenario: a title nested under the provisioning envelope is used."""
    # GIVEN a dashboard in Grafana provisioning envelope format with the title
    # inside the nested `dashboard` sub-object rather than at the top level
    raw_dashboard = {
        "dashboard": {"title": "My Nested Dashboard", "panels": [], "uid": "abc123"},
        "overwrite": True,
    }
    state = _state_with_cos_agent_dashboards([raw_dashboard])

    # WHEN a reconcile runs
    with ctx(ctx.on.update_status(), state=state) as mgr:
        state_out = mgr.run()

    # THEN the nested title is used instead of a `no_title` placeholder
    templates = _forwarded_dashboards(state_out)
    assert any("my_nested_dashboard" in k for k in templates), (
        f"nested title not used for filename; got keys: {list(templates)}"
    )
    assert not any("no_title" in k for k in templates)


def test_add_dashboards_same_title_do_not_overwrite(tmp_path):
    """Defense in depth: `_add_dashboards` must not clobber same-title dashboards.

    Independently of any title-extraction logic upstream, two dashboards that
    resolve to the same (title, charm, rel_id) triple must still be written to
    distinct files on disk (disambiguated by their content identity).
    """
    # GIVEN two dashboards from the same charm/relation with an identical title
    # but different content
    dashboards = [
        {
            "charm": "cos-agent-cos-proxy",
            "relation_id": "17",
            "title": "same title",
            "content": {"uid": "uid_a", "overwrite": True},
        },
        {
            "charm": "cos-agent-cos-proxy",
            "relation_id": "17",
            "title": "same title",
            "content": {"uid": "uid_b", "overwrite": True},
        },
    ]

    # WHEN they are written to disk
    _add_dashboards(dashboards, dest_path=tmp_path)

    # THEN two distinct files exist, one per dashboard content
    written = sorted(tmp_path.glob("*.json"))
    assert len(written) == 2, f"expected 2 files, got: {[f.name for f in written]}"
    uids = {json.loads(f.read_text())["uid"] for f in written}
    assert uids == {"uid_a", "uid_b"}


def test_add_dashboards_filename_is_stable_across_calls(tmp_path):
    """The generated filename must be stable for unchanged content (no churn)."""
    # GIVEN the same dashboard written twice
    dash = {
        "charm": "cos-agent-cos-proxy",
        "relation_id": "17",
        "title": "",  # untitled: identity must come from content, not the title
        "content": {"uid": "stable_uid", "overwrite": True},
    }

    # WHEN it is written on two separate reconciles
    _add_dashboards([dash], dest_path=tmp_path)
    first = {f.name for f in tmp_path.glob("*.json")}
    _add_dashboards([dash], dest_path=tmp_path)
    second = {f.name for f in tmp_path.glob("*.json")}

    # THEN the same single filename is produced (no stale/duplicate files)
    assert first == second
    assert len(second) == 1
