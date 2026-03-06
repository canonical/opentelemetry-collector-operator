# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Dashboard forwarding to Grafana."""

import json

from cosl.utils import LZMABase64
from ops.testing import Relation, State


def encode_as_dashboard(dct: dict):
    return LZMABase64.compress(json.dumps(dct))


def test_dashboard_propagation(ctx):
    """Scenario: Dashboards are forwarded when a dashboard provider is related."""
    # GIVEN multiple remote charms with dashboards
    content_in = {
        0: encode_as_dashboard({"whoami": "0"}),
        1: encode_as_dashboard({"whoami": "1"}),
    }
    data = {
        idx: {
            "templates": {
                f"file:dashboard-{idx}": {"charm": "some-charm", "content": content_in[idx]}
            }
        }
        for idx in content_in
    }
    # WHEN they are related to the grafana-dashboards-consumer endpoint
    consumer0 = Relation(
        "grafana-dashboards-consumer",
        remote_app_data={"dashboards": json.dumps(data[0])},
        id=100,
    )
    consumer1 = Relation(
        "grafana-dashboards-consumer",
        remote_app_data={"dashboards": json.dumps(data[1])},
        id=101,
    )
    # AND otelcol is related to multiple Grafana instances
    provider0 = Relation("grafana-dashboards-provider")
    provider1 = Relation("grafana-dashboards-provider")

    state = State(
        relations=[consumer0, consumer1, provider0, provider1],
        leader=True,
    )
    # WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        state_out = mgr.run()
        for rel in state_out.relations:
            # THEN each Grafana instance receives otelcol's bundled dashboard and aggregated dashboards
            if "-provider" in rel.endpoint:
                dashboard_str = rel.local_app_data["dashboards"]
                assert "file:juju_file:dashboard-0-some-charm-100" in dashboard_str
                assert "file:juju_file:dashboard-1-some-charm-101" in dashboard_str
                assert "file:overview-dashboard" in dashboard_str
