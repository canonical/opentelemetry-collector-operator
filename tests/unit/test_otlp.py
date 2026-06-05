# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: OTLP endpoints and rules transfer."""

import json

import pytest
from charmlibs.interfaces.otlp import OtlpEndpoint
from charms.grafana_agent.v0.cos_agent import CosAgentProviderUnitData
from cosl.utils import LZMABase64
from ops.testing import Model, PeerRelation, Relation, State, SubordinateRelation

from src.integrations import send_otlp

MODEL_NAME = "foo-model"
MODEL_UUID = "f4d59020-c8e7-4053-8044-a2c1e5591c7f"
MODEL = Model(MODEL_NAME, uuid=MODEL_UUID)
OTELCOL_METADATA = {
    "model": MODEL_NAME,
    "model_uuid": MODEL_UUID,
    "application": "otelcol",  # from app_name in conftest.py
    "unit": "otelcol/0",
    "charm_name": "opentelemetry-collector",
}

# A marker alert rule provided by a related application (e.g. postgresql).
RELATED_APP_ALERT = "PostgresqlInvalidIndex"
# A marker log (logql) alert rule provided by a related application over `receive-loki-logs`.
RELATED_APP_LOG_ALERT = "ZincTooManyLogs"


def _postgresql_alert_groups() -> dict:
    """Return a `{"groups": [...]}` alert-rules payload for the postgresql marker alert."""
    return {
        "groups": [
            {
                "name": "postgresql_index_group",
                "rules": [
                    {
                        "alert": RELATED_APP_ALERT,
                        "expr": "pg_general_index_info_pg_relation_size > 0",
                        "for": "6h",
                        "labels": {
                            "severity": "critical",
                            "juju_model": MODEL_NAME,
                            "juju_model_uuid": MODEL_UUID,
                            "juju_application": "postgresql",
                            "juju_charm": "postgresql",
                        },
                    }
                ],
            }
        ]
    }


# Alert rules as provided by an application related over `metrics-endpoint`
# (the relation databag funnels alert rules through as a JSON string).
RELATED_APP_ALERT_RULES = {"alert_rules": json.dumps(_postgresql_alert_groups())}


def _decompress(rules: str) -> dict:
    assert rules, "expected a non-empty compressed `rules` databag value"
    return json.loads(LZMABase64.decompress(rules))


def _forwarded_rules(decompressed: dict, kind: str) -> list:
    """Flatten the rules of a given kind ('promql' or 'logql') from a decompressed databag."""
    return [
        rule
        for group in decompressed[kind].get("groups", [])
        for rule in group.get("rules", [])
    ]


def test_send_otlp(ctx):
    # GIVEN otelcol supports (defined by OtlpRequirer) a subset of OTLP protocols and telemetries
    # * a remote app provides multiple OtlpEndpoints
    remote_app_data_1 = {
        "endpoints": json.dumps(
            [
                {
                    "protocol": "http",
                    "endpoint": "http://provider-123:4318",
                    "telemetries": ["logs", "metrics"],
                }
            ]
        )
    }
    remote_app_data_2 = {
        "endpoints": json.dumps(
            [
                {
                    "protocol": "grpc",
                    "endpoint": "http://provider-456:4317",
                    "telemetries": ["traces"],
                },
                {
                    "protocol": "http",
                    "endpoint": "http://provider-456:4318",
                    "telemetries": ["metrics"],
                },
            ]
        )
    }

    expected_endpoints = {
        456: OtlpEndpoint(
            protocol="grpc",
            endpoint="http://provider-456:4317",
            telemetries=["traces"],
        ),
        123: OtlpEndpoint(
            protocol="http",
            endpoint="http://provider-123:4318",
            telemetries=["logs", "metrics"],
        ),
    }

    # WHEN they are related over the "send-otlp" endpoint
    provider_1 = Relation(
        "send-otlp",
        id=123,
        remote_app_data=remote_app_data_1,
    )
    provider_2 = Relation(
        "send-otlp",
        id=456,
        remote_app_data=remote_app_data_2,
    )
    state = State(relations=[provider_1, provider_2], leader=True)

    # AND WHEN any event executes the reconciler
    with ctx(ctx.on.update_status(), state=state) as mgr:
        remote_endpoints = send_otlp(mgr.charm)

    # THEN the returned endpoints are filtered accordingly
    assert {k: v.model_dump() for k, v in remote_endpoints.items()} == {
        k: v.model_dump() for k, v in expected_endpoints.items()
    }


@pytest.mark.parametrize("forward_rules", [True, False])
def test_forwarding_otlp_rule_counts(ctx, forward_rules):
    # GIVEN multiple send-otlp relations
    sender_1 = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
    sender_2 = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
    state = State(
        relations=[sender_1, sender_2],
        leader=True,
        model=MODEL,
        config={"forward_alert_rules": forward_rules},
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    for relation in list(state_out.relations):
        if relation.endpoint == "send-otlp":
            assert (decompressed := _decompress(relation.local_app_data.get("rules")))

            # THEN bundled rules are included in the forwarded databag
            logql_group_names = {r.get("name") for r in decompressed["logql"].get("groups", [])}
            promql_group_names = {r.get("name") for r in decompressed["promql"].get("groups", [])}
            assert not logql_group_names
            bundled_rule_base_name = f"{MODEL_NAME}_f4d59020_otelcol".replace('-', '_')
            assert f"{bundled_rule_base_name}_Exporter_rules" in promql_group_names


def _zinc_log_alert_groups() -> dict:
    """Return a `{"groups": [...]}` logql alert-rules payload for the zinc marker log alert."""
    return {
        "groups": [
            {
                "name": "zinc_log_group",
                "rules": [
                    {
                        "alert": RELATED_APP_LOG_ALERT,
                        "expr": 'rate({juju_application="zinc"}[5m]) > 100',
                        "for": "5m",
                        "labels": {
                            "severity": "warning",
                            "juju_model": MODEL_NAME,
                            "juju_model_uuid": MODEL_UUID,
                            "juju_application": "zinc",
                            "juju_charm": "zinc-k8s",
                        },
                    }
                ],
            }
        ]
    }


def _metrics_endpoint_source() -> list:
    """Source: an app related over `metrics-endpoint` (e.g. postgresql) providing promql rules."""
    return [
        Relation(
            "metrics-endpoint",
            remote_app_name="postgresql",
            remote_app_data=RELATED_APP_ALERT_RULES,
        )
    ]


def _cos_agent_source() -> list:
    """Source: a principal app (postgresql) related over the `cos-agent` subordinate relation.

    This is the real path postgresql uses in production: alert rules arrive in the principal unit
    databag, are copied into the peer relation by the cos-agent library during reconcile, then
    staged to disk and forwarded over OTLP. A `peers` relation is required for the leader to store
    the principal data.
    """
    provider_data = CosAgentProviderUnitData(
        metrics_alert_rules=_postgresql_alert_groups(),
        log_alert_rules={},
        dashboards=[],
        metrics_scrape_jobs=[],
        log_slots=[],
    )
    return [
        SubordinateRelation(
            "cos-agent",
            remote_app_name="postgresql",
            remote_unit_id=0,
            remote_unit_data={CosAgentProviderUnitData.KEY: provider_data.json()},
        ),
        PeerRelation("peers"),
    ]


def _receive_loki_logs_source() -> list:
    """Source: an app related over `receive-loki-logs` (e.g. zinc) providing logql rules."""
    return [
        Relation(
            "receive-loki-logs",
            remote_app_name="zinc",
            remote_app_data={"alert_rules": json.dumps(_zinc_log_alert_groups())},
        )
    ]


@pytest.mark.parametrize("forward_rules", [True, False])
@pytest.mark.parametrize(
    "make_source, kind, marker_alert, juju_app, always_forwarded",
    [
        pytest.param(
            _metrics_endpoint_source,
            "promql",
            RELATED_APP_ALERT,
            "postgresql",
            False,
            id="metrics-endpoint",
        ),
        pytest.param(
            _cos_agent_source,
            "promql",
            RELATED_APP_ALERT,
            "postgresql",
            True,
            id="cos-agent",
        ),
        pytest.param(
            _receive_loki_logs_source,
            "logql",
            RELATED_APP_LOG_ALERT,
            "zinc",
            False,
            id="receive-loki-logs",
        ),
    ],
)
def test_related_app_alerts_forwarded_over_otlp(
    ctx, make_source, kind, marker_alert, juju_app, always_forwarded, forward_rules
):
    """Regression test for https://github.com/canonical/opentelemetry-collector-operator/issues/297.

    Alert rules from an application related over `metrics-endpoint`, `cos-agent` or
    `receive-loki-logs` (e.g. postgresql, zinc) must be forwarded in the `send-otlp` relation
    databag, not only the charm's bundled rules.

    NOTE: Unlike the metrics-endpoint/loki paths, the cos-agent alert staging in `charm._reconcile`
    is gated only on `is_leader()` (not on `forward_alert_rules`), so cos-agent alerts are forwarded
    regardless of that config (``always_forwarded``). This mirrors the pre-existing cos-agent ->
    remote-write behaviour.
    """
    # GIVEN an app providing alert rules over the source relation AND a send-otlp relation
    send_otlp_relation = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
    state = State(
        relations=[*make_source(), send_otlp_relation],
        leader=True,
        model=MODEL,
        config={"forward_alert_rules": forward_rules},
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN the related app's alert rule is present in the send-otlp databag iff forwarding applies
    out_relation = state_out.get_relation(send_otlp_relation.id)
    decompressed = _decompress(out_relation.local_app_data.get("rules"))
    forwarded_rules = _forwarded_rules(decompressed, kind)
    forwarded_alerts = {rule.get("alert") for rule in forwarded_rules}
    if forward_rules or always_forwarded:
        assert marker_alert in forwarded_alerts
        # AND the related app's juju topology labels are preserved on the forwarded rule
        marker = next(r for r in forwarded_rules if r.get("alert") == marker_alert)
        assert marker["labels"]["juju_application"] == juju_app
    else:
        assert marker_alert not in forwarded_alerts


def test_forwarded_rules_have_topology(ctx):
    """Test that otelcol adds its own topology metadata in the databag.

    This test ensures that rules are always labeled even if labels are not
    present in the upstream rules already. `cos-lib` tests the rest of the
    labeling rules feature.
    """
    # GIVEN multiple send-otlp relations
    sender_1 = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
    sender_2 = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
    state = State(relations=[sender_1, sender_2], leader=True, model=MODEL)

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)
    for relation in list(state_out.relations):
        if relation.endpoint == "send-otlp":
            # THEN otelcol adds its own topology metadata to the databag
            assert json.loads(relation.local_app_data.get("metadata")) == OTELCOL_METADATA
