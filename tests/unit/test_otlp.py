# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: OTLP endpoints and rules transfer."""

import json
from contextlib import ExitStack
from unittest.mock import patch

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


def _forwarded_alert_names(decompressed: dict, kind: str = "promql") -> set:
    """Collect the alert names of a given kind from a decompressed databag."""
    return {rule.get("alert") for rule in _forwarded_rules(decompressed, kind)}


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


@pytest.mark.parametrize("forward_rules", [True, False])
def test_related_app_alerts_forwarded_over_otlp(ctx, forward_rules):
    """Regression test for https://github.com/canonical/opentelemetry-collector-operator/issues/297.

    Alert rules from applications related over `metrics-endpoint`/`cos-agent` (e.g. postgresql)
    must be forwarded in the `send-otlp` relation databag, not only the charm's bundled rules.
    """
    # GIVEN an app providing alert rules over metrics-endpoint AND a send-otlp relation
    metrics_endpoint = Relation(
        "metrics-endpoint",
        remote_app_name="postgresql",
        remote_app_data=RELATED_APP_ALERT_RULES,
    )
    send_otlp_relation = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
    state = State(
        relations=[metrics_endpoint, send_otlp_relation],
        leader=True,
        model=MODEL,
        config={"forward_alert_rules": forward_rules},
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN the related app's alert rule is present in the send-otlp databag iff forwarding is on
    out_relation = state_out.get_relation(send_otlp_relation.id)
    decompressed = _decompress(out_relation.local_app_data.get("rules"))
    forwarded_rules = _forwarded_rules(decompressed, "promql")
    forwarded_alerts = {rule.get("alert") for rule in forwarded_rules}
    if forward_rules:
        assert RELATED_APP_ALERT in forwarded_alerts
        # AND the related app's juju topology labels are preserved on the forwarded rule
        marker = next(r for r in forwarded_rules if r.get("alert") == RELATED_APP_ALERT)
        assert marker["labels"]["juju_application"] == "postgresql"
    else:
        assert RELATED_APP_ALERT not in forwarded_alerts


@pytest.mark.parametrize("forward_rules", [True, False])
def test_related_app_alerts_forwarded_over_otlp_via_cos_agent(ctx, forward_rules):
    """Regression test for https://github.com/canonical/opentelemetry-collector-operator/issues/297.

    Same as `test_related_app_alerts_forwarded_over_otlp` but exercising the real `cos-agent`
    subordinate path (the one postgresql uses in production), where alert rules arrive in the
    principal unit databag, are copied into the peer relation by the cos-agent library during
    reconcile, then staged to disk and forwarded over OTLP.

    NOTE: Unlike the metrics-endpoint/loki paths, the cos-agent alert staging in `charm._reconcile`
    is gated only on `is_leader()` (not on `forward_alert_rules`), so cos-agent alerts are forwarded
    regardless of that config. This mirrors the pre-existing cos-agent -> remote-write behaviour.
    """
    # GIVEN a principal app (postgresql) related over the cos-agent subordinate relation,
    # publishing metrics alert rules in its unit databag
    provider_data = CosAgentProviderUnitData(
        metrics_alert_rules=_postgresql_alert_groups(),
        log_alert_rules={},
        dashboards=[],
        metrics_scrape_jobs=[],
        log_slots=[],
    )
    cos_agent = SubordinateRelation(
        "cos-agent",
        remote_app_name="postgresql",
        remote_unit_id=0,
        remote_unit_data={CosAgentProviderUnitData.KEY: provider_data.json()},
    )
    # AND a peers relation (the cos-agent leader stores principal data there) and a send-otlp relation
    peers = PeerRelation("peers")
    send_otlp_relation = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
    state = State(
        relations=[cos_agent, peers, send_otlp_relation],
        leader=True,
        model=MODEL,
        config={"forward_alert_rules": forward_rules},
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN the related app's alert rule is present in the send-otlp databag (leader-gated only)
    out_relation = state_out.get_relation(send_otlp_relation.id)
    decompressed = _decompress(out_relation.local_app_data.get("rules"))
    forwarded_alerts = _forwarded_alert_names(decompressed, "promql")
    assert RELATED_APP_ALERT in forwarded_alerts


@pytest.mark.parametrize("forward_rules", [True, False])
def test_related_app_log_alerts_forwarded_over_otlp(ctx, forward_rules):
    """Log (logql) alert rules received over `receive-loki-logs` must also be forwarded over OTLP."""
    # GIVEN an app providing log alert rules over receive-loki-logs AND a send-otlp relation
    log_alerts = {
        "alert_rules": json.dumps(
            {
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
        )
    }
    receive_loki_logs = Relation(
        "receive-loki-logs",
        remote_app_name="zinc",
        remote_app_data=log_alerts,
    )
    send_otlp_relation = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
    state = State(
        relations=[receive_loki_logs, send_otlp_relation],
        leader=True,
        model=MODEL,
        config={"forward_alert_rules": forward_rules},
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    # THEN the related app's log alert rule is present in the logql databag iff forwarding is on
    out_relation = state_out.get_relation(send_otlp_relation.id)
    decompressed = _decompress(out_relation.local_app_data.get("rules"))
    forwarded_log_alerts = _forwarded_alert_names(decompressed, "logql")
    if forward_rules:
        assert RELATED_APP_LOG_ALERT in forwarded_log_alerts
    else:
        assert RELATED_APP_LOG_ALERT not in forwarded_log_alerts


def test_reconcile_stages_otlp_rules_after_related_app_staging(ctx):
    """Guard the temporal ordering contract that makes OTLP rule forwarding work.

    `send_otlp` forwards whatever rule files are staged in the *_RULES_DEST_PATH directories, so it
    MUST run:
      * AFTER `cleanup` (which wipes the rule directories), and
      * AFTER every integration that stages related-app alerts into those directories:
        `scrape_metrics` (metrics-endpoint), `receive_loki_logs` (loki) and the cos-agent
        `_add_alerts` calls in `charm._reconcile`.

    This ordering is otherwise only enforced by a code comment, so a future reorder would silently
    regress https://github.com/canonical/opentelemetry-collector-operator/issues/297. This test
    spies on the reconcile call order to fail fast if that contract is broken.
    """
    # `charm.py` does `import integrations`, so spy on that same module object
    import integrations

    call_order: list[str] = []
    spied = [
        "cleanup",
        "_add_alerts",  # cos-agent metrics/logs alerts staged from charm._reconcile
        "receive_loki_logs",
        "scrape_metrics",
        "send_otlp",
    ]
    real = {name: getattr(integrations, name) for name in spied}

    def make_spy(name):
        def spy(*args, **kwargs):
            call_order.append(name)
            return real[name](*args, **kwargs)

        return spy

    # GIVEN a cos-agent principal staging alerts, a peers relation, and a send-otlp relation
    provider_data = CosAgentProviderUnitData(
        metrics_alert_rules=_postgresql_alert_groups(),
        log_alert_rules={},
        dashboards=[],
        metrics_scrape_jobs=[],
        log_slots=[],
    )
    cos_agent = SubordinateRelation(
        "cos-agent",
        remote_app_name="postgresql",
        remote_unit_id=0,
        remote_unit_data={CosAgentProviderUnitData.KEY: provider_data.json()},
    )
    state = State(
        relations=[
            cos_agent,
            PeerRelation("peers"),
            Relation("send-otlp", remote_app_data={"endpoints": "[]"}),
        ],
        leader=True,
        model=MODEL,
        config={"forward_alert_rules": True},
    )

    # WHEN any event executes the reconciler
    with ExitStack() as stack:
        for name in spied:
            stack.enter_context(patch.object(integrations, name, make_spy(name)))
        ctx.run(ctx.on.update_status(), state=state)

    # THEN send_otlp runs after cleanup and after every related-app staging step
    assert "send_otlp" in call_order
    send_otlp_idx = call_order.index("send_otlp")
    assert call_order.index("cleanup") < send_otlp_idx
    for stager in ("_add_alerts", "receive_loki_logs", "scrape_metrics"):
        assert stager in call_order, f"{stager} was not called"
        # Use the LAST occurrence: every staging write must precede the forwarding read
        last_idx = len(call_order) - 1 - call_order[::-1].index(stager)
        assert last_idx < send_otlp_idx, f"send_otlp must run after {stager}"


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
