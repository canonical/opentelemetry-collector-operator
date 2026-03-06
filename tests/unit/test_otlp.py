# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: OTLP endpoints and rules transfer."""

import json

import pytest
from cosl.utils import LZMABase64
from ops.testing import Model, Relation, State

from src.integrations import send_otlp
from charmlibs.otlp import OtlpConsumerAppData, OtlpEndpoint, RulesModel

ALL_PROTOCOLS = ["grpc", "http"]
ALL_TELEMETRIES = ["logs", "metrics", "traces"]
EMPTY_CONSUMER = {
    "rules": json.dumps({"logql": {}, "promql": {}}),
    "metadata": json.dumps({}),
}
SEND_OTLP = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
OTELCOL_METADATA = {
    "application": "otelcol",
    "charm_name": "opentelemetry-collector",
    "model": "otelcol",
    "model_uuid": "f4d59020-c8e7-4053-8044-a2c1e5591c7f",
    "unit": "otelcol/0",
}

def _decompress(rules: str) -> dict:
    return json.loads(LZMABase64.decompress(rules))


def test_send_otlp(ctx):
    # GIVEN otelcol supports (defined by OtlpProvider) a subset of OTLP protocols and telemetries
    # * a remote app provides multiple OtlpEndpoints
    remote_app_data_1 = {
        "endpoints": json.dumps(
            [
                {
                    "protocol": "http",
                    "endpoint": "http://provider-123.endpoint:4318",
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
                    "endpoint": "http://provider-456.endpoint:4317",
                    "telemetries": ["traces"],
                },
                {
                    "protocol": "http",
                    "endpoint": "http://provider-456.endpoint:4318",
                    "telemetries": ["metrics"],
                },
            ]
        )
    }

    expected_endpoints = {
        456: OtlpEndpoint(
            protocol="http",
            endpoint="http://provider-456.endpoint:4318",
            telemetries=["metrics"],
        ),
        123: OtlpEndpoint(
            protocol="http",
            endpoint="http://provider-123.endpoint:4318",
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
        model=Model("otelcol", uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"),
        config={"forward_alert_rules": forward_rules},
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)

    for relation in list(state_out.relations):
        if relation.endpoint == "send-otlp":
            assert (decompressed := _decompress(relation.local_app_data.get("rules")))
            databag = OtlpConsumerAppData.model_validate({"rules": decompressed, "metadata": {}})

            # THEN bundled rules are included in the forwarded databag
            assert isinstance(databag.rules, RulesModel)
            logql_group_names = {r.get("name") for r in databag.rules.logql.get("groups", [])}
            promql_group_names = {r.get("name") for r in databag.rules.promql.get("groups", [])}
            assert not logql_group_names
            assert "otelcol_f4d59020_otelcol_Exporter_alerts" in promql_group_names


def test_forwarded_rules_have_topology(ctx):
    """Test that otelcol adds its own topology metadata in the databag.

    This test ensures that rules are always labeled even if labels are not
    present in the upstream rules already. This is easier than checking if
    rules are labeled in the send-otlp databag since cos-lib tests the rest of
    the labeling rules feature.
    """
    # GIVEN multiple send-otlp relations
    sender_1 = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
    sender_2 = Relation("send-otlp", remote_app_data={"endpoints": "[]"})
    state = State(
        relations=[sender_1, sender_2],
        leader=True,
        model=Model("otelcol", uuid="f4d59020-c8e7-4053-8044-a2c1e5591c7f"),
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.update_status(), state=state)
    for relation in list(state_out.relations):
        if relation.endpoint == "send-otlp":
            # THEN otelcol adds its own topology metadata to the databag
            assert json.loads(relation.local_app_data.get("metadata")) == OTELCOL_METADATA
