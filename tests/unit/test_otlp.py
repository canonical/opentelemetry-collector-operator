# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: OTLP endpoints and rules transfer."""

import json

import pytest
from charmlibs.interfaces.otlp import OtlpEndpoint
from cosl.utils import LZMABase64
from ops.testing import Model, Relation, State

from src.integrations import send_otlp

MODEL_NAME = "foo-model"
MODEL_UUID = "f4d59020-c8e7-4053-8044-a2c1e5591c7f"
MODEL = Model(MODEL_NAME, uuid=MODEL_UUID)
OTELCOL_METADATA = {
    "application": "otelcol",
    "charm_name": "opentelemetry-collector",
    "model": MODEL_NAME,
    "model_uuid": MODEL_UUID,
    "unit": "otelcol/0",
}


def _decompress(rules: str) -> dict:
    return json.loads(LZMABase64.decompress(rules))


def test_send_otlp(ctx):
    # GIVEN otelcol supports (defined by OtlpRequirer) a subset of OTLP protocols and telemetries
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
            assert "otelcol_f4d59020_otelcol_Exporter_rules" in promql_group_names


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
