# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: compression of the alert rules published over send-remote-write.

The charm may only compress its alert rules if the remote-write provider advertises that
it is able to read them compressed, so that this charm stays compatible with providers
running an older version of the `prometheus_remote_write` library.
"""

import json

import pytest
from charms.prometheus_k8s.v1.prometheus_remote_write import (
    ALERT_RULES_ENCODINGS_KEY,
    ALERT_RULES_KEY,
    JSON_ENCODING,
    LZMA_ENCODING,
)
from cosl.utils import LZMABase64
from ops.testing import Model, Relation, State

MODEL = Model("my_model", uuid="74a5690b-89c9-44dd-984b-f69f26a6b751")

LZMA_ADVERTISED = {ALERT_RULES_ENCODINGS_KEY: json.dumps([LZMA_ENCODING, JSON_ENCODING])}


def _published_rules(state: State, relation: Relation) -> str:
    return state.get_relation(relation.id).local_app_data[ALERT_RULES_KEY]


@pytest.mark.parametrize(
    "remote_app_data, compressed",
    [
        pytest.param(LZMA_ADVERTISED, True, id="lzma_advertised"),
        pytest.param({}, False, id="legacy_provider"),
        pytest.param(
            {ALERT_RULES_ENCODINGS_KEY: json.dumps([JSON_ENCODING])}, False, id="json_only"
        ),
    ],
)
def test_alert_rules_are_compressed_only_for_a_capable_provider(ctx, remote_app_data, compressed):
    # GIVEN a send-remote-write relation to a provider with a given set of supported encodings
    remote_write_relation = Relation(
        "send-remote-write", remote_app_name="prometheus", remote_app_data=remote_app_data
    )
    state = State(
        leader=True,
        model=MODEL,
        relations=[remote_write_relation],
    )

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.relation_changed(relation=remote_write_relation), state)

    # THEN the alert rules are compressed only if the provider said it can read them
    published = _published_rules(state_out, remote_write_relation)
    if compressed:
        with pytest.raises(json.JSONDecodeError):
            json.loads(published)
        rules = json.loads(LZMABase64.decompress(published))
    else:
        rules = json.loads(published)

    # AND the rules themselves are unaffected by the encoding
    assert rules["groups"]


@pytest.mark.parametrize(
    "remote_app_data, compressed",
    [
        pytest.param({}, False, id="plain"),
        pytest.param(LZMA_ADVERTISED, True, id="compressed"),
    ],
)
def test_metrics_endpoint_rules_are_forwarded_over_remote_write(ctx, remote_app_data, compressed):
    """Rules received over `metrics-endpoint` must reach the `send-remote-write` databag.

    The rules this charm forwards, rather than its own, are the ones that make a payload
    large enough to need compressing. `test_alert_rule_filtering` covers this path but
    asserts the unit status only, and `test_otlp` covers forwarding from `receive-otlp`.
    """
    # GIVEN an app sending its alert rules to this charm over metrics-endpoint,
    # AND a remote-write provider that may or may not be able to read them compressed
    scrape_relation = Relation(
        "metrics-endpoint",
        remote_app_name="workload",
        remote_app_data={
            "alert_rules": json.dumps(
                {
                    "groups": [
                        {
                            "name": "forwarded-group",
                            "rules": [
                                {
                                    "alert": "WorkloadDown",
                                    "expr": 'up{juju_application="workload"} < 1',
                                    "for": "0m",
                                    "labels": {"severity": "critical"},
                                }
                            ],
                        }
                    ]
                }
            ),
            "scrape_metadata": json.dumps(
                {
                    "model": MODEL.name,
                    "model_uuid": MODEL.uuid,
                    "application": "workload",
                    "charm_name": "workload-charm",
                }
            ),
        },
    )
    remote_write_relation = Relation(
        "send-remote-write", remote_app_name="prometheus", remote_app_data=remote_app_data
    )
    state = State(
        leader=True,
        model=MODEL,
        config={"forward_alert_rules": True},
        relations=[scrape_relation, remote_write_relation],
    )

    # WHEN the charm reconciles
    state_out = ctx.run(ctx.on.relation_changed(relation=scrape_relation), state)

    # THEN the rules received from the workload made it into the payload, in whichever
    # encoding was negotiated, and under this charm's topology, as otelcol re-labels
    # what it forwards
    published = _published_rules(state_out, remote_write_relation)
    forwarded = json.loads(LZMABase64.decompress(published) if compressed else published)
    assert any("forwarded_group" in group["name"] for group in forwarded["groups"])
