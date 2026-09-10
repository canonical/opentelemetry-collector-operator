# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
"""Feature: negotiated (LZMA) compression of `alert_rules` on the Loki relations.

The charm aggregates alert rules from workloads related over `receive-loki-logs`
and re-forwards them to Loki over `send-loki-logs`. Both relations use
`charms.loki_k8s.v1.loki_push_api`'s negotiated per-field compression scheme: a
provider advertises which encodings it can decode (`alert_rules_encodings`), and
whichever side is writing `alert_rules` picks the best mutually-supported
encoding, falling back to plain JSON for a legacy/absent advertisement.
"""

import json

from charms.loki_k8s.v1.loki_push_api import (
    ALERT_RULES_ENCODINGS_KEY,
    ALERT_RULES_KEY,
    LZMA_ENCODING,
    _encode_alert_rules,
)
from cosl.utils import LZMABase64
from ops.testing import Model, Relation, State

MODEL_NAME = "test"
MODEL_UUID = "20ce8299-3634-4bef-8bd8-5ace6c8816b4"
MODEL = Model(MODEL_NAME, uuid=MODEL_UUID)

FORWARD_ALERT_RULES: dict = {"forward_alert_rules": True}


def _loki_alert_rules(group_name: str) -> str:
    return json.dumps(
        {
            "groups": [
                {
                    "name": group_name,
                    "rules": [
                        {
                            "alert": f"{group_name}Valid",
                            "expr": 'sum(rate({job="valid"}[5m])) > 0',
                            "for": "1m",
                            "labels": {"severity": "warning"},
                            "annotations": {"summary": "valid-a"},
                        },
                    ],
                }
            ]
        }
    )


VALID_LOKI_ALERT_RULE_RELATION = Relation(
    "receive-loki-logs",
    remote_app_name="loki-alert-rule-valid",
    remote_app_data={"alert_rules": _loki_alert_rules("valid-group")},
)

# `send-loki-logs` must be paired with a mandatory-relation sink or an incoming
# `cos-agent`/`juju-info` relation to avoid unrelated blocked-status noise; the
# tests below only assert on relation-data contents, not on overall unit status,
# so the bare relation below is sufficient.
SEND_LOKI_LOGS = Relation(
    "send-loki-logs",
    interface="loki_push_api",
    remote_app_name="loki",
)


def test_send_loki_logs_compresses_when_downstream_advertises_lzma(ctx):
    # GIVEN a workload relation with valid alert rules and a downstream Loki that
    # advertises LZMA support on send-loki-logs
    send_loki_logs_relation = Relation(
        "send-loki-logs",
        interface="loki_push_api",
        remote_app_name="loki",
        remote_app_data={ALERT_RULES_ENCODINGS_KEY: json.dumps(["lzma", "json"])},
    )
    state = State(
        leader=True,
        relations=[VALID_LOKI_ALERT_RULE_RELATION, send_loki_logs_relation],
        model=MODEL,
        config=FORWARD_ALERT_RULES,
    )

    # WHEN the receive-loki-logs relation is processed and the aggregated rules
    # are (re)published on send-loki-logs
    out_0 = ctx.run(ctx.on.relation_changed(relation=VALID_LOKI_ALERT_RULE_RELATION), state)
    out_1 = ctx.run(
        ctx.on.relation_changed(relation=out_0.get_relation(send_loki_logs_relation.id)),
        out_0,
    )

    # THEN the alert_rules written to send-loki-logs are LZMA-compressed, not plain JSON
    raw = out_1.get_relation(send_loki_logs_relation.id).local_app_data[ALERT_RULES_KEY]
    assert not raw.startswith("{")
    decoded = json.loads(LZMABase64.decompress(raw))
    assert decoded["groups"]


def test_send_loki_logs_plain_json_when_downstream_is_legacy(ctx):
    # GIVEN a workload relation with valid alert rules and a downstream Loki that does
    # not advertise any supported encodings (legacy provider)
    state = State(
        leader=True,
        relations=[VALID_LOKI_ALERT_RULE_RELATION, SEND_LOKI_LOGS],
        model=MODEL,
        config=FORWARD_ALERT_RULES,
    )

    # WHEN the receive-loki-logs relation is processed and the aggregated rules
    # are (re)published on send-loki-logs
    out_0 = ctx.run(ctx.on.relation_changed(relation=VALID_LOKI_ALERT_RULE_RELATION), state)
    out_1 = ctx.run(
        ctx.on.relation_changed(relation=out_0.get_relation(SEND_LOKI_LOGS.id)), out_0
    )

    # THEN the alert_rules written to send-loki-logs are plain JSON
    raw = out_1.get_relation(SEND_LOKI_LOGS.id).local_app_data[ALERT_RULES_KEY]
    assert json.loads(raw)["groups"]


def test_receive_loki_logs_decodes_compressed_payload_from_workload(ctx):
    # GIVEN a workload that publishes its alert rules LZMA-compressed on receive-loki-logs
    valid_rules = json.loads(_loki_alert_rules("compressed-group"))
    compressed_relation = Relation(
        "receive-loki-logs",
        remote_app_name="compressed-workload",
        remote_app_data={ALERT_RULES_KEY: _encode_alert_rules(valid_rules, LZMA_ENCODING)},
    )
    state = State(
        leader=True,
        relations=[compressed_relation, SEND_LOKI_LOGS],
        model=MODEL,
        config=FORWARD_ALERT_RULES,
    )

    # WHEN the receive-loki-logs relation is processed and the aggregated rules
    # are (re)published on send-loki-logs
    out_0 = ctx.run(ctx.on.relation_changed(relation=compressed_relation), state)
    out_1 = ctx.run(
        ctx.on.relation_changed(relation=out_0.get_relation(SEND_LOKI_LOGS.id)), out_0
    )

    # THEN the charm decoded the compressed payload and forwarded the rule onward
    raw = out_1.get_relation(SEND_LOKI_LOGS.id).local_app_data[ALERT_RULES_KEY]
    forwarded_rules = json.loads(raw)
    alert_names = {
        rule["alert"] for group in forwarded_rules["groups"] for rule in group["rules"]
    }
    assert "compressed-groupValid" in alert_names


def test_receive_loki_logs_malformed_payload_does_not_block_charm(ctx):
    # GIVEN a workload relation with an alert_rules value that is neither valid JSON
    # nor a valid compressed payload
    malformed_relation = Relation(
        "receive-loki-logs",
        remote_app_name="malformed-workload",
        remote_app_data={ALERT_RULES_KEY: "not valid json, nor valid lzma/base64"},
    )
    state = State(
        leader=True,
        relations=[malformed_relation, SEND_LOKI_LOGS],
        model=MODEL,
        config=FORWARD_ALERT_RULES,
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.relation_changed(relation=malformed_relation), state)

    # THEN the charm does not crash or block because of the unreadable payload
    assert state_out.unit_status.name != "blocked"


def test_receive_loki_logs_double_json_encoded_payload_does_not_block_charm(ctx):
    """A plain JSON *string* (not a compressed payload) is rejected with a clear error.

    Regression test for https://github.com/canonical/prometheus-k8s-operator/pull/864
    review feedback from @Abuelodelanada: ``json.loads('"foo"')`` returns the Python
    string ``"foo"``, which then falls into the "this must be a compressed payload"
    branch and fails to decompress. This must not raise an unhandled/opaque exception.
    """
    # GIVEN a workload relation whose alert_rules value is a JSON string literal
    double_encoded_relation = Relation(
        "receive-loki-logs",
        remote_app_name="double-encoded-workload",
        remote_app_data={ALERT_RULES_KEY: json.dumps("foo")},
    )
    state = State(
        leader=True,
        relations=[double_encoded_relation, SEND_LOKI_LOGS],
        model=MODEL,
        config=FORWARD_ALERT_RULES,
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.relation_changed(relation=double_encoded_relation), state)

    # THEN the charm does not crash or block because of the unreadable payload
    assert state_out.unit_status.name != "blocked"


def test_receive_loki_logs_non_object_payload_does_not_block_charm(ctx):
    """A syntactically valid JSON payload that isn't an object is rejected clearly."""
    # GIVEN a workload relation whose alert_rules value decodes to a JSON list
    non_object_relation = Relation(
        "receive-loki-logs",
        remote_app_name="non-object-workload",
        remote_app_data={ALERT_RULES_KEY: json.dumps([1, 2, 3])},
    )
    state = State(
        leader=True,
        relations=[non_object_relation, SEND_LOKI_LOGS],
        model=MODEL,
        config=FORWARD_ALERT_RULES,
    )

    # WHEN any event executes the reconciler
    state_out = ctx.run(ctx.on.relation_changed(relation=non_object_relation), state)

    # THEN the charm does not crash or block because of the unreadable payload
    assert state_out.unit_status.name != "blocked"


def test_aggregated_alert_rules_forwarded_from_multiple_workloads(ctx):
    # GIVEN two workloads on receive-loki-logs: one publishing plain JSON (legacy), one
    # publishing LZMA-compressed rules, and a downstream Loki advertising LZMA support
    plain_rules = json.loads(_loki_alert_rules("plain-group"))
    compressed_rules = json.loads(_loki_alert_rules("compressed-group"))
    plain_relation = Relation(
        "receive-loki-logs",
        remote_app_name="plain-workload",
        remote_app_data={ALERT_RULES_KEY: json.dumps(plain_rules)},
    )
    compressed_relation = Relation(
        "receive-loki-logs",
        remote_app_name="compressed-workload",
        remote_app_data={ALERT_RULES_KEY: _encode_alert_rules(compressed_rules, LZMA_ENCODING)},
    )
    send_loki_logs_relation = Relation(
        "send-loki-logs",
        interface="loki_push_api",
        remote_app_name="loki",
        remote_app_data={ALERT_RULES_ENCODINGS_KEY: json.dumps(["lzma", "json"])},
    )
    state = State(
        leader=True,
        relations=[plain_relation, compressed_relation, send_loki_logs_relation],
        model=MODEL,
        config=FORWARD_ALERT_RULES,
    )

    # WHEN both receive-loki-logs relations are processed and the aggregated rules
    # are (re)published on send-loki-logs
    out_0 = ctx.run(ctx.on.relation_changed(relation=plain_relation), state)
    out_1 = ctx.run(
        ctx.on.relation_changed(relation=out_0.get_relation(compressed_relation.id)),
        out_0,
    )
    out_2 = ctx.run(
        ctx.on.relation_changed(relation=out_1.get_relation(send_loki_logs_relation.id)),
        out_1,
    )

    # THEN both workloads' rules are present in the (compressed) aggregated payload
    raw = out_2.get_relation(send_loki_logs_relation.id).local_app_data[ALERT_RULES_KEY]
    assert not raw.startswith("{")
    forwarded_rules = json.loads(LZMABase64.decompress(raw))
    alert_names = {
        rule["alert"] for group in forwarded_rules["groups"] for rule in group["rules"]
    }
    assert "plain-groupValid" in alert_names
    assert "compressed-groupValid" in alert_names


def test_aggregated_alert_rules_skip_unreadable_workload_but_forward_others(ctx):
    """One unreadable workload relation doesn't prevent other workloads' rules forwarding.

    Regression test for the log-aggregation change: a malformed relation is collected
    and logged once, without blocking the charm or dropping the other, healthy
    workload's rules from the aggregated payload sent onward.
    """
    # GIVEN two workloads on receive-loki-logs: one with unreadable alert_rules, one
    # with valid rules, and a downstream Loki advertising LZMA support
    healthy_rules = json.loads(_loki_alert_rules("healthy-group"))
    broken_relation = Relation(
        "receive-loki-logs",
        remote_app_name="broken-workload",
        remote_app_data={ALERT_RULES_KEY: "not valid json, nor valid lzma/base64"},
    )
    healthy_relation = Relation(
        "receive-loki-logs",
        remote_app_name="healthy-workload",
        remote_app_data={ALERT_RULES_KEY: json.dumps(healthy_rules)},
    )
    send_loki_logs_relation = Relation(
        "send-loki-logs",
        interface="loki_push_api",
        remote_app_name="loki",
        remote_app_data={ALERT_RULES_ENCODINGS_KEY: json.dumps(["lzma", "json"])},
    )
    state = State(
        leader=True,
        relations=[broken_relation, healthy_relation, send_loki_logs_relation],
        model=MODEL,
        config=FORWARD_ALERT_RULES,
    )

    # WHEN both receive-loki-logs relations are processed and the aggregated rules
    # are (re)published on send-loki-logs
    out_0 = ctx.run(ctx.on.relation_changed(relation=broken_relation), state)
    out_1 = ctx.run(
        ctx.on.relation_changed(relation=out_0.get_relation(healthy_relation.id)),
        out_0,
    )
    out_2 = ctx.run(
        ctx.on.relation_changed(relation=out_1.get_relation(send_loki_logs_relation.id)),
        out_1,
    )

    # THEN the charm did not block...
    assert out_2.unit_status.name != "blocked"

    # ...and the healthy workload's rules still made it into the aggregated payload
    raw = out_2.get_relation(send_loki_logs_relation.id).local_app_data[ALERT_RULES_KEY]
    forwarded_rules = json.loads(LZMABase64.decompress(raw))
    alert_names = {
        rule["alert"] for group in forwarded_rules["groups"] for rule in group["rules"]
    }
    assert "healthy-groupValid" in alert_names
