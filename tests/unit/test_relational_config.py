# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Relation-dependent OpenTelemetry Collector config."""

import json

from ops.testing import Relation, State

from helpers import get_otelcol_config_file


def check_valid_pipelines(cfg):
    """Assert that each pipeline has at least one receiver-exporter pair."""
    pipelines = [cfg["service"]["pipelines"][p] for p in cfg["service"]["pipelines"]]
    pairs = [(len(p["receivers"]) > 0, len(p["exporters"]) > 0) for p in pipelines]
    assert all(all(condition for condition in pair) for pair in pairs)


def test_traces_exporters(ctx, unit_name, config_folder):
    """Scenario: Fan-out tracing architecture to a single Tempo backend."""
    # GIVEN a relation to a Tempo charm
    remote_app_data = {
        "receivers": json.dumps(
            [
                {
                    "protocol": {"name": "otlp_grpc", "type": "grpc"},
                    "url": "tempo1.example.com:4317",
                },
                {
                    "protocol": {"name": "otlp_http", "type": "http"},
                    "url": "http://tempo1.example.com:4318",
                },
            ]
        )
    }
    local_app_data = {"receivers": json.dumps(["otlp_http", "otlp_grpc"])}
    data_sink = Relation(
        endpoint="send-traces",
        interface="tracing",
        remote_app_data=remote_app_data,
        local_app_data=local_app_data,
    )
    state_in = State(relations=[data_sink])

    # WHEN any event executes the reconciler
    ctx.run(ctx.on.update_status(), state=state_in)

    # THEN the config file exists
    cfg = get_otelcol_config_file(unit_name, config_folder)
    # AND exactly one otlphttp/rel-*/send-traces exporter exists
    send_traces_exporters = [k for k in cfg["exporters"] if k.endswith("/send-traces")]
    assert len(send_traces_exporters) == 1
    # AND the exporter is named using the relation ID
    rel_id = data_sink.id
    assert f"otlphttp/rel-{rel_id}/send-traces" in cfg["exporters"]
    # AND the pipelines are valid
    check_valid_pipelines(cfg)


def test_traces_exporters_multiple_backends(ctx, unit_name, config_folder):
    """Scenario: Fan-out tracing architecture to multiple Tempo backends."""
    # GIVEN two simultaneous send-traces relations (one per Tempo instance)
    local_app_data = {"receivers": json.dumps(["otlp_http", "otlp_grpc"])}
    tempo1_relation = Relation(
        endpoint="send-traces",
        interface="tracing",
        remote_app_data={
            "receivers": json.dumps(
                [
                    {
                        "protocol": {"name": "otlp_http", "type": "http"},
                        "url": "http://tempo1.example.com:4318",
                    },
                ]
            )
        },
        local_app_data=local_app_data,
    )
    tempo2_relation = Relation(
        endpoint="send-traces",
        interface="tracing",
        remote_app_data={
            "receivers": json.dumps(
                [
                    {
                        "protocol": {"name": "otlp_http", "type": "http"},
                        "url": "http://tempo2.example.com:4318",
                    },
                ]
            )
        },
        local_app_data=local_app_data,
    )
    state_in = State(relations=[tempo1_relation, tempo2_relation])

    # WHEN any event executes the reconciler
    ctx.run(ctx.on.update_status(), state=state_in)

    # THEN the config file exists
    cfg = get_otelcol_config_file(unit_name, config_folder)
    # AND two distinct otlphttp/rel-*/send-traces exporters exist — one per backend
    send_traces_exporters = [k for k in cfg["exporters"] if k.endswith("/send-traces")]
    assert len(send_traces_exporters) == 2
    # AND each exporter is named using its relation ID
    assert f"otlphttp/rel-{tempo1_relation.id}/send-traces" in cfg["exporters"]
    assert f"otlphttp/rel-{tempo2_relation.id}/send-traces" in cfg["exporters"]
    # AND both exporters are wired into the traces pipeline
    pipeline_exporters = cfg["service"]["pipelines"][f"traces/{unit_name}"]["exporters"]
    for exporter_name in send_traces_exporters:
        assert exporter_name in pipeline_exporters
    # AND the pipelines are valid
    check_valid_pipelines(cfg)


def test_traces_exporter_removed_on_relation_broken(ctx, unit_name, config_folder):
    """Scenario: Removing one send-traces relation drops its exporter, leaves the other intact."""
    # GIVEN two simultaneous send-traces relations
    local_app_data = {"receivers": json.dumps(["otlp_http", "otlp_grpc"])}
    tempo1_relation = Relation(
        endpoint="send-traces",
        interface="tracing",
        remote_app_data={
            "receivers": json.dumps(
                [
                    {
                        "protocol": {"name": "otlp_http", "type": "http"},
                        "url": "http://tempo1.example.com:4318",
                    },
                ]
            )
        },
        local_app_data=local_app_data,
    )
    tempo2_relation = Relation(
        endpoint="send-traces",
        interface="tracing",
        remote_app_data={
            "receivers": json.dumps(
                [
                    {
                        "protocol": {"name": "otlp_http", "type": "http"},
                        "url": "http://tempo2.example.com:4318",
                    },
                ]
            )
        },
        local_app_data=local_app_data,
    )

    # WHEN the second relation is broken
    state_in = State(relations=[tempo1_relation, tempo2_relation])
    ctx.run(ctx.on.relation_broken(tempo2_relation), state=state_in)

    # THEN exactly one send-traces exporter remains in the config
    cfg = get_otelcol_config_file(unit_name, config_folder)
    send_traces_exporters = [k for k in cfg["exporters"] if k.endswith("/send-traces")]
    assert len(send_traces_exporters) == 1, (
        f"Expected 1 send-traces exporter after removal, got {send_traces_exporters}"
    )
    # AND it belongs to the relation that was NOT removed
    assert f"otlphttp/rel-{tempo1_relation.id}/send-traces" in cfg["exporters"]
    assert f"otlphttp/rel-{tempo2_relation.id}/send-traces" not in cfg["exporters"]
