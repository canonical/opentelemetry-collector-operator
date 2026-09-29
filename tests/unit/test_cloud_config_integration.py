# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: cloud-config signal-specific credentials."""

from ops.testing import Relation, State

from tests.unit.helpers import get_otelcol_config_file


def test_cloud_config_relation_uses_signal_specific_credentials(ctx, unit_name, config_folder):
    """Scenario: cloud-config exporters use distinct credentials for each signal."""
    cloud_relation = Relation(
        endpoint="cloud-config",
        interface="grafana_cloud_config",
        remote_app_name="grafana-cloud-integrator",
        remote_app_data={
            "prometheus_url": "https://prometheus-prod.example/api/prom/push",
            "prometheus_username": "1076854",
            "prometheus_password": "prom-token",
            "loki_url": "https://logs-prod.example/loki/api/v1/push",
            "loki_username": "639149",
            "loki_password": "loki-token",
            "tempo_url": "https://tempo-prod.example/otlp",
            "tempo_username": "tempo-user",
            "tempo_password": "tempo-token",
        },
    )
    state_in = State(relations=[cloud_relation])

    # WHEN any event executes the reconciler
    ctx.run(ctx.on.update_status(), state=state_in)

    # THEN the config file exists and has distinct auth per signal
    cfg = get_otelcol_config_file(unit_name, config_folder)
    assert cfg["extensions"]["basicauth/cloud-integrator-prometheus"]["client_auth"] == {
        "username": "1076854",
        "password": "prom-token",
    }
    assert cfg["extensions"]["basicauth/cloud-integrator-loki"]["client_auth"] == {
        "username": "639149",
        "password": "loki-token",
    }
    assert cfg["extensions"]["basicauth/cloud-integrator-tempo"]["client_auth"] == {
        "username": "tempo-user",
        "password": "tempo-token",
    }
    assert cfg["exporters"]["prometheusremotewrite/cloud-config"]["auth"] == {
        "authenticator": "basicauth/cloud-integrator-prometheus"
    }
    assert cfg["exporters"]["loki/cloud-config"]["auth"] == {
        "authenticator": "basicauth/cloud-integrator-loki"
    }
    assert cfg["exporters"]["otlphttp/cloud-config"]["auth"] == {
        "authenticator": "basicauth/cloud-integrator-tempo"
    }
