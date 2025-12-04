# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Opentelemetry-collector config builder."""

import copy
import pytest
from config_manager import ConfigManager


def test_add_log_forwarding():
    # GIVEN an empty config
    config_manager = ConfigManager("otelcol/0", "", "", insecure_skip_verify=True)

    # WHEN a loki exporter is added to the config
    expected_loki_forwarding_cfg = {
        "default_labels_enabled": {
            "exporter": False,
            "job": True,
        },
        "endpoint": "http://192.168.1.244/cos-loki-0/loki/api/v1/push",
        "retry_on_failure": {
            "max_elapsed_time": "5m",
        },
        "sending_queue": {"enabled": True, "queue_size": 1000, "storage": "file_storage"},
        "tls": {
            "insecure_skip_verify": False,
        },
    }
    config_manager.add_log_forwarding(
        endpoints=[{"url": "http://192.168.1.244/cos-loki-0/loki/api/v1/push"}],
        insecure_skip_verify=False,
    )
    # THEN it exists in the loki exporter config
    config = dict(
        sorted(config_manager.config._config["exporters"]["loki/send-loki-logs/0"].items())
    )
    expected_config = dict(sorted(expected_loki_forwarding_cfg.items()))
    assert config == expected_config


def test_add_traces_forwarding():
    # GIVEN an empty config
    config_manager = ConfigManager("otelcol/0", "", "", insecure_skip_verify=True)

    # WHEN a traces exporter is added to the config
    expected_traces_forwarding_cfg = {
        "endpoint": "http://192.168.1.244:4318",
        "retry_on_failure": {
            "max_elapsed_time": "5m",
        },
        "sending_queue": {"enabled": True, "queue_size": 1000, "storage": "file_storage"},
    }
    config_manager.add_traces_forwarding(
        endpoint="http://192.168.1.244:4318",
    )
    # THEN it exists in the traces exporter config
    config = dict(
        sorted(config_manager.config._config["exporters"]["otlphttp/send-traces"].items())
    )
    expected_config = dict(sorted(expected_traces_forwarding_cfg.items()))
    assert config == expected_config


def test_add_remote_write():
    # GIVEN an empty config
    config_manager = ConfigManager("otelcol/0", "", "", insecure_skip_verify=True)

    # WHEN a remote write exporter is added to the config
    expected_remote_write_cfg = {
        "endpoint": "http://192.168.1.244/cos-prometheus-0/api/v1/write",
        "tls": {
            "insecure_skip_verify": True,
        },
    }
    config_manager.add_remote_write(
        endpoints=[{"url": "http://192.168.1.244/cos-prometheus-0/api/v1/write"}],
    )
    # THEN it exists in the remote write exporter config
    config = dict(
        sorted(
            config_manager.config._config["exporters"][
                "prometheusremotewrite/send-remote-write/0"
            ].items()
        )
    )
    expected_config = dict(sorted(expected_remote_write_cfg.items()))
    assert config == expected_config


def test_add_prometheus_scrape():
    # GIVEN an empty config
    config_manager = ConfigManager("otelcol/0", "", "", insecure_skip_verify=True)

    # WHEN a scrape job is added to the config
    first_job = [
        {
            "metrics_path": "/metrics",
            "static_configs": [{"targets": ["*:9001"]}],
            "job_name": "first_job",
            "scrape_interval": "15s",
        }
    ]
    expected_prom_recv_cfg = {
        "config": {
            "scrape_configs": [
                {
                    "metrics_path": "/metrics",
                    "static_configs": [{"targets": ["*:9001"]}],
                    "job_name": "first_job",
                    "scrape_interval": "15s",
                    # Added dynamically by add_prometheus_scrape
                    "tls_config": {"insecure_skip_verify": True},
                },
            ],
        }
    }
    config_manager.add_prometheus_scrape_jobs(first_job)
    # THEN it exists in the prometheus receiver config
    # AND insecure_skip_verify is injected into the config
    assert (
        config_manager.config._config["receivers"]["prometheus/metrics-endpoint/otelcol/0"]
        == expected_prom_recv_cfg
    )

    # AND WHEN more scrape jobs are added to the config
    more_jobs = [
        {
            "metrics_path": "/metrics",
            "job_name": "second_job",
        },
        {
            "metrics_path": "/metrics",
            "job_name": "third_job",
        },
    ]
    config_manager.add_prometheus_scrape_jobs(more_jobs)
    # THEN the original scrape job was overwritten and the newly added scrape jobs were added
    job_names = [
        job["job_name"]
        for job in config_manager.config._config["receivers"][
            "prometheus/metrics-endpoint/otelcol/0"
        ]["config"]["scrape_configs"]
    ]
    assert job_names == ["second_job", "third_job"]


@pytest.mark.parametrize(
    "enabled_pipelines",
    [
        [],
        [("logs", True)],
        [("logs", True), ("traces", False)],
        [("logs", False), ("metrics", False)],
        [("logs", True), ("metrics", True), ("traces", True)],
    ],
)
def test_add_debug_exporters_(enabled_pipelines):
    # GIVEN an empty config
    config_manager = ConfigManager("otelcol/0", "", "")
    initial_cfg = copy.copy(config_manager.config._config)

    # WHEN a debug exporters are added to the config
    config_manager.add_debug_exporters(enabled_pipelines)

    # THEN the config remains unchanged if no pipelines are enabled
    if not any(enabled for _, enabled in enabled_pipelines):
        assert initial_cfg == config_manager.config._config
        return

    # AND only one debug exporter is added to the list of exporters
    assert 1 == sum(
        "debug/juju-config-enabled" in key for key in config_manager.config._config["exporters"]
    )
    # AND there are no additional pipelines configured
    assert ["logs/otelcol/0", "metrics/otelcol/0", "traces/otelcol/0"] == list(
        config_manager.config._config["service"]["pipelines"].keys()
    )
    # AND the debug exporter is only attached to the enabled pipelines
    for pipeline, enabled in enabled_pipelines:
        exporter_exists = "debug/juju-config-enabled" in config_manager.config._config["service"][
            "pipelines"
        ][f"{pipeline}/otelcol/0"].get("exporters", [])
        assert exporter_exists if enabled else not exporter_exists
