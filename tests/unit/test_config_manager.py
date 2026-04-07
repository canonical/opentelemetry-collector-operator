# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Opentelemetry-collector config builder."""

import copy

import pytest

from src.config_manager import ConfigManager
from charmlibs.interfaces.otlp import OtlpEndpoint


def test_add_log_forwarding():
    # GIVEN an empty config
    config_manager = ConfigManager("otelcol/0", "0", "", "", insecure_skip_verify=True)

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
    config_manager = ConfigManager("otelcol/0", "0", "", "", insecure_skip_verify=True)

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
    config_manager = ConfigManager("otelcol/0", "0", "", "", insecure_skip_verify=True)

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
    config_manager = ConfigManager("otelcol/0", "0", "", "", insecure_skip_verify=True)

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
    "enabled_pipelines,expected_pipelines",
    [
        (
            {"logs": False, "metrics": False, "traces": False},
            {
                "logs/otelcol/0": {"receivers": ["otlp/foo"], "exporters": []},
                "metrics/otelcol/0": {"receivers": ["otlp/foo"], "exporters": []},
                "traces/otelcol/0": {"receivers": ["otlp/foo"], "exporters": []},
            },
        ),
        (
            {"logs": True, "metrics": True, "traces": True},
            {
                "logs/otelcol/0": {
                    "receivers": ["otlp/foo"],
                    "exporters": ["debug/juju-config-enabled"],
                },
                "metrics/otelcol/0": {
                    "receivers": ["otlp/foo"],
                    "exporters": ["debug/juju-config-enabled"],
                },
                "traces/otelcol/0": {
                    "receivers": ["otlp/foo"],
                    "exporters": ["debug/juju-config-enabled"],
                },
            },
        ),
        (
            {"logs": True, "metrics": False, "traces": True},
            {
                "logs/otelcol/0": {
                    "receivers": ["otlp/foo"],
                    "exporters": ["debug/juju-config-enabled"],
                },
                "metrics/otelcol/0": {"receivers": ["otlp/foo"]},
                "traces/otelcol/0": {
                    "receivers": ["otlp/foo"],
                    "exporters": ["debug/juju-config-enabled"],
                },
            },
        ),
    ],
)
def test_add_debug_exporters(enabled_pipelines, expected_pipelines):
    # GIVEN an empty config
    config_manager = ConfigManager("otelcol/0", "foo", "", "")
    initial_cfg = copy.copy(config_manager.config._config)

    # WHEN a debug exporters are added to the config
    config_manager.add_debug_exporters(**enabled_pipelines)

    # THEN the config remains unchanged if no pipelines are enabled
    if not any(enabled_pipelines.values()):
        assert initial_cfg == config_manager.config._config
        return

    # AND only one debug exporter is added to the list of exporters
    assert 1 == sum(
        "debug/juju-config-enabled" in key for key in config_manager.config._config["exporters"]
    )
    # AND there are no additional pipelines configured
    assert list(config_manager.config._config["service"]["pipelines"].keys()) == [
        "logs/otelcol/0",
        "metrics/otelcol/0",
        "traces/otelcol/0",
    ]
    # AND the debug exporter is only attached to the enabled pipelines
    assert expected_pipelines == config_manager.config._config["service"]["pipelines"]


def test_add_otlp_forwarding():
    # GIVEN an empty config
    config_manager = ConfigManager("otelcol/0", "otelcol", "", "", insecure_skip_verify=True)

    # WHEN the OTLP providers for multiple relations have provided the preferred protocols
    unit_name = "otelcol/0"
    config_manager.add_otlp_forwarding(
        relation_map={
            0: OtlpEndpoint(
                **{
                    "protocol": "grpc",
                    "endpoint": "https://1.2.3.4:grpc-port",
                    "telemetries": ["metrics", "traces"],
                }
            ),
            1: OtlpEndpoint(
                **{
                    "protocol": "http",
                    "endpoint": "http://host-1:http-port",
                    "telemetries": ["logs"],
                }
            ),
            2: OtlpEndpoint(
                **{
                    "protocol": "grpc",
                    "endpoint": "https://host-2:grpc-port",
                    "telemetries": ["logs", "traces"],
                }
            ),
        }
    )

    # THEN the exporter config contains appropriate "otlp" and "otlphttp" exporters
    expected_exporters = {
        f"otlp/rel-0/{unit_name}": {
            "endpoint": "https://1.2.3.4:grpc-port",
            "tls": {"insecure": False, "insecure_skip_verify": True},
        },
        f"otlphttp/rel-1/{unit_name}": {
            "endpoint": "http://host-1:http-port",
            "tls": {"insecure": True, "insecure_skip_verify": True},
        },
        f"otlp/rel-2/{unit_name}": {
            "endpoint": "https://host-2:grpc-port",
            "tls": {"insecure": False, "insecure_skip_verify": True},
        },
    }
    # AND the exporters are added to the appropriate pipelines
    expected_pipelines = {
        "logs/otelcol/0": {
            "receivers": ["otlp/otelcol"],
            "exporters": [f"otlphttp/rel-1/{unit_name}", f"otlp/rel-2/{unit_name}"],
        },
        "metrics/otelcol/0": {
            "receivers": ["otlp/otelcol"],
            "exporters": [f"otlp/rel-0/{unit_name}"],
        },
        "traces/otelcol/0": {
            "receivers": ["otlp/otelcol"],
            "exporters": [f"otlp/rel-0/{unit_name}", f"otlp/rel-2/{unit_name}"],
        },
    }
    assert config_manager.config._config["exporters"] == expected_exporters
    assert config_manager.config._config["service"]["pipelines"] == expected_pipelines


def test_add_external_configs_adds_components_to_requested_pipelines():
    config_manager = ConfigManager("otelcol/0", "otelcol", "", "", insecure_skip_verify=True)

    config_manager.add_external_configs(
        [
            {
                "config_yaml": """
receivers:
  prometheus/custom:
    config:
      scrape_configs:
        - job_name: custom
          static_configs:
            - targets: ["0.0.0.0:9000"]
""",
                "pipelines": ["metrics"],
            }
        ]
    )

    receiver_name = "prometheus/custom/otelcol/0"
    assert receiver_name in config_manager.config._config["receivers"]
    assert receiver_name in config_manager.config._config["service"]["pipelines"]["metrics/otelcol/0"]["receivers"]


@pytest.mark.parametrize(
    "input_replacement,expected_replacement",
    [
        # Single capture group ${1}
        ("${1}.juju-73d163-3-lxd-0", "$${1}.juju-73d163-3-lxd-0"),
        # Multiple capture groups ${1} and ${2}
        ("${1}-${2}", "$${1}-$${2}"),
        # Plain $var env-var-like
        ("$MY_VAR", "$$MY_VAR"),
        # Already escaped $$ — must be idempotent
        ("$${1}.juju-73d163-3-lxd-0", "$${1}.juju-73d163-3-lxd-0"),
        # No dollar signs — unchanged
        ("static-replacement", "static-replacement"),
        # Empty string
        ("", ""),
    ],
)
def test_sanitize_escape_prometheus_scrape_configs_parametrized(
    input_replacement, expected_replacement
):
    """Test that bare $ signs in relabel_configs replacement fields are properly escaped."""
    # GIVEN a scrape config with a relabeling rule containing a replacement value
    scrape_configs = [
        {
            "job_name": "test_job",
            "relabel_configs": [
                {
                    "action": "replace",
                    "regex": "([^.]+).*",
                    "replacement": input_replacement,
                }
            ],
        }
    ]

    # WHEN sanitize_escape_prometheus_scrape_configs is called
    result = ConfigManager.sanitize_escape_prometheus_scrape_configs(scrape_configs)

    # THEN the replacement value is correctly escaped
    assert result[0]["relabel_configs"][0]["replacement"] == expected_replacement


def test_sanitize_escape_prometheus_scrape_configs_nested_relabel_configs():
    """Test escaping in a realistic scrape config with relabel_configs as in the issue."""
    # GIVEN a scrape config like those provided by ceph-mon via cos_agent
    scrape_configs = [
        {
            "job_name": "juju_ceph-mon_prometheus_scrape",
            "static_configs": [{"targets": ["10.0.0.1:9283"]}],
            "relabel_configs": [
                {
                    "source_labels": ["__address__"],
                    "action": "replace",
                    "regex": "([^.]+).*",
                    "replacement": "${1}.juju-73d163-3-lxd-0",
                    "target_label": "instance",
                }
            ],
        }
    ]

    # WHEN sanitize_escape_prometheus_scrape_configs is called
    result = ConfigManager.sanitize_escape_prometheus_scrape_configs(scrape_configs)

    # THEN the replacement value has its bare $ escaped
    assert result[0]["relabel_configs"][0]["replacement"] == "$${1}.juju-73d163-3-lxd-0"
    # AND other fields are unchanged
    assert result[0]["job_name"] == "juju_ceph-mon_prometheus_scrape"
    assert result[0]["static_configs"] == [{"targets": ["10.0.0.1:9283"]}]


def test_sanitize_escape_prometheus_scrape_configs_multiple_jobs_mixed():
    """Test that multiple jobs are handled correctly, including already-escaped ones."""
    # GIVEN two jobs: one with bare $ signs, one already escaped
    scrape_configs = [
        {
            "job_name": "job_bare",
            "relabel_configs": [{"replacement": "${1}.host"}],
        },
        {
            "job_name": "job_already_escaped",
            "relabel_configs": [{"replacement": "$${1}.host"}],
        },
    ]

    # WHEN sanitize_escape_prometheus_scrape_configs is called
    result = ConfigManager.sanitize_escape_prometheus_scrape_configs(scrape_configs)

    # THEN bare $ in job_bare is escaped
    assert result[0]["relabel_configs"][0]["replacement"] == "$${1}.host"
    # AND already-escaped $$ in job_already_escaped is unchanged
    assert result[1]["relabel_configs"][0]["replacement"] == "$${1}.host"


def test_sanitize_escape_prometheus_scrape_configs_no_mutation():
    """Test that the original input is not mutated (deep copy guarantee)."""
    # GIVEN a scrape config with bare $ signs
    original = [{"relabel_configs": [{"replacement": "${1}.host"}]}]
    original_copy = copy.deepcopy(original)

    # WHEN sanitize_escape_prometheus_scrape_configs is called
    ConfigManager.sanitize_escape_prometheus_scrape_configs(original)

    # THEN the original input is not mutated
    assert original == original_copy


def test_sanitize_escape_prometheus_scrape_configs_idempotent():
    """Test that calling the method twice returns the same result (idempotent)."""
    # GIVEN a scrape config with bare $ signs
    scrape_configs = [{"relabel_configs": [{"replacement": "${1}.host"}]}]

    # WHEN sanitize_escape_prometheus_scrape_configs is called twice
    once = ConfigManager.sanitize_escape_prometheus_scrape_configs(scrape_configs)
    twice = ConfigManager.sanitize_escape_prometheus_scrape_configs(once)

    # THEN the result is the same both times
    assert once == twice


@pytest.mark.parametrize(
    "external_configs",
    [
        [{"config_yaml": "[]", "pipelines": ["metrics"]}],
        [{"config_yaml": "receivers: []", "pipelines": ["metrics"]}],
        ["not-a-dict"],
    ],
)
def test_add_external_configs_skips_malformed_entries(external_configs):
    config_manager = ConfigManager("otelcol/0", "otelcol", "", "", insecure_skip_verify=True)
    initial_config = copy.deepcopy(config_manager.config._config)

    config_manager.add_external_configs(external_configs)

    assert config_manager.config._config == initial_config
