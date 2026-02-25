# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Opentelemetry-collector config builder."""

from copy import deepcopy

import pytest
import yaml
import copy

from config_builder import ConfigBuilder, Component, Port, build_port_map


@pytest.mark.parametrize("pipelines", ([], ["logs", "metrics", "traces"]))
@pytest.mark.parametrize(
    "component",
    (Component.receiver, Component.exporter, Component.connector, Component.processor),
)
def test_add_pipeline_component(pipelines, component):
    """All pipeline components (receiver, exporter, connector, processor) behave the same.

    Pipeline names can follow the type[/name] format, valid for e.g. logs, metrics, traces, logs/2, ...

    https://opentelemetry.io/docs/collector/configuration/#basics
    """
    # GIVEN an empty config
    config = ConfigBuilder("", "", "", "")
    # WHEN adding a pipeline component with a nested config
    sample_config = {"a": {"b": "c"}}
    config.add_component(
        component=component,
        name="foo",
        config=sample_config,
        pipelines=pipelines,
    )
    # THEN the nested config is added to the config
    assert "foo" in config._config[component.value]
    assert sample_config == config._config[component.value]["foo"]
    # AND the pipeline is not added if none were specified
    if not pipelines:
        assert not config._config["service"]["pipelines"]
    # AND the pipelines are added to the service::pipelines config if specified
    for pipeline in pipelines:
        assert "foo" in config._config["service"]["pipelines"][pipeline][component.value]


@pytest.mark.parametrize("pipelines", ([], ["logs", "metrics", "traces"]))
@pytest.mark.parametrize(
    "component",
    (Component.receiver, Component.exporter, Component.connector, Component.processor),
)
def test_add_to_pipeline(pipelines, component):
    """All pipeline components (receiver, exporter, connector, processor) behave the same.

    https://opentelemetry.io/docs/collector/configuration/#basics
    """
    # GIVEN an empty config
    config = ConfigBuilder("", "", "", "")
    # WHEN adding a pipeline component
    config._add_to_pipeline("foo", component, pipelines)
    # THEN the pipeline component is added to the pipeline config
    if not pipelines:
        assert not config._config["service"]["pipelines"]
    for pipeline in pipelines:
        assert "foo" in config._config["service"]["pipelines"][pipeline][component.value]


def test_add_extension():
    # GIVEN an empty config
    config = ConfigBuilder("", "", "", "")
    # WHEN adding a pipeline with a config
    sample_config = {"a": {"b": "c"}}
    config.add_extension("foo", sample_config)
    # THEN the extension is added to the top-level extensions config
    assert sample_config == config._config["extensions"]["foo"]
    # AND the extension is added to the service::extensions config
    assert "foo" in config._config["service"]["extensions"]


def test_add_telemetry():
    # GIVEN an empty config
    config = ConfigBuilder("", "", "", "")
    # WHEN adding a pipeline with a config
    sample_config = [{"a": {"b": "c"}}]
    config.add_telemetry("logs", {"level": "INFO"})
    config.add_telemetry("metrics", {"level": "normal"})
    config.add_telemetry("metrics", {"some_config": sample_config})
    # THEN the respective telemetry sections are added to the service::telemetry config
    assert ["logs", "metrics"] == list(config._config["service"]["telemetry"].keys())
    # AND the telemetry is added to the service::telemetry config
    assert config._config["service"]["telemetry"]["metrics"] == {"some_config": sample_config}
    assert config._config["service"]["telemetry"]["logs"] == {"level": "INFO"}


def test_rendered_default_is_valid():
    # GIVEN a default config
    # WHEN the config is rendered
    config = ConfigBuilder("", "", "", "")
    config.add_default_config()
    config_yaml = yaml.safe_load(config.build())
    # THEN a nop exporter is added for each pipeline missing one
    pipelines = [
        config_yaml["service"]["pipelines"][p] for p in config_yaml["service"]["pipelines"]
    ]
    pairs = [(len(p["receivers"]) > 0, len(p["exporters"]) > 0) for p in pipelines]
    # AND each pipeline has at least one receiver-exporter pair
    assert all(all(condition for condition in pair) for pair in pairs)


def test_receivers_tls_empty_config():
    # GIVEN an "empty" config
    config = ConfigBuilder("", "", "", "")
    # WHEN tls is enabled
    config._add_tls_to_all_receivers("/some/cert.crt", "/some/private.key")
    # THEN it has no effect on the rendered config
    assert config.build() == ConfigBuilder("", "", "", "").build()


def test_receivers_tls_no_protocols():
    # GIVEN a config without any protocols
    config = ConfigBuilder("", "", "", "")
    config.add_component(
        Component.receiver, "prometheus", {"config": {"foo": "bar"}}, pipelines=["metrics"]
    )

    # TODO When we impl fluent config (with immutable builder), then we won't need to copy anymore, because we would:
    #  yaml1 = config.enable_receiver_tls("foo", "bar").yaml
    #  yaml2 = config.yaml
    config_copy = copy.deepcopy(config)

    # WHEN tls is enabled
    config._add_tls_to_all_receivers("/some/cert.crt", "/some/private.key")

    # THEN it has no effect on the rendered config
    assert config.build() == config_copy.build()


def test_receivers_tls_unknown_protocols():
    # GIVEN a config with an unknown protocols
    config = ConfigBuilder("", "", "", "")
    config.add_component(
        Component.receiver,
        "some_receiver",
        {"protocols": {"unknown_protocol_name": {"endpoint": "0.0.0.0:1234"}}},
        pipelines=["metrics"],
    )
    config_copy = copy.deepcopy(config)

    # WHEN tls is enabled
    config._add_tls_to_all_receivers("/some/cert.crt", "/some/private.key")

    # THEN it has no effect on the rendered config
    assert config.build() == config_copy.build()


def test_receivers_tls_known_protocols():
    # GIVEN a config with known protocols (http, grpc)
    config = ConfigBuilder("", "", "", "")
    config.add_component(
        Component.receiver,
        "some-http-receiver",
        {"protocols": {"http": {"endpoint": "0.0.0.0:1234"}}},
        pipelines=["metrics"],
    )
    config.add_component(
        Component.receiver,
        "another-http-receiver",
        {"protocols": {"http": {"endpoint": "0.0.0.0:1235"}}},
        pipelines=["metrics"],
    )
    config.add_component(
        Component.receiver,
        "some-grpc-receiver",
        {"protocols": {"grpc": {"endpoint": "0.0.0.0:5678"}}},
        pipelines=["metrics"],
    )
    config.add_component(
        Component.receiver,
        "another-grpc-receiver",
        {"protocols": {"grpc": {"endpoint": "0.0.0.0:5679"}}},
        pipelines=["metrics"],
    )
    config.add_component(
        Component.receiver,
        "with-existing-tls",
        {
            "protocols": {
                "grpc": {
                    "endpoint": "0.0.0.0:5679",
                    "tls": {"key_file": "foo", "cert_file": "bar"},
                }
            }
        },
        pipelines=["metrics"],
    )

    # WHEN tls is enabled
    config._add_tls_to_all_receivers("/some/cert.crt", "/some/private.key")
    config_dict = yaml.safe_load(config.build())

    # THEN all receivers' http, grpc protocols gain a tls section
    for tls_section in (
        config_dict["receivers"]["some-http-receiver"]["protocols"]["http"]["tls"],
        config_dict["receivers"]["another-http-receiver"]["protocols"]["http"]["tls"],
        config_dict["receivers"]["some-grpc-receiver"]["protocols"]["grpc"]["tls"],
        config_dict["receivers"]["another-grpc-receiver"]["protocols"]["grpc"]["tls"],
    ):
        assert "key_file" in tls_section
        assert tls_section["key_file"] == "/some/private.key"
        assert "cert_file" in tls_section
        assert tls_section["cert_file"] == "/some/cert.crt"

    # AND receivers which had a configured tls section, keep their configuration
    assert (
        config_dict["receivers"]["with-existing-tls"]["protocols"]["grpc"]["tls"]["key_file"]
        == "foo"
    )
    assert (
        config_dict["receivers"]["with-existing-tls"]["protocols"]["grpc"]["tls"]["cert_file"]
        == "bar"
    )


def test_insecure_skip_verify():
    # GIVEN an empty config without exporters
    config = ConfigBuilder("", "", "", "")
    config_copy = deepcopy(config)
    # WHEN updating the tls::insecure_skip_verify exporter configuration
    config._add_exporter_insecure_skip_verify(False)
    # THEN it has no effect on the rendered config
    assert config._config == config_copy._config
    # WHEN multiple exporters are added
    config.add_component(Component.exporter, "foo", {"endpoint": "foo"})
    config.add_component(
        Component.exporter,
        "bar",
        {
            "endpoint": "bar",
            "tls": {"insecure_skip_verify": True},
        },
    )
    # AND the tls::insecure_skip_verify configuration is added
    config._add_exporter_insecure_skip_verify(False)
    # THEN tls::insecure_skip_verify is set for each exporter which was missing this configuration
    assert config._config["exporters"]["foo"]["tls"]["insecure_skip_verify"] is False
    # AND any existing tls::insecure_skip_verify configuration is untouched
    assert config._config["exporters"]["bar"]["tls"]["insecure_skip_verify"] is True


def test_some_exporters_exclude_tls_config():
    # GIVEN an empty config without exporters
    config = ConfigBuilder("", "", "", "")
    # WHEN multiple nop exporters are added
    config.add_component(Component.exporter, "nop", {"config": {"foo": "bar"}})
    config.add_component(Component.exporter, "nop/descriptor", {"config": {"foo": "bar"}})
    # WHEN multiple debug exporters are added
    config.add_component(Component.exporter, "debug", {"config": {"foo": "bar"}})
    config.add_component(Component.exporter, "debug/descriptor", {"config": {"foo": "bar"}})
    # AND the tls::insecure_skip_verify configuration is added
    config._add_exporter_insecure_skip_verify(True)
    # THEN tls::insecure_skip_verify is not set for nop exporters
    assert all("tls" not in exp.keys() for exp in config._config["exporters"].values())


def test_global_scrape_timeout_and_interval():
    # GIVEN a config with multiple prometheus receivers
    config = ConfigBuilder("", "", "", "")
    config.add_component(Component.receiver, name="prometheus", config={"config": {}})
    config.add_component(
        Component.receiver, name="prometheus/empty-cfgs", config={"config": {"scrape_configs": []}}
    )
    config.add_component(
        Component.receiver,
        name="prometheus/missing-timeout",
        config={"config": {"scrape_configs": [{"scrape_interval": "1s"}]}},
    )
    config.add_component(
        Component.receiver,
        name="prometheus/missing-interval",
        config={"config": {"scrape_configs": [{"scrape_timeout": "1s"}]}},
    )
    config.add_component(
        Component.receiver,
        name="prometheus/multiple-cfgs",
        config={
            "config": {
                "scrape_configs": [
                    {"scrape_interval": "1s", "scrape_timeout": "1s"},
                    {"scrape_interval": "1s", "scrape_timeout": "1s"},
                ]
            }
        },
    )
    # WHEN the global scrape interval and timeout is set
    config._set_prometheus_receiver_global_timeout_and_interval("1m", "10s")
    # THEN all prometheus receivers are updated
    for receiver in config._config["receivers"].values():
        if receiver["config"]:
            for scrape_cfg in receiver["config"]["scrape_configs"]:
                assert scrape_cfg["scrape_interval"] == "1m"
                assert scrape_cfg["scrape_timeout"] == "10s"


# ──────────────────────────────────────────────────────────────────────────────
# Feature: build_port_map
# ──────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("overrides", ["", "   "])
def test_build_port_map_returns_defaults(overrides):
    """An empty or whitespace-only override string returns the Port enum defaults unchanged."""
    # GIVEN an empty or whitespace-only override string
    # WHEN building the port map
    port_map = build_port_map(overrides)
    # THEN all ports match the enum defaults
    for port in Port:
        assert port_map[port.name] == port.value


def test_build_port_map_single_override():
    """A single override changes only the specified port."""
    # GIVEN an override for a single port
    overrides = "loki_http=3501"
    # WHEN building the port map
    port_map = build_port_map(overrides)
    # THEN the overridden port has the new value
    assert port_map["loki_http"] == 3501
    # AND all other ports keep their defaults
    for port in Port:
        if port.name != "loki_http":
            assert port_map[port.name] == port.value


def test_build_port_map_multiple_overrides():
    """Multiple comma-separated overrides are all applied."""
    # GIVEN overrides for two ports
    overrides = "loki_http=3501,otlp_grpc=4320"
    # WHEN building the port map
    port_map = build_port_map(overrides)
    # THEN both ports have the overridden values
    assert port_map["loki_http"] == 3501
    assert port_map["otlp_grpc"] == 4320


def test_build_port_map_whitespace_is_stripped():
    """Leading/trailing whitespace around names and values is accepted."""
    # GIVEN overrides with extra whitespace
    overrides = "  loki_http = 3501 , otlp_grpc = 4320  "
    # WHEN building the port map
    port_map = build_port_map(overrides)
    # THEN the overrides are applied correctly
    assert port_map["loki_http"] == 3501
    assert port_map["otlp_grpc"] == 4320


@pytest.mark.parametrize(
    "overrides, expected_error",
    [
        ("unknown_port=9999", "Unknown port name"),
        ("loki_http=not_a_number", "must be an integer"),
        ("loki_http3501", "Invalid format"),
        ("loki_http=0", "between 1 and 65535"),
        ("loki_http=65536", "between 1 and 65535"),
        ("loki_http=-1", "between 1 and 65535"),
        ("loki_http=4317", "Duplicate port"),  # 4317 is the default for otlp_grpc
    ],
)
def test_build_port_map_invalid_input_raises(overrides, expected_error):
    """Invalid override strings raise ValueError with a descriptive message."""
    # GIVEN an invalid override string
    # WHEN building the port map THEN a ValueError is raised with the expected message
    with pytest.raises(ValueError, match=expected_error):
        build_port_map(overrides)


def test_config_builder_accepts_port_overrides():
    """ConfigBuilder uses the provided port map in add_default_config."""
    # GIVEN a port map with overridden ports
    port_map = build_port_map("otlp_http=4400,otlp_grpc=4401,health=13200")
    # WHEN creating a ConfigBuilder with those ports and building the config
    config = ConfigBuilder("unit/0", "host0", "1m", "10s", ports=port_map)
    config.add_default_config()
    built = yaml.safe_load(config.build())
    # THEN the OTLP receiver endpoints use the overridden ports
    otlp_receiver = built["receivers"]["otlp/host0"]
    assert str(4400) in otlp_receiver["protocols"]["http"]["endpoint"]
    assert str(4401) in otlp_receiver["protocols"]["grpc"]["endpoint"]
    # AND the health_check extension uses the overridden port
    assert str(13200) in built["extensions"]["health_check"]["endpoint"]
