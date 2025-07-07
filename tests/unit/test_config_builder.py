# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Opentelemetry-collector config builder."""

from copy import deepcopy

import pytest
import yaml
import copy

from config_builder import ConfigBuilder, Component


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
    config = ConfigBuilder()
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
    config = ConfigBuilder()
    # WHEN adding a pipeline component
    config._add_to_pipeline("foo", component, pipelines)
    # THEN the pipeline component is added to the pipeline config
    if not pipelines:
        assert not config._config["service"]["pipelines"]
    for pipeline in pipelines:
        assert "foo" in config._config["service"]["pipelines"][pipeline][component.value]


def test_add_extension():
    # GIVEN an empty config
    config = ConfigBuilder()
    # WHEN adding a pipeline with a config
    sample_config = {"a": {"b": "c"}}
    config.add_extension("foo", sample_config)
    # THEN the extension is added to the top-level extensions config
    assert sample_config == config._config["extensions"]["foo"]
    # AND the extension is added to the service::extensions config
    assert "foo" in config._config["service"]["extensions"]


def test_add_telemetry():
    # GIVEN an empty config
    config = ConfigBuilder()
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
    config = ConfigBuilder()
    config.add_default_config()
    config_yaml = yaml.safe_load(config.build())
    # THEN a debug exporter is added for each pipeline missing one
    pipelines = [
        config_yaml["service"]["pipelines"][p] for p in config_yaml["service"]["pipelines"]
    ]
    pairs = [(len(p["receivers"]) > 0, len(p["exporters"]) > 0) for p in pipelines]
    # AND each pipeline has at least one receiver-exporter pair
    assert all(all(condition for condition in pair) for pair in pairs)


def test_receivers_tls_empty_config():
    # GIVEN an "empty" config
    config = ConfigBuilder()
    # WHEN tls is enabled
    config._add_tls_to_all_receivers("/some/cert.crt", "/some/private.key")
    # THEN it has no effect on the rendered config
    assert config.build() == ConfigBuilder().build()


def test_receivers_tls_no_protocols():
    # GIVEN a config without any protocols
    config = ConfigBuilder()
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
    config = ConfigBuilder()
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
    config = ConfigBuilder()
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
    config = ConfigBuilder()
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


def test_debug_exporter_no_tls_config():
    # GIVEN an empty config without exporters
    config = ConfigBuilder()
    # WHEN multiple debug exporters are added
    config.add_component(Component.exporter, "debug", {"config": {"foo": "bar"}})
    config.add_component(Component.exporter, "debug/descriptor", {"config": {"foo": "bar"}})
    # AND the tls::insecure_skip_verify configuration is added
    config._add_exporter_insecure_skip_verify(True)
    # THEN tls::insecure_skip_verify is not set for debug exporters
    assert all("tls" not in exp.keys() for exp in config._config["exporters"].values())
