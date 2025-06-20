"""Helper module to build the configuration for OpenTelemetry Collector."""

import hashlib
import logging
from copy import deepcopy
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


def sha256(hashable) -> str:
    """Use instead of the builtin hash() for repeatable values."""
    if isinstance(hashable, str):
        hashable = hashable.encode("utf-8")
    return hashlib.sha256(hashable).hexdigest()


def tail_sampling_config(
    tracing_sampling_rate_charm: float,
    tracing_sampling_rate_workload: float,
    tracing_sampling_rate_error: float,
) -> Dict[str, Any]:
    """The default configuration for the tail sampling processor used by tracing."""
    # policies, as defined by tail sampling processor definition:
    # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/tailsamplingprocessor
    # each of them is evaluated separately and processor decides whether to pass the trace through or not
    # see the description of tail sampling processor above for the full decision tree
    return yaml.safe_load(
        f"""
        policies:
          - name: error-traces-policy
            type: and
            and:
              and_sub_policy:
                # status_code processor is using span_status property of spans within a trace
                # see https://opentelemetry.io/docs/concepts/signals/traces/#span-status for reference
                - name: trace-status-policy
                  type: status_code
                  status_code:
                    status_codes:
                    - ERROR
                - name: probabilistic-policy
                  type: probabilistic
                  probabilistic:
                    sampling_percentage: {tracing_sampling_rate_error}
          - name: charm-traces-policy
            type: and
            and:
              and_sub_policy:
                - name: service-name-policy
                  type: string_attribute
                  string_attribute:
                    key: service.name
                    values:
                    - ".+-charm"
                    enabled_regex_matching: true
                - name: probabilistic-policy
                  type: probabilistic
                  probabilistic:
                    sampling_percentage: {tracing_sampling_rate_charm}
          # NOTE: this is the exact inverse match of the charm tracing policy
          - name: workload-traces-policy
            type: and
            and:
              and_sub_policy:
                - name: service-name-policy
                  type: string_attribute
                  string_attribute:
                    key: service.name
                    values:
                    - ".+-charm"
                    enabled_regex_matching: true
                    invert_match: true
                - name: probabilistic-policy
                  type: probabilistic
                  probabilistic:
                    sampling_percentage: {tracing_sampling_rate_workload}
        """
    )


PORTS = SimpleNamespace(
    LOKI_HTTP=3500,
    OTLP_GRPC=4317,
    OTLP_HTTP=4318,
    METRICS=8888,
    HEALTH=13133,
    # Tracing
    JAEGER_GRPC=14250,
    JAEGER_THRIFT_HTTP=14268,
    ZIPKIN=9411,
)


class Config:
    """Configuration manager for OpenTelemetry Collector."""

    def __init__(self):
        self._config = {
            "extensions": {},
            "receivers": {},
            "exporters": {},
            "connectors": {},
            "processors": {},
            "service": {
                "extensions": [],
                "pipelines": {},
                "telemetry": {},
            },
        }
        self._cert_file: Optional[str] = None
        self._key_file: Optional[str] = None
        self._insecure_skip_verify: bool = False

    @property
    def yaml(self) -> str:
        """Return the config as a string."""
        config = deepcopy(self)
        config._add_debug_exporters()
        config._config = config._add_receiver_tls(config._config, self._cert_file, self._key_file)
        config._config = config._add_exporter_insecure_skip_verify(
            config._config, self._insecure_skip_verify
        )
        return yaml.dump(config._config)

    @property
    def hash(self):
        """Return the config as a SHA256 hash."""
        return sha256(yaml.safe_dump(self.yaml))

    @property
    def ports(self) -> List[int]:
        """Return the ports that are used in the Collector config."""
        return list(vars(PORTS).values())

    @classmethod
    def default_config(cls) -> "Config":
        """Return the default config for OpenTelemetry Collector."""
        return (
            cls()
            # Currently, we always include the OTLP receiver to ensure the config is valid at all times.
            # We also need these receivers for tracing.
            # There must be at least one pipeline and it must have a valid receiver exporter pair.
            .add_receiver(
                "otlp",
                {
                    "protocols": {
                        "http": {"endpoint": f"0.0.0.0:{PORTS.OTLP_HTTP}"},
                        "grpc": {"endpoint": f"0.0.0.0:{PORTS.OTLP_GRPC}"},
                    },
                },
                pipelines=["logs", "metrics", "traces"],
            )
            # TODO https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/healthcheckextension
            # Add TLS config to extensions
            .add_extension("health_check", {"endpoint": f"0.0.0.0:{PORTS.HEALTH}"})
            .add_telemetry("logs", {"level": "DEBUG"})
            .add_telemetry("metrics", {"level": "normal"})
        )

    def add_receiver(
        self, name: str, receiver_config: Dict[str, Any], pipelines: Optional[List[str]] = None
    ) -> "Config":
        """Add a receiver to the config.

        Receivers are enabled by adding them to the appropriate pipelines within the service section.

        Args:
            name: a string representing the pre-defined receiver name.
            receiver_config: a (potentially nested) dict representing the config contents.
            pipelines: a list of strings for which service pipelines (logs, metrics, traces) the receiver should be added to.

        Returns:
            Config since this is a builder method.
        """
        self._config["receivers"][name] = receiver_config
        if pipelines:
            self._add_to_pipeline(name, "receivers", pipelines)
        return self

    def add_exporter(
        self, name: str, exporter_config: Dict[str, Any], pipelines: Optional[List[str]] = None
    ) -> "Config":
        """Add an exporter to the config.

        Exporters are enabled by adding them to the appropriate pipelines within the service section.

        Args:
            name: a string representing the pre-defined exporter name.
            exporter_config: a (potentially nested) dict representing the config contents.
            pipelines: a list of strings for which service pipelines (logs, metrics, traces) the exporter should be added to.

        Returns:
            Config since this is a builder method.
        """
        self._config["exporters"][name] = exporter_config
        if pipelines:
            self._add_to_pipeline(name, "exporters", pipelines)
        return self

    def add_connector(
        self, name: str, connector_config: Dict[str, Any], pipelines: Optional[List[str]] = None
    ) -> "Config":
        """Add a connector to the config.

        Connectors are enabled by adding them to the appropriate pipelines within the service section.

        Args:
            name: a string representing the pre-defined connector name.
            connector_config: a (potentially nested) dict representing the config contents.
            pipelines: a list of strings for which service pipelines (logs, metrics, traces) the connector should be added to.

        Returns:
            Config since this is a builder method.
        """
        self._config["connectors"][name] = connector_config
        if pipelines:
            self._add_to_pipeline(name, "connectors", pipelines)
        return self

    def add_processor(
        self, name: str, processor_config: Dict[str, Any], pipelines: Optional[List[str]] = None
    ) -> "Config":
        """Add a processor to the config.

        Processors are enabled by adding them to the appropriate pipelines within the service section.

        Args:
            name: a string representing the pre-defined processor name.
            processor_config: a (potentially nested) dict representing the config contents.
            pipelines: a list of strings for which service pipelines (logs, metrics, traces) the processor should be added to.

        Returns:
            Config since this is a builder method.
        """
        self._config["processors"][name] = processor_config
        if pipelines:
            self._add_to_pipeline(name, "processors", pipelines)
        return self

    def add_extension(self, name: str, extension_config: Dict[str, Any]) -> "Config":
        """Add an extension to the config.

        Extensions are enabled by adding them to the appropriate service section.

        Args:
            name: a string representing the pre-defined extension name.
            extension_config: a (potentially nested) dict representing the config contents.

        Returns:
            Config since this is a builder method.
        """
        if name not in self._config["service"]["extensions"]:
            self._config["service"]["extensions"].append(name)
        self._config["extensions"][name] = extension_config
        return self

    def add_telemetry(self, category: str, telem_config: Any) -> "Config":
        """Add internal telemetry to the config.

        Telemetry is enabled by adding it to the appropriate service section.

        Args:
            category: a string representing the pre-defined internal-telemetry types (logs, metrics, traces).
            telem_config: a list of (potentially nested) dict(s) representing the config contents.

        Returns:
            Config since this is a builder method.
        """
        # https://opentelemetry.io/docs/collector/internal-telemetry
        self._config["service"]["telemetry"].setdefault(category, {})
        self._config["service"]["telemetry"][category] = telem_config
        return self

    def _add_to_pipeline(self, name: str, category: str, pipelines: List[str]) -> "Config":
        """Add a pipeline component to the service::pipelines config.

        Args:
            name: a string, uniquely identifying this pipeline component.
            category: a string identifying thy type of pipeline component (receiver, exporter, processor, ...).
            pipelines: a list of strings identifying which signal pipeline type(s) to assign the pipeline component to.

        Returns:
            Config since this is a builder method.
        """
        # Create the pipeline dict key chain if it doesn't exist
        for pipeline in pipelines:
            self._config["service"]["pipelines"].setdefault(
                pipeline,
                {
                    category: [name],
                },
            )
            # Add to pipeline if it doesn't exist in the list already
            if name not in self._config["service"]["pipelines"][pipeline].setdefault(
                category,
                [],
            ):
                self._config["service"]["pipelines"][pipeline][category].append(name)
        return self

    def _add_debug_exporters(self):
        """A pipeline requires at least one receiver and exporter, otherwise the otelcol service errors.

        To avoid this scenario, we create the debug exporter and assign it in the pipeline for
        each signal type (logs, metrics, traces) which has a receiver without an exporter pair
        in the config. In other words, the charm has no outgoing relations for that signal type
        so we send them to debug.

        IMPORTANT: This method should be run prior to rendering the config.
        """
        debug_exporter_required = False
        for signal in ["logs", "metrics", "traces"]:
            pipeline = self._config["service"]["pipelines"].get(signal, {})
            if pipeline:
                if pipeline.get("receivers", []) and not pipeline.get("exporters", []):
                    self._add_to_pipeline("debug", "exporters", [signal])
                    debug_exporter_required = True
        if debug_exporter_required:
            self.add_exporter("debug", {"verbosity": "basic"})

    def add_prometheus_scrape(
        self, jobs: List, incoming_metrics: bool, insecure_skip_verify: bool = False
    ):
        """Update the Prometheus receiver config with scrape jobs if an incoming relation requires it."""
        if not incoming_metrics:
            # TODO For now, the only incoming and outgoing metrics relations are remote-write/scrape,
            # so we don't need to mix and match between them yet.
            return self

        # create the scrape_configs key path if it does not exist
        if jobs:
            self._config["receivers"].setdefault("prometheus", {}).setdefault(
                "config", {}
            ).setdefault("scrape_configs", [])
        for scrape_job in jobs:
            # Otelcol acts as a client and scrapes the metrics-generating server, so we enable
            # toggling of skipping the validation of the server certificate
            scrape_job.update({"tls_config": {"insecure_skip_verify": insecure_skip_verify}})
            self._config["receivers"]["prometheus"]["config"]["scrape_configs"].append(scrape_job)
        return self

    def enable_receiver_tls(self, cert_file: str, key_file: str):
        """Enable server (receivers) tls. Both cert_file and key_file must be set.

        Raises:
            ValueError, if either cert_file or key_file are empty.
        """
        if not cert_file or not key_file:
            raise ValueError("Both cert_file and key_file must be set.")

        self._cert_file = cert_file
        self._key_file = key_file

    @classmethod
    def _add_receiver_tls(
        cls, config: dict, cert_file: Optional[str], key_file: Optional[str]
    ) -> dict:
        """Return the updated config in a new dict.

        Ref: https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configtls/README.md#server-configuration

        If the key-value pair already exists, the value is not updated.

        Since we use the root cert store, we do not fine-grain the certs per exporter.
        """
        config = config.copy()
        if not cert_file or not key_file:
            return config

        # NOTE: TLS can't be added to zipkin because it doesn't have a "protocols" section
        for receiver in config.get("receivers", {}):
            for protocol in {"http", "grpc", "thrift_http"}:
                try:
                    section = config["receivers"][receiver]["protocols"][protocol]
                except KeyError:
                    continue
                else:
                    section.setdefault("tls", {})
                    section["tls"].setdefault("key_file", key_file)
                    section["tls"].setdefault("cert_file", cert_file)

        return config

    def _add_exporter_insecure_skip_verify(
        self, config: dict, insecure_skip_verify: bool = False
    ) -> dict:
        """Insert `tls::insecure_skip_verify` into every exporter's config with the juju config value.

        If the key-value pair already exists, the value is not updated.

        This allows the charm admin to skip verifying the server's certificate. Since we use the root cert
        store, we do not fine-grain the certs per exporter.

        IMPORTANT: This method should be run prior to rendering the config.
        """
        config = config.copy()
        for exporter in config.get("exporters", {}):
            if exporter.split("/")[0] == "debug":
                continue
            config["exporters"][exporter].setdefault("tls", {}).setdefault(
                "insecure_skip_verify", insecure_skip_verify
            )
        return config

    def set_exporter_insecure_skip_verify(self, insecure_skip_verify: bool):
        """Enable skipping client (exporters) certificate validation."""
        self._insecure_skip_verify = insecure_skip_verify
