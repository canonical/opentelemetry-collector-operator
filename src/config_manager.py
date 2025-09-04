"""Helper module to build the configuration for OpenTelemetry Collector."""

import logging
from typing import Any, Optional, Dict, List, Literal, Set

import yaml

from config_builder import Component, ConfigBuilder, Port
from integrations import ProfilingEndpoint
from constants import FILE_STORAGE_DIRECTORY

logger = logging.getLogger(__name__)


def tail_sampling_config(
    tracing_sampling_rate_charm: float,
    tracing_sampling_rate_workload: float,
    tracing_sampling_rate_error: float,
) -> Dict[str, Any]:
    """Generate configuration for the tail sampling processor.

    This function creates a configuration dictionary for the tail sampling processor
    that implements a multi-policy sampling strategy:
    - Error traces: Samples a configurable percentage of traces with ERROR status
    - Charm traces: Samples traces from charm services based on a configurable rate
    - Workload traces: Samples traces from non-charm workloads based on a configurable rate

    Args:
        tracing_sampling_rate_charm: Sampling rate (0-100) for charm-originated traces
        tracing_sampling_rate_workload: Sampling rate (0-100) for workload traces
        tracing_sampling_rate_error: Sampling rate (0-100) for error traces

    Returns:
        Dict[str, Any]: A dictionary containing the tail sampling configuration
                      in the format expected by the OpenTelemetry Collector.

    Note:
        The tail sampling processor evaluates each policy in order, and a trace
        will be sampled if it matches any of the policies. The error policy
        takes precedence over the others.
        See the description of tail sampling processor for the full decision tree:
        https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/tailsamplingprocessor
    """
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


class ConfigManager:
    """High-level configuration manager for OpenTelemetry Collector.

    This class provides a simplified interface for configuring the OpenTelemetry
    Collector by abstracting away the low-level details of the configuration format.
    It builds on top of the ConfigBuilder class to provide feature-oriented
    methods for common configuration scenarios.
    """

    def __init__(
        self,
        unit_name: str,
        global_scrape_interval: str,
        global_scrape_timeout: str,
        receiver_tls: bool = False,
        insecure_skip_verify: bool = False,
        queue_size: int = 1000,
        max_elapsed_time_min: int = 5,
    ):
        """Generate a default OpenTelemetry collector ConfigManager.

        The base configuration is our opinionated default.

        Args:
            unit_name: the name of the unit
            global_scrape_interval: set a global scrape interval for all prometheus receivers on build
            global_scrape_timeout: set a global scrape timeout for all prometheus receivers on build
            receiver_tls: whether to inject TLS config in all receivers on build
            insecure_skip_verify: value for `insecure_skip_verify` in all exporters
            queue_size: size of the sending queue for exporters
            max_elapsed_time_min: maximum elapsed time for retrying failed requests in minutes
        """
        self._unit_name = unit_name
        self._insecure_skip_verify = insecure_skip_verify
        self._queue_size = queue_size
        self._max_elapsed_time_min = max_elapsed_time_min
        self.config = ConfigBuilder(
            unit_name=self._unit_name,
            global_scrape_interval=global_scrape_interval,
            global_scrape_timeout=global_scrape_timeout,
            receiver_tls=receiver_tls,
            exporter_skip_verify=insecure_skip_verify,
        )
        self.config.add_default_config()
        self.config.add_extension("file_storage", {"directory": FILE_STORAGE_DIRECTORY})

    @property
    def sending_queue_config(self) -> Dict[str, Any]:
        """Return the default sending queue configuration."""
        return {
            "sending_queue": {
                "enabled": True,
                "queue_size": self._queue_size,
                "storage": "file_storage",
            },
            "retry_on_failure": {
                "max_elapsed_time": f"{self._max_elapsed_time_min}m",
            },
        }

    @property
    def prometheus_remotewrite_wal_config(self) -> Dict[str, Any]:
        """Return the default WAL configuration for Prometheus remote write.

        FIXME The WAL config is broken upstream, so we remove it until this is fixed:
        https://github.com/canonical/opentelemetry-collector-k8s-operator/issues/105
        """
        return {}

    def add_log_ingestion(self) -> None:
        """Configure the collector to receive logs via Loki protocol.

        This method sets up the Loki receiver to accept log entries from sources
        like Promtail. The receiver will be available on the port specified by
        `Port.loki_http` and will be added to the 'logs' pipeline.

        See Also:
            https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/lokireceiver
        """
        self.config.add_component(
            Component.receiver,
            f"loki/receive-loki-logs/{self._unit_name}",
            {
                "protocols": {
                    "http": {
                        "endpoint": f"0.0.0.0:{Port.loki_http.value}",
                    },
                },
                "use_incoming_timestamp": True,
            },
            pipelines=[f"logs/{self._unit_name}"],
        )

    def add_log_forwarding(self, endpoints: List[dict], insecure_skip_verify: bool) -> None:
        """Configure log forwarding to one or more Loki endpoints.

        This method sets up the Loki exporter to forward logs to the specified
        endpoints. It also configures appropriate processors to format the logs
        and extract relevant attributes as Loki labels.

        The LogRecord format is controlled with the `loki.format` hint.

        The Loki exporter converts OTLP resource and log attributes into Loki labels, which are indexed.
        Configuring hints (e.g. `loki.attribute.labels`) specifies which attributes should be placed as labels.
        The hints are themselves attributes and will be ignored when exporting to Loki.

        See Also:
            https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.122.0/exporter/lokiexporter
        """
        for idx, endpoint in enumerate(endpoints):
            self.config.add_component(
                Component.exporter,
                f"loki/send-loki-logs/{idx}",
                {
                    "endpoint": endpoint["url"],
                    "default_labels_enabled": {"exporter": False, "job": True},
                    "tls": {"insecure_skip_verify": insecure_skip_verify},
                    **self.sending_queue_config,
                },
                pipelines=[f"logs/{self._unit_name}"],
            )
        # TODO: Luca: this was gated by having outgoing logs. Do we need that?
        self.config.add_component(
            Component.processor,
            "resource/send-loki-logs",
            {
                "attributes": [
                    {
                        "action": "insert",
                        "key": "loki.format",
                        "value": "raw",  # logfmt, json, raw
                    },
                ]
            },
            pipelines=[f"logs/{self._unit_name}"],
        )
        self.config.add_component(
            Component.processor,
            "attributes/send-loki-logs",
            {
                "actions": [
                    {
                        "action": "upsert",
                        "key": "loki.attribute.labels",
                        # These labels are set in `_scrape_configs` of the `v1.loki_push_api` lib
                        "value": "container, job, filename, juju_application, juju_charm, juju_model, juju_model_uuid, juju_unit, snap_name, path",
                    },
                ]
            },
            pipelines=[f"logs/{self._unit_name}"],
        )

    def add_profile_ingestion(self):
        """Configure ingesting profiles."""
        self.config.add_component(
            Component.receiver,
            "otlp",
            {
                "protocols": {
                    "http": {"endpoint": f"0.0.0.0:{Port.otlp_http.value}"},
                    "grpc": {"endpoint": f"0.0.0.0:{Port.otlp_grpc.value}"},
                },
            },
            pipelines=["profiles"],
        )

    def add_profile_forwarding(self, endpoints: List[ProfilingEndpoint]):
        """Configure forwarding profiles to a profiling backend (Pyroscope)."""
        # if we don't do this, and there is no relation on receive-profiles, otelcol will complain
        # that there are no receivers configured for this exporter.
        self.add_profile_ingestion()

        for idx, endpoint in enumerate(endpoints):
            self.config.add_component(
                Component.exporter,
                # first component of this ID is the exporter type
                f"otlp/profiling/{idx}",
                {
                    "endpoint": endpoint.endpoint,
                    # we need `insecure` as well as `insecure_skip_verify` because the endpoint
                    # we're receiving from pyroscope is a grpc one and has no scheme prefix, and
                    # the client defaults to https and fails to handshake unless we set `insecure=False`.
                    "tls": {
                        "insecure": endpoint.insecure,
                        "insecure_skip_verify": self._insecure_skip_verify,
                    },
                },
                pipelines=["profiles"],
            )

    def add_self_scrape(self, identifier: str, labels: Dict) -> None:
        """Configure the collector to scrape its own metrics.

        This sets up a Prometheus receiver that scrapes the collector's own
        metrics endpoint and enriches the metrics with the provided labels.

        Args:
            identifier: Unique JujuTopology identifier for this collector instance,
                      used in the job name
            labels: Dictionary of labels to attach to all scraped metrics.

        See Also:
            https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/prometheusreceiver
        """
        self.config.add_component(
            Component.receiver,
            f"prometheus/self-monitoring/{self._unit_name}",
            {
                "config": {
                    "scrape_configs": [
                        {
                            # This job name is overwritten with "otelcol" when remote-writing
                            "job_name": f"juju_{identifier}_self-monitoring",
                            "scrape_interval": "60s",
                            "static_configs": [
                                {
                                    "targets": [f"0.0.0.0:{Port.metrics.value}"],
                                    "labels": labels,
                                }
                            ],
                        }
                    ]
                }
            },
            pipelines=[f"metrics/{self._unit_name}"],
        )

    def add_prometheus_scrape_jobs(self, jobs: List[Dict]):
        """Add Prometheus scrape configurations to the collector.

        This method updates the Prometheus receiver configuration with the
        provided scrape jobs. Each job should be a dictionary following the
        Prometheus scrape configuration format.

        Args:
            jobs: List of Prometheus scrape job configurations. Each job should
                 be a dictionary that matches the Prometheus scrape_config format.

        Note:
            The scrape jobs will be added to the Prometheus receiver configuration
            with TLS verification settings inherited from the ConfigManager instance.
        """
        if not jobs:
            return
        for scrape_job in jobs:
            # Otelcol acts as a client and scrapes the metrics-generating server, so we enable
            # toggling of skipping the validation of the server certificate
            scrape_job.update({"tls_config": {"insecure_skip_verify": self._insecure_skip_verify}})

        self.config.add_component(
            Component.receiver,
            f"prometheus/metrics-endpoint/{self._unit_name}",
            config={"config": {"scrape_configs": jobs}},
            pipelines=[f"metrics/{self._unit_name}"],
        )

    def add_remote_write(self, endpoints: List[Dict[str, str]]):
        """Configure forwarding alert rules to prometheus/mimir via remote-write."""
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/prometheusremotewriteexporter
        for idx, endpoint in enumerate(endpoints):
            self.config.add_component(
                Component.exporter,
                f"prometheusremotewrite/send-remote-write/{idx}",
                {
                    "endpoint": endpoint["url"],
                    "tls": {"insecure_skip_verify": self._insecure_skip_verify},
                    **self.prometheus_remotewrite_wal_config,
                },
                pipelines=[f"metrics/{self._unit_name}"],
            )

        # TODO Receive alert rules via remote write
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/37277

    def add_traces_ingestion(
        self,
        requested_tracing_protocols: Set[Literal["zipkin", "jaeger_grpc", "jaeger_thrift_http"]],
    ) -> None:
        """Configure trace ingestion for supported protocols.

        Sets up the appropriate receivers based on the requested tracing protocols.
        The supported protocols are:
        - otlp: For traces in OpenTelemetry Protocol format (always enabled)
        - zipkin: For traces in Zipkin format
        - jaeger_grpc: For traces in Jaeger gRPC format
        - jaeger_thrift_http: For traces in Jaeger Thrift over HTTP format

        Args:
            requested_tracing_protocols: Set of protocol names to enable.
                                      If empty, a warning will be logged.

        Note:
            The receivers will be added to the 'traces' pipeline.
        """
        if not requested_tracing_protocols:
            logger.warning("No tempo receivers enabled: otel-collector cannot ingest traces.")
            return

        if "zipkin" in requested_tracing_protocols:
            self.config.add_component(
                Component.receiver,
                f"zipkin/receive-traces/{self._unit_name}",
                {"endpoint": f"0.0.0.0:{Port.zipkin.value}"},
                pipelines=[f"traces/{self._unit_name}"],
            )
        if (
            "jaeger_grpc" in requested_tracing_protocols
            or "jaeger_thrift_http" in requested_tracing_protocols
        ):
            jaeger_config = {"protocols": {}}
            if "jaeger_grpc" in requested_tracing_protocols:
                jaeger_config["protocols"].update(
                    {"grpc": {"endpoint": f"0.0.0.0:{Port.jaeger_grpc.value}"}}
                )
            if "jaeger_thrift_http" in requested_tracing_protocols:
                jaeger_config["protocols"].update(
                    {"thrift_http": {"endpoint": f"0.0.0.0:{Port.jaeger_thrift_http.value}"}}
                )
            self.config.add_component(
                Component.receiver,
                f"jaeger/receive-traces/{self._unit_name}",
                jaeger_config,
                pipelines=[f"traces/{self._unit_name}"],
            )

    def add_traces_processing(
        self,
        sampling_rate_charm: float,
        sampling_rate_workload: float,
        sampling_rate_error: float,
    ) -> None:
        """Configure trace sampling and processing.

        Sets up the tail sampling processor with different sampling rates for:
        - Error traces
        - Traces from the charm
        - Traces from the workload

        Args:
            sampling_rate_charm: Sampling rate (0-100) for charm-originated traces
            sampling_rate_workload: Sampling rate (0-100) for workload traces
            sampling_rate_error: Sampling rate (0-100) for error traces

        Note:
            Error traces are identified by their status code, while charm vs workload
            traces are distinguished by the 'service.name' attribute.
        """
        self.config.add_component(
            Component.processor,
            "tail_sampling",
            tail_sampling_config(
                tracing_sampling_rate_charm=sampling_rate_charm,
                tracing_sampling_rate_workload=sampling_rate_workload,
                tracing_sampling_rate_error=sampling_rate_error,
            ),
            pipelines=[f"traces/{self._unit_name}"],
        )

    def add_traces_forwarding(self, endpoint: str) -> None:
        """Configure trace forwarding to a Tempo endpoint.

        Sets up an OTLP HTTP exporter to forward traces to the specified endpoint.

        Args:
            endpoint: The URL of the Tempo endpoint to forward traces to.

        Note:
            Currently, only one endpoint is supported due to limitations in the
            Tempo charm. The exporter will be added to the 'traces' pipeline.
        """
        self.config.add_component(
            Component.exporter,
            "otlphttp/send-traces",
            {
                "endpoint": endpoint,
                **self.sending_queue_config,
            },
            pipelines=[f"traces/{self._unit_name}"],
        )

    def add_cloud_integrator(
        self,
        username: Optional[str],
        password: Optional[str],
        prometheus_url: Optional[str],
        loki_url: Optional[str],
        tempo_url: Optional[str],
    ) -> None:
        """Configure forwarding telemetry to the endpoints provided by a cloud-integrator charm.

        Args:
            username: Username for basic authentication (if required)
            password: Password for basic authentication (if required)
            prometheus_url: URL for forwarding metrics (e.g., Prometheus remote write)
            loki_url: URL for forwarding logs to Loki
            tempo_url: URL for forwarding traces to Tempo

        Note:
            If both username and password are provided, they will be used for
            basic authentication with all configured endpoints. The TLS settings
            (including insecure_skip_verify) will be inherited from the ConfigManager.
        """
        exporter_auth_config = {}
        if username and password:
            self.config.add_extension(
                "basicauth/cloud-integrator",
                {
                    "client_auth": {
                        "username": username,
                        "password": password,
                    }
                },
            )
            exporter_auth_config = {"auth": {"authenticator": "basicauth/cloud-integrator"}}
        if prometheus_url:
            self.config.add_component(
                Component.exporter,
                "prometheusremotewrite/cloud-config",
                {
                    "endpoint": prometheus_url,
                    "tls": {"insecure_skip_verify": self._insecure_skip_verify},
                    **exporter_auth_config,
                    **self.prometheus_remotewrite_wal_config,
                },
                pipelines=[f"metrics/{self._unit_name}"],
            )
        if loki_url:
            self.config.add_component(
                Component.exporter,
                "loki/cloud-config",
                {
                    "endpoint": loki_url,
                    "tls": {"insecure_skip_verify": self._insecure_skip_verify},
                    "default_labels_enabled": {"exporter": False, "job": True},
                    "headers": {"Content-Encoding": "snappy"},  # TODO: check if this is needed
                    **exporter_auth_config,
                    **self.sending_queue_config,
                },
                pipelines=[f"logs/{self._unit_name}"],
            )
        if tempo_url:
            self.config.add_component(
                Component.exporter,
                "otlphttp/cloud-config",
                {
                    "endpoint": tempo_url,
                    "tls": {"insecure_skip_verify": self._insecure_skip_verify},
                    **exporter_auth_config,
                    **self.sending_queue_config,
                },
                pipelines=[f"traces/{self._unit_name}"],
            )

    def add_custom_processors(self, processors_raw: str) -> None:
        """Add custom processors from Juju configuration.

        This method parses the 'processors' configuration option and adds it to
        the OpenTelemetry Collector configuration.
        """
        for processor_name, processor_config in yaml.safe_load(processors_raw).items():
            self.config.add_component(
                Component.processor,
                f"{processor_name}/{self._unit_name}/_custom",
                processor_config,
                pipelines=[
                    f"metrics/{self._unit_name}",
                    f"logs/{self._unit_name}",
                    f"traces/{self._unit_name}",
                ],
            )
