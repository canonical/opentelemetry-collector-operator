#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on Machines."""

import json
import logging
import socket
import os
import shutil
from collections import namedtuple
from pathlib import Path
from typing import Any, Dict, List, Optional, cast
from constants import (
    RECV_CA_CERT_FOLDER_PATH,
    CONFIG_PATH,
    SERVER_CERT_PATH,
    SERVER_CERT_PRIVATE_KEY_PATH,
    SERVICE_NAME,
)
import yaml
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.loki_k8s.v1.loki_push_api import LokiPushApiConsumer, LokiPushApiProvider
from charms.operator_libs_linux.v2 import snap  # type: ignore
from charms.prometheus_k8s.v0.prometheus_scrape import (
    MetricsEndpointConsumer,
)
from charms.prometheus_k8s.v1.prometheus_remote_write import (
    PrometheusRemoteWriteConsumer,
)
from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificateTransferRequires,
)
from charms.grafana_cloud_integrator.v0.cloud_config_requirer import (
    Credentials,
    GrafanaCloudConfigRequirer,
)
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateRequestAttributes,
    Mode,
    PrivateKey,
    TLSCertificatesRequiresV4,
)
from cosl import JujuTopology, LZMABase64
from ops import CharmBase, main, Container
from ops.model import ActiveStatus, MaintenanceStatus, WaitingStatus, Relation

from config import PORTS, Config, sha256

from snap_management import SnapSpecError, install_otelcol_snap

logger = logging.getLogger(__name__)
PathMapping = namedtuple("PathMapping", ["src", "dest"])


def _aggregate_alerts(rules: Dict, rule_path_map: PathMapping, forward_alert_rules: bool):
    rules = rules if forward_alert_rules else {}
    if os.path.exists(rule_path_map.dest):
        shutil.rmtree(rule_path_map.dest)
    shutil.copytree(rule_path_map.src, rule_path_map.dest)
    for topology_identifier, rule in rules.items():
        rule_file = Path(rule_path_map.dest) / f"juju_{topology_identifier}.rules"
        rule_file.write_text(yaml.safe_dump(rule))
        logger.debug(f"updated alert rules file {rule_file.as_posix()}")


def get_dashboards(relations: List[Relation]) -> List[Dict[str, Any]]:
    """Returns a deduplicated list of all dashboards received by this otelcol."""
    aggregate = {}
    for rel in relations:
        dashboards = json.loads(rel.data[rel.app].get("dashboards", "{}"))  # type: ignore
        if "templates" not in dashboards:
            continue
        for template in dashboards["templates"]:
            content = json.loads(
                LZMABase64.decompress(dashboards["templates"][template].get("content"))
            )
            entry = {
                "charm": dashboards["templates"][template].get("charm", "charm_name"),
                "relation_id": rel.id,
                "title": template,
                "content": content,
            }
            aggregate[template] = entry

    return list(aggregate.values())


def forward_dashboards(charm: CharmBase):
    """Instantiate the GrafanaDashboardProvider and update the dashboards in the relation databag.

    First, dashboards from relations (including those bundled with Otelcol) and save them to disk.
    Then, update the relation databag with these dashboards for Grafana.
    """
    charm_root = charm.charm_dir.absolute()
    dashboard_paths = PathMapping(
        src=charm_root.joinpath(*"src/grafana_dashboards".split("/")),
        dest=charm_root.joinpath(*"grafana_dashboards".split("/")),
    )
    if not os.path.isdir(dashboard_paths.dest):
        shutil.copytree(dashboard_paths.src, dashboard_paths.dest, dirs_exist_ok=True)

    # The leader copies dashboards from relations and save them to disk."""
    if not charm.unit.is_leader():
        return
    shutil.rmtree(dashboard_paths.dest)
    shutil.copytree(dashboard_paths.src, dashboard_paths.dest)
    for dash in get_dashboards(charm.model.relations["grafana-dashboards-consumer"]):
        # Build dashboard custom filename
        charm_name = dash.get("charm", "charm-name")
        rel_id = dash.get("relation_id", "rel_id")
        title = dash.get("title", "").replace(" ", "_").replace("/", "_").lower()
        filename = f"juju_{title}-{charm_name}-{rel_id}.json"
        with open(Path(dashboard_paths.dest, filename), mode="w", encoding="utf-8") as f:
            f.write(json.dumps(dash["content"]))
            logger.debug("updated dashboard file %s", f.name)

    # GrafanaDashboardProvider is garbage collected, see the `_reconcile`` docstring for more details
    grafana_dashboards_provider = GrafanaDashboardProvider(
        charm,
        relation_name="grafana-dashboards-provider",
        dashboards_path=dashboard_paths.dest,
    )
    # Scan the built-in dashboards and update relations with changes
    grafana_dashboards_provider.reload_dashboards()

    # TODO: Do we need to implement dashboard status changed logic?
    #   This propagates Grafana's errors to the charm which provided the dashboard
    # grafana_dashboards_provider._reinitialize_dashboard_data(inject_dropdowns=False)


def receive_ca_certs(charm: CharmBase, container: Container) -> str:
    """Returns a 'pebble replan sentinel' (hash of all certs), for pebble to determine whether a replan is required."""
    # Obtain certs from relation data
    certificate_transfer = CertificateTransferRequires(charm, "receive-ca-cert")
    ca_certs = certificate_transfer.get_all_certificates()

    # Clean-up previously existing certs
    container.remove_path(RECV_CA_CERT_FOLDER_PATH, recursive=True)

    # Write current certs
    for i, cert in enumerate(ca_certs):
        container.push(RECV_CA_CERT_FOLDER_PATH + f"/{i}.crt", cert, make_dirs=True)

    # Refresh system certs
    container.exec(["update-ca-certificates", "--fresh"]).wait()

    # A hot-reload doesn't pick up new system certs - need to restart the service
    return sha256(yaml.safe_dump(ca_certs))


def server_cert(charm: CharmBase, container: Container) -> str:
    """Write private key (from juju secret) and server cert (from relation data) to the workload container.

    Returns:
        Hash of server cert and private key, to be used as reload sentinel.
    """
    # Common name length must be >= 1 and <= 64, so fqdn is too long.
    common_name = charm.unit.name.replace("/", "-")
    domain = socket.getfqdn()
    csr_attrs = CertificateRequestAttributes(common_name=common_name, sans_dns=frozenset({domain}))
    certificates = TLSCertificatesRequiresV4(
        charm=charm,
        relationship_name="receive-server-cert",
        certificate_requests=[csr_attrs],
        mode=Mode.UNIT,
    )

    # TLSCertificatesRequiresV4 is garbage collected, see the `_reconcile`` docstring for more
    # details. So we need to call _configure() ourselves:
    certificates._configure(None)  # type: ignore[reportArgumentType]

    provider_certificate, private_key = certificates.get_assigned_certificate(
        certificate_request=csr_attrs
    )
    if not provider_certificate or not private_key:
        if not provider_certificate:
            logger.debug("TLS disabled: Certificate is not available")
        if not private_key:
            logger.debug("TLS disabled: Private key is not available")

        # Cleanup, in case this happens is after a "revoked" or "renewal" events.
        container.remove_path(SERVER_CERT_PATH, recursive=True)
        container.remove_path(SERVER_CERT_PRIVATE_KEY_PATH, recursive=True)
        return sha256("")

    existing_cert = (
        container.pull(path=SERVER_CERT_PATH).read()
        if container.exists(path=SERVER_CERT_PATH)
        else ""
    )
    if not existing_cert or provider_certificate.certificate != Certificate.from_string(
        existing_cert
    ):
        container.push(
            path=f"{SERVER_CERT_PATH}",
            source=str(provider_certificate.certificate),
            make_dirs=True,
        )
        logger.info("Pushed certificate pushed to workload")

    existing_key = (
        container.pull(path=SERVER_CERT_PRIVATE_KEY_PATH).read()
        if container.exists(path=SERVER_CERT_PRIVATE_KEY_PATH)
        else ""
    )
    if not existing_key or private_key != PrivateKey.from_string(existing_key):
        container.push(
            path=f"{SERVER_CERT_PRIVATE_KEY_PATH}",
            source=str(private_key),
            make_dirs=True,
        )
        logger.info("Pushed private key to workload")

    return sha256(str(private_key) + str(provider_certificate.certificate))


def is_server_cert_on_disk(container: Container) -> bool:
    """Return True if the server cert and private key are present in the workload container."""
    return container.exists(path=SERVER_CERT_PATH) and container.exists(
        path=SERVER_CERT_PRIVATE_KEY_PATH
    )

class OpenTelemetryCollectorError(Exception):
    """Custom exception type for Grafana Agent."""

    pass


class OpenTelemetryCollectorInstallError(OpenTelemetryCollectorError):
    """Custom exception type for install related errors."""

    pass



class OpentelemetryCollectorOperatorCharm(CharmBase):
    """Charm to run OpenTelemetry Collector on Machines."""

    _metrics_rules_src_path = "src/prometheus_alert_rules"
    _metrics_rules_dest_path = "prometheus_alert_rules"
    _loki_rules_src_path = "src/loki_alert_rules"
    _loki_rules_dest_path = "loki_alert_rules"

    def __init__(self, *args):
        super().__init__(*args)
        self.topology = JujuTopology.from_charm(self)
        self.otel_config = Config.default_config()
        self._reconcile()

    def _reconcile(self):
        """Recreate the world state for the charm.

        With this pattern, we do not hold instances as attributes. When using events-based
        libraries, these instances will be garbage collected:
        > Reference to ops.Object at path OpenTelemetryCollectorCharm/INSTANCE has been
        > garbage collected between when the charm was initialised and when the event was emitted.
        """
        container = self.unit.get_container(self._container_name)
        charm_root = self.charm_dir.absolute()
        replan_sentinel: str = ""
        forward_alert_rules = cast(bool, self.config["forward_alert_rules"])
        insecure_skip_verify = cast(bool, self.model.config.get("tls_insecure_skip_verify"))

        # TLS: receive-ca-cert
        replan_sentinel += receive_ca_certs(self, container)

        # TLS: server cert
        replan_sentinel += server_cert(self, container)
        if server_cert_on_disk := is_server_cert_on_disk(container):
            self.otel_config.enable_receiver_tls(SERVER_CERT_PATH, SERVER_CERT_PRIVATE_KEY_PATH)

        # TLS: insecure-skip-verify
        self.otel_config.set_exporter_insecure_skip_verify(
            cast(bool, self.model.config.get("tls_insecure_skip_verify"))
        )

        forward_dashboards(self)

        # Logs setup
        loki_rules_paths = PathMapping(
            src=charm_root.joinpath(*self._loki_rules_src_path.split("/")),
            dest=charm_root.joinpath(*self._loki_rules_dest_path.split("/")),
        )
        loki_provider = LokiPushApiProvider(
            self,
            relation_name="receive-loki-logs",
            port=PORTS.LOKI_HTTP,
            scheme="https" if is_server_cert_on_disk(container) else "http",
        )
        # LokiPushApiConsumer is garbage collected, see the `_reconcile`` docstring for more details
        loki_consumer = LokiPushApiConsumer(
            self,
            relation_name="send-loki-logs",
            alert_rules_path=loki_rules_paths.dest,
            forward_alert_rules=forward_alert_rules,
        )
        _aggregate_alerts(loki_provider.alerts, loki_rules_paths, forward_alert_rules)
        loki_consumer.reload_alerts()
        self._add_log_ingestion(insecure_skip_verify)
        self._add_log_forwarding(loki_consumer.loki_endpoints, insecure_skip_verify)

        # Metrics setup
        metrics_rules_paths = PathMapping(
            src=charm_root.joinpath(*self._metrics_rules_src_path.split("/")),
            dest=charm_root.joinpath(*self._metrics_rules_dest_path.split("/")),
        )
        # MetricsEndpointConsumer is garbage collected, see the `_reconcile`` docstring for more details
        metrics_consumer = MetricsEndpointConsumer(self)
        # Receive alert rules and scrape jobs
        _aggregate_alerts(metrics_consumer.alerts, metrics_rules_paths, forward_alert_rules)
        self._add_self_scrape(insecure_skip_verify)
        self.otel_config.add_prometheus_scrape(
            metrics_consumer.jobs(), self._incoming_metrics, insecure_skip_verify
        )
        # PrometheusRemoteWriteConsumer is garbage collected, see the `_reconcile`` docstring for more details
        remote_write = PrometheusRemoteWriteConsumer(
            self, alert_rules_path=metrics_rules_paths.dest
        )
        # Forward alert rules and scrape jobs to Prometheus
        remote_write.reload_alerts()
        self._add_remote_write(remote_write.endpoints, insecure_skip_verify)

        # Enable forwarding telemetry with GrafanaCloudIntegrator
        cloud_integrator = GrafanaCloudConfigRequirer(self, relation_name="cloud-config")
        # We're intentionally not getting the CA cert from Grafana Cloud Integrator;
        # we decided that we should only get certs from receive-ca-cert.
        self._add_cloud_integrator(
            credentials=cloud_integrator.credentials,
            prometheus_url=cloud_integrator.prometheus_url
            if cloud_integrator.prometheus_ready
            else None,
            loki_url=cloud_integrator.loki_url if cloud_integrator.loki_ready else None,
            insecure_skip_verify=insecure_skip_verify,
        )

        # Push the config and Push the config and deploy/update
        container.push(CONFIG_PATH, self.otel_config.yaml, make_dirs=True)
        replan_sentinel += self.otel_config.hash

        container.add_layer(
            self._container_name, self._pebble_layer(replan_sentinel), combine=True
        )
        # TODO Conditionally open ports based on the otelcol config file rather than opening all ports
        self.unit.set_ports(*self.otel_config.ports)

        if bool(self.model.relations.get("receive-server-cert")) and not server_cert_on_disk:
            # A tls relation to a CA was formed, but we didn't get the cert yet.
            container.stop(SERVICE_NAME)
            self.unit.status = WaitingStatus("Waiting for cert")
        else:
            container.replan()
            self.unit.status = ActiveStatus()


    def _install(self) -> None:
        """Install/refresh the OpenTelemetry Collector snap."""
        self.unit.status = MaintenanceStatus("Installing opentelemetry-collector snap")
        # OpenTelemetry-collector is not yet available, so no config update needed yet.
        # On install, create a config file, to avoid a transient error:
        #   error reading config file open /etc/opentelemetry-collector.yaml: no such file or directory
        if not os.path.exists(CONFIG_PATH):
            self.write_file(CONFIG_PATH, yaml.dump(self._generate_config()))
        try:
            install_otelcol_snap(
                config={"reporting-enabled": "1" if self.config["reporting_enabled"] else "0"},
            )
        except (snap.SnapError, SnapSpecError) as e:
            raise OpenTelemetryCollectorInstallError("Failed to install opentelemetry-collector.") from e


    @property
    def _incoming_metrics(self) -> bool:
        return any(self.model.relations.get("metrics-endpoint", []))

    @property
    def _incoming_logs(self) -> bool:
        return any(self.model.relations.get("receive-loki-logs", []))

    @property
    def _outgoing_metrics(self) -> bool:
        return any(self.model.relations.get("send-remote-write", [])) or any(
            self.model.relations.get("cloud-config", [])
        )

    @property
    def _outgoing_logs(self) -> bool:
        return any(self.model.relations.get("send-loki-logs", [])) or any(
            self.model.relations.get("cloud-config", [])
        )

    def _add_self_scrape(self, insecure_skip_verify: bool):
        """Configure self-monitoring scrape jobs."""
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/prometheusreceiver
        self.otel_config.add_receiver(
            "prometheus",
            {
                "config": {
                    "scrape_configs": [
                        {
                            # This job name is overwritten with "otelcol" when remote-writing
                            "job_name": f"juju_{self.topology.identifier}_self-monitoring",
                            "scrape_interval": "60s",
                            "static_configs": [
                                {
                                    "targets": [f"0.0.0.0:{PORTS.METRICS}"],
                                    "labels": {
                                        "instance": f"{self.topology.identifier}_{self.topology.unit}",
                                        "juju_charm": self.topology.charm_name,
                                        "juju_model": self.topology.model,
                                        "juju_model_uuid": self.topology.model_uuid,
                                        "juju_application": self.topology.application,
                                        "juju_unit": self.topology.unit,
                                    },
                                }
                            ],
                        }
                    ]
                }
            },
            pipelines=["metrics"],
        )

    def _add_remote_write(self, endpoints: List[Dict[str, str]], insecure_skip_verify: bool):
        """Configure forwarding alert rules to prometheus/mimir via remote-write."""
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/prometheusremotewriteexporter
        for idx, endpoint in enumerate(endpoints):
            self.otel_config.add_exporter(
                f"prometheusremotewrite/{idx}",
                {
                    "endpoint": endpoint["url"],
                    "tls": {"insecure_skip_verify": insecure_skip_verify},
                },
                pipelines=["metrics"],
            )

        # TODO Receive alert rules via remote write
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/37277

    def _add_log_ingestion(self, insecure_skip_verify: bool):
        """Configure receiving logs, allowing Promtail instances to specify the Otelcol as their lokiAddress."""
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/receiver/lokireceiver

        # For now, the only incoming and outgoing log relations are loki push api,
        # so we don't need to mix and match between them yet.
        if self._incoming_logs:
            self.otel_config.add_receiver(
                "loki",
                {
                    "protocols": {
                        "http": {
                            "endpoint": f"0.0.0.0:{PORTS.LOKI_HTTP}",
                        },
                    },
                    "use_incoming_timestamp": True,
                },
                pipelines=["logs"],
            )

    def _add_log_forwarding(self, endpoints: List[dict], insecure_skip_verify: bool):
        """Configure sending logs to Loki via the Loki push API endpoint.

        The LogRecord format is controlled with the `loki.format` hint.

        The Loki exporter converts OTLP resource and log attributes into Loki labels, which are indexed.
        Configuring hints (e.g. `loki.attribute.labels`) specifies which attributes should be placed as labels.
        The hints are themselves attributes and will be ignored when exporting to Loki.
        """
        # https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/v0.122.0/exporter/lokiexporter
        for idx, endpoint in enumerate(endpoints):
            self.otel_config.add_exporter(
                f"loki/{idx}",
                {
                    "endpoint": endpoint["url"],
                    "default_labels_enabled": {"exporter": False, "job": True},
                    "tls": {"insecure_skip_verify": insecure_skip_verify},
                },
                pipelines=["logs"],
            )
        if self._outgoing_logs:
            self.otel_config.add_processor(
                "resource",
                {
                    "attributes": [
                        {
                            "action": "insert",
                            "key": "loki.format",
                            "value": "raw",  # logfmt, json, raw
                        },
                    ]
                },
                pipelines=["logs"],
            ).add_processor(
                "attributes",
                {
                    "actions": [
                        {
                            "action": "upsert",
                            "key": "loki.attribute.labels",
                            # These labels are set in `_scrape_configs` of the `v1.loki_push_api` lib
                            "value": "container, job, filename, juju_application, juju_charm, juju_model, juju_model_uuid, juju_unit",
                        },
                    ]
                },
                pipelines=["logs"],
            )

    def _add_cloud_integrator(
        self,
        credentials: Optional[Credentials],
        prometheus_url: Optional[str],
        loki_url: Optional[str],
        insecure_skip_verify: bool,
    ):
        """Configure forwarding telemetry to the endpoints provided by a cloud-integrator charm."""
        exporter_auth_config = {}
        if credentials:
            self.otel_config.add_extension(
                "basicauth/cloud-integrator",
                {
                    "client_auth": {
                        "username": credentials.username,
                        "password": credentials.password,
                    }
                },
            )
            exporter_auth_config = {"auth": {"authenticator": "basicauth/cloud-integrator"}}
        if prometheus_url:
            self.otel_config.add_exporter(
                "prometheusremotewrite/cloud-integrator",
                {
                    "endpoint": prometheus_url,
                    "tls": {"insecure_skip_verify": insecure_skip_verify},
                    **exporter_auth_config,
                },
                pipelines=["metrics"],
            )
        if loki_url:
            self.otel_config.add_exporter(
                "loki/cloud-integrator",
                {
                    "endpoint": loki_url,
                    "tls": {"insecure_skip_verify": insecure_skip_verify},
                    "default_labels_enabled": {"exporter": False, "job": True},
                    "headers": {"Content-Encoding": "snappy"},  # TODO: check if this is needed
                    **exporter_auth_config,
                },
                pipelines=["logs"],
            )


if __name__ == "__main__":  # pragma: nocover
    main(OpentelemetryCollectorOperatorCharm)
