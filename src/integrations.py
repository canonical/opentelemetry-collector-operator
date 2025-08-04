# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A helper module to manage integrations for the charm."""

import json
import logging
import shutil
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, cast, get_args

import yaml
from charmlibs.pathops import PathProtocol
from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificateTransferRequires,
)
from charms.grafana_cloud_integrator.v0.cloud_config_requirer import (
    GrafanaCloudConfigRequirer,
)
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.loki_k8s.v1.loki_push_api import LokiPushApiConsumer, LokiPushApiProvider
from charms.prometheus_k8s.v0.prometheus_scrape import (
    MetricsEndpointConsumer,
)
from charms.prometheus_k8s.v1.prometheus_remote_write import (
    PrometheusRemoteWriteConsumer,
)
from charms.tempo_coordinator_k8s.v0.tracing import (
    ReceiverProtocol,
    TracingEndpointProvider,
    TracingEndpointRequirer,
    TransportProtocolType,
    receiver_protocol_to_transport_protocol,
)
from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateRequestAttributes,
    Mode,
    TLSCertificatesRequiresV4,
)
from cosl import LZMABase64
from ops import CharmBase, tracing
from ops.model import Relation

from config_builder import Port, sha256
from constants import (
    DASHBOARDS_DEST_PATH,
    DASHBOARDS_SRC_PATH,
    LOKI_RULES_DEST_PATH,
    LOKI_RULES_SRC_PATH,
    METRICS_RULES_DEST_PATH,
    METRICS_RULES_SRC_PATH,
)

logger = logging.getLogger(__name__)


def cleanup():
    """Cleanup folders for alerts and dashboards.

    This function should be called before all integrations to ensure the charm works holistically.
    """
    shutil.rmtree(METRICS_RULES_DEST_PATH, ignore_errors=True)
    shutil.rmtree(LOKI_RULES_DEST_PATH, ignore_errors=True)
    shutil.rmtree(DASHBOARDS_DEST_PATH, ignore_errors=True)


def _add_alerts(alerts: Dict, dest_path: Path):
    """Save the alerts to files in the specified destination folder.

    For K8s charms, alerts are saved in the charm container.

    Args:
        alerts: Dictionary of alerts to save to disk
        dest_path: Path to the folder where alerts will be saved
    """
    dest_path.mkdir(parents=True, exist_ok=True)
    for topology_identifier, rule in alerts.items():
        rule_file = dest_path.joinpath(f"juju_{topology_identifier}.rules")
        rule_file.write_text(yaml.safe_dump(rule))
        logger.debug(f"updated alert rules file {rule_file.as_posix()}")


def receive_loki_logs(charm: CharmBase, tls: bool):
    """Integrate with other charms via the receive-loki-logs relation endpoint.

    This function must be called before `send_loki_logs`, so that the charm
    can gather all the alerts from relation data before sending them all
    to Loki.
    """
    forward_alert_rules = cast(bool, charm.config.get("forward_alert_rules"))
    charm_root = charm.charm_dir.absolute()
    loki_provider = LokiPushApiProvider(
        charm,
        relation_name="receive-loki-logs",
        port=Port.loki_http.value,
        scheme="https" if tls else "http",
    )
    charm.__setattr__("loki_provider", loki_provider)
    shutil.copytree(
        charm_root.joinpath(*LOKI_RULES_SRC_PATH.split("/")),
        charm_root.joinpath(*LOKI_RULES_DEST_PATH.split("/")),
        dirs_exist_ok=True,
    )
    _add_alerts(
        alerts=loki_provider.alerts if forward_alert_rules else {},
        dest_path=charm_root.joinpath(*LOKI_RULES_DEST_PATH.split("/")),
    )


def send_loki_logs(charm: CharmBase) -> List[Dict]:
    """Integrate with Loki via the send-loki-logs relation endpoint.

    If used together with `receive_loki_logs`, this function must be called after.

    Returns:
        A list of dictionaries with Loki Push API endpoints, for instance:
        [
            {"url": "http://loki1:3100/loki/api/v1/push"},
            {"url": "http://loki2:3100/loki/api/v1/push"},
        ]
    """
    forward_alert_rules = cast(bool, charm.config.get("forward_alert_rules"))
    loki_consumer = LokiPushApiConsumer(
        charm,
        relation_name="send-loki-logs",
        alert_rules_path=LOKI_RULES_DEST_PATH,
        forward_alert_rules=forward_alert_rules,
    )
    charm.__setattr__("loki_consumer", loki_consumer)
    # TODO: Luca: probably don't need this anymore
    loki_consumer.reload_alerts()
    return loki_consumer.loki_endpoints


def scrape_metrics(charm: CharmBase) -> List:
    """Integrate with other charms via the metrics-endpoint relation endpoint.

    This function must be called before `send_remote_write`, so that the charm
    can gather all the alerts from relation data before sending them all.

    Returns:
        A list consisting of all the static scrape configurations
        for each related `MetricsEndpointProvider` that has specified
        its scrape targets.
    """
    metrics_consumer = MetricsEndpointConsumer(charm)
    charm.__setattr__("metrics_consumer", metrics_consumer)
    forward_alert_rules = cast(bool, charm.config.get("forward_alert_rules"))
    charm_root = charm.charm_dir.absolute()

    shutil.copytree(
        charm_root.joinpath(*METRICS_RULES_SRC_PATH.split("/")),
        charm_root.joinpath(*METRICS_RULES_DEST_PATH.split("/")),
        dirs_exist_ok=True,
    )
    _add_alerts(
        alerts=metrics_consumer.alerts if forward_alert_rules else {},
        dest_path=charm_root.joinpath(*METRICS_RULES_DEST_PATH.split("/")),
    )
    return metrics_consumer.jobs()


def send_remote_write(charm: CharmBase) -> List[Dict[str, str]]:
    """Integrate via send-remote-write to send metrics to a Prometheus-compatible endpoint.

    Returns:
        A list of dictionaries where each dictionary provides information about
        a single remote_write endpoint.
    """
    charm_root = charm.charm_dir.absolute()
    remote_write = PrometheusRemoteWriteConsumer(
        charm,
        alert_rules_path=charm_root.joinpath(METRICS_RULES_DEST_PATH).as_posix(),
    )
    charm.__setattr__("remote_write", remote_write)
    # TODO: add alerts from remote write
    # https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/37277
    # TODO: Luca: probably don't need this anymore
    remote_write.reload_alerts()
    return remote_write.endpoints


def _get_tracing_receiver_url(protocol: ReceiverProtocol, tls_enabled: bool) -> str:
    """Build the endpoint URL for a tracing receiver.

    Args:
        protocol: The tracing protocol to build the URL for.
        tls_enabled: Whether to use HTTPS (True) or HTTP (False) for the URL.


    Returns:
        str: The complete URL for the tracing receiver endpoint.

    Note:
        The method assumes the receiver is in the same model since the charm
        doesn't have ingress support. The FQDN is used as the hostname.
    """
    scheme = "http"
    if tls_enabled:
        scheme = "https"

    # The correct transport protocol is specified in the tracing library, and it's always
    # either http or grpc.
    if receiver_protocol_to_transport_protocol[protocol] == TransportProtocolType.grpc:
        return f"{socket.getfqdn()}:{Port.otlp_grpc.value}"
    return f"{scheme}://{socket.getfqdn()}:{Port.otlp_http.value}"


def receive_traces(charm: CharmBase, tls: bool) -> Set:
    """Integrate with other charms via the receive-traces relation endpoint.

    Returns:
        All receiver protocols that have been requested.
    """
    tracing_provider = TracingEndpointProvider(charm, relation_name="receive-traces")
    charm.__setattr__("tracing_provider", tracing_provider)
    # Enable traces ingestion with TracingEndpointProvider, i.e. configure the receivers
    requested_tracing_protocols = set(tracing_provider.requested_protocols()).union(
        {
            receiver
            for receiver in get_args(ReceiverProtocol)
            if charm.config.get(f"always_enable_{receiver}")
        }
    )
    # Send tracing receivers over relation data to charms sending traces to otel collector
    if charm.unit.is_leader():
        tracing_provider.publish_receivers(
            tuple(
                (
                    protocol,
                    _get_tracing_receiver_url(
                        protocol=protocol,
                        tls_enabled=tls,
                    ),
                )
                for protocol in requested_tracing_protocols
            )
        )
    return requested_tracing_protocols


def send_traces(charm: CharmBase) -> Optional[str]:
    """Integrate with Tempo via the send-traces relation endpoint.

    Returns:
        The tracing OTLP HTTP endpoint if the Provider is ready, None otherwise
    """
    # Enable pushing traces to a backend (i.e. Tempo) with TracingEndpointRequirer, i.e. configure the exporters
    tracing_requirer = TracingEndpointRequirer(
        charm,
        relation_name="send-traces",
        protocols=[
            "otlp_http",  # for charm traces
            "otlp_grpc",  # for forwarding workload traces
        ],
    )
    charm.__setattr__("tracing_requirer", tracing_requirer)
    if not tracing_requirer.is_ready():
        return None
    return tracing_requirer.get_endpoint("otlp_http")


def send_charm_traces(charm: CharmBase) -> Optional[str]:
    """Integrate with Tempo via the send-charm-traces relation endpoint.

    Returns:
        The tracing OTLP HTTP endpoint if the Provider is ready, None otherwise
    """
    charm_tracing_requirer = tracing.Tracing(
        charm,
        tracing_relation_name="send-charm-traces",
        ca_relation_name="receive-ca-cert",
    )
    charm.__setattr__("charm_tracing_requirer", charm_tracing_requirer)


def _get_dashboards(relations: List[Relation]) -> List[Dict[str, Any]]:
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


def _add_dashboards(dashboards: List[Dict[str, str]], dest_path: Path):
    """Save the dashboards to files in the specified destination folder.

    For K8s charms, dashboards are saved in the charm container.

    Args:
        dashboards: List of dictionaries representing a dashboard, with the following format:
            {
                "charm": charm_name,
                "relation_id": data.relation_id,
                "content": content,
                "title": title,
            }
        dest_path: Path to the folder where dashboards will be saved
    """
    dest_path.mkdir(parents=True, exist_ok=True)
    for dash in dashboards:
        # Build dashboard custom filename
        charm_name = dash.get("charm", "charm-name")
        rel_id = dash.get("relation_id", "rel_id")
        title = dash.get("title", "").replace(" ", "_").replace("/", "_").lower()
        filename = f"juju_{title}-{charm_name}-{rel_id}.json"
        with open(Path(dest_path, filename), mode="w", encoding="utf-8") as f:
            f.write(json.dumps(dash["content"]))
            logger.debug("updated dashboard file %s", f.name)


def forward_dashboards(charm: CharmBase):
    """Instantiate the GrafanaDashboardProvider and update the dashboards in the relation databag.

    First, dashboards from relations (including those bundled with Otelcol) and save them to disk.
    Then, update the relation databag with these dashboards for Grafana.
    """
    src_path = charm.charm_dir.absolute().joinpath(*DASHBOARDS_SRC_PATH.split("/"))
    dest_path = charm.charm_dir.absolute().joinpath(*DASHBOARDS_DEST_PATH.split("/"))

    # The leader copies dashboards from relations and save them to disk."""
    if not charm.unit.is_leader():
        return

    shutil.copytree(src_path, dest_path, dirs_exist_ok=True)
    _add_dashboards(
        dashboards=_get_dashboards(charm.model.relations["grafana-dashboards-consumer"]),
        dest_path=dest_path,
    )

    grafana_dashboards_provider = GrafanaDashboardProvider(
        charm,
        relation_name="grafana-dashboards-provider",
        dashboards_path=dest_path.as_posix(),
    )
    charm.__setattr__("grafana_dashboards_provider", grafana_dashboards_provider)
    # Scan the built-in dashboards and update relations with changes
    grafana_dashboards_provider.reload_dashboards()

    # TODO: Do we need to implement dashboard status changed logic?
    #   This propagates Grafana's errors to the charm which provided the dashboard
    # grafana_dashboards_provider._reinitialize_dashboard_data(inject_dropdowns=False)


# TODO: Luca: move this into the GrafanCloudIntegrator library
@dataclass
class CloudIntegratorData:
    """Wrapper around the data returned by GrafanaCloudIntegrator."""

    username: Optional[str]
    password: Optional[str]
    prometheus_url: Optional[str]
    loki_url: Optional[str]
    tempo_url: Optional[str]


def cloud_integrator(charm: CharmBase) -> CloudIntegratorData:
    """Integrate with a GrafanaCloudIntegrator charm via the cloud-config relation endpoint."""
    # We're intentionally not getting the CA cert from Grafana Cloud Integrator;
    # we decided that we should only get certs from receive-ca-cert.
    cloud_integrator = GrafanaCloudConfigRequirer(charm, relation_name="cloud-config")
    charm.__setattr__("cloud_integrator", cloud_integrator)
    username, password = (
        (cloud_integrator.credentials.username, cloud_integrator.credentials.password)
        if cloud_integrator.credentials
        else (None, None)
    )
    return CloudIntegratorData(
        username=username,
        password=password,
        prometheus_url=cloud_integrator.prometheus_url
        if cloud_integrator.prometheus_ready
        else None,
        loki_url=cloud_integrator.loki_url if cloud_integrator.loki_ready else None,
        tempo_url=cloud_integrator.tempo_url if cloud_integrator.tempo_ready else None,
    )


def receive_server_cert(
    charm: CharmBase,
    server_cert_path: PathProtocol,
    private_key_path: PathProtocol,
) -> str:
    """Integrate to receive a certificate and private key for the charm from relation data.

    The certificate and key are obtained via the tls_certificates(v4) library,
    and pushed to the workload container.

    Returns:
        Hash of server cert and private key, to be used as reload trigger if it changed.
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

    # Request a certificate
    # TLSCertificatesRequiresV4 is garbage collected, see the `_reconcile`` docstring for more
    # details. So we need to call _configure() ourselves:
    certificates._configure(None)  # type: ignore[reportArgumentType]

    provider_certificate, private_key = certificates.get_assigned_certificate(
        certificate_request=csr_attrs
    )
    # If there no certificate or private key coming from relation data, cleanup
    # the existing ones. This typically happens after a "revoked" or "renewal"
    # event.
    if not provider_certificate or not private_key:
        if not provider_certificate:
            logger.debug("TLS disabled: Certificate is not available")
        if not private_key:
            logger.debug("TLS disabled: Private key is not available")

        server_cert_path.unlink() if server_cert_path.exists() else None
        private_key_path.unlink() if private_key_path.exists() else None
        return sha256("")

    # Push the certificate and key to disk
    server_cert_path.parent.mkdir(parents=True, exist_ok=True)
    server_cert_path.write_text(str(provider_certificate.certificate))
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key_path.write_text(str(private_key))

    logger.info("Certificate and private key have been pushed to disk")

    return sha256(str(provider_certificate.certificate) + str(private_key))


def receive_ca_cert(
    charm: CharmBase, recv_ca_cert_folder_path: PathProtocol, refresh_certs: Callable
) -> str:
    """Reconcile the certificates from the `receive-ca-cert` relation.

    This function saves the certificates to disk, and runs
    `update-ca-certificates` to trust them.

    Returns:
        Hash of the certificates to trust, to be used as reload trigger when changed.
    """
    # Obtain certs from relation data
    certificate_transfer = CertificateTransferRequires(charm, "receive-ca-cert")
    charm.__setattr__("certificate_transfer", certificate_transfer)
    ca_certs = certificate_transfer.get_all_certificates()

    # Clean-up previously existing certs
    if recv_ca_cert_folder_path.exists():
        for cert in recv_ca_cert_folder_path.glob("*.crt"):
            cert.unlink()

    # Write current certs
    if ca_certs:
        recv_ca_cert_folder_path.mkdir(parents=True, exist_ok=True)
        for i, cert in enumerate(ca_certs):
            cert_path = recv_ca_cert_folder_path.joinpath(f"{i}.crt")
            cert_path.write_text(cert)

    # Refresh system certs
    refresh_certs()

    # A hot-reload doesn't pick up new system certs - need to restart the service
    return sha256(yaml.safe_dump(ca_certs))
