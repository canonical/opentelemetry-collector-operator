#!/usr/bin/env python3
# Copyright 2025 jose
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk
"""A Juju charm for OpenTelemetry Collector on machines."""

import json
import logging
import socket
import ops
import os
import shutil
import subprocess
from collections import namedtuple
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union, cast, get_args
from ops import CharmBase
from ops.model import ActiveStatus, MaintenanceStatus, WaitingStatus, Relation
from constants import (
    RECV_CA_CERT_FOLDER_PATH,
    CONFIG_HASH_PATH,
    CONFIG_PATH,
    SERVER_CERT_PATH,
    SERVER_CERT_PRIVATE_KEY_PATH,
)
import yaml
from charms.grafana_agent.v0.cos_agent import COSAgentRequirer, ReceiverProtocol
from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.loki_k8s.v1.loki_push_api import LokiPushApiConsumer, LokiPushApiProvider
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
)
from charms.tempo_coordinator_k8s.v0.tracing import (
    ReceiverProtocol,
    TracingEndpointProvider,
    TransportProtocolType,
    receiver_protocol_to_transport_protocol,
)
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateRequestAttributes,
    Mode,
    PrivateKey,
    TLSCertificatesRequiresV4,
)
from charms.operator_libs_linux.v2 import snap  # type: ignore
from cosl import JujuTopology, LZMABase64
from snap_management import SnapSpecError, SnapInstallError, SnapServiceError, install_snap, node_exporter_snap_name, opentelemetry_collector_snap_name

from config import PORTS, Config, sha256, tail_sampling_config

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)

_FsType = str
_MountOption = str
_MountOptions = List[_MountOption]

PathMapping = namedtuple("PathMapping", ["src", "dest"])
VALID_LOG_LEVELS = ["info", "debug", "warning", "error", "critical"]

SNAPS = [opentelemetry_collector_snap_name, node_exporter_snap_name]

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


def receive_ca_certs(charm: CharmBase) -> str:
    """Returns a sentinel (hash of all certs), to determine whether a restart is required."""
    # Obtain certs from relation data
    certificate_transfer = CertificateTransferRequires(charm, "receive-ca-cert")
    ca_certs = certificate_transfer.get_all_certificates()

    # Clean-up previously existing certs
    if os.path.exists(RECV_CA_CERT_FOLDER_PATH):
        shutil.rmtree(RECV_CA_CERT_FOLDER_PATH)
        os.makedirs(RECV_CA_CERT_FOLDER_PATH, exist_ok=True)

    # Write current certs
    for i, cert in enumerate(ca_certs):
        with open(os.path.join(RECV_CA_CERT_FOLDER_PATH, f"{i}.crt"), "w") as f:
            f.write(cert)

    # Refresh system certs
    subprocess.run(["update-ca-certificates", "--fresh"])

    # A hot-reload doesn't pick up new system certs - need to restart the service
    return sha256(yaml.safe_dump(ca_certs))


def server_cert(charm: CharmBase) -> str:
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
        if os.path.exists(SERVER_CERT_PATH):
            os.remove(SERVER_CERT_PATH)
        if os.path.exists(SERVER_CERT_PRIVATE_KEY_PATH):
            os.remove(SERVER_CERT_PRIVATE_KEY_PATH)
        return sha256("")

    existing_cert = (
        open(SERVER_CERT_PATH, "r").read()
        if os.path.exists(SERVER_CERT_PATH)
        else ""
    )
    if not existing_cert or provider_certificate.certificate != Certificate.from_string(
        existing_cert
    ):
        os.makedirs(os.path.dirname(SERVER_CERT_PATH), exist_ok=True)
        with open(SERVER_CERT_PATH, "w") as f:
            f.write(str(provider_certificate.certificate))
        logger.info("Pushed certificate pushed to workload")

    existing_key = (
        open(SERVER_CERT_PRIVATE_KEY_PATH, "r").read()
        if os.path.exists(SERVER_CERT_PRIVATE_KEY_PATH)
        else ""
    )
    if not existing_key or private_key != PrivateKey.from_string(existing_key):
        os.makedirs(os.path.dirname(SERVER_CERT_PRIVATE_KEY_PATH), exist_ok=True)
        with open(SERVER_CERT_PRIVATE_KEY_PATH, "w") as f:
            f.write(str(private_key))
        logger.info("Pushed private key to workload")

    return sha256(str(private_key) + str(provider_certificate.certificate))


def is_server_cert_on_disk() -> bool:
    """Return True if the server cert and private key are present in the machine."""
    return (
        os.path.exists(SERVER_CERT_PATH)
        and os.path.isfile(SERVER_CERT_PATH)
        and os.path.exists(SERVER_CERT_PRIVATE_KEY_PATH)
        and os.path.isfile(SERVER_CERT_PRIVATE_KEY_PATH)
    )


@dataclass
class _SnapFstabEntry:
    """Representation of an individual fstab entry for snap plugs."""

    source: str
    target: str
    fstype: Union[_FsType, None]
    options: _MountOptions
    dump: int
    fsck: int

    owner: str = field(init=False)
    endpoint_source: str = field(init=False)
    relative_target: str = field(init=False)

    def __post_init__(self):
        """Populate with calculated values at runtime."""
        self.owner = re.sub(
            r"^(.*?)?/snap/(?P<owner>([A-Za-z0-9_-])+)/.*$", r"\g<owner>", self.source
        )
        self.endpoint_source = re.sub(
            r"^(.*?)?/snap/([A-Za-z0-9_-])+/(?P<path>.*$)", r"\g<path>", self.source
        )
        self.relative_target = re.sub(
            r"^(.*?)?/snap/grafana-agent/\d+/shared-logs+(?P<path>/.*$)", r"\g<path>", self.target
        )

@dataclass
class SnapFstab:
    """Build a small representation/wrapper for snap fstab files."""

    fstab_file: Union[Path, str]
    entries: List[_SnapFstabEntry] = field(init=False)

    def __post_init__(self):
        """Populate with calculated values at runtime."""
        self.fstab_file = (
            self.fstab_file if isinstance(self.fstab_file, Path) else Path(self.fstab_file)
        )
        if not self.fstab_file.exists():
            self.entries = []
            return

        entries = []
        for line in self.fstab_file.read_text().split("\n"):
            if not line.strip():
                # skip whitespace-only lines
                continue
            raw_entry = line.split()
            fields = {
                "source": raw_entry[0],
                "target": raw_entry[1],
                "fstype": None if raw_entry[2] == "none" else raw_entry[2],
                "options": raw_entry[3].split(","),
                "dump": int(raw_entry[4]),
                "fsck": int(raw_entry[5]),
            }
            entry = _SnapFstabEntry(**fields)
            entries.append(entry)

        self.entries = entries

    def entry(self, owner: str, endpoint_name: Optional[str]) -> Optional[_SnapFstabEntry]:
        """Find and return a specific entry if it exists."""
        entries = [e for e in self.entries if e.owner == owner]

        if len(entries) > 1 and endpoint_name:
            # If there's more than one entry, the endpoint name may not directly map to
            # the source *or* path. charmed-kafka uses 'logs' as the plug name, and maps
            # .../common/logs to .../log inside Grafana Agent
            #
            # The only meaningful scenario in which this could happen (multiple fstab
            # entries with the same snap "owning" the originating path) is if a snap provides
            # multiple paths as part of the same plug.
            #
            # In this case, for a cheap comparison (rather than implementing some recursive
            # LCS just for this), convert all possible endpoint sources into a list of unique
            # characters, as well as the endpoint name, and build a sequence of entries with
            # a value that's the length of the intersection, the pick the first one i.e. the one
            # with the largest intersection.
            ordered_entries = sorted(
                entries,
                # descending order
                reverse=True,
                # size of the character-level similarity of the two strings
                key=lambda e: len(set(endpoint_name) & set(e.endpoint_source)),
            )
            return ordered_entries[0]

        if len(entries) > 1 or not entries:
            logger.debug(
                "Ambiguous or unknown mountpoint for snap %s at slot %s, not relabeling.",
                owner,
                endpoint_name,
            )
            return None

        return entries[0]


class OpentelemetryCollectorOperatorCharm(ops.CharmBase):
    """Charm the service."""

    _metrics_rules_src_path = "src/prometheus_alert_rules"
    _metrics_rules_dest_path = "prometheus_alert_rules"
    _loki_rules_src_path = "src/loki_alert_rules"
    _loki_rules_dest_path = "loki_alert_rules"

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self.topology = JujuTopology.from_charm(self)
        self.otel_config = Config.default_config()
        self.restart_sentinel = ""
        self._reconcile()

    def _reconcile(self):
        """Recreate the world state for the charm.

        With this pattern, we do not hold instances as attributes. When using events-based
        libraries, these instances will be garbage collected:
        > Reference to ops.Object at path OpenTelemetryCollectorK8sCharm/INSTANCE has been
        > garbage collected between when the charm was initialised and when the event was emitted.
        """
        self._install()
        self._remove()

        charm_root = self.charm_dir.absolute()
        restart_sentinel: str = ""
        forward_alert_rules = cast(bool, self.config["forward_alert_rules"])
        insecure_skip_verify = cast(bool, self.model.config.get("tls_insecure_skip_verify"))

        # TLS: receive-ca-cert
        restart_sentinel += receive_ca_certs(self)

        # TLS: server cert
        restart_sentinel += server_cert(self)
        if server_cert_on_disk := is_server_cert_on_disk():
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
            scheme="https" if is_server_cert_on_disk() else "http",
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

        # Enable traces ingestion with TracingEndpointProvider, i.e. configure the receivers
        tracing_provider = TracingEndpointProvider(self, relation_name="receive-traces")
        requested_tracing_protocols = set(tracing_provider.requested_protocols()).union(
            {
                receiver
                for receiver in get_args(ReceiverProtocol)
                if self.config.get(f"always_enable_{receiver}")
            }
        )
        # Send tracing receivers over relation data to charms sending traces to otel collector
        if self.unit.is_leader():
            tracing_provider.publish_receivers(
                tuple(
                    (
                        protocol,
                        self._get_tracing_receiver_url(
                            protocol=protocol,
                            tls_enabled=is_server_cert_on_disk(),
                        ),
                    )
                    for protocol in requested_tracing_protocols
                )
            )
        self._add_traces_ingestion(requested_tracing_protocols)

        # TODO: add tail sampling processor (use otelcol-contrib distribution?) and then
        # uncomment tracing-related setup.

        # Add default processors to traces
        # self._add_traces_processing()
        # # Enable pushing traces to a backend (i.e. Tempo) with TracingEndpointRequirer, i.e. configure the exporters
        # tracing_requirer = TracingEndpointRequirer(
        #     self,
        #     relation_name="send-traces",
        #     protocols=[
        #         "otlp_http",  # for charm traces
        #         "otlp_grpc",  # for forwarding workload traces
        #     ],
        # )
        # if tracing_requirer.is_ready():
        #     if tracing_otlp_http_endpoint := tracing_requirer.get_endpoint("otlp_http"):
        #         self.otel_config.add_exporter(
        #             name="otlphttp/tempo",
        #             exporter_config={"endpoint": tracing_otlp_http_endpoint},
        #             pipelines=["traces"],
        #         )

        # # Enable forwarding telemetry with GrafanaCloudIntegrator
        # cloud_integrator = GrafanaCloudConfigRequirer(self, relation_name="cloud-config")
        # # We're intentionally not getting the CA cert from Grafana Cloud Integrator;
        # # we decided that we should only get certs from receive-ca-cert.
        # self._add_cloud_integrator(
        #     credentials=cloud_integrator.credentials,
        #     prometheus_url=cloud_integrator.prometheus_url
        #     if cloud_integrator.prometheus_ready
        #     else None,
        #     loki_url=cloud_integrator.loki_url if cloud_integrator.loki_ready else None,
        #     tempo_url=cloud_integrator.tempo_url if cloud_integrator.tempo_ready else None,
        #     insecure_skip_verify=insecure_skip_verify,
        # )

        # Add COS agent
        cos_agent = COSAgentRequirer(self)
        # Add COS agent metrics scrape jobs and add the receiver in the metrics pipeline
        self.otel_config.add_receiver(
            "prometheus/cos-agent",
            {"config": {"scrape_configs": cos_agent.metrics_jobs}},
            pipelines=["metrics"],
        )
        # Add COS agent alert rules
        _aggregate_alerts(cos_agent.metrics_alerts, metrics_rules_paths, forward_alert_rules)
        # TODO: Add COS agent logs
        # Connect logging snap endpoints
        for plug in cos_agent.snap_log_endpoints:
            try:
                self.snap(opentelemetry_collector_snap_name).connect("logs", service=plug.owner, slot=plug.name)
            except snap.SnapError as e:
                logger.error(f"error connecting plug {plug} to grafana-agent:logs")
                logger.error(e.message)
        # Add COS agent loki log rules
        endpoint_owners = {
            endpoint.owner: {
                "juju_application": topology.application,
                "juju_unit": topology.unit,
            }
            for endpoint, topology in cos_agent.snap_log_endpoints_with_topology
        }
        otelcol_fstab = SnapFstab(Path("/var/lib/snapd/mount/snap.grafana-agent.fstab"))
        for fstab_entry in otelcol_fstab.entries:
            if fstab_entry.owner not in endpoint_owners.keys():
                continue

            # TODO: check if any of this logging logic makes sense
            self.otel_config.add_receiver(
                f"filelog/{fstab_entry.owner}",  # maybe???
                {
                    "include": [
                        f"{fstab_entry.target}/**"
                        if fstab_entry
                        else "/snap/opentelemetry-collector/current/shared-logs/**"
                    ],
                    "start_at": "beginning",
                    "operators": {},
                    # operators:
                    #   - type: drop
                    #     expression: ".*file is a directory.*"
                    #   - type: structured_metadata
                    #     metadata:
                    #       filename: filename
                    #   - type: labeldrop
                    #     labels: ["filename"]
                },
            )
        _aggregate_alerts(cos_agent.logs_alerts, loki_rules_paths, forward_alert_rules)
        # TODO: Add COS agent dashboards

        # Add custom processors from Juju config
        self._add_custom_processors()

        # Push the config and Push the config and deploy/update
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            f.write(self.otel_config.yaml)
        restart_sentinel += self.otel_config.hash

        if bool(self.model.relations.get("receive-server-cert")) and not server_cert_on_disk:
            # A tls relation to a CA was formed, but we didn't get the cert yet.
            self._stop_snap(opentelemetry_collector_snap_name)
            self.unit.status = WaitingStatus("Waiting for cert")
        else:
            # Only restart when the sentinel is changed, following the k8s charm's behaviour.
            import time
            time.sleep(5)

            previous_hash = ""
            if os.path.exists(CONFIG_HASH_PATH):
                with open(CONFIG_HASH_PATH, "r") as f:
                    previous_hash = f.read().strip()
            if previous_hash != restart_sentinel:
                self._restart_snap(opentelemetry_collector_snap_name)
                with open(CONFIG_HASH_PATH, "w") as f:
                    f.write(restart_sentinel)
            self.unit.status = ActiveStatus()

    def _install(self) -> None:
        if self.hook != "install":
            return

        for snap_package in SNAPS:
            self._install_snap(snap_package)
            self._start_snap(snap_package)

    def _remove(self) -> None:
        if self.hook != "remove":
            return

        for snap_package in SNAPS:
            self._remove_snap(snap_package)

    def _install_snap(self, snap_name: str) -> None:
        self.unit.status = MaintenanceStatus(f"Installing {snap_name} snap")
        try:
            install_snap(snap_name)
        except (snap.SnapError, SnapSpecError) as e:
            raise SnapInstallError(f"Failed to install {snap_name}") from e

    def _remove_snap(self, snap_name: str) -> None:
        self.unit.status = MaintenanceStatus(f"Uninstalling {snap_name} snap")
        try:
            self.snap(snap_name).ensure(state=snap.SnapState.Absent)
        except (snap.SnapError, SnapSpecError) as e:
            raise SnapInstallError(f"Failed to uninstall {snap_name}") from e

    def _start_snap(self, snap_name: str) -> None:
        import time
        time.sleep(5)
        self.unit.status = MaintenanceStatus(f"Starting {snap_name} snap")

        try:
            self.snap(snap_name).start(enable=True)
        except snap.SnapError as e:
            raise SnapServiceError(f"Failed to start {snap_name}") from e

    def _stop_snap(self, snap_name: str) -> None:
        import time
        time.sleep(5)
        self.unit.status = MaintenanceStatus(f"Stopping {snap_name} snap")

        try:
            self.snap(snap_name).stop()
        except snap.SnapError as e:
            raise SnapServiceError(f"Failed to stop {snap_name}") from e

    def _restart_snap(self, snap_name: str) -> None:
        import time
        time.sleep(5)
        self.unit.status = MaintenanceStatus(f"Restarting {snap_name} snap")

        try:
            self.snap(snap_name).restart()
        except snap.SnapError as e:
            raise SnapServiceError(f"Failed to restart {snap_name}") from e

    def snap(self, snap_name: str):
        """Return the snap object for the given snap."""
        # This is handled in a property to avoid calls to snapd until they're necessary.
        return snap.SnapCache()[snap_name]

    @property
    def hook(self) -> str:
        """Return hook name."""
        return os.environ["JUJU_HOOK_NAME"]

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

    def _add_custom_processors(self):
        """Add custom processors from Juju config."""
        if processors_raw := cast(str, self.config.get("processors")):
            for processor_name, processor_config in yaml.safe_load(processors_raw).items():
                self.otel_config.add_processor(
                    name=processor_name,
                    processor_config=processor_config,
                    pipelines=["metrics", "logs", "traces"],
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

    def _add_traces_ingestion(self, requested_tracing_protocols: Set[ReceiverProtocol]):
        """Configure the tracing receivers for otel-collector to ingest traces.

        Args:
            requested_tracing_protocols: The tracing protocols for which to enable receivers.
        """
        # TODO: check with the team, do we keep this?
        # TODO: should we just add the otlp protocols always? probably yes
        if not requested_tracing_protocols:
            logger.warning("No tempo receivers enabled: otel-collector cannot ingest traces.")
            return

        if "zipkin" in requested_tracing_protocols:
            self.otel_config.add_receiver(
                name="zipkin",
                receiver_config={"endpoint": f"0.0.0.0:{PORTS.ZIPKIN}"},
                pipelines=["traces"],
            )
        if (
            "jaeger_grpc" in requested_tracing_protocols
            or "jaeger_thrift_http" in requested_tracing_protocols
        ):
            jaeger_config = {"protocols": {}}
            if "jaeger_grpc" in requested_tracing_protocols:
                jaeger_config["protocols"].update(
                    {"grpc": {"endpoint": f"0.0.0.0:{PORTS.JAEGER_GRPC}"}}
                )
            if "jaeger_thrift_http" in requested_tracing_protocols:
                jaeger_config["protocols"].update(
                    {"thrift_http": {"endpoint": f"0.0.0.0:{PORTS.JAEGER_THRIFT_HTTP}"}}
                )
            self.otel_config.add_receiver(
                name="jaeger", receiver_config=jaeger_config, pipelines=["traces"]
            )

    def _add_traces_processing(self):
        """Configure the processors for traces."""
        self.otel_config.add_processor(
            name="tail_sampling",
            processor_config=tail_sampling_config(
                tracing_sampling_rate_charm=cast(
                    float, self.config.get("tracing_sampling_rate_charm")
                ),
                tracing_sampling_rate_workload=cast(
                    float, self.config.get("tracing_sampling_rate_workload")
                ),
                tracing_sampling_rate_error=cast(
                    float, self.config.get("tracing_sampling_rate_error")
                ),
            ),
            pipelines=["traces"],
        )

    def _add_cloud_integrator(
        self,
        credentials: Optional[Credentials],
        prometheus_url: Optional[str],
        loki_url: Optional[str],
        tempo_url: Optional[str],
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
        if tempo_url:
            self.otel_config.add_exporter(
                name="otlphttp/cloud-integrator",
                exporter_config={
                    "endpoint": tempo_url,
                    "tls": {"insecure_skip_verify": insecure_skip_verify},
                    **exporter_auth_config,
                },
                pipelines=["traces"],
            )

    def _get_tracing_receiver_url(self, protocol: ReceiverProtocol, tls_enabled: bool):
        """Build the endpoint for the tracing receiver based on the protocol and TLS.

        Args:
            protocol: The ReceiverProtocol of a certain receiver (e.g., 'otlp_grpc', 'zipkin').
            tls_enabled: Flag indicating whether the endpoint should use 'https' or not.
        """
        scheme = "http"
        if tls_enabled:
            scheme = "https"

        # The correct transport protocol is specified in the tracing library, and it's always
        # either http or grpc.
        # We assume the user of the receiver is in-model, since this charm doesn't have ingress.
        if receiver_protocol_to_transport_protocol[protocol] == TransportProtocolType.grpc:
            return f"{socket.getfqdn()}:{PORTS.OTLP_GRPC}"
        return f"{scheme}://{socket.getfqdn()}:{PORTS.OTLP_HTTP}"


if __name__ == "__main__":  # pragma: nocover
    ops.main(OpentelemetryCollectorOperatorCharm)
