#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on machines."""

import logging
import os
from typing import cast

import ops
import subprocess
from charmlibs.pathops import LocalPath
from charms.grafana_agent.v0.cos_agent import COSAgentRequirer
from charms.operator_libs_linux.v2 import snap  # type: ignore
from cosl import JujuTopology
from ops import BlockedStatus, RelationChangedEvent
from ops.model import ActiveStatus, MaintenanceStatus, WaitingStatus

import integrations
from config_builder import Component, Port
from config_manager import ConfigManager
from constants import (
    CONFIG_PATH,
    DASHBOARDS_DEST_PATH,
    LOKI_RULES_DEST_PATH,
    METRICS_RULES_DEST_PATH,
    RECV_CA_CERT_FOLDER_PATH,
    SERVER_CERT_PATH,
    SERVER_CERT_PRIVATE_KEY_PATH,
)
from singleton_snap import SingletonSnapManager
from snap_management import (
    SnapInstallError,
    SnapMap,
    SnapServiceError,
    SnapSpecError,
    install_snap,
)
from snap_fstab import SnapFstab

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)
VALID_LOG_LEVELS = ["info", "debug", "warning", "error", "critical"]


def is_tls_ready() -> bool:
    """Return True if the server cert and private key are present on disk."""
    return (
        LocalPath(SERVER_CERT_PATH).exists() and LocalPath(SERVER_CERT_PRIVATE_KEY_PATH).exists()
    )


def refresh_certs():
    """Run `update-ca-certificates` to refresh the trusted system certs."""
    subprocess.run(["update-ca-certificates", "--fresh"], check=True)


def hook() -> str:
    """Return Juju hook name."""
    return os.environ["JUJU_HOOK_NAME"]


class OpenTelemetryCollectorCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        if hook() == "install":  # FIXME: install is not enough, we also need upgrade
            self._install()
        if hook() == "stop":
            self._stop()
        self._reconcile()

    def _reconcile(self):
        insecure_skip_verify = cast(bool, self.config.get("tls_insecure_skip_verify"))
        topology = JujuTopology.from_charm(self)
        integrations.cleanup()

        # Integrate with TLS relations
        receive_ca_certs_hash = integrations.receive_ca_cert(
            self,
            recv_ca_cert_folder_path=LocalPath(RECV_CA_CERT_FOLDER_PATH),
            refresh_certs=refresh_certs,
        )
        server_cert_hash = integrations.receive_server_cert(
            self,
            server_cert_path=LocalPath(SERVER_CERT_PATH),
            private_key_path=LocalPath(SERVER_CERT_PRIVATE_KEY_PATH),
        )

        # Create the config manager
        config_manager = ConfigManager(
            receiver_tls=is_tls_ready(),
            insecure_skip_verify=cast(bool, self.config.get("tls_insecure_skip_verify")),
        )

        # COS Agent setup
        cos_agent = COSAgentRequirer(self)
        cos_agent_relations = self.model.relations.get("cos-agent", [])
        # Trigger _on_relation_data_changed so that data from cos-agent is stored in the peer relation
        # TODO: instead of calling a private method, expose a public one in the COS Agent library
        for relation in cos_agent_relations:
            if not relation.units:
                continue
            changed_event = RelationChangedEvent(
                handle=self.handle,
                relation=relation,
                app=relation.app,
                unit=next(iter(relation.units)),  # subordinate relations only have one unit
            )
            cos_agent._on_relation_data_changed(changed_event)
        ## COS Agent metrics
        if cos_agent.metrics_jobs:
            config_manager.config.add_component(
                Component.receiver,
                name="prometheus/cos-agent",
                config={"config": {"scrape_configs": cos_agent.metrics_jobs}},
                pipelines=["metrics"],
            )
        integrations._add_alerts(
            alerts=cos_agent.metrics_alerts,
            dest_path=self.charm_dir.absolute().joinpath(METRICS_RULES_DEST_PATH),
        )
        ## COS Agent logs
        ### Connect logging snap endpoints
        for plug in cos_agent.snap_log_endpoints:
            try:
                self.snap("opentelemetry-collector").connect(
                    "logs", service=plug.owner, slot=plug.name
                )
            except snap.SnapError as e:
                logger.error(f"error connecting plug {plug} to opentelemetry-collector:logs")
                logger.error(e.message)
                # TODO: should we fail loudly and error?
        endpoint_owners = {
            endpoint.owner: {
                "juju_application": topology.application,
                "juju_unit": topology.unit,
            }
            for endpoint, topology in cos_agent.snap_log_endpoints_with_topology
        }
        otelcol_fstab = SnapFstab(
            LocalPath("/var/lib/snapd/mount/snap.opentelemetry-collector.fstab")
        )
        for fstab_entry in otelcol_fstab.entries:
            if fstab_entry.owner not in endpoint_owners.keys():
                continue

            config_manager.config.add_component(
                component=Component.receiver,
                name=f"filelog/{fstab_entry.owner}-{fstab_entry.relative_target}",
                config={
                    "include": [
                        f"{fstab_entry.target}/**"
                        if fstab_entry
                        else "/snap/opentelemetry-collector/current/shared-logs/**"
                    ],
                    "start_at": "beginning",
                    "include_file_name": True,
                    "include_file_path": True,
                    "attributes": {
                        "job": f"{fstab_entry.owner}-{fstab_entry.relative_target}",
                        "juju_application": endpoint_owners[fstab_entry.owner]["juju_application"],
                        "juju_unit": endpoint_owners[fstab_entry.owner]["juju_unit"],
                        "juju_charm": topology.charm_name,
                        "juju_model": topology.model,
                        "juju_model_uuid": topology.model_uuid,
                        "snap_name": fstab_entry.owner,
                    },
                    "operators": [
                        # Add file name to 'filename' label
                        {
                            "type": "copy",
                            "from": 'attributes["log.file.path"]',
                            "to": 'attributes["filename"]',
                        },
                        # Add file path to `path` label
                        {
                            "type": "add",
                            "field": "attributes.path",
                            "value": 'EXPR(let lashSlashIndex = lastIndexOf(attributes["log.file.path"], "/"); attributes["log.file.path"][:lastSlashIndex])',
                        },
                    ],
                },
                pipelines=["logs"],
            )
        integrations._add_alerts(
            alerts=cos_agent.logs_alerts,
            dest_path=self.charm_dir.absolute().joinpath(LOKI_RULES_DEST_PATH),
        )

        # Logs setup
        integrations.receive_loki_logs(self, tls=is_tls_ready())
        loki_endpoints = integrations.send_loki_logs(self)
        if self._has_incoming_logs_relation:
            config_manager.add_log_ingestion()
        config_manager.add_log_forwarding(loki_endpoints, insecure_skip_verify)

        # Metrics setup
        config_manager.add_self_scrape(
            identifier=topology.identifier,
            labels={
                "instance": f"{topology.identifier}_{topology.unit}",
                "juju_charm": topology.charm_name,
                "juju_model": topology.model,
                "juju_model_uuid": topology.model_uuid,
                "juju_application": topology.application,
                "juju_unit": topology.unit,
            },
        )
        # For now, the only incoming and outgoing metrics relations are remote-write/scrape
        metrics_consumer_jobs = integrations.scrape_metrics(self)
        config_manager.add_prometheus_scrape_jobs(metrics_consumer_jobs)
        if self._has_outgoing_metrics_relation:
            # This is conditional because otherwise remote_write.endpoints causes error on relation-broken
            remote_write_endpoints = integrations.send_remote_write(self)
            config_manager.add_remote_write(remote_write_endpoints)

        # Tracing setup
        requested_tracing_protocols = integrations.receive_traces(self, tls=is_tls_ready())
        config_manager.add_traces_ingestion(requested_tracing_protocols)
        # TODO: Luca: uncomment this as soon as we have tail sampling in the snap
        # Add default processors to traces
        # config_manager.add_traces_processing(
        #     sampling_rate_charm=cast(bool, self.config.get("tracing_sampling_rate_charm")),
        #     sampling_rate_workload=cast(bool, self.config.get("tracing_sampling_rate_workload")),
        #     sampling_rate_error=cast(bool, self.config.get("tracing_sampling_rate_error")),
        # )
        tracing_otlp_http_endpoint = integrations.send_traces(self)
        if tracing_otlp_http_endpoint:
            config_manager.add_traces_forwarding(tracing_otlp_http_endpoint)

        # Dashboards setup
        ## COS Agent dashboards
        integrations._add_dashboards(
            dashboards=cos_agent.dashboards,
            dest_path=LocalPath(self.charm_dir.absolute().joinpath(DASHBOARDS_DEST_PATH)),
        )
        integrations.forward_dashboards(self)

        # GrafanaCloudIntegrator setup
        cloud_integrator_data = integrations.cloud_integrator(self)
        config_manager.add_cloud_integrator(
            username=cloud_integrator_data.username,
            password=cloud_integrator_data.password,
            prometheus_url=cloud_integrator_data.prometheus_url,
            loki_url=cloud_integrator_data.loki_url,
            tempo_url=cloud_integrator_data.tempo_url,
        )

        # Add custom processors from Juju config
        if custom_processors := cast(str, self.config.get("processors")):
            config_manager.add_custom_processors(custom_processors)

        # Push the config and Push the config and deploy/update
        config_path = LocalPath(CONFIG_PATH)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(config_manager.config.build())

        # TODO: Conditionally open ports based on the otelcol config file rather than opening all ports
        # Append port 9100 for Node Exporter # TODO: is this needed?
        self.unit.set_ports(*[port.value for port in Port])

        # If the config file or any cert has changed, a change in the hash
        # will trigger a restart
        hash_file = LocalPath("/opt/otelcol_reload")
        old_hash = ""
        if hash_file.exists():
            old_hash = hash_file.read_text()
        current_hash = ",".join(
            [config_manager.config.hash, receive_ca_certs_hash, server_cert_hash]
        )
        if current_hash != old_hash:
            for snap_name in SnapMap.snaps():
                self.snap(snap_name).restart()

        # Set status
        if self._has_server_cert_relation and not is_tls_ready():
            # A tls relation to a CA was formed, but we didn't get the cert yet.
            self.snap("opentelemetry-collector").stop()
            self.unit.status = WaitingStatus("CSR sent; otelcol down while waiting for a cert")
            return
        # Start the otelcol snap in case it was stopped while waiting for certificates
        self.snap("opentelemetry-collector").start()

        for snap_name in SnapMap.snaps():
            snap_revision = SnapMap.get_revision(snap_name)
            installed_revision = max(SingletonSnapManager.get_revisions(snap_name))
            if snap_revision != installed_revision:
                logger.error(
                    f"Mismatching snap revisions for {snap_name}. "
                    f"The charm requested rev{snap_revision}, but a different app installed "
                    f"rev{installed_revision}. When multiple collector units require different "
                    "snap revisions, the newest one will be installed. "
                    "Please refresh this charm to a revision that uses the same snap as your "
                    "most-recently updated collector."
                )
                self.unit.status = BlockedStatus(f"Mismatching snap revisions for {snap_name}")
                return

        self.unit.status = ActiveStatus()

    def _install(self) -> None:
        manager = SingletonSnapManager(self.unit.name)

        for snap_name in SnapMap.snaps():
            snap_revision = SnapMap.get_revision(snap_name)
            manager.register(snap_name, snap_revision)
            if snap_revision >= max(manager.get_revisions(snap_name)):
                # Install the snap
                self.unit.status = MaintenanceStatus(f"Installing {snap_name} snap")
                install_snap(snap_name)
                # Start the snap
                self.unit.status = MaintenanceStatus(f"Starting {snap_name} snap")
                try:
                    self.snap(snap_name).start(enable=True)
                except snap.SnapError as e:
                    raise SnapServiceError(f"Failed to start {snap_name}") from e

            # Merge configurations under a directory into one,
            # and write it to the default otelcol config file.
            # This is a placeholder for actual configuration merging logic.
            # For example:
            #
            # content = merge_config()
            # with open('etc/otelcol/config.yaml', 'w') as f:
            #     f.write(content)
            #     f.flush()
            pass

    def _stop(self) -> None:
        manager = SingletonSnapManager(self.unit.name)
        for snap_name in SnapMap.snaps():
            snap_revision = SnapMap.get_revision(snap_name)
            manager.unregister(snap_name, snap_revision)
            if not manager.is_used_by_other_units(snap_name):
                # Remove the snap
                self.unit.status = MaintenanceStatus(f"Uninstalling {snap_name} snap")
                try:
                    self.snap(snap_name).ensure(state=snap.SnapState.Absent)
                except (snap.SnapError, SnapSpecError) as e:
                    raise SnapInstallError(f"Failed to uninstall {snap_name}") from e
            # TODO: Luca if the snap is used by other units, we should probably `ensure`
            # that the max_revision is installed instead.

    def snap(self, snap_name: str) -> snap.Snap:
        """Return the snap object for the given snap.

        This method provides lazy initialization of snap objects, avoiding unnecessary
        calls to snapd until they're actually needed.
        """
        return snap.SnapCache()[snap_name]

    @property
    def _has_incoming_logs_relation(self) -> bool:
        return any(self.model.relations.get("receive-loki-logs", []))

    @property
    def _has_outgoing_metrics_relation(self) -> bool:
        return any(self.model.relations.get("send-remote-write", []))

    @property
    def _has_server_cert_relation(self) -> bool:
        return any(self.model.relations.get("receive-server-cert", []))


if __name__ == "__main__":  # pragma: nocover
    ops.main(OpenTelemetryCollectorCharm)
