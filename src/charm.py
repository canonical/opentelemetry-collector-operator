#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""A Juju charm for OpenTelemetry Collector on machines."""

import logging
import os
import re
import shutil
import socket
import subprocess
from typing import Any, Dict, List, Mapping, Optional, cast

from cosl.reconciler import observe_events, all_events
import ops
from charmlibs.pathops import LocalPath
from charms.grafana_agent.v0.cos_agent import COSAgentRequirer
from charms.operator_libs_linux.v2 import snap  # type: ignore
from cosl import JujuTopology, MandatoryRelationPairs
from ops import BlockedStatus, CharmBase, RelationChangedEvent
from ops.model import ActiveStatus, MaintenanceStatus, WaitingStatus
from tenacity import retry, stop_after_attempt, wait_fixed

import integrations
from config_builder import Component
from config_manager import ConfigManager
from constants import (
    CONFIG_FOLDER,
    DASHBOARDS_DEST_PATH,
    LOKI_RULES_DEST_PATH,
    METRICS_RULES_DEST_PATH,
    NODE_EXPORTER_DISABLED_COLLECTORS,
    NODE_EXPORTER_ENABLED_COLLECTORS,
    RECV_CA_CERT_FOLDER_PATH,
    SERVER_CERT_PATH,
    SERVER_CERT_PRIVATE_KEY_PATH,
)
from singleton_snap import SingletonSnapManager, SnapRegistrationFile
from snap_fstab import SnapFstab
from snap_management import (
    SnapInstallError,
    SnapMap,
    SnapServiceError,
    SnapSpecError,
    install_snap,
)

# Log messages can be retrieved using juju debug-log
logger = logging.getLogger(__name__)
VALID_LOG_LEVELS = ["info", "debug", "warning", "error", "critical"]


# TODO: move this method outside of charm.py together with the cos-agent integrations
def _filelog_receiver_config(
    include: List[str], exclude: List[str], attributes: Dict[str, str]
) -> Dict[str, Any]:
    """Build the config for the filelog receiver."""
    config = {
        "include": include,
        "start_at": "beginning",
        "include_file_name": True,
        "include_file_path": True,
        "attributes": attributes,
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
                "value": 'EXPR(let lastSlashIndex = lastIndexOf(attributes["log.file.path"], "/"); attributes["log.file.path"][:lastSlashIndex])',
            },
        ],
    }
    if exclude:
        config["exclude"] = exclude
    return config


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


def _get_missing_mandatory_relations(charm: CharmBase) -> Optional[str]:
    """Check whether mandatory relations are in place.

    The charm can use this information to set BlockedStatus.
    Without any matching outgoing relation, the collector could incur data loss.
    Incoming relations are evaluated with AND, while outgoing relations with OR.

    Returns:
        A string containing the missing relations in string format, or None if
        all the mandatory relation pairs are present.
    """
    relation_pairs = MandatoryRelationPairs(
        pairs={
            "cos-agent": [  # must be paired with:
                {"cloud-config"},  # or
                {"send-remote-write"},  # or
                {"send-loki-logs"},  # or
                {"grafana-dashboards-provider"},
            ],
            "juju-info": [  # must be paired with:
                {"cloud-config"},  # or
                {"send-remote-write"},  # or
                {"send-loki-logs"},
            ],
        }
    )
    active_relations = {name for name, relation in charm.model.relations.items() if relation}
    missing_str = relation_pairs.get_missing_as_str(*active_relations)
    return missing_str or None


class OpenTelemetryCollectorCharm(ops.CharmBase):
    """Charm the service."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)

        # FIXME: install is not enough, we also need upgrade
        observe_events(self, (ops.InstallEvent, ), self._install_snaps)
        observe_events(self, (ops.StopEvent, ops.RemoveEvent), self._stop)
        observe_events(self, all_events.difference({self.on.stop, self.on.remove}), self._reconcile)

    def _reconcile(self):
        insecure_skip_verify = cast(bool, self.config.get("tls_insecure_skip_verify"))
        topology = JujuTopology.from_charm(self)
        # NOTE: Only the leader aggregates alerts, to prevent duplication. COS Agent alerts
        # come from peer data, so the leader can access all of them, regardless where multiple
        # principals are located.
        if self.unit.is_leader():
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

        # Global scrape configs
        global_configs = {
            "global_scrape_interval": cast(str, self.config.get("global_scrape_interval")),
            "global_scrape_timeout": cast(str, self.config.get("global_scrape_timeout")),
        }
        for name, global_config in global_configs.items():
            pattern = r"^\d+[ywdhms]$"
            match = re.fullmatch(pattern, global_config)
            if not match:
                self.unit.status = BlockedStatus(
                    f"The {name} config requires format: '\\d+[ywdhms]'."
                )
                return

        # Create the config manager
        config_manager = ConfigManager(
            global_scrape_interval=global_configs["global_scrape_interval"],
            global_scrape_timeout=global_configs["global_scrape_timeout"],
            receiver_tls=is_tls_ready(),
            insecure_skip_verify=cast(bool, self.config.get("tls_insecure_skip_verify")),
            queue_size=cast(int, self.config.get("queue_size")),
            max_elapsed_time_min=cast(int, self.config.get("max_elapsed_time_min")),
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
        ## Node exporter metrics
        config_manager.config.add_component(
            Component.receiver,
            name="prometheus/node-exporter",
            config={
                "config": {
                    "scrape_configs": [
                        {
                            # This job name is overwritten with "otelcol" when remote-writing
                            "job_name": f"juju_{topology.identifier}_node-exporter",
                            "scrape_interval": "60s",
                            "static_configs": [
                                {
                                    "targets": [
                                        "0.0.0.0:9100"  # TODO: extract this node-exporter port somewhere
                                    ],
                                    "labels": {
                                        "instance": socket.getfqdn(),
                                        "juju_charm": topology.charm_name,
                                        "juju_model": topology.model,
                                        "juju_model_uuid": topology.model_uuid,
                                        "juju_application": topology.application,
                                        "juju_unit": topology.unit,
                                    },
                                }
                            ],
                        }
                    ],
                }
            },
            pipelines=["metrics"],
        )
        ## COS Agent metrics
        if cos_agent.metrics_jobs:
            config_manager.config.add_component(
                Component.receiver,
                name=f"prometheus/cos-agent-{self.unit.name}",
                config={"config": {"scrape_configs": cos_agent.metrics_jobs}},
                pipelines=[f"metrics/{self.unit.name}"],
            )
        if self.unit.is_leader():
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
                config=_filelog_receiver_config(
                    include=[
                        f"{fstab_entry.target}/**"
                        if fstab_entry
                        else "/snap/opentelemetry-collector/current/shared-logs/**"
                    ],
                    exclude=[],
                    attributes={
                        "job": f"{fstab_entry.owner}-{fstab_entry.relative_target}",
                        "juju_application": endpoint_owners[fstab_entry.owner]["juju_application"],
                        "juju_unit": endpoint_owners[fstab_entry.owner]["juju_unit"],
                        "juju_charm": topology.charm_name,  # type: ignore
                        "juju_model": topology.model,
                        "juju_model_uuid": topology.model_uuid,
                        "snap_name": fstab_entry.owner,
                    },
                ),
                pipelines=[f"logs/{self.unit.name}"],
            )
        ### Add /var/log scrape job
        var_log_exclusions = cast(str, self.config.get("path_exclude")).split(",")
        config_manager.config.add_component(
            component=Component.receiver,
            name="filelog/var-log",
            config=_filelog_receiver_config(
                include=["/var/log/**/*log"],
                exclude=var_log_exclusions,
                attributes={
                    "job": "opentelemetry-collector-var-log",
                    "juju_application": topology.application,
                    "juju_unit": topology.unit,  # type: ignore
                    "juju_charm": topology.charm_name,
                    "juju_model": topology.model,
                    "juju_model_uuid": topology.model_uuid,
                    # NOTE: No snap_name attribute is necessary as these logs are not from a snap
                },
            ),
            pipelines=["logs"],
        )

        if self.unit.is_leader():
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
        if self._has_incoming_traces_relation:
            requested_tracing_protocols = integrations.receive_traces(self, tls=is_tls_ready())
            config_manager.add_traces_ingestion(requested_tracing_protocols)
            # Add default processors to traces
            config_manager.add_traces_processing(
                sampling_rate_charm=cast(bool, self.config.get("tracing_sampling_rate_charm")),
                sampling_rate_workload=cast(
                    bool, self.config.get("tracing_sampling_rate_workload")
                ),
                sampling_rate_error=cast(bool, self.config.get("tracing_sampling_rate_error")),
            )
        tracing_otlp_http_endpoint = integrations.send_traces(self)
        if tracing_otlp_http_endpoint:
            config_manager.add_traces_forwarding(tracing_otlp_http_endpoint)
        integrations.send_charm_traces(self)

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
        config_filename = f"{SnapRegistrationFile._normalize_name(self.unit.name)}.yaml"
        config_path = LocalPath(os.path.join(CONFIG_FOLDER, config_filename))
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(config_manager.config.build())

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

        self._configure_node_exporter_collectors()
        self.unit.status = ActiveStatus()

        # Mandatory relation pairs
        if missing_relations := _get_missing_mandatory_relations(self):
            self.unit.status = BlockedStatus(missing_relations)

    def _install_snaps(self) -> None:
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

    def _stop(self):
        """Coordinate snap and config file removal.

        If the snap is solely used by this unit, then skip reconciling the charm since it depends
        on snap operations.
        """
        manager = SingletonSnapManager(self.unit.name)
        reconcile_required = True
        for snap_name in SnapMap.snaps():
            snap_revision = SnapMap.get_revision(snap_name)
            if manager.get_units(snap_name):
                manager.unregister(snap_name, snap_revision)
                if not manager.is_used_by_other_units(snap_name):
                    # Remove the snap
                    self.unit.status = MaintenanceStatus(f"Uninstalling {snap_name} snap")
                    try:
                        self.snap(snap_name).ensure(state=snap.SnapState.Absent)
                    except (snap.SnapError, SnapSpecError) as e:
                        raise SnapInstallError(f"Failed to uninstall {snap_name}") from e
                    # Remove the config file
                    if snap_name == "opentelemetry-collector":
                        shutil.rmtree(LocalPath(CONFIG_FOLDER))
                        logger.info(
                            f"Removed the opentelemetry-collector config folder: {CONFIG_FOLDER}"
                        )
                    reconcile_required = False

                # TODO: Luca if the snap is used by other units, we should probably `ensure`
                # that the max_revision is installed instead.
            else:
                reconcile_required = False

        if reconcile_required:
            self._reconcile()

    def _configure_node_exporter_collectors(self):
        """Configure the node-exporter snap collectors."""
        configs = {
            "collectors": " ".join(list(NODE_EXPORTER_ENABLED_COLLECTORS)),
            "no-collectors": " ".join(list(NODE_EXPORTER_DISABLED_COLLECTORS)),
        }
        ne_snap = self.snap("node-exporter")
        self._set_snap_configs_with_retry(ne_snap, configs)

    # We use tenacity because .set() performs a HTTP request to the snapd server which is not always ready
    @retry(stop=stop_after_attempt(5), wait=wait_fixed(5))
    def _set_snap_configs_with_retry(self, snap, configs: Mapping[str, snap.JSONAble]):
        snap.set(configs)  # type: ignore

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
    def _has_incoming_traces_relation(self) -> bool:
        return any(self.model.relations.get("receive-traces", []))

    @property
    def _has_outgoing_metrics_relation(self) -> bool:
        return any(self.model.relations.get("send-remote-write", []))

    @property
    def _has_server_cert_relation(self) -> bool:
        return any(self.model.relations.get("receive-server-cert", []))


if __name__ == "__main__":  # pragma: nocover
    ops.main(OpenTelemetryCollectorCharm)
