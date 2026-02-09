# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

# TODO: Update once we have moved to a lib
"""OpenTelemetry protocol (OTLP) Library.

## Overview

This document explains how to integrate with the Opentelemetry-collector charm
for the purpose of providing OTLP telemetry to Opentelemetry-collector. This document is the
authoritative reference on the structure of relation data that is
shared between Opentelemetry-collector charms and any other charm that intends to
provide OTLP telemetry for Opentelemetry-collector.
"""

import json
import logging
import socket
from enum import Enum, unique
from typing import ClassVar, Dict, List, Optional, Sequence

from cosl.juju_topology import JujuTopology
from ops import CharmBase, Relation
from ops.framework import Object
from pydantic import BaseModel, ConfigDict, ValidationError

DEFAULT_CONSUMER_RELATION_NAME = "send-otlp"
DEFAULT_PROVIDER_RELATION_NAME = "receive-otlp"
RELATION_INTERFACE_NAME = "otlp"

logger = logging.getLogger(__name__)


@unique
class ProtocolType(str, Enum):
    """OTLP protocols used by the OpenTelemetry Collector."""

    grpc = "grpc"
    """gRPC protocol for sending/receiving OTLP data."""
    http = "http"
    """HTTP protocol for sending/receiving OTLP data."""


@unique
class TelemetryType(str, Enum):
    """OTLP telemetries used by the OpenTelemetry Collector."""

    logs = "logs"
    """OTLP logs data."""
    metrics = "metrics"
    """OTLP metrics data."""
    traces = "traces"
    """OTLP traces data."""


_TELEMETRY_TYPES = {t.value for t in TelemetryType}


class ProtocolPort(BaseModel):
    """A pydantic model for OTLP protocols and their associated port."""

    model_config = ConfigDict(extra="forbid")

    grpc: Optional[int] = None
    http: Optional[int] = None


class OtlpEndpoint(BaseModel):
    """A pydantic model for a single OTLP endpoint."""

    model_config = ConfigDict(extra="forbid")

    protocol: ProtocolType
    endpoint: str
    telemetries: List[TelemetryType]


class OtlpProviderAppData(BaseModel):
    """A pydantic model for the OTLP provider's unit databag."""

    KEY: ClassVar[str] = "otlp"

    model_config = ConfigDict(extra="forbid")

    endpoints: List[OtlpEndpoint]


class OtlpConsumer(Object):
    """A class for consuming OTLP endpoints."""

    def __init__(
        self,
        charm: CharmBase,
        relation_name: str = DEFAULT_CONSUMER_RELATION_NAME,
        protocols: Optional[Sequence[str]] = None,
    ):
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name
        self._protocols = [ProtocolType(p) for p in protocols] if protocols is not None else []

        self.topology = JujuTopology.from_charm(charm)

    def _get_app_databag(self, otlp_databag: str) -> Optional[OtlpProviderAppData]:
        """Load the OtlpProviderAppData from the given databag string.

        For each endpoint in the databag, if it contains unsupported telemetry types, those
        telemetries are filtered out before validation. If an endpoint contains an unsupported
        protocol, it is skipped entirely.
        """
        try:
            data = json.loads(otlp_databag)
            endpoints_data = data.get("endpoints", [])
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse OTLP databag: {e}")
            return None

        valid_endpoints = []
        for endpoint_data in endpoints_data:
            endpoint_data["telemetries"] = [
                t for t in endpoint_data.get("telemetries", []) if t in _TELEMETRY_TYPES
            ]
            try:
                endpoint = OtlpEndpoint.model_validate(endpoint_data)
            except ValidationError:
                continue
            valid_endpoints.append(endpoint)
        try:
            return OtlpProviderAppData(endpoints=valid_endpoints)
        except ValidationError as e:
            logger.error(f"OTLP databag failed validation: {e}")
            return None

    def get_remote_otlp_endpoints(self) -> Dict[int, Dict[str, OtlpEndpoint]]:
        """Return a mapping of relation ID to app name to OTLP endpoint.

        For each remote unit's list of OtlpEndpoints:
            - If a telemetry type is not supported, then the endpoint is accepted, but the
              telemetry is ignored.
            - If the endpoint contains an unsupported protocol it is ignored.
            - The first available (and supported) endpoint is returned.

        Returns:
            Dict mapping relation ID -> {app_name -> OtlpEndpoint}
        """
        aggregate = {}
        for rel in self.model.relations[self._relation_name]:
            app_databags = {}
            if not (otlp := rel.data[rel.app].get(OtlpProviderAppData.KEY)):
                continue
            if not (app_databag := self._get_app_databag(otlp)):
                continue

            # Choose the first valid endpoint in list
            if endpoint_choice := next(
                (e for e in app_databag.endpoints if e.protocol in self._protocols), None
            ):
                app_databags[rel.app.name] = endpoint_choice

            aggregate[rel.id] = app_databags

        return aggregate


class OtlpProvider(Object):
    """A class for publishing all supported OTLP endpoints.

    Args:
        charm: The charm instance.
        protocol_ports: A dictionary mapping ProtocolType to port number.
        relation_name: The name of the relation to use.
        path: An optional path to append to the endpoint URLs.
        supported_telemetries: A list of supported telemetry types.
    """

    def __init__(
        self,
        charm: CharmBase,
        protocol_ports: Dict[str, int],
        relation_name: str = DEFAULT_PROVIDER_RELATION_NAME,
        path: str = "",
        supported_telemetries: Optional[Sequence[str]] = None,
    ):
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name
        self._protocol_ports = ProtocolPort.model_validate(protocol_ports)
        self._path = path
        self._supported_telemetries = (
            [TelemetryType(t) for t in supported_telemetries] if supported_telemetries else []
        )

        self._reconcile()

    def _reconcile(self) -> None:
        self.update_endpoints()

    @property
    def internal_url(self) -> str:
        """Return the internal URL for the OTLP provider."""
        return f"http://{socket.getfqdn()}"

    def _get_otlp_endpoints(self, url: str = "") -> List[OtlpEndpoint]:
        """List all available OTLP endpoints for this server."""
        endpoints = []
        new_url = url if url else self.internal_url
        for protocol, port in self._protocol_ports.model_dump(exclude_none=True).items():
            endpoint = f"{new_url.rstrip('/')}:{port}"
            if self._path:
                endpoint += f"/{self._path.rstrip('/')}"
            endpoints.append(
                OtlpEndpoint(
                    protocol=ProtocolType(protocol),
                    endpoint=endpoint,
                    telemetries=self._supported_telemetries,
                )
            )
        return endpoints

    def update_endpoints(self, url: str = "", relation: Optional[Relation] = None) -> None:
        """Triggers programmatically the update of the relation data.

        This method should be used when the charm relying on this library needs to update the
        relation data in response to something occurring outside the `otlp` relation lifecycle,
        e.g., in case of a host address change because the charmed operator becomes connected to
        an Ingress after the `otlp` relation is established.

        Only the leader unit can write to app data.

        Args:
            url: An optional URL to use instead of the internal URL.
            relation: An optional instance of `class:ops.model.Relation` to update.
                If not provided, all instances of the `otlp`
                relation are updated.
        """
        if not self._charm.unit.is_leader():
            return

        relations = [relation] if relation else self.model.relations[self._relation_name]
        for relation in relations:
            otlp = {
                OtlpProviderAppData.KEY: OtlpProviderAppData(
                    endpoints=self._get_otlp_endpoints(url)
                ).model_dump(exclude_none=True)
            }
            relation.data[self._charm.app].update({k: json.dumps(v) for k, v in otlp.items()})
