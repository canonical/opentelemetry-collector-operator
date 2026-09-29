"""Grafana Cloud Integrator Configuration Requirer."""

from __future__ import annotations

import logging

from ops.framework import EventBase, EventSource, Object, ObjectEvents

LIBID = "e6f580481c1b4388aa4d2cdf412a47fa"
LIBAPI = 0
LIBPATCH = 11

DEFAULT_RELATION_NAME = "grafana-cloud-config"

logger = logging.getLogger(__name__)


class Credentials:
    """Credentials for the remote endpoints."""

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password


class CloudConfigAvailableEvent(EventBase):
    """Event emitted when cloud config is available."""


class CloudConfigRevokedEvent(EventBase):
    """Event emitted when cloud config is revoked."""


class GrafanaCloudConfigEvents(ObjectEvents):
    """Event descriptor for `GrafanaCloudConfigRequirer`."""

    cloud_config_available = EventSource(CloudConfigAvailableEvent)
    cloud_config_revoked = EventSource(CloudConfigRevokedEvent)


class GrafanaCloudConfigRequirer(Object):
    """Requirer side of the Grafana Cloud Config relation."""

    on = GrafanaCloudConfigEvents()  # pyright: ignore[reportAssignmentType]

    def __init__(self, charm, relation_name: str = DEFAULT_RELATION_NAME):
        super().__init__(charm, relation_name)
        self._charm = charm
        self._relation_name = relation_name

        for event in self._change_events:
            self.framework.observe(event, self._on_relation_changed)

        for event in self._broken_events:
            self.framework.observe(event, self._on_relation_broken)

    def _on_relation_changed(self, _event) -> None:
        """Emit a change event when relation data changes."""
        self.on.cloud_config_available.emit()  # pyright: ignore[reportAttributeAccessIssue]

    def _on_relation_broken(self, _event) -> None:
        """Emit a revocation event when the relation is removed."""
        self.on.cloud_config_revoked.emit()  # pyright: ignore[reportAttributeAccessIssue]

    @property
    def _change_events(self):
        relation_events = self._events
        return [
            relation_events.relation_joined,
            relation_events.relation_changed,
            relation_events.relation_created,
        ]

    @property
    def _broken_events(self):
        relation_events = self._events
        return [relation_events.relation_departed, relation_events.relation_broken]

    @property
    def _events(self):
        return self._charm.on[self._relation_name]

    @staticmethod
    def _is_not_empty(value: str) -> bool:
        """Return whether a string value is set and non-whitespace."""
        return bool(value and not value.isspace())

    @property
    def credentials(self) -> Credentials | None:
        """Return credentials from relation data when both are present."""
        if (username := self._data.get("username", "").strip()) and (
            password := self._data.get("password", "").strip()
        ):
            return Credentials(username, password)
        return None

    @property
    def prometheus_credentials(self) -> Credentials | None:
        """Return Prometheus credentials or fall back to shared credentials."""
        return self._signal_credentials("prometheus")

    @property
    def loki_credentials(self) -> Credentials | None:
        """Return Loki credentials or fall back to shared credentials."""
        return self._signal_credentials("loki")

    @property
    def tempo_credentials(self) -> Credentials | None:
        """Return Tempo credentials or fall back to shared credentials."""
        return self._signal_credentials("tempo")

    @property
    def otlp_credentials(self) -> Credentials | None:
        """Return OTLP credentials or fall back to shared credentials."""
        return self._signal_credentials("otlp")

    @property
    def pyroscope_credentials(self) -> Credentials | None:
        """Return Pyroscope credentials or fall back to shared credentials."""
        return self._signal_credentials("pyroscope")

    @property
    def loki_ready(self) -> bool:
        """Return whether a Loki URL is available."""
        return self._is_not_empty(self.loki_url)

    @property
    def prometheus_ready(self) -> bool:
        """Return whether a Prometheus URL is available."""
        return self._is_not_empty(self.prometheus_url)

    @property
    def tempo_ready(self) -> bool:
        """Return whether a Tempo URL is available."""
        return self._is_not_empty(self.tempo_url)

    @property
    def otlp_ready(self) -> bool:
        """Return whether an OTLP URL is available."""
        return self._is_not_empty(self.otlp_url)

    @property
    def pyroscope_ready(self) -> bool:
        """Return whether a Pyroscope URL is available."""
        return self._is_not_empty(self.pyroscope_url)

    @property
    def tls_ca_ready(self) -> bool:
        """Return whether a TLS CA is available."""
        return self._is_not_empty(self.tls_ca)

    @property
    def loki_url(self) -> str:
        """Return the Loki URL from relation data."""
        return self._data.get("loki_url", "")

    @property
    def tempo_url(self) -> str:
        """Return the Tempo URL from relation data."""
        return self._data.get("tempo_url", "")

    @property
    def otlp_url(self) -> str:
        """Return the OTLP URL from relation data."""
        return self._data.get("otlp_url", "")

    @property
    def prometheus_url(self) -> str:
        """Return the Prometheus URL from relation data."""
        return self._data.get("prometheus_url", "")

    @property
    def pyroscope_url(self) -> str:
        """Return the Pyroscope URL from relation data."""
        return self._data.get("pyroscope_url", "")

    @property
    def tls_ca(self) -> str:
        """Return the TLS CA from relation data."""
        return self._data.get("tls-ca", "")

    @property
    def _data(self) -> dict[str, str]:
        for relation in self._charm.model.relations.get(self._relation_name, []):
            if relation.app is None:
                continue
            return dict(relation.data[relation.app])
        return {}

    def _signal_credentials(self, signal_name: str) -> Credentials | None:
        """Return signal-specific credentials, falling back to shared credentials."""
        username_key = f"{signal_name}_username"
        password_key = f"{signal_name}_password"
        if (username := self._data.get(username_key, "").strip()) and (
            password := self._data.get(password_key, "").strip()
        ):
            return Credentials(username, password)
        return self.credentials
