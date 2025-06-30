"""Charm constants, for better testability."""

from typing import Final

RECV_CA_CERT_FOLDER_PATH: Final[str] = "/usr/local/share/ca-certificates/juju_receive-ca-cert"
SERVER_CERT_PATH: Final[str] = (
    "/usr/local/share/ca-certificates/juju_tls-certificates/otelcol-server.crt"
)
SERVER_CERT_PRIVATE_KEY_PATH: Final[str] = "/etc/otelcol/private.key"
CONFIG_PATH: Final[str] = "/etc/otelcol/config.yaml"
SERVICE_NAME: Final[str] = "otelcol"
METRICS_RULES_SRC_PATH: Final[str] = "src/prometheus_alert_rules"
METRICS_RULES_DEST_PATH: Final[str] = "prometheus_alert_rules"
LOKI_RULES_SRC_PATH: Final[str] = "src/loki_alert_rules"
LOKI_RULES_DEST_PATH: Final[str] = "loki_alert_rules"
DASHBOARDS_SRC_PATH: Final[str] = "src/grafana_dashboards"
DASHBOARDS_DEST_PATH: Final[str] = "grafana_dashboards"
