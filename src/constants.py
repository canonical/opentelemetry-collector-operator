"""Charm constants, for better testability."""

from typing import Final, Set

RECV_CA_CERT_FOLDER_PATH: Final[str] = "/usr/local/share/ca-certificates/juju_receive-ca-cert"
SERVER_CERT_PATH: Final[str] = (
    "/var/snap/opentelemetry-collector/common/juju_tls-certificates/otelcol-server.crt"
)
SERVER_CERT_PRIVATE_KEY_PATH: Final[str] = "/var/snap/opentelemetry-collector/common/private.key"
CONFIG_FOLDER: Final[str] = "/etc/otelcol/config.d"
SERVICE_NAME: Final[str] = "otelcol"
METRICS_RULES_SRC_PATH: Final[str] = "src/prometheus_alert_rules"
METRICS_RULES_DEST_PATH: Final[str] = "prometheus_alert_rules"
LOKI_RULES_SRC_PATH: Final[str] = "src/loki_alert_rules"
LOKI_RULES_DEST_PATH: Final[str] = "loki_alert_rules"
DASHBOARDS_SRC_PATH: Final[str] = "src/grafana_dashboards"
DASHBOARDS_DEST_PATH: Final[str] = "grafana_dashboards"

# SNAP_COMMON dir: https://snapcraft.io/docs/data-locations#p-94053-system-data
FILE_STORAGE_DIRECTORY: Final[str] = "/var/snap/opentelemetry-collector/common/"

# Ref: https://github.com/prometheus/node_exporter?tab=readme-ov-file#collectors
NODE_EXPORTER_DISABLED_COLLECTORS: Final[Set[str]] = set()
NODE_EXPORTER_ENABLED_COLLECTORS: Final[Set[str]] = {"drm", "logind", "systemd", "mountstats", "processes", "sysctl"}
