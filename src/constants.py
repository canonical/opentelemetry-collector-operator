"""Charm constants, for better testability."""

from typing import Final, Set

SERVICE_NAME: Final[str] = "otelcol"
CERT_DIR: Final[str] = "/var/snap/opentelemetry-collector/common/certs"
SERVER_CERT_PATH: Final[str] = "/var/snap/opentelemetry-collector/common/otelcol-server-cert.crt"
SERVER_CERT_PRIVATE_KEY_PATH: Final[str] = "/var/snap/opentelemetry-collector/common/otelcol-private-key.key"
RECV_CA_CERT_FOLDER_PATH: Final[str] = "/usr/local/share/ca-certificates/juju_receive-ca-cert"
SERVER_CA_CERT_PATH: Final[str] = "/usr/local/share/ca-certificates/juju_receive-ca-cert/cos-ca.crt"
CONFIG_FOLDER: Final[str] = "/etc/otelcol/config.d"
LOGROTATE_PATH: Final[str] = "/etc/logrotate.d/otelcol"
LOGROTATE_SRC_PATH: Final[str] = "src/logrotate.d/otelcol"
METRICS_RULES_SRC_PATH: Final[str] = "src/prometheus_alert_rules"
METRICS_RULES_DEST_PATH: Final[str] = "prometheus_alert_rules"
LOKI_RULES_SRC_PATH: Final[str] = "src/loki_alert_rules"
LOKI_RULES_DEST_PATH: Final[str] = "loki_alert_rules"
DASHBOARDS_SRC_PATH: Final[str] = "src/grafana_dashboards"
DASHBOARDS_DEST_PATH: Final[str] = "grafana_dashboards"
# NOTE: this file path is hardcoded in src/logrotate.d/otelcol as well
INTERNAL_TELEMETRY_LOG_FILE: Final[str] = "/var/snap/opentelemetry-collector/common/otelcol.log"

# SNAP_COMMON dir: https://snapcraft.io/docs/data-locations#p-94053-system-data
FILE_STORAGE_DIRECTORY: Final[str] = "/var/snap/opentelemetry-collector/common/"

# Directory where node-exporter's textfile collector reads metrics files written by
# subordinates. Each subordinate unit should write a file named after the unit
# (slashes replaced with underscores) containing Prometheus text-based metrics.
# Using $SNAP_COMMON (which is owned by root) because the charm (and node-exporter) runs as root
NODE_EXPORTER_TEXTFILE_DIR: Final[str] = "/var/snap/node-exporter/common/textfile-collector.d"

# Ref: https://github.com/prometheus/node_exporter?tab=readme-ov-file#collectors
NODE_EXPORTER_DISABLED_COLLECTORS: Final[Set[str]] = set()
NODE_EXPORTER_ENABLED_COLLECTORS: Final[Set[str]] = {
    "drm",
    "logind",
    "systemd",
    "mountstats",
    "processes",
    "sysctl",
	"textfile",
	f"textfile.directory={NODE_EXPORTER_TEXTFILE_DIR}",
}
