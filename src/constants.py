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

# Ref: https://github.com/prometheus/node_exporter?tab=readme-ov-file#collectors
NODE_EXPORTER_AVAILABLE_COLLECTORS: Final[Set[str]] = {
    "arp",
    "bcache",
    "bonding",
    "boottime",
    "btrfs",
    "buddyinfo",
    "cgroups",
    "conntrack",
    "cpu",
    "cpu_vulnerabilities",
    "cpufreq",
    "devstat",
    "diskstats",
    "dmi",
    "drbd",
    "drm",
    "edac",
    "entropy",
    "ethtool",
    "exec",
    "fibrechannel",
    "filefd",
    "filesystem",
    "hwmon",
    "infiniband",
    "interrupts",
    "ipvs",
    "ksmd",
    "lnstat",
    "loadavg",
    "logind",
    "mdadm",
    "meminfo",
    "meminfo_numa",
    "mountstats",
    "netclass",
    "netdev",
    "netisr",
    "netstat",
    "network_route",
    "nfs",
    "nfsd",
    "nvme",
    "os",
    "pcidevice",
    "perf",
    "powersupplyclass",
    "pressure",
    "processes",
    "qdisc",
    "rapl",
    "schedstat",
    "selinux",
    "slabinfo",
    "sockstat",
    "softirqs",
    "softnet",
    "stat",
    "sysctl",
    "systemd",
    "tapestats",
    "tcpstat",
    "textfile",
    "thermal",
    "thermal_zone",
    "time",
    "timex",
    "udp_queues",
    "uname",
    "vmstat",
    "watchdog",
    "wifi",
    "xfrm",
    "xfs",
    "zfs",
    "zoneinfo",
}
