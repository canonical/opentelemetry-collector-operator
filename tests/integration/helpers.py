# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests helpers."""

import re
from typing import Dict, Final
import jubilant
import yaml
from tenacity import retry, stop_after_attempt, wait_fixed


# Exclude some logs to avoid circular ingestion during tests
PATH_EXCLUDE: Final[str] = "/var/log/**/{cloud-init-output.log,syslog,auth.log};/var/log/juju/**"
# Configure debug exporters for all pipelines to inspect / assert against the OTLP data
ENABLE_BASIC_DEBUG_EXPORTERS: Final[Dict[str, str]] = {
    "debug_exporter_for_logs": "true",
    "debug_exporter_for_metrics": "true",
}
SNAP_STATUS_COMMAND: Final[str] = "sudo snap services opentelemetry-collector"


@retry(stop=stop_after_attempt(20), wait=wait_fixed(10))
async def is_pattern_in_debug_logs(juju: jubilant.Juju, grep_filters: list):
    cmd = (
        "sudo snap logs opentelemetry-collector -n=all"
        + " | "
        + " | ".join([f"grep {p}" for p in grep_filters])
    )
    debug_logs = juju.ssh("otelcol/0", command=cmd)

    if not debug_logs:
        raise Exception(f"Filters {grep_filters} not found in the debug logs")
    return True


async def is_pattern_not_in_debug_logs(juju: jubilant.Juju, pattern: str):
    debug_logs = juju.ssh("otelcol/0", command="sudo snap logs opentelemetry-collector -n=all")
    if re.search(pattern, debug_logs):
        raise Exception(f"Pattern {pattern} found in the debug logs")
    return True


def get_hostname(juju: jubilant.Juju, machine: str) -> str:
    return juju.ssh(f"ubuntu/{machine}", "hostname").strip()


def get_snap_service_status(juju: jubilant.Juju, machine: str) -> str:
    """Gets the status of the otelcol snap using `snap services opentelemetry-collector`. This function assumes that the snap is already installed.

    Example output:
    Service                                          Startup  Current  Notes
    opentelemetry-collector.opentelemetry-collector  enabled  active   -
    """
    snap_status = juju.ssh(f"ubuntu/{machine}", SNAP_STATUS_COMMAND)
    lines = snap_status.strip().splitlines()

    parts = lines[1].split()
    return parts[2].lower()


def get_receiver_config(
    juju: jubilant.Juju, unit: str, receiver_name: str, otelcol_config_file: str
) -> str:
    config_file = juju.ssh(unit, f"cat {otelcol_config_file}")
    cfg = yaml.safe_load(config_file)

    receivers = cfg.get("receivers", {})
    for name in receivers.keys():
        if receiver_name in name:
            return name
    return ""
