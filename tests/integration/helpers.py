# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests helpers."""

import re
from typing import Final
import jubilant
from tenacity import retry, stop_after_attempt, wait_fixed

# Exclude some logs to avoid circular ingestion during tests
PATH_EXCLUDE: Final[str] = "/var/log/**/{cloud-init-output.log,syslog,auth.log};/var/log/juju/**"


@retry(stop=stop_after_attempt(10), wait=wait_fixed(10))
async def is_pattern_in_snap_logs(juju: jubilant.Juju, grep_filters: list):
    cmd = (
        "sudo snap logs opentelemetry-collector -n=all"
        + " | "
        + " | ".join([f"grep {p}" for p in grep_filters])
    )
    otelcol_logs = juju.ssh("otelcol/0", command=cmd)

    if not otelcol_logs:
        raise Exception(f"Filters {grep_filters} not found in the otelcol logs")
    return True


@retry(stop=stop_after_attempt(10), wait=wait_fixed(10))
async def is_pattern_not_in_logs(juju: jubilant.Juju, pattern: str):
    otelcol_logs = juju.ssh("otelcol/0", command="sudo snap logs opentelemetry-collector -n=all")
    if re.search(pattern, otelcol_logs):
        raise Exception(f"Pattern {pattern} found in the otelcol logs")
    return True


def ssh_and_execute_command_in_machine(juju: jubilant.Juju, machine: str, command: str):
    return juju.ssh(machine, command)


def is_snap_active(snap_service_output: str) -> bool:
    """Check if a snap service is active based on the output of `snap services <snap>`. This function assumes that the snap is installed.

    Example output:
    Service                                          Startup  Current  Notes
    opentelemetry-collector.opentelemetry-collector  enabled  active   -
    """
    lines = snap_service_output.strip().splitlines()

    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 3:
            current = parts[2]
            if current.lower() == "active":
                return True
    return False
