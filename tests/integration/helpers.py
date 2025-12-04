# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests helpers."""

import re
from typing import Dict, Final
import jubilant
from tenacity import retry, stop_after_attempt, wait_fixed


PATH_EXCLUDE: Final[str] = "/var/log/**/{cloud-init-output.log,syslog,auth.log};/var/log/juju/**"
# Configure debug exporters for all pipelines to inspect / assert against the OTLP data
ENABLE_BASIC_DEBUG_EXPORTERS: Final[Dict[str, str]] = {
    "enable_debug_exporter_for_logs": "true",
    "enable_debug_exporter_for_metrics": "true",
}


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
