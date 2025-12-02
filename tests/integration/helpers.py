# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests helpers."""

import re
from typing import Final

import jubilant
from tenacity import retry, stop_after_attempt, wait_fixed

from constants import INTERNAL_TELEMETRY_LOG_FILE

PATH_EXCLUDE: Final[str] = "/var/log/**/{cloud-init-output.log,syslog,auth.log};/var/log/juju/**"


@retry(stop=stop_after_attempt(10), wait=wait_fixed(10))
async def is_pattern_in_snap_logs(juju: jubilant.Juju, grep_filters: list):
    cmd = (
        f"tail -10000 {INTERNAL_TELEMETRY_LOG_FILE}"
        + " | "
        + " | ".join([f"grep {p}" for p in grep_filters])
    )
    otelcol_logs = juju.ssh("otelcol/0", command=cmd)

    if not otelcol_logs:
        raise Exception(f"Filters {grep_filters} not found in the otelcol logs")
    return True


@retry(stop=stop_after_attempt(10), wait=wait_fixed(10))
async def is_pattern_not_in_logs(juju: jubilant.Juju, pattern: str):
    otelcol_logs = juju.ssh("otelcol/0", command=f"tail -10000 {INTERNAL_TELEMETRY_LOG_FILE}")
    if re.search(pattern, otelcol_logs):
        raise Exception(f"Pattern {pattern} found in the otelcol logs")
    return True
