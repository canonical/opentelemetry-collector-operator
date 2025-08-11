# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration tests helpers."""

import re
import jubilant
from tenacity import retry, stop_after_attempt, wait_fixed

# FIXME: Reduce retry count once fixed
# https://github.com/canonical/opentelemetry-collector-operator/issues/32

@retry(stop=stop_after_attempt(25), wait=wait_fixed(10))
async def is_pattern_in_snap_logs(juju: jubilant.Juju, grep_filters: list):
    cmd = "sudo snap logs opentelemetry-collector -n=all" + " | " + " | ".join([f"grep {p}" for p in grep_filters])
    otelcol_logs = juju.ssh("otelcol/0", command=cmd)

    if not otelcol_logs:
        raise Exception(f"Filters {grep_filters} not found in the otelcol logs")
    return True

@retry(stop=stop_after_attempt(25), wait=wait_fixed(10))
async def is_pattern_not_in_logs(juju: jubilant.Juju, pattern: str):
    otelcol_logs = juju.ssh("otelcol/0", command="sudo snap logs opentelemetry-collector -n=all")
    if re.search(pattern, otelcol_logs):
        raise Exception(f"Pattern {pattern} found in the otelcol logs")
    return True
