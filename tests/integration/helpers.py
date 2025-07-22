import re

import jubilant
from tenacity import retry, stop_after_attempt, wait_exponential


# Wait 1, 2, 4, 8, 10, 10, etc. seconds
@retry(stop=stop_after_attempt(10), wait=wait_exponential(max=10))
async def is_pattern_in_logs(juju: jubilant.Juju, pattern: str):
    otelcol_logs = juju.ssh("otelcol/0", command="sudo snap logs opentelemetry-collector -n=all")
    if re.search(pattern, otelcol_logs):
        raise Exception(f"Pattern {pattern} found in the otelcol logs")
    return True
