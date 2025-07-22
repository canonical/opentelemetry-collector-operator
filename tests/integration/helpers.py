import logging
import re

import jubilant
from tenacity import retry, stop_after_attempt, wait_fixed

logger = logging.getLogger(__name__)

@retry(stop=stop_after_attempt(3), wait=wait_fixed(10))
async def is_pattern_in_logs(juju: jubilant.Juju, pattern: str) -> bool:
    otelcol_logs = juju.ssh("otelcol/0", command="sudo snap logs opentelemetry-collector -n=all")
    if not re.search(pattern, otelcol_logs):
        logger.warning(f"Pattern {pattern} found in the otelcol logs")
        return False
    return True
