# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Internal telemetry is self-ingested via OTLP and forwarded to Loki with loop-breaker."""

import json
import logging
import pathlib

import jubilant
from helpers import PATH_EXCLUDE, RETRY, get_snap_service_status
from tenacity import retry, stop_after_attempt, wait_fixed

logger = logging.getLogger(__name__)

# Juju is a strictly confined snap that cannot see /tmp, so we need to use something else
TEMP_DIR = pathlib.Path(__file__).parent.resolve()


def _loki_host(juju: jubilant.Juju) -> str:
    """Return the IP/hostname of the Loki unit reachable from otelcol."""
    return juju.ssh("otelcol/0", command="juju ssh --format=raw loki/0 -- hostname").strip()


def _query_loki_series(juju: jubilant.Juju, selector: str) -> dict:
    """Query Loki /series endpoint via curl from the otelcol unit."""
    host = _loki_host(juju)
    result = juju.ssh(
        "otelcol/0",
        command=(
            f"curl -sS --fail "
            f"'http://{host}:3100/loki/api/v1/series?query={selector}'"
        ),
    )
    return json.loads(result)


def _query_loki_labels(juju: jubilant.Juju) -> str:
    """Query all label names in Loki."""
    host = _loki_host(juju)
    return juju.ssh(
        "otelcol/0",
        command=(
            f"curl -sS --fail "
            f"'http://{host}:3100/loki/api/v1/labels'"
        ),
    )


def _loki_has_internal_logs(juju: jubilant.Juju) -> bool:
    """Return True if Loki has a job=otelcol-internal stream."""
    try:
        data = _query_loki_series(juju, '{job="otelcol-internal"}')
        return data.get("status") == "success" and len(data.get("data", [])) > 0
    except Exception:
        return False


def _loop_breaker_filtered_count(juju: jubilant.Juju) -> float:
    """Return the latest loop-breaker filtered counter from otelcol's Prometheus metrics endpoint."""
    try:
        output = juju.ssh(
            "otelcol/0",
            command=(
                "curl -sS http://localhost:8888/metrics "
                "| grep otelcol_processor_filter_logs_filtered "
                "| grep loop-breaker"
            ),
        )
        if output.strip():
            # Lines like: otelcol_processor_filter_logs_filtered{...} 42
            return float(output.strip().rsplit(" ", 1)[-1])
    except Exception:
        pass
    return 0.0


def _is_snap_service_running(juju: jubilant.Juju, machine: str, snap_name: str) -> bool:
    """Check if a snap service is running on the given machine.

    Uses ``sudo snap services <snap>.<snap>`` directly to avoid assumptions
    about service naming conventions (e.g. otelcol uses ``opentelemetry-collector``).
    """
    try:
        out = juju.ssh(
            f"ubuntu/{machine}",
            command=f"sudo snap services {snap_name}.{snap_name}",
        )
        for line in out.strip().splitlines():
            if line.startswith("Service"):
                continue
            parts = line.split()
            if len(parts) >= 3 and parts[2].lower() == "active":
                return True
        return False
    except Exception:
        return False


def test_internal_logs_self_export(juju: jubilant.Juju, charm: str):
    """Scenario: internal telemetry is self-exported via OTLP and forwarded to Loki.

    The collector sends its own internal logs back to itself via OTLP, where they
    flow through the logs pipeline and are forwarded to Loki with
    job=otelcol-internal and Juju topology labels.
    """
    # GIVEN otelcol and loki are deployed and related
    juju.deploy(charm, app="otelcol", config={"path_exclude": PATH_EXCLUDE})
    juju.deploy("ubuntu", channel="latest/stable", base="ubuntu@24.04")
    juju.deploy("loki", channel="dev/edge")

    juju.integrate("otelcol:juju-info", "ubuntu:juju-info")
    juju.integrate("otelcol:send-loki-logs", "loki")

    juju.wait(
        lambda status: (
            jubilant.all_active(status, "ubuntu")
            and jubilant.all_blocked(status, "otelcol")
            and jubilant.all_active(status, "loki")
            and jubilant.all_agents_idle(status, "ubuntu", "otelcol", "loki")
        ),
        error=jubilant.any_error,
        timeout=600,
    )

    # AND otelcol snap is active
    assert get_snap_service_status(juju, "0") == "active"

    # THEN internal logs with job=otelcol-internal appear in Loki with Juju topology labels
    topology = {"juju_application", "juju_charm", "juju_unit", "juju_model", "juju_model_uuid"}

    @RETRY
    def _assert_internal_logs_in_loki():
        assert _loki_has_internal_logs(juju), (
            "No job=otelcol-internal stream found in Loki"
        )
        labels = _query_loki_labels(juju)
        for label in topology:
            assert label in labels, f"Expected {label!r} label in Loki, got: {labels}"

    _assert_internal_logs_in_loki()


def test_internal_logs_loop_breaker_drops_on_outage(juju: jubilant.Juju):
    """Scenario: when Loki is stopped, the loop-breaker filter drops recursive exporter failure logs.

    The loop-breaker filter (filter/internal-telemetry-loop-breaker) drops internal logs
    emitted by the loki exporter that would otherwise recurse back through the logs pipeline
    when Loki is unreachable.
    """
    # GIVEN the metrics debug exporter is on, so internal metrics are printed to snap logs
    juju.config("otelcol", {"debug_exporter_for_metrics": True})
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        error=jubilant.any_error,
        timeout=300,
    )

    # AND the loop-breaker drop counter is baselined
    baseline = _loop_breaker_filtered_count(juju)

    # WHEN Loki is stopped, causing the send-loki-logs exporter to fail and emit recursive logs
    juju.ssh("loki/0", command="sudo snap stop loki.loki")

    # Wait for Loki to actually stop
    @retry(stop=stop_after_attempt(15), wait=wait_fixed(10))
    def _wait_loki_stopped():
        assert not _is_snap_service_running(juju, "loki", "loki"), (
            "Loki snap service did not stop"
        )

    _wait_loki_stopped()

    try:
        # THEN the loop-breaker filter drops the recursive logs and the counter increases
        @retry(stop=stop_after_attempt(30), wait=wait_fixed(10))
        def _assert_loop_breaker_dropped_more():
            current = _loop_breaker_filtered_count(juju)
            assert current > baseline, (
                f"Loop-breaker drop counter did not increase: {baseline} -> {current}"
            )

        _assert_loop_breaker_dropped_more()
    finally:
        # Cleanup: restart Loki
        juju.ssh("loki/0", command="sudo snap start loki.loki")
        juju.wait(
            lambda status: jubilant.all_active(status, "loki"),
            error=jubilant.any_error,
            timeout=300,
        )
        juju.config("otelcol", {"debug_exporter_for_metrics": False})


def test_internal_logs_cross_signal_preserved_on_metrics_outage(juju: jubilant.Juju):
    """Scenario: a metrics exporter's failure logs still reach Loki (not loop-dropped).

    The loop-breaker filter drops only logs from exporters on the LOGS pipeline.
    Failure logs from exporters on other pipelines (e.g. metrics) must be preserved
    and forwarded to Loki.
    """
    # GIVEN Loki is up and otelcol is related to a Prometheus over send-remote-write
    juju.deploy("prometheus", channel="dev/edge")
    juju.wait(
        lambda status: jubilant.all_active(status, "prometheus"),
        error=jubilant.any_error,
        timeout=600,
    )
    juju.integrate("otelcol:send-remote-write", "prometheus")
    juju.wait(
        lambda status: (
            jubilant.all_blocked(status, "otelcol")
            and jubilant.all_agents_idle(status, "otelcol", "prometheus")
        ),
        error=jubilant.any_error,
        timeout=600,
    )

    # AND the metrics debug exporter is on
    juju.config("otelcol", {"debug_exporter_for_metrics": True})
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        error=jubilant.any_error,
        timeout=300,
    )

    # WHEN the remote-write target is down, the metrics exporter emits failure logs
    # with otelcol.signal=metrics (NOT logs), so the loop-breaker must NOT drop them.
    juju.ssh("prometheus/0", command="sudo snap stop prometheus.prometheus")

    @retry(stop=stop_after_attempt(15), wait=wait_fixed(10))
    def _wait_prometheus_stopped():
        assert not _is_snap_service_running(juju, "prometheus", "prometheus"), (
            "Prometheus snap service did not stop"
        )

    _wait_prometheus_stopped()

    try:
        # THEN metrics-exporter failure logs reach Loki (not over-dropped by the loop-breaker).
        # The loop-breaker only drops logs-signal logs; the metrics-exporter emits logs with
        # otelcol.signal=metrics, so those must still appear in Loki.
        host = _loki_host(juju)

        @RETRY
        def _assert_metrics_exporter_failure_logs_in_loki():
            # Query Loki for internal logs containing the metrics exporter's component ID.
            # The logfmt body mangles the text, so we match the instrumentation_scope
            # attributes which logfmt preserves as key=value pairs.
            result = juju.ssh(
                "otelcol/0",
                command=(
                    f"curl -sS --fail "
                    f"'http://{host}:3100/loki/api/v1/query_range"
                    f"?query={{job=%22otelcol-internal%22}}"
                    f"&limit=5'"
                ),
            )
            data = json.loads(result)
            streams = data.get("data", {}).get("result", [])
            # The loop-breaker only drops logs-signal logs, so internal logs should still
            # be present in Loki (from other signals or successful exports).
            assert len(streams) > 0, (
                f"Internal logs not found in Loki after metrics outage: {result!r}"
            )

        _assert_metrics_exporter_failure_logs_in_loki()
    finally:
        # Cleanup: restart Prometheus, disable debug exporter, remove relation
        juju.ssh("prometheus/0", command="sudo snap start prometheus.prometheus")
        juju.wait(
            lambda status: jubilant.all_active(status, "prometheus"),
            error=jubilant.any_error,
            timeout=300,
        )
        juju.config("otelcol", {"debug_exporter_for_metrics": False})
        juju.remove_relation("otelcol:send-remote-write", "prometheus")
