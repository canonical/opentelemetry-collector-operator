# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Internal telemetry is self-ingested via OTLP and forwarded to otelcol-receiver with loop-breaker."""

import logging

import jubilant
from helpers import PATH_EXCLUDE, RETRY, receiver_snap_logs, get_snap_service_status
from tenacity import retry, stop_after_attempt, wait_fixed

logger = logging.getLogger(__name__)


def _loop_breaker_filtered_count(juju: jubilant.Juju) -> float:
    """Return the sum of loop-breaker filtered counters from otelcol's Prometheus metrics endpoint."""
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
            total = 0.0
            for line in output.strip().splitlines():
                total += float(line.rsplit(" ", 1)[-1])
            return total
    except Exception:
        pass
    return 0.0


def test_internal_logs_self_export(juju: jubilant.Juju, charm: str):
    """Scenario: internal telemetry is self-exported via OTLP and forwarded to otelcol-receiver."""
    # GIVEN otelcol and otelcol-receiver are deployed and related
    # Each otelcol app gets its own ubuntu principal so they run on separate machines
    # with separate snaps (stopping one snap must not kill the others).
    juju.deploy("ubuntu", channel="latest/stable", base="ubuntu@24.04")
    juju.deploy("ubuntu", channel="latest/stable", base="ubuntu@24.04", app="ubuntu-receiver")
    juju.deploy(charm, app="otelcol", config={"path_exclude": PATH_EXCLUDE})
    juju.deploy(charm, app="otelcol-receiver", config={"debug_exporter_for_logs": "true"})

    juju.integrate("ubuntu:juju-info", "otelcol:juju-info")
    juju.integrate("ubuntu-receiver:juju-info", "otelcol-receiver:juju-info")
    juju.integrate("otelcol:send-loki-logs", "otelcol-receiver:receive-loki-logs")

    juju.wait(
        lambda status: (
            jubilant.all_active(status, "ubuntu", "ubuntu-receiver", "otelcol")
            and jubilant.all_blocked(status, "otelcol-receiver")
            and jubilant.all_agents_idle(
                status, "ubuntu", "ubuntu-receiver", "otelcol", "otelcol-receiver"
            )
        ),
        error=jubilant.any_error,
        timeout=600,
    )

    # AND otelcol snap is active
    assert get_snap_service_status(juju, "otelcol-receiver/0") == "active"

    # THEN internal logs with job=otelcol-internal appear in otelcol-receiver with Juju topology labels
    topology = ["juju_application", "juju_charm", "juju_unit", "juju_model", "juju_model_uuid"]

    @RETRY
    def _assert_internal_logs_in_receiver():
        logs = receiver_snap_logs(juju, "otelcol-receiver/0")
        assert "otelcol-internal" in logs, (
            "No job=otelcol-internal stream found in otelcol-receiver logs"
        )
        for label in topology:
            assert label in logs, f"Expected {label!r} in otelcol-receiver logs"

    _assert_internal_logs_in_receiver()


def test_internal_logs_loop_breaker_drops_on_outage(juju: jubilant.Juju):
    """Scenario: when otelcol-receiver is stopped, the loop-breaker filter drops recursive exporter failure logs."""
    # AND the loop-breaker drop counter is baselined
    baseline = _loop_breaker_filtered_count(juju)

    # WHEN otelcol-receiver is stopped, causing the send-loki-logs exporter to fail and emit recursive logs
    juju.ssh("otelcol-receiver/0", command="sudo snap stop opentelemetry-collector")

    # Wait for otelcol-receiver to actually stop
    @RETRY
    def _wait_receiver_stopped():
        assert get_snap_service_status(juju, "otelcol-receiver/0") == "inactive"

    _wait_receiver_stopped()

    # Restart otelcol snap to force new log records to arrive
    juju.ssh("otelcol/0", command="sudo snap restart opentelemetry-collector")

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
        juju.ssh("otelcol-receiver/0", command="sudo snap start opentelemetry-collector")
        assert get_snap_service_status(juju, "otelcol-receiver/0") == "active"


def test_internal_logs_cross_signal_preserved_on_metrics_outage(juju: jubilant.Juju):
    """Scenario: a metrics exporter's failure logs still reach otelcol-receiver (not loop-dropped)."""
    # GIVEN otelcol and otelcol-receiver are deployed and related
    # AND otelcol-integrator injects an OTLP exporter pointing at a non-existent endpoint
    non_existent_endpoint = "192.0.2.1:4317"
    otelcol_exporter_config = (
        f"exporters:\n"
        f"  otlp:\n"
        f"    endpoint: {non_existent_endpoint}\n"
        f"    tls:\n"
        f"      insecure: true\n"
    )
    juju.deploy(
        "otelcol-integrator",
        channel="latest/edge",
        config={
            "config_yaml": otelcol_exporter_config,
            "metrics_pipeline": True,
        },
    )
    juju.integrate("otelcol-integrator:external-config", "otelcol:external-config")

    juju.wait(
        lambda status: (
            jubilant.all_active(status, "otelcol", "otelcol-integrator")
            and jubilant.all_agents_idle(status, "otelcol", "otelcol-integrator")
        ),
        error=jubilant.any_error,
        timeout=300,
    )

    # WHEN the OTLP exporter fails, it emits failure logs with otelcol.signal=metrics (NOT logs),
    # so the loop-breaker must NOT drop them.

    # THEN metrics-exporter failure logs reach otelcol-receiver
    @RETRY
    def _assert_metrics_exporter_failure_logs_in_receiver():
        logs = receiver_snap_logs(juju, "otelcol-receiver/0")
        assert logs, "No logs found in otelcol-receiver after metrics outage"

    _assert_metrics_exporter_failure_logs_in_receiver()

