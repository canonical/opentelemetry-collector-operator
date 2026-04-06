# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: External config routes logs to rsyslog."""

import json
import time
import uuid

import jubilant
from tenacity import retry, stop_after_attempt, wait_fixed
from helpers import PATH_EXCLUDE

RSYSLOG_OUTPUT_FILE = "/var/log/otelcol-integrator.log"
RSYSLOG_REMOTE_PORT = 1514
PATH_EXCLUDE_WITH_REMOTE_LOG = f"{PATH_EXCLUDE};{RSYSLOG_OUTPUT_FILE}*"

ENABLE_IMUDP = (
    "printf '%s\\n' "
    "'module(load=\"imudp\")' "
    "'ruleset(name=\"otelcol_remote_logs\") {' "
    f"'  action(type=\"omfile\" file=\"{RSYSLOG_OUTPUT_FILE}\")' "
    "'  stop' "
    "'}' "
    f"'input(type=\"imudp\" port=\"{RSYSLOG_REMOTE_PORT}\" ruleset=\"otelcol_remote_logs\")' "
    "| sudo tee /etc/rsyslog.d/00-otelcol-imudp.conf >/dev/null"
)

OTELCOL_CONFIG = """receivers:
  loki/external:
    protocols:
      http:
        endpoint: 0.0.0.0:3500

processors:
  transform/body-to-syslog:
    log_statements:
      - context: log
        statements:
          - set(attributes["message"], body)
          - set(attributes["appname"], "otelcol")
          - set(attributes["hostname"], "otelcol")
          - set(attributes["priority"], 14)

exporters:
  syslog/rsyslog:
    endpoint: 127.0.0.1
    port: {rsyslog_port}
    network: udp
    protocol: rfc5424
"""


def setup_rsyslog(juju: jubilant.Juju):
    juju.ssh(
        "ubuntu/0",
        command=(
            f"{ENABLE_IMUDP} && "
            f"sudo install -o syslog -g adm -m 0640 /dev/null {RSYSLOG_OUTPUT_FILE} && "
            "sudo systemctl restart rsyslog.service"
        ),
    )
    listening = juju.ssh(
        "ubuntu/0",
        command=f"sudo ss -lunp | grep ':{RSYSLOG_REMOTE_PORT} ' || true",
    )
    assert f":{RSYSLOG_REMOTE_PORT} " in listening, f"rsyslog is not listening on :{RSYSLOG_REMOTE_PORT}: {listening}"


def push_loki_log_to_otelcol(juju: jubilant.Juju, message: str):
    endpoint = "http://127.0.0.1:3500/loki/api/v1/push"
    timestamp_ns = f"{int(time.time())}000000000"
    payload = {
        "streams": [
            {
                "stream": {"job": "myjob", "hostname": "testhost"},
                "values": [[timestamp_ns, message]],
            }
        ]
    }
    curl_cmd = (
        f"curl -sS --fail -X POST {endpoint} "
        "-H 'Content-Type: application/json' "
        f"--data '{json.dumps(payload, separators=(',', ':'))}'"
    )
    juju.ssh("ubuntu/0", command=curl_cmd)


def push_otlp_log_to_otelcol(juju: jubilant.Juju, message: str):
    endpoint = "http://127.0.0.1:4318/v1/logs"
    timestamp_ns = f"{int(time.time())}000000000"
    payload = {
        "resourceLogs": [
            {
                "scopeLogs": [
                    {
                        "logRecords": [
                            {
                                "timeUnixNano": timestamp_ns,
                                "body": {"stringValue": message},
                            }
                        ]
                    }
                ]
            }
        ]
    }
    curl_cmd = (
        f"curl -sS --fail -X POST {endpoint} "
        "-H 'Content-Type: application/json' "
        f"--data '{json.dumps(payload, separators=(',', ':'))}'"
    )
    juju.ssh("ubuntu/0", command=curl_cmd)


@retry(stop=stop_after_attempt(25), wait=wait_fixed(5))
def assert_log_reaches_rsyslog(juju: jubilant.Juju, message: str):
    output = juju.ssh(
        "ubuntu/0",
        command=f"sudo grep -F -- '{message}' {RSYSLOG_OUTPUT_FILE} || true",
    )
    assert message in output, f"message '{message}' not found in {RSYSLOG_OUTPUT_FILE}"


def test_deploy_and_prepare_otelcol(juju: jubilant.Juju, charm: str):
    # GIVEN ubuntu and otelcol are deployed and related
    juju.deploy("ubuntu", channel="latest/stable", base="ubuntu@22.04")
    juju.wait(
        lambda status: jubilant.all_active(status, "ubuntu"),
        error=lambda status: jubilant.any_error(status, "ubuntu"),
        timeout=420,
    )
    juju.deploy(
        charm,
        app="otelcol",
        config={"path_exclude": PATH_EXCLUDE_WITH_REMOTE_LOG},
    )
    juju.integrate("otelcol:juju-info", "ubuntu:juju-info")
    juju.wait(
        lambda status: jubilant.all_blocked(status, "otelcol"),
        error=lambda status: jubilant.any_error(status, "otelcol", "ubuntu"),
        timeout=420,
    )

    # WHEN otelcol snap is refreshed and rsyslog is prepared
    output = juju.ssh(
        "otelcol/0", command="sudo snap refresh opentelemetry-collector --channel=edge"
    )
    if "refreshed" not in output and "has no updates available" not in output:
        raise Exception(f"opentelemetry-collector not refreshed: {output}")
    setup_rsyslog(juju)


def test_configure_and_relate_otelcol_integrator(juju: jubilant.Juju):
    # GIVEN otelcol-integrator is deployed and configured with external receiver/processor/exporter
    juju.deploy("otelcol-integrator", channel="latest/edge")
    juju.config(
        "otelcol-integrator",
        values={
            "config_yaml": OTELCOL_CONFIG.format(rsyslog_port=RSYSLOG_REMOTE_PORT),
            "logs_pipeline": True,
        },
    )
    juju.wait(
        lambda status: jubilant.all_active(status, "otelcol-integrator"),
        error=lambda status: jubilant.any_error(status, "otelcol-integrator"),
        timeout=420,
    )

    # WHEN otelcol consumes that external-config relation
    juju.integrate("otelcol:external-config", "otelcol-integrator:external-config")

    # THEN all involved apps settle without errors.
    # NOTE: otelcol is expected to remain blocked in this scenario (no outbound relation).
    juju.wait(
        lambda status: (
            jubilant.all_active(status, "ubuntu", "otelcol-integrator")
            and jubilant.all_blocked(status, "otelcol")
            and jubilant.all_agents_idle(status, "ubuntu", "otelcol", "otelcol-integrator")
        ),
        timeout=420,
    )


def test_loki_push_log_reaches_rsyslog(juju: jubilant.Juju):
    # GIVEN an empty target file (truncate in-place to preserve the inode;
    # replacing the file would leave rsyslog writing to the old, unlinked inode)
    juju.ssh("ubuntu/0", command=f"sudo truncate -s 0 {RSYSLOG_OUTPUT_FILE}")
    # WHEN a log is sent to otelcol's Loki endpoint
    message = f"otelcol-external-config-{uuid.uuid4().hex}"
    push_loki_log_to_otelcol(juju, message)

    # THEN it arrives at rsyslog output
    assert_log_reaches_rsyslog(juju, message)


def test_otlp_push_log_reaches_rsyslog(juju: jubilant.Juju):
    # GIVEN an empty target file
    juju.ssh("ubuntu/0", command=f"sudo truncate -s 0 {RSYSLOG_OUTPUT_FILE}")
    # WHEN a log is sent to otelcol's OTLP endpoint
    message = f"otelcol-otlp-{uuid.uuid4().hex}"
    push_otlp_log_to_otelcol(juju, message)

    # THEN it arrives at rsyslog output (OTLP shares the same logs pipeline)
    assert_log_reaches_rsyslog(juju, message)
