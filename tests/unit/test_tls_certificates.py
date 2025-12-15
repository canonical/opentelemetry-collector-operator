# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Otelcol server can run in HTTPS mode."""

import json
from unittest.mock import patch

import pytest
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    TLSCertificatesRequiresV4,
)
from helpers import get_otelcol_config_file, get_otelcol_file
from ops.testing import Relation, State

from constants import (
    SERVER_CA_CERT_PATH,
    SERVER_CERT_PATH,
    SERVER_CERT_PRIVATE_KEY_PATH,
)


def no_certs_in_receivers(otelcol_config: dict):
    return not any(
        ("key_file" in protocol.get("tls", {}) or "cert_file" in protocol.get("tls", {}))
        for receiver in otelcol_config["receivers"].values()
        for protocol in receiver.get("protocols", {}).values()
    )


def test_no_tls_certificates_relation(ctx, unit_name, config_folder):
    """Scenario: Otelcol deployed without tls-certificates relation."""
    # GIVEN otelcol deployed in isolation
    ctx.run(ctx.on.update_status(), State())
    # THEN the config file doesn't include "key_file" nor "cert_file"
    assert no_certs_in_receivers(get_otelcol_config_file(unit_name, config_folder))
    # AND WHEN telemetry sources (e.g. flog) join to create a receiver
    data_source = Relation(
        endpoint="receive-loki-logs",
        interface="loki_push_api",
    )
    state_in = State(relations=[data_source])
    ctx.run(ctx.on.update_status(), state_in)
    # THEN receivers in the config file don't include "key_file" nor "cert_file"
    assert no_certs_in_receivers(get_otelcol_config_file(unit_name, config_folder))


def test_waiting_for_cert(ctx):
    """Scenario: a tls-certificates relation joined, but we didn't get the cert yet."""
    # GIVEN otelcol deployed in isolation
    # WHEN a tls-certificates relation joins but the CA didn't reply with a cert yet
    ssc = Relation(
        endpoint="receive-server-cert",
        interface="tls-certificate",
    )
    state_in = State(relations=[ssc])
    state_out = ctx.run(ctx.on.update_status(), state=state_in)
    # THEN the charm is in waiting state
    assert state_out.unit_status.name == "waiting"
    assert "waiting for a cert" in state_out.unit_status.message


def test_transitioned_from_http_to_https_to_http(
    ctx, unit_name, cert_obj, private_key, server_cert, ca_cert, config_folder, server_cert_paths
):
    """Scenario: a tls-certificates relation joins and is later removed."""
    # GIVEN otelcol has received a cert
    ssc = Relation(
        endpoint="receive-server-cert",
        interface="tls-certificate",
    )
    data_sink = Relation(
        endpoint="send-loki-logs",
        interface="loki_push_api",
        remote_units_data={
            0: {"endpoint": '{"url": "http://fqdn-0:3100/loki/api/v1/push"}'},
        },
    )
    state_in = State(relations=[ssc, data_sink])
    # Note: We patch the cert creation process on disk since it requires a dynamic cert, CSR, CA,
    # and cert chain in the remote app databag
    with patch.object(
        TLSCertificatesRequiresV4, "_find_available_certificates", return_value=None
    ), patch.object(
        TLSCertificatesRequiresV4, "get_assigned_certificate", return_value=(cert_obj, private_key)
    ), patch.object(Certificate, "from_string", return_value=cert_obj):
        ctx.run(ctx.on.update_status(), state=state_in)
    # THEN the cert and private key files were written to disk
    assert server_cert == get_otelcol_file(server_cert_paths[0])
    assert private_key == get_otelcol_file(server_cert_paths[1])
    assert ca_cert == get_otelcol_file(server_cert_paths[2])
    otelcol_config = get_otelcol_config_file(unit_name, config_folder)
    # AND config file includes "key_file" and "cert_file" for receivers with a "protocols" section
    protocols = otelcol_config["receivers"]["otlp/juju-abcde-0"]["protocols"]
    for protocol in protocols:
        assert protocols[protocol]["tls"]["cert_file"] == SERVER_CERT_PATH
        assert protocols[protocol]["tls"]["key_file"] == SERVER_CERT_PRIVATE_KEY_PATH
    # WHEN the tls-certificates relation is removed
    state_in = State(relations=[data_sink])
    ctx.run(ctx.on.update_status(), state=state_in)
    # THEN the config file doesn't include "key_file" nor "cert_file" for all receivers
    otelcol_config = get_otelcol_config_file(unit_name, config_folder)
    assert no_certs_in_receivers(otelcol_config)
    # AND the cert and private key files are not on disk
    with pytest.raises(AssertionError, match="file does not exist"):
        get_otelcol_file(SERVER_CERT_PATH)
    with pytest.raises(AssertionError, match="file does not exist"):
        get_otelcol_file(SERVER_CA_CERT_PATH)
    with pytest.raises(AssertionError, match="file does not exist"):
        get_otelcol_file(SERVER_CERT_PRIVATE_KEY_PATH)

@pytest.mark.skip(reason="https://github.com/canonical/operator/issues/1858")
def test_https_endpoint_is_provided(ctx, cert_obj, private_key):
    """Scenario: Otelcol provides other charms its TLS endpoint."""
    # GIVEN otelcol is in TLS mode
    ssc = Relation(
        endpoint="receive-server-cert",
        interface="tls-certificate",
    )
    data_source = Relation(
        endpoint="receive-loki-logs",
        interface="loki_push_api",
    )
    state_in = State(relations=[ssc, data_source])
    # WHEN a relation_changed event on the "receive-loki-logs" endpoint fires
    state_out = ctx.run(ctx.on.relation_changed(data_source), state=state_in)
    # THEN Otelcol provides its TLS endpoint in the databag
    for relation in state_out.relations:
        if relation.endpoint == "receive-loki-logs":
            assert "https" in json.loads(relation.local_unit_data["endpoint"])["url"]
