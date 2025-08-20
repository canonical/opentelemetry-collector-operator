import json
from unittest.mock import patch

import pytest
from ops.testing import Relation, State

from charms.tls_certificates_interface.v4.tls_certificates import (
    TLSCertificatesRequiresV4,
    Certificate,
)
from tests.unit.helpers import get_otelcol_file


@pytest.fixture
def tls_mock(cert_obj, private_key):
    with patch.object(
        TLSCertificatesRequiresV4, "_find_available_certificates", return_value=None
    ), patch.object(
        TLSCertificatesRequiresV4, "get_assigned_certificate", return_value=(cert_obj, private_key)
    ), patch.object(Certificate, "from_string", return_value=cert_obj):
        yield

def test_profiling_pipeline_disabled_by_default(ctx, unit_name, config_folder):
    """Scenario: we don't have a profiling relation."""
    # GIVEN otelcol deployed in isolation
    state_in = State()
    ctx.run(ctx.on.update_status(), state=state_in)

    # THEN the there is no `profiling` pipeline
    cfg = get_otelcol_file(unit_name, config_folder)
    assert 'profiles' not in cfg['service']['pipelines']
    assert not any('profiling' in exporter_name for exporter_name in cfg['exporters'])


@pytest.mark.parametrize("insecure_skip_verify", (True, False))
@pytest.mark.parametrize("insecure", (True, False))
def test_send_profiles_integration(ctx, insecure_skip_verify, insecure, unit_name, config_folder):
    """Scenario: a profiling relation joined and sent us a grpc endpoint."""
    # GIVEN otelcol deployed in isolation

    pyro_url = "my.fqdn.cluster.local:12345"
    # WHEN a profiling relation joins and pyroscope sent an endpoint
    send_profiles = Relation(
        endpoint="send-profiles",
        remote_app_data={
            "otlp_grpc_endpoint_url": json.dumps(pyro_url),
            "insecure": json.dumps(insecure),
        }
    )
    state_in = State(relations=[send_profiles],
                     config={"tls_insecure_skip_verify": insecure_skip_verify})
    ctx.run(ctx.on.update_status(), state=state_in)

    # THEN the profiling pipeline contains an exporter to the expected url
    cfg = get_otelcol_file(unit_name, config_folder)
    assert cfg['service']['pipelines']['profiles']['exporters'][0] == 'otlp/profiling/0'
    assert cfg['service']['pipelines']['profiles']['receivers'][0] == "otlp"
    assert cfg['exporters']['otlp/profiling/0']['endpoint'] == pyro_url
    tls_config = cfg["exporters"]["otlp/profiling/0"]["tls"]
    assert tls_config["insecure"] is insecure
    assert tls_config["insecure_skip_verify"] == insecure_skip_verify


@patch("socket.getfqdn", return_value="localhost")
@pytest.mark.parametrize("insecure_skip_verify", (True, False))
def test_receive_profiles_integration(sock_mock, ctx, insecure_skip_verify, unit_name, config_folder):
    """Scenario: a receive-profiles relation joined."""
    # GIVEN otelcol deployed in isolation
    # WHEN a receive-profiles relation joins and pyroscope sent an endpoint
    receive_profiles = Relation(
        endpoint="receive-profiles"
    )
    state_in = State(relations=[receive_profiles],
                     config={"tls_insecure_skip_verify": insecure_skip_verify},
                     leader=True)
    state_out = ctx.run(ctx.on.update_status(), state=state_in)

    # THEN the profiling pipeline contains a profiling pipeline, but no exporters other than debug
    cfg = get_otelcol_file(unit_name,config_folder)
    assert cfg['service']['pipelines']['profiles']['exporters'] == ['debug']

    # AND we publish to app databag our profile ingestion endpoints for otlp_http and otlp_grpc
    receive_profiles_app_data = state_out.get_relation(receive_profiles.id).local_app_data
    assert receive_profiles_app_data['otlp_grpc_endpoint_url']


@pytest.mark.parametrize("insecure_skip_verify", (True, False))
@pytest.mark.parametrize("insecure", (True, False))
@pytest.mark.usefixtures("server_cert_paths", "recv_ca_folder_path", "tls_mock")
def test_profiling_integration_tls(ctx, unit_name, insecure, config_folder, insecure_skip_verify):
    """Scenario: a profiling relation joined and sent us a grpc endpoint."""
    # GIVEN otelcol deployed with self-signed-certs
    # Relation 1
    cert1a = "-----BEGIN CERTIFICATE-----\n ... cert1a ... \n-----END CERTIFICATE-----"
    cert1b = "-----BEGIN CERTIFICATE-----\n ... cert1b ... \n-----END CERTIFICATE-----"

    # Relation 2
    cert2a = "-----BEGIN CERTIFICATE-----\n ... cert2a ... \n-----END CERTIFICATE-----"
    cert2b = "-----BEGIN CERTIFICATE-----\n ... cert2b ... \n-----END CERTIFICATE-----"
    server_cert_rel = Relation(
        endpoint="receive-server-cert",
        remote_app_data={"certificates": json.dumps([cert1a, cert1b])}
    )
    ca_cert_rel = Relation(
        "receive-ca-cert", remote_app_data={"certificates": json.dumps([cert2a, cert2b])}
    )

    pyro_url = "my.fqdn.cluster.local:12345"
    # WHEN a profiling relation joins and pyroscope sent an endpoint
    profiling = Relation(
        endpoint="send-profiles",
        remote_app_data={
            "otlp_grpc_endpoint_url": json.dumps(pyro_url),
            "insecure": json.dumps(insecure),
        }
    )
    state_in = State(relations=[profiling, server_cert_rel, ca_cert_rel],
                     config={"tls_insecure_skip_verify": insecure_skip_verify})

    with patch("charm.refresh_certs", lambda: True):
        ctx.run(ctx.on.update_status(), state=state_in)

    # THEN  the profiling pipeline contains an exporter to the expected url
    cfg = get_otelcol_file(unit_name, config_folder)
    assert cfg['service']['pipelines']['profiles']['exporters'][0] == 'otlp/profiling/0'
    assert cfg['exporters']['otlp/profiling/0']['endpoint'] == pyro_url
    tls_config = cfg["exporters"]["otlp/profiling/0"]["tls"]
    assert tls_config["insecure"] is insecure
    assert tls_config["insecure_skip_verify"] == insecure_skip_verify
