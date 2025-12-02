from dataclasses import dataclass
from pathlib import Path
from shutil import copytree
from textwrap import dedent
from unittest.mock import MagicMock, patch

import pytest
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    TLSCertificatesRequiresV4,
)
from ops.testing import Context

from charm import OpenTelemetryCollectorCharm
from config_manager import ConfigManager

CHARM_ROOT = Path(__file__).parent.parent.parent


@pytest.fixture
def unit_id():
    return 0


@pytest.fixture
def app_name():
    return "otelcol"


@pytest.fixture
def unit_name(unit_id, app_name):
    return f"{app_name}/{unit_id}"


@pytest.fixture
def ctx(tmp_path, unit_id, app_name):
    src_dirs = ["grafana_dashboards", "loki_alert_rules", "prometheus_alert_rules", "logrotate.d"]
    # Create a virtual charm_root so Scenario respects the `src_dirs`
    # Related to https://github.com/canonical/operator/issues/1673
    for src_dir in src_dirs:
        source_path = CHARM_ROOT / "src" / src_dir
        target_path = tmp_path / "src" / src_dir
        copytree(source_path, target_path, dirs_exist_ok=True)
    with patch("charm.refresh_certs", lambda: True):
        yield Context(
            OpenTelemetryCollectorCharm, charm_root=tmp_path, unit_id=unit_id, app_name=app_name
        )


@pytest.fixture
def server_cert():
    return "mocked_server_certificate"


@pytest.fixture
def ca_cert():
    return "mocked_ca_certificate"


@pytest.fixture
def private_key():
    return "mocked_private_key"


@dataclass
class Cert:
    raw: str


class MockCertificate:
    def __init__(self, server_cert, ca_cert):
        self.certificate = Cert(server_cert)
        self.ca = Cert(ca_cert)


@pytest.fixture(autouse=True)
def cert_obj(server_cert, ca_cert):
    return MockCertificate(server_cert, ca_cert)


@pytest.fixture
def tls_mock(cert_obj, private_key):
    with (
        patch.object(TLSCertificatesRequiresV4, "_find_available_certificates", return_value=None),
        patch.object(
            TLSCertificatesRequiresV4,
            "get_assigned_certificate",
            return_value=(cert_obj, private_key),
        ),
        patch.object(Certificate, "from_string", return_value=cert_obj),
    ):
        yield


@pytest.fixture(autouse=True)
def juju_hook_name(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("JUJU_HOOK_NAME", "fake")


@pytest.fixture(autouse=True)
def otelcol_version():
    with patch.object(
        OpenTelemetryCollectorCharm, "_otelcol_version", property(lambda *_: "0.0.0")
    ):
        yield OpenTelemetryCollectorCharm


@pytest.fixture(autouse=True)
def mock_lock_dir(tmp_path):
    with patch("singleton_snap.SingletonSnapManager.LOCK_DIR", tmp_path / "lock_dir"):
        yield


@pytest.fixture(autouse=True)
def config_folder(tmp_path):
    config_file = tmp_path / "config.d"
    with patch("charm.CONFIG_FOLDER", config_file):
        yield config_file


@pytest.fixture(autouse=True)
def otelcol_log_file(tmp_path):
    config_file = str(tmp_path / "otelcol.log")
    with patch("config_builder.INTERNAL_TELEMETRY_LOG_FILE", config_file):
        yield config_file


@pytest.fixture
def recv_ca_folder_path(tmp_path):
    """Mock the received CA certificates directory path and ensure it exists."""
    ca_dir = tmp_path / "juju_receive-ca-cert"
    with patch("charm.RECV_CA_CERT_FOLDER_PATH", ca_dir):
        yield ca_dir


@pytest.fixture
def server_cert_paths(tmp_path):
    """Mock the received certificate directories paths and ensure they exists."""
    with patch("charm.SERVER_CERT_PATH", tmp_path / "juju_server-cert") as server_cert:
        with patch("charm.SERVER_CERT_PRIVATE_KEY_PATH", tmp_path / "juju_privkey") as privkey:
            with patch("charm.SERVER_CA_CERT_PATH", tmp_path / "juju_ca-cert") as ca_cert:
                yield server_cert, privkey, ca_cert


@pytest.fixture(autouse=True)
def logrotate_file(tmp_path):
    """Mock the logrotate file path and ensure it exists."""
    with patch("charm.LOGROTATE_PATH", tmp_path / "logrotate.d/otelcol") as logrotate_file:
        yield logrotate_file


@pytest.fixture(autouse=True)
def mock_snap_operations():
    """Mock snap installation and service management operations."""
    # Create a mock for the snap.Snap class
    mock_snap = MagicMock()

    # Configure the mock snap instance
    mock_snap.ensure.return_value = None
    mock_snap.start.return_value = None
    mock_snap.stop.return_value = None
    mock_snap.restart.return_value = None

    # Mock the snap.Snap class to return our mock instance
    with patch("charm.snap.Snap", return_value=mock_snap):
        yield


@pytest.fixture(autouse=True)
def mock_singleton_snap_manager():
    """Mock SingletonSnapManager methods."""
    with patch("singleton_snap.SingletonSnapManager.get_revisions", return_value={1, 2}):
        yield


@pytest.fixture(autouse=True)
def mock_snap_map():
    """Mock SnapMap methods."""
    with patch("snap_management.SnapMap.get_revision", return_value=2):
        yield


@pytest.fixture(autouse=True)
def mock_cos_agent_update_tracing():
    """Mock the COS Agent's update_tracing_receivers method to prevent it from accessing the tracing attribute."""
    with patch(
        "charms.grafana_agent.v0.cos_agent.COSAgentRequirer.update_tracing_receivers",
        return_value=None,
    ):
        yield


@pytest.fixture(autouse=True)
def mock_ensure_certs_dir(request):
    """Mock the _ensure_certs_dir method to avoid PermissionError in tests."""
    with (
        patch("charm.OpenTelemetryCollectorCharm._ensure_certs_dir"),
        patch("charm.CERT_DIR", "/tmp/test_certs"),
    ):
        yield


@pytest.fixture(autouse=True)
def mock_cleanup_certificates_on_remove(request):
    """Mock the _cleanup_certificates_on_remove method to avoid complex dependencies."""
    if "cleanup_certificates_on_remove" in request.node.name:
        yield
    else:
        with patch("charm.OpenTelemetryCollectorCharm._cleanup_certificates_on_remove"):
            yield


@pytest.fixture(autouse=True, scope="function")
def cleanup_temp_files():
    """Clean up any temporary files that might have been created during tests."""
    yield
    # Clean up any remaining temporary directories
    import shutil
    import glob
    import os

    try:
        # Look for any directories in /tmp that match our test pattern
        for temp_dir in glob.glob("/tmp/tmp*/otelcol_*"):
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass


# Certificate testing fixtures
@pytest.fixture
def sample_ca_cert():
    """Sample CA certificate content for testing."""
    return dedent("""\
        -----BEGIN CERTIFICATE-----
        MIIEEzCCAnugAwIBAgIVAO/E0PkhzNYw2zOnc1gUphCXMIbvMA0GCSqGSIb3DQEB
        CwUAMCExDTALBgNVBAoTBEp1anUxEDAOBgNVBAMTB2p1anUtY2EwHhcNMjUxMDE2
        MTM1NzE5WhcNMzUxMDE2MTQwMjE5WjAhMQ0wCwYDVQQKEwRKdWp1MRAwDgYDVQQD
        EwdqdWp1LWNhMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAzpvU/8aa
        RacEOYQkAL1Pi3Ag8wgcSlr3dFyFKfBHJbRDio+kX5W0OWsF2A6BHW7qJB9OuwD3
        4Jk6qMo31HzP7ESNQ9RV2GqANmtz7ykzEBUR29Ql+lcut6LUH9ghCMgnSnY8HuYc
        ez1UhjhvXK86nidlBdf7lP7CamyyJio+q7vgaLjMaz+FQvitB16bvGUcDGaCtD3a
        ZDZPEu5Anzz7IPC3fuH5WdCgzrgi5R+up5H29UaYzCH9yUDiYU286gOowyH4MDgS
        2Kn3BU2+PXrOFtRfmTPxQ6kX0EWEhpNTTU2fnfe6TfZ8OyBT6yGAj6gsbnmSldDa
        KuzqkJWiOlrgYkvTYaYJsa0SAZxyHKOPkF5aah/PNsigi2WdM7BoxcjdjH8MvMYp
        qYwiVrwPDFDa5nzdp6cW9olJ/cdloZW6bVdgKDs3gJIh2dHiV2pW02ulGzg4eqru
        9ib94W1sR+3ELo0M9GrIr3na1G6GSpRLN1kFLP2+daBC6YBI/HzYcepZAgMBAAGj
        QjBAMA4GA1UdDwEB/wQEAwICpDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR3
        8+e1gq/izCNuacdsUjt78PnfpjANBgkqhkiG9w0BAQsFAAOCAYEAp4OXlO6WyGXy
        clts452ujuYuq11EdXUMiYxB8XEfqjoGuhplcLxXeE5nWIU8X7enLSa3TqyqS4F/
        /WnC5SAPu0wPPwOYX5i4Ng9KcBo6vpsBom2TEoeLRRQd9CY4kX2F0+FQQQogtRpy
        yq7WuT0TOloHjN1AVFJZPlGPcxkm7SnqF4a3CwfTKmGrYmjStSHQXYH8A2m+2o6T
        0ilzLSaVKVuKuYfSqgUR2xlJ/3FHb5yvi9Aw0EdneGU+mpAFYlXExxd+qgs1KYTX
        AODWGeScvD+6D8pKsYAkBx2lWMlkLnoJKmohyz0tvdpvXm/paCGeFFiO/5tHd49r
        njnHoRZnhu5yvadsu0kXiEFsLswWj9xe9ONcg9SjMSOQ7q/ucnSAtur3MKSAN/Ub
        boS+t/C7s/Xn9HfNcpM0J0rgrOEWgj+t6YuYTDWEsOXCgnsOTCI4BWSCEpAPwWWN
        6vqscXomNMAY8BLg5W+QVWDIsEwWcgul7zi2EN0CyiLWkuWvTlY5
        -----END CERTIFICATE-----
        """).strip()


# Additional certificate fixtures for testing various scenarios
@pytest.fixture
def sample_incomplete_cert():
    """Sample incomplete CA certificate content for testing."""
    return "-----BEGIN CERTIFICATE-----\nINCOMPLETE_CERT"


@pytest.fixture
def sample_invalid_cert():
    """Sample invalid CA certificate content for testing."""
    return "INVALID_CERT_CONTENT"


@pytest.fixture
def config_manager():
    """Create a ConfigManager instance for testing."""
    return ConfigManager(
        unit_name="test/0",
        global_scrape_interval="15s",
        global_scrape_timeout="",
        insecure_skip_verify=True,
    )
