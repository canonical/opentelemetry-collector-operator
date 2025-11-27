from dataclasses import dataclass
from pathlib import Path
from shutil import copytree
from textwrap import dedent
from unittest.mock import MagicMock, patch
import tempfile

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
    src_dirs = ["grafana_dashboards", "loki_alert_rules", "prometheus_alert_rules"]
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
    with patch.object(
        TLSCertificatesRequiresV4, "_find_available_certificates", return_value=None
    ), patch.object(
        TLSCertificatesRequiresV4, "get_assigned_certificate", return_value=(cert_obj, private_key)
    ), patch.object(Certificate, "from_string", return_value=cert_obj):
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
    with patch("charm.OpenTelemetryCollectorCharm._ensure_certs_dir"), \
         patch("charm.CERT_DIR", "/tmp/test_certs"):
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
        MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
        BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
        aWRnaXRzIFB0eUzMkQwHhcNMTMwOTEyMjE1MjAyWhcNMTQwOTEyMjE1MjAyWjBF
        MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
        ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
        CgKCAQEAwxKxPqB/NBOOfJUA9t4gCjGcNnHvEjQc8g8MJp8qN3lqf8d4d8d4d8d4
        d8d4d8d8d8d8d4d8d8d4d8d8d4d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d4d8d4d8d4d8d4d
        -----END CERTIFICATE-----""").strip()


@pytest.fixture
def second_ca_cert():
    """Second sample CA certificate for testing multiple certificates."""
    return dedent("""\
        -----BEGIN CERTIFICATE-----
        MIIDXjCCAkYCCQCCKpT1rYK7pzANBgkqhkiG9w0BAQFADCBiDELMAkGA1UEBhMC
        -----END CERTIFICATE-----""").strip()


@pytest.fixture
def mock_charm():
    """Create a mock charm instance for testing."""
    # Create the charm with proper mocking
    with patch('charm.OpenTelemetryCollectorCharm.__init__') as mock_init:
        # Mock the framework to avoid breakpoint issues
        mock_framework = MagicMock()
        mock_framework.breakpoint = MagicMock()

        # Set up the unit mock for certificate directory isolation
        mock_unit = MagicMock()
        mock_unit.name = "otelcol/0"

        def init_side_effect(self, *args, **kwargs):
            self.unit = mock_unit
            self.framework = mock_framework
            return

        mock_init.side_effect = init_side_effect

        charm = OpenTelemetryCollectorCharm(MagicMock())

        # Create proper method mocks
        def write_ca_certificates_to_disk(scrape_jobs):
            """Mock implementation of _write_ca_certificates_to_disk."""
            cert_paths = {}
            for job in scrape_jobs:
                tls_config = job.get("tls_config", {})
                ca_content = tls_config.get("ca")

                # Skip jobs without valid certificate content
                if not ca_content or not ca_content.strip().startswith("-----BEGIN CERTIFICATE-----"):
                    continue

                job_name = job.get("job_name", "default")
                safe_job_name = job_name.replace("/", "_").replace(" ", "_").replace("-", "_")
                # Just return expected paths for tests
                cert_paths[job_name] = f"/var/snap/opentelemetry-collector/common/certs/otel_{safe_job_name}_ca.pem"

            return cert_paths

        def ensure_certs_dir():
            """Mock implementation of _ensure_certs_dir."""
            pass  # Just succeed

        # Assign the mocks directly to avoid __get__ issues
        charm._write_ca_certificates_to_disk = write_ca_certificates_to_disk
        charm._ensure_certs_dir = ensure_certs_dir

        return charm


@pytest.fixture
def config_manager():
    """Create a ConfigManager instance for testing."""
    return ConfigManager(
        unit_name="test/0",
        global_scrape_interval="15s",
        global_scrape_timeout="",
        insecure_skip_verify=True,
    )


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)
