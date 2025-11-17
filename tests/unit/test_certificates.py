"""Unit tests for certificate handling functionality in machine charm."""

import pytest
from unittest.mock import MagicMock, patch


# Tests for _write_ca_certificates_to_disk method
@pytest.mark.parametrize(
    "jobs,expected_cert_mapping",
    [
        # Single job with simple name
        (
            [
                {
                    "job_name": "juju-controller",
                    "tls_config": {
                        "ca_file": "sample_ca_cert",  # Will be replaced with fixture
                        "insecure_skip_verify": False
                    }
                }
            ],
            {"juju-controller": "/var/snap/opentelemetry-collector/common/certs/otel_juju_controller_ca.pem"}
        ),
        # Single job with filename sanitization
        (
            [
                {
                    "job_name": "test/job with spaces-and-dashes",
                    "tls_config": {
                        "ca_file": "sample_ca_cert",  # Will be replaced with fixture
                        "insecure_skip_verify": False
                    }
                }
            ],
            {"test/job with spaces-and-dashes": "/var/snap/opentelemetry-collector/common/certs/otel_test_job_with_spaces_and_dashes_ca.pem"}
        ),
        # Multiple jobs with different certificates
        (
            [
                {
                    "job_name": "job-1",
                    "tls_config": {
                        "ca_file": "sample_ca_cert",  # Will be replaced with fixture
                        "insecure_skip_verify": False
                    }
                },
                {
                    "job_name": "job-2",
                    "tls_config": {
                        "ca_file": "second_ca_cert",  # Will be replaced with fixture
                        "insecure_skip_verify": False
                    }
                }
            ],
            {
                "job-1": "/var/snap/opentelemetry-collector/common/certs/otel_job_1_ca.pem",
                "job-2": "/var/snap/opentelemetry-collector/common/certs/otel_job_2_ca.pem"
            }
        ),
    ],
)
def test_write_certificates_to_disk_scenarios(mock_charm, sample_ca_cert, second_ca_cert, jobs, expected_cert_mapping):
    """Test various scenarios for writing CA certificates to disk."""
    # Replace certificate placeholders with actual fixtures
    cert_mapping = {"sample_ca_cert": sample_ca_cert, "second_ca_cert": second_ca_cert}

    for job in jobs:
        ca_file_key = job["tls_config"]["ca_file"]
        job["tls_config"]["ca_file"] = cert_mapping[ca_file_key]

    # Execute
    with patch('charm.Path') as mock_path_class:
        mock_cert_dir = MagicMock()
        mock_cert_dir.mkdir = MagicMock()

        # Create mock files dynamically based on expected mapping
        mock_files = {}
        for job_name, expected_path in expected_cert_mapping.items():
            mock_file = MagicMock()
            mock_file.write_text = MagicMock()
            mock_file.chmod = MagicMock()
            mock_file.__str__ = MagicMock(return_value=expected_path)
            mock_files[job_name] = mock_file

        # Configure __truediv__ to return appropriate mocks
        def truediv_side_effect(path):
            for job_name, expected_path in expected_cert_mapping.items():
                safe_name = job_name.replace("-", "_").replace("/", "_").replace(" ", "_")
                if safe_name in path:
                    return mock_files[job_name]
            return MagicMock()

        mock_cert_dir.__truediv__ = MagicMock(side_effect=truediv_side_effect)
        mock_path_class.return_value = mock_cert_dir

        result = mock_charm._write_ca_certificates_to_disk(jobs)

    # Verify results
    assert len(result) == len(expected_cert_mapping)
    for job_name, expected_path in expected_cert_mapping.items():
        assert job_name in result
        assert result[job_name] == expected_path

    # Verify file operations
    for mock_file in mock_files.values():
        mock_file.write_text.assert_called_once()
        mock_file.chmod.assert_called_once_with(0o644)


@pytest.mark.parametrize(
    "jobs,expected_count",
    [
        # Jobs without certificate content - should return empty
        ([
            {
                "job_name": "test-job",
                "tls_config": {"insecure_skip_verify": True}
            }
        ], 0),
        # Jobs with file path instead of content - should return empty
        ([
            {
                "job_name": "test-job-with-file-path",
                "tls_config": {
                    "ca_file": "/existing/path/to/cert.pem",
                    "insecure_skip_verify": False
                }
            }
        ], 0),
        # Empty tls_config
        ([
            {
                "job_name": "test-job",
                "tls_config": {}
            }
        ], 0),
    ],
)
def test_write_certificates_to_disk_no_certificates(mock_charm, jobs, expected_count):
    """Test cases where no certificates should be processed."""
    with patch('charm.Path') as mock_path_class:
        mock_cert_dir = MagicMock()
        mock_path_class.return_value = mock_cert_dir

        with patch.object(mock_charm, '_ensure_certs_dir'):
            result = mock_charm._write_ca_certificates_to_disk(jobs)

    # Verify - no certificates should be processed
    assert len(result) == expected_count
    mock_cert_dir.mkdir.assert_not_called()


def test_write_certificates_to_disk_directory_creation(mock_charm, sample_ca_cert):
    """Test that the certificate directory is created when needed."""
    jobs = [
        {
            "job_name": "juju-controller",
            "tls_config": {
                "ca_file": sample_ca_cert,
                "insecure_skip_verify": False
            }
        }
    ]

    with patch('charm.Path') as mock_path_class:
        mock_cert_dir = MagicMock()
        mock_cert_dir.mkdir = MagicMock()
        mock_cert_dir.chmod = MagicMock()
        mock_cert_dir.exists.return_value = False  # Directory doesn't exist, so mkdir should be called
        mock_cert_file = MagicMock()
        mock_cert_file.write_text = MagicMock()
        mock_cert_file.chmod = MagicMock()
        mock_cert_file.__str__ = MagicMock(return_value="/var/snap/opentelemetry-collector/common/certs/otel_juju_controller_ca.pem")

        mock_cert_dir.__truediv__ = MagicMock(return_value=mock_cert_file)
        mock_path_class.return_value = mock_cert_dir

        result = mock_charm._write_ca_certificates_to_disk(jobs)

    # Verify that the certificate is written and directory is created
    assert len(result) == 1
    assert "juju-controller" in result
    assert result["juju-controller"] == "/var/snap/opentelemetry-collector/common/certs/otel_juju_controller_ca.pem"

    # Verify file operations
    mock_cert_file.write_text.assert_called_once_with(sample_ca_cert)
    mock_cert_file.chmod.assert_called_once_with(0o644)


def test_write_certificates_to_disk_file_write_error(mock_charm, sample_ca_cert):
    """Test that file write errors are handled gracefully."""
    jobs = [
        {
            "job_name": "juju-controller",
            "tls_config": {
                "ca_file": sample_ca_cert,
                "insecure_skip_verify": False
            }
        }
    ]

    with patch('charm.Path') as mock_path_class:
        mock_cert_dir = MagicMock()
        mock_cert_file = MagicMock()
        # Mock file write to raise an exception
        mock_cert_file.write_text = MagicMock(side_effect=OSError("Permission denied"))
        mock_cert_file.chmod = MagicMock()

        mock_cert_dir.__truediv__ = MagicMock(return_value=mock_cert_file)
        mock_path_class.return_value = mock_cert_dir

        with patch.object(mock_charm, '_ensure_certs_dir'):
            result = mock_charm._write_ca_certificates_to_disk(jobs)

    # Verify that failed certificate is not included in results
    assert len(result) == 0
    assert "juju-controller" not in result


# Tests for update_jobsWithCAPaths method
@pytest.mark.parametrize(
    "jobs,cert_paths,expected_results",
    [
        # Jobs with matching names should get updated
        (
            [
                {
                    "job_name": "job-with-cert",
                    "tls_config": {
                        "ca_file": "original_cert_content",
                        "insecure_skip_verify": False
                    }
                },
                {
                    "job_name": "job-without-cert",
                    "tls_config": {
                        "insecure_skip_verify": True
                    }
                }
            ],
            {"job-with-cert": "/var/snap/opentelemetry-collector/common/certs/otel_job_with_cert_ca.pem"},
            [
                {
                    "job_name": "job-with-cert",
                    "tls_config": {
                        "ca_file": "/var/snap/opentelemetry-collector/common/certs/otel_job_with_cert_ca.pem",
                        "insecure_skip_verify": False
                    }
                },
                {
                    "job_name": "job-without-cert",
                    "tls_config": {
                        "insecure_skip_verify": True
                    }
                }
            ]
        ),
        # Jobs without tls_config should get config added
        (
            [{"job_name": "test-job"}],
            {"test-job": "/var/snap/opentelemetry-collector/common/certs/otel_test_job_ca.pem"},
            [
                {
                    "job_name": "test-job",
                    "tls_config": {
                        "ca_file": "/var/snap/opentelemetry-collector/common/certs/otel_test_job_ca.pem"
                    }
                }
            ]
        ),
    ],
)
def test_update_jobs_with_ca_paths_various_scenarios(config_manager, jobs, cert_paths, expected_results):
    """Test various scenarios for updating jobs with certificate paths."""
    # Execute
    result = config_manager.update_jobs_with_ca_paths(jobs, cert_paths)

    # Verify
    assert len(result) == len(expected_results)
    for i, expected_job in enumerate(expected_results):
        assert result[i]["job_name"] == expected_job["job_name"]
        if "tls_config" in expected_job:
            assert "tls_config" in result[i]
            assert result[i]["tls_config"] == expected_job["tls_config"]
        else:
            assert "tls_config" not in result[i]


@pytest.mark.parametrize(
    "job_name,cert_paths,expected_ca_file",
    [
        # No matching cert path - should remain unchanged
        ("test-job", {"different-job": "/path/to/cert.pem"}, "original_cert_content"),
        # Empty cert paths - should remain unchanged
        ("test-job", {}, "original_cert_content"),
        # Default job name with matching cert - should be updated
        ("default", {"default": "/var/snap/opentelemetry-collector/common/certs/otel_default_ca.pem"}, "/var/snap/opentelemetry-collector/common/certs/otel_default_ca.pem"),
    ],
)
def test_update_jobs_with_ca_paths_no_changes(config_manager, job_name, cert_paths, expected_ca_file):
    """Test cases where jobs should remain unchanged."""
    # Test data
    jobs = [
        {
            "job_name": job_name,
            "tls_config": {
                "ca_file": "original_cert_content",
                "insecure_skip_verify": False
            }
        }
    ]

    # Execute
    result = config_manager.update_jobs_with_ca_paths(jobs, cert_paths)

    # Verify - job should remain unchanged
    assert len(result) == 1
    assert result[0]["tls_config"]["ca_file"] == expected_ca_file


def test_update_jobs_with_ca_paths_preserves_other_config(config_manager):
    """Test that other TLS configuration is preserved when updating ca_file."""
    jobs = [
        {
            "job_name": "test-job",
            "tls_config": {
                "ca_file": "original_cert_content",
                "insecure_skip_verify": False,
                "server_name": "example.com"
            }
        }
    ]

    cert_paths = {
        "test-job": "/var/snap/opentelemetry-collector/common/certs/otel_test_job_ca.pem"
    }

    result = config_manager.update_jobs_with_ca_paths(jobs, cert_paths)

    assert len(result) == 1
    assert result[0]["tls_config"]["ca_file"] == "/var/snap/opentelemetry-collector/common/certs/otel_test_job_ca.pem"
    assert not result[0]["tls_config"]["insecure_skip_verify"]
    assert result[0]["tls_config"]["server_name"] == "example.com"

# Integration test - end-to-end flow
def test_ensure_certs_dir_creates_directory_when_not_exists():
    """Test that _ensure_certs_dir creates directory when it doesn't exist."""
    from charm import OpenTelemetryCollectorCharm

    with patch('charm.Path') as mock_path_class:
        mock_cert_dir = MagicMock()
        mock_cert_dir.exists.return_value = False
        mock_cert_dir.mkdir = MagicMock()
        mock_cert_dir.chmod = MagicMock()
        mock_path_class.return_value = mock_cert_dir

        # Create a partial mock that doesn't call __init__
        charm = object.__new__(OpenTelemetryCollectorCharm)
        charm._ensure_certs_dir = OpenTelemetryCollectorCharm._ensure_certs_dir.__get__(charm, OpenTelemetryCollectorCharm)

        # Call the method
        charm._ensure_certs_dir()

        # Verify directory creation
        mock_cert_dir.mkdir.assert_called_once_with(parents=True, exist_ok=True)
        mock_cert_dir.chmod.assert_called_once_with(0o755)


def test_ensure_certs_dir_skips_when_directory_exists():
    """Test that _ensure_certs_dir skips creation when directory exists."""
    from charm import OpenTelemetryCollectorCharm

    with patch('charm.Path') as mock_path_class:
        mock_cert_dir = MagicMock()
        mock_cert_dir.exists.return_value = True
        mock_cert_dir.mkdir = MagicMock()
        mock_cert_dir.chmod = MagicMock()
        mock_path_class.return_value = mock_cert_dir

        # Create a partial mock that doesn't call __init__
        charm = object.__new__(OpenTelemetryCollectorCharm)
        charm._ensure_certs_dir = OpenTelemetryCollectorCharm._ensure_certs_dir.__get__(charm, OpenTelemetryCollectorCharm)

        # Call the method
        charm._ensure_certs_dir()

        # Verify directory creation is NOT called
        mock_cert_dir.mkdir.assert_not_called()
        mock_cert_dir.chmod.assert_not_called()


def test_certificate_integration_end_to_end(mock_charm, config_manager, sample_ca_cert, second_ca_cert):
    """Test the complete certificate processing flow end-to-end."""
    # Create jobs with certificates
    jobs = [
        {
            "job_name": "juju-controller",
            "tls_config": {
                "ca_file": sample_ca_cert,
                "insecure_skip_verify": False
            }
        },
        {
            "job_name": "monitoring-service",
            "tls_config": {
                "ca_file": second_ca_cert,
                "insecure_skip_verify": False
            }
        }
    ]

    # Expected paths for verification
    expected_paths = {
        "juju-controller": "/var/snap/opentelemetry-collector/common/certs/otel_juju_controller_ca.pem",
        "monitoring-service": "/var/snap/opentelemetry-collector/common/certs/otel_monitoring_service_ca.pem"
    }

    # Mock file operations
    with patch('charm.Path') as mock_path_class:
        mock_cert_dir = MagicMock()

        # Create mock files for each certificate
        mock_controller_file = MagicMock()
        mock_controller_file.write_text = MagicMock()
        mock_controller_file.chmod = MagicMock()
        mock_controller_file.__str__ = MagicMock(return_value=expected_paths["juju-controller"])

        mock_monitoring_file = MagicMock()
        mock_monitoring_file.write_text = MagicMock()
        mock_monitoring_file.chmod = MagicMock()
        mock_monitoring_file.__str__ = MagicMock(return_value=expected_paths["monitoring-service"])

        # Configure __truediv__ to return different mocks based on the path
        def truediv_side_effect(path):
            if "juju_controller" in path:
                return mock_controller_file
            if "monitoring_service" in path:
                return mock_monitoring_file
            return MagicMock()

        mock_cert_dir.__truediv__ = MagicMock(side_effect=truediv_side_effect)
        mock_path_class.return_value = mock_cert_dir

        # Step 1: Write certificates
        cert_paths = mock_charm._write_ca_certificates_to_disk(jobs)

        # Step 2: Update jobs with certificate paths
        updated_jobs = config_manager.update_jobs_with_ca_paths(jobs, cert_paths)

    # Verify end-to-end results
    assert len(cert_paths) == 2
    assert len(updated_jobs) == 2

    # Verify certificate paths
    assert "juju-controller" in cert_paths
    assert "monitoring-service" in cert_paths
    assert cert_paths["juju-controller"] == expected_paths["juju-controller"]
    assert cert_paths["monitoring-service"] == expected_paths["monitoring-service"]

    # Verify updated jobs
    for job in updated_jobs:
        job_name = job["job_name"]
        assert job_name in expected_paths
        assert job["tls_config"]["ca_file"] == expected_paths[job_name]
        assert not job["tls_config"]["insecure_skip_verify"]

    # Verify file operations
    mock_controller_file.write_text.assert_called_once_with(sample_ca_cert)
    mock_controller_file.chmod.assert_called_once_with(0o644)
    mock_monitoring_file.write_text.assert_called_once_with(second_ca_cert)
    mock_monitoring_file.chmod.assert_called_once_with(0o644)
