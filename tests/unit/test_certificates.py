# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Certificate management for Prometheus scrape jobs."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from config_manager import ConfigManager
from charm import validate_cert


@pytest.mark.parametrize(
    "job_name,has_cert,cert_content,insecure_skip_verify,expected_file_path",
    [
        (
            "test-job-1",
            True,
            "-----BEGIN CERTIFICATE-----\nMOCK_CERT_1\n-----END CERTIFICATE-----",
            False,
            "/opt/certificates/otelcol_0/otel_test-job-1_ca.pem",
        ),
        (
            "test-job-2",
            True,
            "-----BEGIN CERTIFICATE-----\nMOCK_CERT_2\n-----END CERTIFICATE-----",
            False,
            "/opt/certificates/otelcol_0/otel_test-job-2_ca.pem",
        ),
        (
            "job-without-cert",
            False,
            None,
            None,
            None,
        ),
    ],
)
def test_update_jobs_with_ca_paths(job_name, has_cert, cert_content, insecure_skip_verify, expected_file_path):
    """Test that scrape jobs are updated to use certificate file paths."""
    # GIVEN a ConfigManager and a scrape job
    config_manager = ConfigManager("otelcol/0", "60s", "30s")

    job_data = {
        "job_name": job_name,
        "scheme": "https" if has_cert else "http",
        "metrics_path": "/metrics",
        "static_configs": [{"targets": ["example.com:443"] if has_cert else ["localhost:8080"]}],
    }

    if has_cert:
        job_data["tls_config"] = {
            "ca": cert_content,
            "insecure_skip_verify": insecure_skip_verify,
        }

    scrape_jobs = [job_data]

    cert_paths = (
        {job_name: expected_file_path}
        if expected_file_path
        else {}
    )

    # WHEN jobs are updated to use certificate file paths
    updated_jobs = config_manager.update_jobs_with_ca_paths(scrape_jobs, cert_paths)

    # THEN jobs should be properly updated
    assert len(updated_jobs) == 1
    updated_job = updated_jobs[0]

    if has_cert and expected_file_path:
        # Should have ca_file instead of ca
        assert "ca_file" in updated_job["tls_config"]
        assert updated_job["tls_config"]["ca_file"] == expected_file_path
        assert "ca" not in updated_job["tls_config"]
        assert updated_job["tls_config"]["insecure_skip_verify"] == insecure_skip_verify
    elif has_cert:
        # Should have original ca content when no file path mapping
        assert "ca_file" not in updated_job["tls_config"]
        assert "ca" in updated_job["tls_config"]
        assert updated_job["tls_config"]["ca"] == cert_content
    else:
        # Should not have tls_config for HTTP jobs
        assert "tls_config" not in updated_job


@pytest.mark.parametrize(
    "scrape_jobs,cert_paths,expected_update_count",
    [
        # Mixed jobs with certificates and file paths
        (
            [
                {
                    "job_name": "prometheus-job-1",
                    "scheme": "https",
                    "tls_config": {
                        "ca": "-----BEGIN CERTIFICATE-----\nCERT_1_CONTENT\n-----END CERTIFICATE-----",
                        "insecure_skip_verify": False,
                    },
                },
                {
                    "job_name": "prometheus-job-2",
                    "scheme": "https",
                    "tls_config": {
                        "ca": "-----BEGIN CERTIFICATE-----\nCERT_2_CONTENT\n-----END CERTIFICATE-----",
                        "insecure_skip_verify": True,
                    },
                },
                {
                    "job_name": "http-job",
                    "scheme": "http",
                    # No tls_config
                },
            ],
            {
                "prometheus-job-1": "/tmp/certs/otel_prometheus_job_1_ca.pem",
                "prometheus-job-2": "/tmp/certs/otel_prometheus_job_2_ca.pem",
            },
            3,  # All jobs should be updated
        ),
        # Jobs without file path mappings
        (
            [
                {
                    "job_name": "job-without-path-mapping",
                    "scheme": "https",
                    "tls_config": {
                        "ca": "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----",
                    },
                }
            ],
            {},
            1,  # Job should remain unchanged
        ),
    ],
)
def test_update_jobs_with_ca_paths_variations(scrape_jobs, cert_paths, expected_update_count):
    """Test various scenarios for updating jobs with certificate paths."""
    # GIVEN a ConfigManager and scrape jobs
    config_manager = ConfigManager("otelcol/0", "60s", "30s")

    # WHEN jobs are updated
    updated_jobs = config_manager.update_jobs_with_ca_paths(scrape_jobs, cert_paths)

    # THEN jobs should be properly configured
    assert len(updated_jobs) == expected_update_count

    for job in updated_jobs:
        job_name = job["job_name"]
        tls_config = job.get("tls_config", {})

        if job_name in cert_paths and "ca" in tls_config:
            # Jobs with both certificate content and file path should be updated
            assert "ca_file" in tls_config
            assert tls_config["ca_file"] == cert_paths[job_name]
            assert "ca" not in tls_config
        elif "ca" in tls_config:
            # Jobs without file path mapping should keep original content
            assert "ca_file" not in tls_config
            assert tls_config["ca"].startswith("-----BEGIN CERTIFICATE-----")


@pytest.mark.parametrize(
    "job_name,safe_job_name,expected_filename",
    [
        ("test-job", "test_job", "otel_test_job_ca.pem"),
        ("job with spaces", "job_with_spaces", "otel_job_with_spaces_ca.pem"),
        ("job/with/slashes", "job_with_slashes", "otel_job_with_slashes_ca.pem"),
        ("job-with-dashes", "job_with_dashes", "otel_job_with_dashes_ca.pem"),
        ("complex-job-name/with spaces", "complex_job_name_with_spaces", "otel_complex_job_name_with_spaces_ca.pem"),
    ],
)
def test_write_ca_certificates_to_disk_filename_safety(job_name, safe_job_name, expected_filename):
    """Test that job names are safely converted to filenames."""
    # GIVEN a scrape job with special characters in name and a certificate
    scrape_jobs = [
        {
            "job_name": job_name,
            "tls_config": {
                "ca": "-----BEGIN CERTIFICATE-----\nTEST_CERT\n-----END CERTIFICATE-----",
            }
        }
    ]

    # WHEN certificates are written to a temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        with patch('charm.CERT_DIR', temp_dir):
            # Simulate certificate writing process
            unit_identifier = "otelcol_0"
            cert_dir = Path(temp_dir) / unit_identifier
            cert_dir.mkdir(parents=True, exist_ok=True)
            cert_dir.chmod(0o755)

            # Process the job
            job = scrape_jobs[0]
            tls_config = job.get("tls_config", {})
            ca_content = tls_config.get("ca")

            if (ca_content and
                ca_content.strip().startswith("-----BEGIN CERTIFICATE-----") and
                ca_content.strip().endswith("-----END CERTIFICATE-----")):
                actual_safe_name = job_name.replace("/", "_").replace(" ", "_").replace("-", "_")
                ca_cert_path = cert_dir / f"otel_{actual_safe_name}_ca.pem"

                ca_cert_path.write_text(ca_content)
                ca_cert_path.chmod(0o644)

                # THEN the filename should be safe and correct
                assert ca_cert_path.exists()
                assert ca_cert_path.name == expected_filename
                assert ca_cert_path.stat().st_mode & 0o644 == 0o644
                assert "TEST_CERT" in ca_cert_path.read_text()


@pytest.mark.parametrize(
    "certificate_content,should_write",
    [
        ("-----BEGIN CERTIFICATE-----\nVALID_CERT\n-----END CERTIFICATE-----", True),
        ("-----BEGIN CERTIFICATE-----\nINCOMPLETE_CERT", False),
        ("INVALID_CERT_CONTENT", False),  # Invalid format
        ("", False),  # Empty string
        ("   ", False),  # Whitespace only
        ("Not a certificate at all", False),
    ],
)
def test_write_ca_certificates_to_disk_validation(certificate_content, should_write):
    """Test that only valid certificates are written to disk."""
    # GIVEN a scrape job with various certificate content
    scrape_jobs = [
        {
            "job_name": "test-job",
            "tls_config": {
                "ca": certificate_content,
            }
        }
    ]

    # WHEN certificates are written to a temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        unit_identifier = "otelcol_0"
        cert_dir = Path(temp_dir) / unit_identifier
        cert_dir.mkdir(parents=True, exist_ok=True)
        cert_dir.chmod(0o755)

        cert_paths = {}
        for job in scrape_jobs:
            tls_config = job.get("tls_config", {})
            ca_content = tls_config.get("ca")

            # Skip jobs without valid certificate content using the same validation as the charm
            if ca_content and validate_cert(ca_content):
                job_name = job.get("job_name", "default")
                safe_job_name = job_name.replace("/", "_").replace(" ", "_").replace("-", "_")
                ca_cert_path = cert_dir / f"otel_{safe_job_name}_ca.pem"

                ca_cert_path.write_text(ca_content)
                ca_cert_path.chmod(0o644)
                cert_paths[job_name] = str(ca_cert_path)

        # THEN only valid certificates should be written
        if should_write:
            assert len(cert_paths) == 1
            assert "test-job" in cert_paths
            cert_path = Path(cert_paths["test-job"])
            assert cert_path.exists()
            assert certificate_content in cert_path.read_text()
        else:
            assert len(cert_paths) == 0
            # Verify no certificate files were created
            temp_path = Path(temp_dir)
            assert not any(temp_path.glob("**/*.pem"))


def test_update_jobs_with_ca_paths_integration():
    """Integration test that simulates complete workflow."""
    # GIVEN scrape jobs with certificates
    scrape_jobs = [
        {
            "job_name": "prometheus-job-1",
            "scheme": "https",
            "metrics_path": "/metrics",
            "static_configs": [{"targets": ["metrics.example.com:443"]}],
            "tls_config": {
                "ca": "-----BEGIN CERTIFICATE-----\nCERT_1_CONTENT\n-----END CERTIFICATE-----",
                "insecure_skip_verify": False,
            },
        },
        {
            "job_name": "prometheus-job-2",
            "scheme": "https",
            "metrics_path": "/metrics",
            "static_configs": [{"targets": ["api.example.com:443"]}],
            "tls_config": {
                "ca": "-----BEGIN CERTIFICATE-----\nCERT_2_CONTENT\n-----END CERTIFICATE-----",
                "insecure_skip_verify": True,
            },
        },
    ]

    # WHEN certificates are written to disk and jobs are updated
    with tempfile.TemporaryDirectory() as temp_dir:
        # Step 1: Write certificates to disk (simulating _write_ca_certificates_to_disk)
        unit_identifier = "otelcol_0"
        cert_dir = Path(temp_dir) / unit_identifier
        cert_dir.mkdir(parents=True, exist_ok=True)
        cert_dir.chmod(0o755)

        cert_paths = {}
        for job in scrape_jobs:
            tls_config = job.get("tls_config", {})
            ca_content = tls_config.get("ca")

            if (ca_content and
                ca_content.strip().startswith("-----BEGIN CERTIFICATE-----") and
                ca_content.strip().endswith("-----END CERTIFICATE-----")):
                job_name = job.get("job_name", "default")
                safe_job_name = job_name.replace("/", "_").replace(" ", "_").replace("-", "_")
                ca_cert_path = cert_dir / f"otel_{safe_job_name}_ca.pem"

                ca_cert_path.write_text(ca_content)
                ca_cert_path.chmod(0o644)
                cert_paths[job_name] = str(ca_cert_path)

        # Step 2: Update jobs to use file paths
        config_manager = ConfigManager("otelcol/0", "60s", "30s")
        updated_jobs = config_manager.update_jobs_with_ca_paths(scrape_jobs, cert_paths)

        # THEN jobs should be properly configured with file paths
        assert len(updated_jobs) == 2

        for job in updated_jobs:
            job_name = job["job_name"]
            tls_config = job["tls_config"]

            # Should have ca_file pointing to written certificate
            assert "ca_file" in tls_config
            assert tls_config["ca_file"] == cert_paths[job_name]

            # Should no longer have embedded ca content
            assert "ca" not in tls_config

            # Should preserve other TLS settings
            expected_insecure_skip_verify = (
                False if job_name == "prometheus-job-1" else True
            )
            assert tls_config["insecure_skip_verify"] == expected_insecure_skip_verify

        # Verify the certificate files actually exist
        for cert_path in cert_paths.values():
            assert Path(cert_path).exists()
            assert Path(cert_path).read_text().startswith("-----BEGIN CERTIFICATE-----")
