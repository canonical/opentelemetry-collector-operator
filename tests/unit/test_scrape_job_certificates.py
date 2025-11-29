# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Certificate management for Prometheus scrape jobs."""

from pathlib import Path

import pytest
from ops.testing import Relation, State, SubordinateRelation

from config_manager import ConfigManager
from tests.unit.conftest import (
    sample_ca_cert,
)


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
                        "ca": sample_ca_cert,
                        "insecure_skip_verify": False,
                    },
                },
                {
                    "job_name": "prometheus-job-2",
                    "scheme": "https",
                    "tls_config": {
                        "ca": sample_ca_cert,
                        "insecure_skip_verify": True,
                    },
                },
                {
                    "job_name": "prometheus-job-3",
                    "scheme": "https",
                    "tls_config": {
                        "ca_file": "/my-ca/file",
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
            4,  # All jobs should be updated
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

        if job_name in cert_paths:
            assert "ca_file" in tls_config
            assert tls_config["ca_file"] == cert_paths[job_name]
            assert "ca" not in tls_config
        else:
            assert tls_config == {}


@pytest.mark.parametrize(
    "job_name,certificate_content,expected_filename,should_write",
    [
        ("test-job", "sample_ca_cert", "otel_test_job_ca.pem", True),
        ("job with spaces", "sample_ca_cert", "otel_job_with_spaces_ca.pem", True),
        ("job/with/slashes", "sample_ca_cert", "otel_job_with_slashes_ca.pem", True),
        ("job-with-dashes", "sample_ca_cert", "otel_job_with_dashes_ca.pem", True),
        ("test-job", "sample_incomplete_cert", "", False),
        ("test-job", "sample_invalid_cert", "", False),  # Invalid format
    ],
)
def test_write_ca_certificates_to_disk_validation(ctx, request, job_name, certificate_content, expected_filename, should_write, mock_ensure_certs_dir):
    """Test that only valid certificates are written to disk using the charm's _write_ca_certificates_to_disk method."""
    # GIVEN a metrics-endpoint relation and
    relation = Relation("metrics-endpoint")
    state = State(
        leader=True,
        relations=[relation],  # source_relation must exist in state for relation_joined
    )
    certificate_content = request.getfixturevalue(certificate_content)
    scrape_jobs = [
        {
            "job_name": job_name,
            "tls_config": {
                "ca": certificate_content,
            }
        }
    ]

    # WHEN a relation joined is fired
    with ctx(ctx.on.relation_joined(relation), state) as manager:
        charm = manager.charm
        cert_paths = charm._write_ca_certificates_to_disk(scrape_jobs)

        # THEN only valid certificates should be written
        if should_write:
            assert len(cert_paths) == 1
            cert_path = Path(cert_paths[job_name])
            assert cert_path.exists()
            assert oct(cert_path.stat().st_mode) == '0o100644'
            assert cert_path.name == expected_filename
            assert certificate_content in cert_path.read_text()

            # Verify the certificate is in a path that contains our unit identifier
            assert charm.unit.name.replace("/", "_") in cert_path.parent.name
        else:
            # The charm should not create any certificate files for invalid certificates
            # No need to check specific files - if cert_paths is empty, the method worked correctly
            assert len(cert_paths) == 0
