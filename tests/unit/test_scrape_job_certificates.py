# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: TLS certificate management for Prometheus scrape jobs."""

from pathlib import Path
from typing import Any, Dict

import pytest
from ops.testing import Relation, State

from config_manager import ConfigManager

# Values a provider may send inline in a job's tls_config. Providers differ in the
# spelling they use: juju-controller, for example, sends the CA under `ca_file`.
INLINE_CA = "-----BEGIN CERTIFICATE-----\nSAMPLE_CA\n-----END CERTIFICATE-----"
SECOND_CA = "-----BEGIN CERTIFICATE-----\nOTHER_CA\n-----END CERTIFICATE-----"
INLINE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nSAMPLE_KEY\n-----END RSA PRIVATE KEY-----"
INLINE_CERT = "-----BEGIN CERTIFICATE-----\nSAMPLE_CERT\n-----END CERTIFICATE-----"
CA_PATH = "/tmp/test_certs/otelcol_0/otel_test-job_4990bd27_ca.pem"
KEY_PATH = "/tmp/test_certs/otelcol_0/otel_test-job_4990bd27_key.pem"
CERT_PATH = "/tmp/test_certs/otelcol_0/otel_test-job_4990bd27_cert.pem"


@pytest.fixture
def manager():
    """Create a ConfigManager instance for testing."""
    return ConfigManager("otelcol/0", "0", "60s", "30s")


@pytest.mark.parametrize(
    "tls_config,cert_paths,expected_tls_config",
    [
        pytest.param(
            {"ca": INLINE_CA, "insecure_skip_verify": False},
            {"test-job": {"ca": CA_PATH}},
            {"ca_file": CA_PATH, "insecure_skip_verify": False},
            id="inline ca replaced by path",
        ),
        pytest.param(
            {"ca_file": INLINE_CA, "server_name": "juju-apiserver"},
            {"test-job": {"ca": CA_PATH}},
            {"ca_file": CA_PATH, "server_name": "juju-apiserver"},
            id="ca_file spelling replaced by path, server_name kept",
        ),
        pytest.param(
            {"ca_file": INLINE_CA, "key_file": INLINE_KEY, "cert_file": INLINE_CERT},
            {"test-job": {"ca": CA_PATH, "key": KEY_PATH, "cert": CERT_PATH}},
            {"ca_file": CA_PATH, "key_file": KEY_PATH, "cert_file": CERT_PATH},
            id="ca, key and cert all replaced by paths",
        ),
        pytest.param(
            {"ca_file": "/an/already/existing/path.pem", "server_name": "juju-apiserver"},
            {},
            {"ca_file": "/an/already/existing/path.pem", "server_name": "juju-apiserver"},
            id="no cert written: tls_config passed through untouched",
        ),
        pytest.param(
            None,
            {},
            None,
            id="job without tls_config stays without tls_config",
        ),
    ],
)
def test_update_jobs_with_cert_paths(manager, tls_config, cert_paths, expected_tls_config):
    """Test that inline PEM material is replaced by file paths and nothing else is dropped."""
    job: Dict[str, Any] = {"job_name": "test-job"}
    if tls_config is not None:
        job["tls_config"] = dict(tls_config)

    updated_jobs = manager.update_jobs_with_cert_paths([job], cert_paths)

    assert len(updated_jobs) == 1
    if expected_tls_config is None:
        assert "tls_config" not in updated_jobs[0]
    else:
        assert updated_jobs[0]["tls_config"] == expected_tls_config


@pytest.mark.parametrize(
    "tls_config,expected_kinds",
    [
        pytest.param(
            {"ca_file": INLINE_CA, "server_name": "juju-apiserver"},
            {"ca": (CA_PATH, "0o100644")},
            id="ca under ca_file (juju-controller spelling)",
        ),
        pytest.param(
            {"ca": INLINE_CA},
            {"ca": (CA_PATH, "0o100644")},
            id="ca under the content spelling",
        ),
        pytest.param(
            {"ca_file": INLINE_CA, "ca": SECOND_CA},
            {"ca": (CA_PATH, "0o100644")},
            id="both spellings: ca_file takes precedence",
        ),
        pytest.param(
            {"ca_file": INLINE_CA, "key_file": INLINE_KEY, "cert_file": INLINE_CERT},
            {
                "ca": (CA_PATH, "0o100644"),
                "key": (KEY_PATH, "0o100600"),
                "cert": (CERT_PATH, "0o100644"),
            },
            id="client key and cert are written too",
        ),
        pytest.param(
            {"ca_file": "/an/already/existing/path.pem", "server_name": "juju-apiserver"},
            {},
            id="non-PEM ca_file (a path) is left as-is",
        ),
        pytest.param(
            {"ca_file": "-----BEGIN CERTIFICATE-----\ntruncated"},
            {},
            id="malformed PEM is not written",
        ),
        pytest.param(
            {"ca_file": "INVALID_CERT_CONTENT"},
            {},
            id="content without PEM markers is not written",
        ),
    ],
)
def test_write_tls_certificates_to_disk(ctx, tls_config, expected_kinds):
    """Test writing inline TLS material from scrape jobs to disk."""
    relation = Relation("metrics-endpoint")
    state = State(
        leader=True,
        relations=[relation],
    )
    scrape_jobs = [{"job_name": "test-job", "tls_config": dict(tls_config)}]

    with ctx(ctx.on.relation_joined(relation), state) as manager_ctx:
        charm = manager_ctx.charm
        cert_paths = charm._write_tls_certificates_to_disk(scrape_jobs)

        if not expected_kinds:
            assert cert_paths == {}
        else:
            assert set(cert_paths["test-job"]) == set(expected_kinds)
            for kind, (expected_path, expected_mode) in expected_kinds.items():
                assert cert_paths["test-job"][kind] == expected_path
                path = Path(expected_path)
                assert path.exists()
                assert oct(path.stat().st_mode) == expected_mode
                assert charm.unit.name.replace("/", "_") in path.parent.name
                kind_marker = {
                    "ca": "CERTIFICATE",
                    "key": "PRIVATE KEY",
                    "cert": "CERTIFICATE",
                }[kind]
                assert kind_marker in path.read_text()


def test_write_tls_certificates_to_disk_sanitizes_job_names(ctx, sample_ca_cert):
    """Test that job names are sanitized before being used in file names."""
    relation = Relation("metrics-endpoint")
    state = State(leader=True, relations=[relation])
    job_name = "test/job with spaces-and-dashes"
    scrape_jobs = [{"job_name": job_name, "tls_config": {"ca_file": sample_ca_cert}}]

    with ctx(ctx.on.relation_joined(relation), state) as manager_ctx:
        charm = manager_ctx.charm
        cert_paths = charm._write_tls_certificates_to_disk(scrape_jobs)

        assert cert_paths[job_name] == {
            "ca": "/tmp/test_certs/otelcol_0/otel_test_job_with_spaces-and-dashes_293dcd03_ca.pem"
        }


def test_write_tls_certificates_to_disk_no_filename_collisions(
    ctx, sample_ca_cert, second_ca_cert
):
    """Test that distinct job names that sanitize to the same string get distinct files.

    "job-1" and "job/1" both sanitize to "job_1"; without a hash of the original
    name in the file name they would overwrite each other's credentials.
    """
    relation = Relation("metrics-endpoint")
    state = State(leader=True, relations=[relation])
    scrape_jobs = [
        {"job_name": "job-1", "tls_config": {"ca_file": sample_ca_cert}},
        {"job_name": "job/1", "tls_config": {"ca_file": second_ca_cert}},
    ]

    with ctx(ctx.on.relation_joined(relation), state) as manager_ctx:
        charm = manager_ctx.charm
        cert_paths = charm._write_tls_certificates_to_disk(scrape_jobs)

        path_one = Path(cert_paths["job-1"]["ca"])
        path_two = Path(cert_paths["job/1"]["ca"])
        assert path_one != path_two
        assert path_one.exists()
        assert path_two.exists()
        assert path_one.read_text() == sample_ca_cert
        assert path_two.read_text() == second_ca_cert


def test_scrape_job_pem_content_is_not_rendered_in_config(ctx, manager, sample_ca_cert):
    """Test that inline PEM material does not end up in the rendered config."""
    relation = Relation("metrics-endpoint")
    state = State(leader=True, relations=[relation])
    scrape_jobs = [
        {
            "job_name": "test-job",
            "scheme": "https",
            "tls_config": {"ca_file": sample_ca_cert, "server_name": "juju-apiserver"},
        }
    ]

    with ctx(ctx.on.relation_joined(relation), state) as manager_ctx:
        charm = manager_ctx.charm
        cert_paths = charm._write_tls_certificates_to_disk(scrape_jobs)
        updated_jobs = manager.update_jobs_with_cert_paths(scrape_jobs, cert_paths)

        tls_config = updated_jobs[0]["tls_config"]
        assert sample_ca_cert not in str(tls_config)
        assert tls_config["ca_file"].endswith("otel_test-job_4990bd27_ca.pem")
        assert tls_config["server_name"] == "juju-apiserver"
        assert Path(tls_config["ca_file"]).read_text() == sample_ca_cert
