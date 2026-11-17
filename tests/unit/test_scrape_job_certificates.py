# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: TLS certificate management for Prometheus scrape jobs."""

import os
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest
from ops.testing import Relation, State

from config_manager import ConfigManager

# Values a provider may send inline in a job's tls_config. Providers differ in the
# spelling they use: juju-controller, for example, sends the CA under `ca_file`.
INLINE_CA = "-----BEGIN CERTIFICATE-----\nSAMPLE_CA\n-----END CERTIFICATE-----"
SECOND_CA = "-----BEGIN CERTIFICATE-----\nOTHER_CA\n-----END CERTIFICATE-----"
INLINE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nSAMPLE_KEY\n-----END RSA PRIVATE KEY-----"
INLINE_CERT = "-----BEGIN CERTIFICATE-----\nSAMPLE_CERT\n-----END CERTIFICATE-----"
MALFORMED_PEM = "-----BEGIN CERTIFICATE-----\ntruncated"
CA_PATH = "/tmp/test_certs/otelcol_0/otel_test-job_4990bd27_ca.pem"
KEY_PATH = "/tmp/test_certs/otelcol_0/otel_test-job_4990bd27_key.pem"
CERT_PATH = "/tmp/test_certs/otelcol_0/otel_test-job_4990bd27_cert.pem"

_REAL_OPEN = os.open


def _open_failing_on_key_files(path, flags, mode=0o777, *args, **kwargs):
    """os.open stand-in that fails with PermissionError for private-key files."""
    if str(path).endswith("_key.pem"):
        raise PermissionError(13, "Permission denied", str(path))
    return _REAL_OPEN(path, flags, mode, *args, **kwargs)


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
    # GIVEN a scrape job with TLS material and the paths where its certificates
    # were written on disk
    job: Dict[str, Any] = {"job_name": "test-job"}
    if tls_config is not None:
        job["tls_config"] = dict(tls_config)

    # WHEN the jobs are updated with the certificate paths
    updated_jobs = manager.update_jobs_with_cert_paths([job], cert_paths)

    # THEN only the inline PEM material is replaced by its file path
    assert len(updated_jobs) == 1
    # AND everything else in tls_config is preserved (or stays absent if there was none)
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
            {"ca_file": MALFORMED_PEM},
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
    # GIVEN a metrics-endpoint relation and a job with inline TLS material
    relation = Relation("metrics-endpoint")
    state = State(
        leader=True,
        relations=[relation],
    )
    scrape_jobs = [{"job_name": "test-job", "tls_config": dict(tls_config)}]

    # WHEN the charm writes the inline material to disk
    with ctx(ctx.on.relation_joined(relation), state) as manager_ctx:
        charm = manager_ctx.charm
        cert_paths = charm._write_tls_certificates_to_disk(scrape_jobs)

        # THEN valid PEM material is written to the unit's certificate directory
        if not expected_kinds:
            assert cert_paths == {}
        else:
            assert set(cert_paths["test-job"]) == set(expected_kinds)
            for kind, (expected_path, expected_mode) in expected_kinds.items():
                assert cert_paths["test-job"][kind] == expected_path
                path = Path(expected_path)
                assert path.exists()
                # AND with the expected permissions and content, in a unit-scoped directory
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
    # GIVEN a metrics-endpoint relation and a job name with slashes, spaces and dashes
    relation = Relation("metrics-endpoint")
    state = State(leader=True, relations=[relation])
    job_name = "test/job with spaces-and-dashes"
    scrape_jobs = [{"job_name": job_name, "tls_config": {"ca_file": sample_ca_cert}}]

    # WHEN the charm writes the inline material to disk
    with ctx(ctx.on.relation_joined(relation), state) as manager_ctx:
        charm = manager_ctx.charm
        cert_paths = charm._write_tls_certificates_to_disk(scrape_jobs)

        # THEN the file name keeps only path-unsafe characters replaced,
        # suffixed with a hash of the original job name
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
    # GIVEN a metrics-endpoint relation and two jobs whose names sanitize
    # to the same string, each with its own CA
    relation = Relation("metrics-endpoint")
    state = State(leader=True, relations=[relation])
    scrape_jobs = [
        {"job_name": "job-1", "tls_config": {"ca_file": sample_ca_cert}},
        {"job_name": "job/1", "tls_config": {"ca_file": second_ca_cert}},
    ]

    # WHEN the charm writes the inline material to disk
    with ctx(ctx.on.relation_joined(relation), state) as manager_ctx:
        charm = manager_ctx.charm
        cert_paths = charm._write_tls_certificates_to_disk(scrape_jobs)

        # THEN each job gets a distinct file
        path_one = Path(cert_paths["job-1"]["ca"])
        path_two = Path(cert_paths["job/1"]["ca"])
        assert path_one != path_two
        assert path_one.exists()
        assert path_two.exists()
        # AND each file holds its own job's material
        assert path_one.read_text() == sample_ca_cert
        assert path_two.read_text() == second_ca_cert


def test_scrape_job_pem_content_is_not_rendered_in_config(ctx, manager, sample_ca_cert):
    """Test that inline PEM material does not end up in the rendered config."""
    # GIVEN a metrics-endpoint relation and a job with an inline CA under ca_file
    relation = Relation("metrics-endpoint")
    state = State(leader=True, relations=[relation])
    scrape_jobs = [
        {
            "job_name": "test-job",
            "scheme": "https",
            "tls_config": {"ca_file": sample_ca_cert, "server_name": "juju-apiserver"},
        }
    ]

    # WHEN the material is written to disk and the job updated with the paths
    with ctx(ctx.on.relation_joined(relation), state) as manager_ctx:
        charm = manager_ctx.charm
        cert_paths = charm._write_tls_certificates_to_disk(scrape_jobs)
        updated_jobs = manager.update_jobs_with_cert_paths(scrape_jobs, cert_paths)

        # THEN the rendered tls_config references the file on disk
        tls_config = updated_jobs[0]["tls_config"]
        assert sample_ca_cert not in str(tls_config)
        assert tls_config["ca_file"].endswith("otel_test-job_4990bd27_ca.pem")
        # AND keeps the other TLS settings, pointing at a file with the PEM content
        assert tls_config["server_name"] == "juju-apiserver"
        assert Path(tls_config["ca_file"]).read_text() == sample_ca_cert


@pytest.mark.parametrize(
    "tls_config,key_write_fails,expected_cert_paths,expected_tls_config",
    [
        pytest.param(
            {"ca_file": INLINE_CA, "key_file": INLINE_KEY, "server_name": "juju-apiserver"},
            True,
            {"test-job": {"ca": CA_PATH}},
            {"ca_file": CA_PATH, "server_name": "juju-apiserver"},
            id="failed key write: the CA gets its path, the key does not reach the config",
        ),
        pytest.param(
            {"ca_file": INLINE_CA, "cert_file": INLINE_CERT, "key_file": INLINE_KEY, "server_name": "juju-apiserver"},
            True,
            {"test-job": {"ca": CA_PATH}},
            {"ca_file": CA_PATH, "server_name": "juju-apiserver"},
            id="failed key write: the orphaned client cert is dropped too (cert without key cannot load)",
        ),
        pytest.param(
            {"ca_file": MALFORMED_PEM},
            False,
            {},
            {},
            id="malformed PEM under ca_file: not written, not rendered inline",
        ),
        pytest.param(
            {"ca": MALFORMED_PEM},
            False,
            {},
            {"ca": MALFORMED_PEM},
            id="malformed PEM under the content spelling: passed through as-is",
        ),
    ],
)
def test_unwritten_material_never_reaches_file_spelling_keys(
    ctx, manager, tls_config, key_write_fails, expected_cert_paths, expected_tls_config
):
    """Material that is not written to disk must not be rendered inline in file-spelling keys.

    The file-spelling keys (ca_file, key_file, cert_file) require a path: inline
    PEM there prevents the Prometheus receiver from loading the configuration,
    so the whole collector refuses to start. The content spelling carries PEM
    natively and is safe to pass through.
    """
    # GIVEN a metrics-endpoint relation and a job with TLS material
    relation = Relation("metrics-endpoint")
    state = State(leader=True, relations=[relation])
    scrape_jobs = [{"job_name": "test-job", "tls_config": dict(tls_config)}]

    # WHEN the charm writes the inline material to disk and the job is
    # updated with the paths
    with ctx(ctx.on.relation_joined(relation), state) as manager_ctx:
        charm = manager_ctx.charm
        if key_write_fails:
            with patch("os.open", side_effect=_open_failing_on_key_files):
                cert_paths = charm._write_tls_certificates_to_disk(scrape_jobs)
        else:
            cert_paths = charm._write_tls_certificates_to_disk(scrape_jobs)
        updated_jobs = manager.update_jobs_with_cert_paths(scrape_jobs, cert_paths)

        # THEN only the material written to disk is replaced by its path
        assert cert_paths == expected_cert_paths
        # AND the rendered tls_config never holds inline PEM in the
        # file-spelling keys
        assert updated_jobs[0]["tls_config"] == expected_tls_config
