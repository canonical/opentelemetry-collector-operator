# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""TLS credentials supplied through prometheus_scrape relations."""

import copy
import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from ops import BlockedStatus
from ops.testing import Relation, State


@pytest.fixture
def scrape_cert_dir(tmp_path, monkeypatch):
    directory = tmp_path / "scrape-certs"
    monkeypatch.setattr("charm.CERT_DIR", str(directory))
    return directory


def metrics_relation(tls_config):
    return Relation(
        "metrics-endpoint",
        remote_app_name="lxd",
        remote_app_data={
            "scrape_jobs": json.dumps([{
                "job_name": "lxd",
                "scheme": "https",
                "static_configs": [{"targets": ["localhost:8443"]}],
                "tls_config": tls_config,
            }]),
            "scrape_metadata": json.dumps({
                "model": "test",
                "model_uuid": "20ce8299-3634-4bef-8bd8-5ace6c8816b4",
                "application": "lxd",
                "charm_name": "lxd",
            }),
        },
    )


@pytest.mark.parametrize("suffix", ["", "_file"], ids=["inline", "relation-pem"])
def test_scrape_mutual_tls(ctx, scrape_cert_dir, config_folder, sample_ca_cert, suffix):
    # GIVEN a scrape provider sending CA and client credentials
    credentials = {
        "ca": sample_ca_cert,
        "cert": sample_ca_cert,
        "key": "-----BEGIN PRIVATE KEY-----\nlocal-test-key\n-----END PRIVATE KEY-----",
    }
    tls = {f"{name}{suffix}": value for name, value in credentials.items()}
    tls.update(server_name="lxd.internal", insecure_skip_verify=False, min_version="TLS12")
    relation = metrics_relation(tls)

    # WHEN the actual relation handler generates the collector configuration
    state = ctx.run(ctx.on.relation_changed(relation), State(leader=True, relations=[relation]))

    # THEN credentials become private unit-local files and other TLS settings survive
    assert state.unit_status.name == "active"
    config = yaml.safe_load((config_folder / "otelcol_0.yaml").read_text())
    job = config["receivers"]["prometheus/metrics-endpoint/otelcol/0"]["config"]["scrape_configs"][0]
    rendered = job["tls_config"]
    for field, content in credentials.items():
        path = Path(rendered[f"{field}_file"])
        assert path.parent == scrape_cert_dir / "otelcol_0"
        assert path.read_text() == content
        assert path.stat().st_mode & 0o777 == 0o600
        assert field not in rendered
    assert rendered["server_name"] == "lxd.internal"
    assert rendered["insecure_skip_verify"] is False
    assert rendered["min_version"] == "TLS12"


@pytest.mark.parametrize("tls", [
    {"insecure_skip_verify": True, "server_name": "host.internal"},
    {"ca_file": "/local/ca.pem", "cert_file": "/local/client.pem", "key_file": "/local/key.pem"},
    {},
])
def test_preserve_tls_without_inline_credentials(ctx, scrape_cert_dir, tls):
    relation = Relation("metrics-endpoint")
    jobs = [{"job_name": "local", "tls_config": copy.deepcopy(tls)}, {"job_name": "http"}]
    with ctx(ctx.on.relation_joined(relation), State(leader=True, relations=[relation])) as manager:
        active = manager.charm._configure_scrape_job_tls(jobs)
        assert active == {Path(value) for field, value in tls.items() if field.endswith("_file")}
    assert jobs == [{"job_name": "local", "tls_config": tls}, {"job_name": "http"}]
    assert not scrape_cert_dir.exists()


def test_rotation_changes_paths_and_cleans_only_after_restart(
    ctx, scrape_cert_dir, sample_ca_cert
):
    relation = metrics_relation({"ca_file": sample_ca_cert})
    state = ctx.run(ctx.on.relation_changed(relation), State(leader=True, relations=[relation]))
    original_paths = set(scrape_cert_dir.rglob("scrape-*.pem"))
    assert len(original_paths) == 1
    other_unit = scrape_cert_dir / "otelcol_1"
    other_unit.mkdir()
    other_file = other_unit / "scrape-other.pem"
    other_file.write_text("other unit")

    # WHEN only the credential bytes change, the new config must restart the snap
    jobs = json.loads(relation.remote_app_data["scrape_jobs"])
    jobs[0]["tls_config"]["ca_file"] = sample_ca_cert + "\n"
    rotated = replace(relation, remote_app_data={
        **relation.remote_app_data, "scrape_jobs": json.dumps(jobs),
    })
    state = replace(state, relations=[rotated])

    def check_old_credentials_remain_readable(_):
        assert all(path.exists() for path in original_paths)

    with patch(
        "charm.OpenTelemetryCollectorCharm._restart_snap",
        side_effect=check_old_credentials_remain_readable,
    ) as restart:
        state = ctx.run(ctx.on.relation_changed(rotated), state)
    restart.assert_called()
    assert not any(path.exists() for path in original_paths)
    assert other_file.exists()
    assert len(list((scrape_cert_dir / "otelcol_0").glob("scrape-*.pem"))) == 1

    with patch("charm.OpenTelemetryCollectorCharm._restart_snap") as restart:
        state = ctx.run(ctx.on.update_status(), state)
    restart.assert_not_called()
    ctx.run(ctx.on.relation_broken(state.get_relation(rotated.id)), state)
    assert not list((scrape_cert_dir / "otelcol_0").glob("scrape-*.pem"))
    assert other_file.exists()


@pytest.mark.parametrize("tls", [
    {"cert_file": "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----"},
    {"key_file": "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----"},
    {"ca": "INVALID_CERT"},
    {"ca": "inline", "ca_file": "/local/ca"},
])
def test_invalid_tls_blocks_without_replacing_config(
    ctx, scrape_cert_dir, config_folder, tls
):
    config_folder.mkdir()
    config_path = config_folder / "otelcol_0.yaml"
    config_path.write_text("previous configuration")
    relation = metrics_relation(tls)
    state = ctx.run(ctx.on.relation_changed(relation), State(leader=True, relations=[relation]))
    assert state.unit_status == BlockedStatus("Invalid scrape TLS credentials. See debug-log")
    assert config_path.read_text() == "previous configuration"


def test_write_failure_is_not_ignored(ctx, scrape_cert_dir, sample_ca_cert):
    scrape_cert_dir.write_text("not a directory")
    relation = metrics_relation({"ca_file": sample_ca_cert})
    state = ctx.run(ctx.on.relation_changed(relation), State(leader=True, relations=[relation]))
    assert state.unit_status.name == "blocked"
