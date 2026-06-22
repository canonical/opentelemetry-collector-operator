# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Regression tests: the otelcol snap is restarted when trusted CAs change on disk.

A running otelcol snap caches its trust store, so a newly trusted CA (added via the
`receive-ca-cert` relation + `update-ca-certificates`) is only picked up after the
snap process is restarted. The restart must therefore be driven by the CA files
materialized on disk under ``RECV_CA_CERT_FOLDER_PATH``, not by the relation data,
because the ``certificate_transfer`` handshake can deliver certs across multiple
hooks and let the relation-derived hash settle on a hook that does not refresh the
system trust store.

Ref: https://github.com/canonical/opentelemetry-collector-operator/issues/304
"""

import functools
import json
from unittest.mock import patch

from ops.testing import Relation, State

from utils import hash_ca_cert_dir

CERT_A = """\
-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUIhzxKRChM6KISvH6MLrDjWOJcF8wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJVGVzdCBDQSBBMCAXDTI2MDYxOTEyNTk0NVoYDzIxMjYw
NTI2MTI1OTQ1WjAUMRIwEAYDVQQDDAlUZXN0IENBIEEwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC9lTLz3GaIzSHq5CaJLfHbQyOPTdMcFJmPDMcHFzrK
4+p7C2ghgWqszx1fGZLp3gWvOXtIFtXEUDmqVyFGeLXMbY1Tuj4uohT6cOmlq0eS
2BGXiMQtojJr/JSyuVVgGmclqr2rpCPJoZCuisf07GxJHip5gca8toW2LF42XazI
L2MkbeFxDTsnzkFZMUjYtYvHMQ9RvGAIOY+ZcYpDEfXE0otfW9FjvE0ovmgp6KgE
s8VYJ36N8y8zDCW1jVcA0KfN8yms+PRa07B4CHbPOpvnCBwqViNnA5K1DKAaT8eM
8p1UHh7GtP1Dnq/ohecFNCIIl4hmV6S2TVp6/IEb8FZ1AgMBAAGjUzBRMB0GA1Ud
DgQWBBSoYMuDm9+gI1y9edMUY+cyabsihzAfBgNVHSMEGDAWgBSoYMuDm9+gI1y9
edMUY+cyabsihzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQC0
zpE5zadj/rLEku+MLTHhzpNUGhJ5M9ITLB2u4i/FgDr5iq8DSRG+V40s/IC6gFQw
cr+phjP2KLQJ5u9kXcPd0SJjnczLpkUjDhk1DvKRtkpuKEyephefrZLbN8LL5GXX
ZH761BGCp2zUIZdKrgUTLD7+v/yOjLUXCtdg2SuEINULL6t3YZWNmSCax/Aj5Spb
98ZYuaWter2HDVxZ0sEVoOSywVLu2fklmd0LPwG4YNRXnPDLBZdM9tr6ZK/pQYrx
5r42RNTyp23PZz9gwvVxOgp0cuo4gQ0OPrhhMpQzl0FoLxneKlZioz8nxRPt9Eyv
PRvWM1nd7HRBMf+jka/M
-----END CERTIFICATE-----"""
CERT_B = """\
-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUD/28AVaqN7iZyT0eZVUdcgjLazIwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJVGVzdCBDQSBCMCAXDTI2MDYxOTEyNTk0NVoYDzIxMjYw
NTI2MTI1OTQ1WjAUMRIwEAYDVQQDDAlUZXN0IENBIEIwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC/r0HhqilLd+27vxGS9wr4vrQncvSe6wh6FbZkcPuX
K0swT3iJJs1KKxHED6gSDC4KmNstB/PxKMRue7cV/omfUzfDWst1kVZ8YnuiHyTN
Xh54v5gPDeQY8qaHtYcuqVSFXEdLkW5fkKaodLGxwCzvC4HGSUfWcU0amVpmszsP
iEnz/yGOhj1i3r3+qFZp4z8iiUvSUUOqtVf2mCRxAes1Bi3nHlmxnI4n1oEl/4Vd
EQP1Ll1gfoQpfBGr9wlM43HaZUT2HYkpxxN+pvZtHOHC+ca5kvp/A/Nq59BW/Ain
ZuSrL/nsMkNK6bl/bc/x4HvPkdSqpKQODqzNofhQhzZtAgMBAAGjUzBRMB0GA1Ud
DgQWBBSFvVOvHAk1/fKC9bdKmHw/MzlhtjAfBgNVHSMEGDAWgBSFvVOvHAk1/fKC
9bdKmHw/MzlhtjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCz
JP5Mwv1HREglqFtqcskxqRnHeZthfgWo8L7Iai8Bu3OuusEgDVFVk2otWWsXx2I1
Eakl2UdnuJCCOldNQEaTHCwo2PHI3utDp3iMGSygvTt7Jwgt9qFWCn6pIYiBTvZj
F3nJXK871X/WiH92hWWNQbr8tU1tTFX7t27Ws+ZNhB3lp+2+JW1frr8C7b0RL9IK
5BobSVPbs4ZWZD+V9C1hkxnqq/bSU9/BZUEiBG7YF1IS/YQIyRo2x5LHWTpzcAan
4/bWpeG7Wm1IKOrNmRy8lE+ShTNu7ysOhw5tHqB/6uax7EIwlddNFDtjSg3rl1sD
BexQoqWvdoDZdSWulk7n
-----END CERTIFICATE-----"""

# A relation-derived hash that is held constant across hooks, to prove the restart
# is driven by the on-disk CA files and not by the relation data.
STALE_RELATION_HASH = "settled-relation-hash"


def write_ca_to_disk_returning_hash(cert, returned_hash, _, recv_ca_cert_folder_path):
    """Stand-in for ``integrations.receive_ca_cert`` that writes a CA then returns a hash.

    Models the production side effect (the CA file landing on disk, which is what
    ``update-ca-certificates`` later folds into the system bundle) while letting the
    test control the returned relation-derived hash. Bind ``cert``/``returned_hash``
    with ``functools.partial`` to use it as a mock ``side_effect``.
    """
    recv_ca_cert_folder_path.mkdir(parents=True, exist_ok=True)
    recv_ca_cert_folder_path.joinpath("0.crt").write_text(cert)
    return returned_hash


# ---------------------------------------------------------------------------
# Unit tests for the hashing primitive
# ---------------------------------------------------------------------------


def test_hash_of_missing_dir_is_stable(tmp_path):
    """The hash of a missing CA directory is deterministic."""
    # GIVEN a CA directory path that does not exist on disk
    missing = tmp_path / "does-not-exist"

    # WHEN the directory is hashed twice
    first = hash_ca_cert_dir(str(missing))
    second = hash_ca_cert_dir(str(missing))

    # THEN both hashes are equal
    assert first == second


def test_hash_changes_when_cert_added(tmp_path):
    """Adding a CA file to the directory changes the hash."""
    # GIVEN an empty CA directory
    ca_dir = tmp_path / "juju_receive-ca-cert"
    ca_dir.mkdir()
    empty_hash = hash_ca_cert_dir(str(ca_dir))

    # WHEN a CA file is added to the directory
    (ca_dir / "0.crt").write_text(CERT_A)
    populated_hash = hash_ca_cert_dir(str(ca_dir))

    # THEN the hash changes
    assert empty_hash != populated_hash


def test_hash_changes_when_cert_content_changes(tmp_path):
    """Changing the content of a CA file changes the hash."""
    # GIVEN a CA directory holding a certificate
    ca_dir = tmp_path / "juju_receive-ca-cert"
    ca_dir.mkdir()
    (ca_dir / "0.crt").write_text(CERT_A)
    hash_a = hash_ca_cert_dir(str(ca_dir))

    # WHEN the certificate content is replaced
    (ca_dir / "0.crt").write_text(CERT_B)
    hash_b = hash_ca_cert_dir(str(ca_dir))

    # THEN the hash changes
    assert hash_a != hash_b


def test_hash_is_stable_for_same_content(tmp_path):
    """The hash does not change when the on-disk certs are unchanged."""
    # GIVEN a CA directory holding two certificates
    ca_dir = tmp_path / "juju_receive-ca-cert"
    ca_dir.mkdir()
    (ca_dir / "0.crt").write_text(CERT_A)
    (ca_dir / "1.crt").write_text(CERT_B)

    # WHEN the unchanged directory is hashed twice
    first = hash_ca_cert_dir(str(ca_dir))
    second = hash_ca_cert_dir(str(ca_dir))

    # THEN both hashes are equal
    assert first == second


def test_hash_is_independent_of_write_order(tmp_path):
    """The hash is independent of glob/filesystem ordering of the cert files."""
    # GIVEN two directories with the same certs written in different order
    dir_one = tmp_path / "one"
    dir_one.mkdir()
    (dir_one / "0.crt").write_text(CERT_A)
    (dir_one / "1.crt").write_text(CERT_B)

    dir_two = tmp_path / "two"
    dir_two.mkdir()
    (dir_two / "1.crt").write_text(CERT_B)
    (dir_two / "0.crt").write_text(CERT_A)

    # WHEN both directories are hashed
    hash_one = hash_ca_cert_dir(str(dir_one))
    hash_two = hash_ca_cert_dir(str(dir_two))

    # THEN the hashes are equal
    assert hash_one == hash_two


# ---------------------------------------------------------------------------
# Behavioural regression tests: snap restart is driven by the on-disk CAs
# ---------------------------------------------------------------------------


def test_snap_restarted_when_ca_arrives(ctx, recv_ca_folder_path, mock_add_alerts):
    """A CA delivered over `receive-ca-cert` restarts the snap.

    This is the core of issue #304: once the CA lands on disk (and would be folded
    into the system trust store by update-ca-certificates), the running snap must be
    restarted so it reloads the new trust store.
    """
    # GIVEN otelcol is related to a CA transfer that provides a certificate
    cert_relation = Relation(
        "receive-ca-cert",
        remote_app_data={"certificates": json.dumps([CERT_A])},
    )
    state = State(leader=True, relations=[cert_relation])

    # WHEN the receive-ca-cert relation-changed hook fires
    with (
        patch("charm.OpenTelemetryCollectorCharm._restart_snap") as mock_restart,
        patch("charm.event", return_value="receive-ca-cert-relation-changed"),
    ):
        ctx.run(ctx.on.relation_changed(cert_relation), state)

    # THEN the CA was written to disk
    assert {f.read_text() for f in recv_ca_folder_path.glob("*.crt")} == {CERT_A}
    # AND the snap was restarted so it reloads the trust store
    assert mock_restart.call_count >= 1


def test_snap_restarted_when_on_disk_ca_changes_but_relation_hash_is_stale(
    ctx, recv_ca_folder_path, mock_add_alerts
):
    """The snap restarts when the CA lands on disk even if the relation hash is stale.

    This is the precise race behind #304. The ``certificate_transfer`` v1 handshake
    can split CA delivery across two ``relation-changed`` hooks: the first hook sees
    the relation data (same hash settles) but the CA is not yet materialized on disk,
    and the second hook actually writes the CA files. A restart trigger keyed on the
    relation-derived hash sees the same value on both hooks and skips the restart;
    a trigger keyed on the on-disk files (the fix) must restart the snap.

    The relation-derived hash is held constant across both hooks so it cannot, by
    itself, distinguish them: only the on-disk CA state differs.
    """
    ca_dir = recv_ca_folder_path

    # GIVEN a first relation-changed where the relation data is visible but
    # the CA has not yet been written to disk (relation hash already settled)
    rel = Relation(
        "receive-ca-cert",
        remote_app_data={"certificates": json.dumps([CERT_A])},
    )
    state = State(leader=True, relations=[rel])
    with (
        patch("integrations.receive_ca_cert", return_value=STALE_RELATION_HASH),
        patch("charm.event", return_value="receive-ca-cert-relation-changed"),
    ):
        ctx.run(ctx.on.relation_changed(rel), state)
    assert not list(ca_dir.glob("*.crt"))

    # WHEN a second relation-changed materializes the CA on disk while the
    # relation-derived hash stays the same as the first hook
    receive_and_write = functools.partial(
        write_ca_to_disk_returning_hash, CERT_A, STALE_RELATION_HASH
    )
    with (
        patch("integrations.receive_ca_cert", side_effect=receive_and_write),
        patch("charm.OpenTelemetryCollectorCharm._restart_snap") as mock_restart,
        patch("charm.event", return_value="receive-ca-cert-relation-changed"),
    ):
        ctx.run(ctx.on.relation_changed(rel), state)

    # THEN the CA is on disk
    assert {f.read_text() for f in ca_dir.glob("*.crt")} == {CERT_A}
    # AND the snap was restarted because the on-disk trust store changed,
    # even though the relation-derived hash did not change between hooks
    assert mock_restart.call_count >= 1


def test_snap_restarted_when_ca_changes_even_if_config_unchanged(ctx, recv_ca_folder_path, mock_add_alerts):
    """A changed CA set restarts the snap even when the otelcol config is unchanged.

    The restart trigger is derived from the on-disk CA files, so the snap must be
    restarted on the reconcile where the on-disk CA set actually changes, even though
    nothing else about the otelcol configuration changed.
    """
    # GIVEN a first reconcile already trusted CERT_A (hash settled)
    rel_a = Relation("receive-ca-cert", remote_app_data={"certificates": json.dumps([CERT_A])})
    with (
        patch("charm.event", return_value="receive-ca-cert-relation-changed"),
    ):
        ctx.run(ctx.on.relation_changed(rel_a), State(leader=True, relations=[rel_a]))
    assert {f.read_text() for f in recv_ca_folder_path.glob("*.crt")} == {CERT_A}

    # WHEN a later reconcile delivers a different CA (CERT_B replaces CERT_A)
    rel_b = Relation("receive-ca-cert", remote_app_data={"certificates": json.dumps([CERT_B])})
    with (
        patch("charm.OpenTelemetryCollectorCharm._restart_snap") as mock_restart,
        patch("charm.event", return_value="receive-ca-cert-relation-changed"),
    ):
        ctx.run(ctx.on.relation_changed(rel_b), State(leader=True, relations=[rel_b]))

    # THEN the new CA is on disk
    assert {f.read_text() for f in recv_ca_folder_path.glob("*.crt")} == {CERT_B}
    # AND the snap was restarted to reload the changed trust store
    assert mock_restart.call_count >= 1


def test_snap_not_restarted_when_nothing_changes(ctx, recv_ca_folder_path, mock_add_alerts):
    """A no-op reconcile with an unchanged CA set does not restart the snap.

    Guards against over-restarting: once the CA is trusted and the hash is settled,
    a subsequent reconcile that changes nothing (e.g. update-status) must leave the
    running snap alone.
    """
    # GIVEN otelcol already trusted CERT_A and the hash settled on a first reconcile
    rel = Relation("receive-ca-cert", remote_app_data={"certificates": json.dumps([CERT_A])})
    state = State(leader=True, relations=[rel])
    with (
        patch("charm.event", return_value="receive-ca-cert-relation-changed"),
    ):
        ctx.run(ctx.on.relation_changed(rel), state)
    assert {f.read_text() for f in recv_ca_folder_path.glob("*.crt")} == {CERT_A}

    # WHEN a no-op reconcile fires with the same CA set still in place
    with (
        patch("charm.OpenTelemetryCollectorCharm._restart_snap") as mock_restart,
    ):
        ctx.run(ctx.on.update_status(), state)

    # THEN the snap is not restarted
    mock_restart.assert_not_called()


def test_snap_restarted_when_server_cert_changes(ctx, recv_ca_folder_path, mock_add_alerts):
    """A new server certificate restarts the snap even when CA and config stay the same.

    The restart trigger includes ``server_cert_hash``, so a changed server certificate
    (different return value from ``receive_server_cert``) must force a restart even
    when the CA directory and the otelcol config are unchanged.
    """
    # GIVEN a first reconcile that settled the hash with server_cert_hash="hash_a"
    ssc = Relation(endpoint="receive-server-cert", interface="tls-certificate")
    state = State(leader=True, relations=[ssc])
    with (
        patch("integrations.receive_server_cert", return_value="hash_a"),
        patch("charm.event", return_value="update_status"),
        patch("charm.is_tls_ready", return_value=True),
    ):
        ctx.run(ctx.on.update_status(), state)

    # WHEN a later reconcile delivers a different server cert hash
    with (
        patch("integrations.receive_server_cert", return_value="hash_b"),
        patch("charm.OpenTelemetryCollectorCharm._restart_snap") as mock_restart,
        patch("charm.event", return_value="update_status"),
        patch("charm.is_tls_ready", return_value=True),
    ):
        before = mock_restart.call_count
        ctx.run(ctx.on.update_status(), state)

    # THEN the snap was restarted because the server cert hash changed
    assert mock_restart.call_count > before
