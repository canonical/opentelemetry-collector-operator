# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Tests for refresh_certs behavior."""

from unittest.mock import patch

from ops.testing import Relation, State


def test_refresh_certs_called_on_receive_ca_cert_relation_changed(ctx):
    """Test that refresh_certs is called on receive-ca-cert-relation-changed hook."""
    # GIVEN receive-ca-cert relation exists
    recv_ca_cert_relation = Relation("receive-ca-cert", remote_app_data={"certificates": "[]"})
    state = State(
        leader=True,
        relations=[recv_ca_cert_relation],
    )

    # Mock refresh_certs to track if it's called (note: ctx already patches it, so we need to reset)
    with patch("charm.refresh_certs") as mock_refresh_certs, \
         patch("integrations._add_alerts"):
        # WHEN the relation changed event is executed
        ctx.run(ctx.on.relation_changed(recv_ca_cert_relation), state)

        # THEN refresh_certs should be called
        mock_refresh_certs.assert_called_once()


def test_refresh_certs_called_on_receive_server_cert_relation_changed(ctx):
    """Test that refresh_certs is called on receive-server-cert-relation-changed hook."""
    # GIVEN receive-server-cert relation exists
    recv_server_cert_relation = Relation("receive-server-cert", remote_app_data={})
    state = State(
        leader=True,
        relations=[recv_server_cert_relation],
    )

    # Mock refresh_certs to track if it's called
    with patch("charm.refresh_certs") as mock_refresh_certs, \
         patch("integrations._add_alerts"):
        # WHEN the relation changed event is executed
        ctx.run(ctx.on.relation_changed(recv_server_cert_relation), state)

        # THEN refresh_certs should be called
        mock_refresh_certs.assert_called_once()


def test_refresh_certs_not_called_on_update_status(ctx):
    """Test that refresh_certs is NOT called on update-status hook."""
    # GIVEN update-status hook is being executed
    state = State(leader=True)

    # Mock refresh_certs to track if it's called
    with patch("charm.refresh_certs") as mock_refresh_certs, \
         patch("integrations._add_alerts"):
        # WHEN the hook is executed
        ctx.run(ctx.on.update_status(), state)

        # THEN refresh_certs should NOT be called
        mock_refresh_certs.assert_not_called()


def test_refresh_certs_not_called_on_config_changed(ctx):
    """Test that refresh_certs is NOT called on config-changed hook."""
    # GIVEN config-changed hook is being executed
    state = State(leader=True)

    # Mock refresh_certs to track if it's called
    with patch("charm.refresh_certs") as mock_refresh_certs, \
         patch("integrations._add_alerts"):
        # WHEN the hook is executed
        ctx.run(ctx.on.config_changed(), state)

        # THEN refresh_certs should NOT be called
        mock_refresh_certs.assert_not_called()
