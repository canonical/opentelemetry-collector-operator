# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
"""Tests for refresh_certs behavior."""

from unittest.mock import patch

import pytest
from ops.testing import Relation, State


@pytest.mark.parametrize(
    "relation_name,remote_app_data",
    [
        ("receive-ca-cert", {"certificates": "[]"}),
        ("receive-server-cert", {}),
    ],
)
def test_refresh_certs_called_on_cert_relation_changed(ctx, relation_name, remote_app_data):
    """Test that refresh_certs is called on certificate relation-changed hooks."""
    # GIVEN a certificate relation exists
    cert_relation = Relation(relation_name, remote_app_data=remote_app_data)
    state = State(
        leader=True,
        relations=[cert_relation],
    )

    # Mock refresh_certs to track if it's called
    with patch("charm.refresh_certs") as mock_refresh_certs, \
         patch("integrations._add_alerts"):
        # WHEN the relation changed event is executed
        ctx.run(ctx.on.relation_changed(cert_relation), state)

        # THEN refresh_certs should be called
        mock_refresh_certs.assert_called_once()


@pytest.mark.parametrize(
    "event_method",
    [
        "update_status",
        "config_changed"
    ],
)
def test_refresh_certs_not_called_on_non_cert_hooks(ctx, event_method):
    """Test that refresh_certs is NOT called on non-certificate hooks."""
    # GIVEN a non-certificate hook is being executed
    state = State(leader=True)

    # Mock refresh_certs to track if it's called
    with patch("charm.refresh_certs") as mock_refresh_certs, \
         patch("integrations._add_alerts"):
        # WHEN the hook is executed
        event = getattr(ctx.on, event_method)()
        ctx.run(event, state)

        # THEN refresh_certs should NOT be called
        mock_refresh_certs.assert_not_called()

def test_refresh_certs_on_reconcile_action_event(ctx):
    # GIVEN the charm
    state = State(leader=True)

    # WHEN the `reconcile` action is executed
    with patch("charm.refresh_certs") as mock_refresh_certs, \
         patch("integrations._add_alerts"):
            ctx.run(
                ctx.on.action('reconcile'),
                state,
            )

            # THEN the refresh_certs function MUST have been called once
            mock_refresh_certs.assert_called_once()
