# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Tests: the model's proxy settings are passed on to the opentelemetry-collector snap.

Juju exposes the model-level proxy configuration (juju-http-proxy, juju-https-proxy
and juju-no-proxy) to charms via the JUJU_CHARM_*_PROXY environment variables. The
charm must forward them to the collector snap, appending local addresses to no-proxy
so that local scrapes and the internal telemetry exporter bypass the proxy. Proxy
options must only be written when they change, because every write restarts the
collector through the snap's configure hook. An invalid model proxy value must not be
applied: the snap keeps its last good settings and the unit blocks. The charm's
validation mirrors the snap hook's rules (the full URL, not just the scheme), and a
value the hook rejects anyway blocks the unit instead of erroring it.
"""

import socket

import pytest
from ops.testing import State

from charm import _validate_proxy_config
from charms.operator_libs_linux.v2.snap import SnapError

HTTPS_PROXY = "http://squid.example.com:3128"
HTTP_PROXY = "http://squid.example.com:3128"
NO_PROXY = "localhost,10.0.0.0/8"
FQDN = "juju-abcde-0"

PROXY_KEYS = ("https-proxy", "http-proxy", "no-proxy")

# "localhost", already present in the model's no-proxy, must not be duplicated
EXPECTED_NO_PROXY = f"{NO_PROXY},127.0.0.1,::1,0.0.0.0,{FQDN}"
EXPECTED_CONFIG = {
    "https-proxy": HTTPS_PROXY,
    "http-proxy": HTTP_PROXY,
    "no-proxy": EXPECTED_NO_PROXY,
}
CLEARED_CONFIG = dict.fromkeys(PROXY_KEYS)


@pytest.fixture(autouse=True)
def no_proxy_env(monkeypatch: pytest.MonkeyPatch):
    """Ensure no proxy variables leak in from the test environment."""
    for var in ("JUJU_CHARM_HTTPS_PROXY", "JUJU_CHARM_HTTP_PROXY", "JUJU_CHARM_NO_PROXY"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def patch_fqdn(monkeypatch: pytest.MonkeyPatch):
    """Make the local addresses appended to no-proxy deterministic."""
    monkeypatch.setattr(socket, "getfqdn", lambda: FQDN)


@pytest.fixture
def proxy_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("JUJU_CHARM_HTTPS_PROXY", HTTPS_PROXY)
    monkeypatch.setenv("JUJU_CHARM_HTTP_PROXY", HTTP_PROXY)
    monkeypatch.setenv("JUJU_CHARM_NO_PROXY", NO_PROXY)


def test_proxy_validation_matches_the_snap_hook_rules():
    """Validation mirrors the snap's configure hook: the full URL, not just the scheme."""
    # valid, case-insensitively
    for url in (
        "HTTP://squid.example.com:3128",
        "https://squid.example.com:3128",
        "http://squid.example.com",
        "Socks5://squid.example.com:1080",
        "socks5h://squid.example.com:1080",
        "http://user:password@squid.example.com:3128/",
        "http://[2001:db8::1]:3128",
        "http://squid.example.com:65535/",
    ):
        assert _validate_proxy_config({"https-proxy": url}) is None, url
    # rejected by the snap's configure hook too
    for url in (
        "squid.example.com:3128",  # no scheme
        "ftp://squid.example.com",  # unsupported scheme
        "http://",  # no host
        "http://user@squid.example.com:99999",  # port out of range
        "http://squid.example.com:0",  # port out of range
        "http://squid.example.com:3128/path",  # trailing path
        "http://squid_example.com",  # underscore is not a valid hostname character
        "http://squid.example.com:3128\n",  # trailing newline
    ):
        error = _validate_proxy_config({"https-proxy": url})
        assert error is not None, url
        assert "Invalid juju-https-proxy" in error
    # an empty value means "no proxy": valid
    assert _validate_proxy_config({"https-proxy": ""}) is None


def test_invalid_proxy_message_hides_credentials():
    """Credentials embedded in a rejected proxy URL are masked in the status message."""
    # scheme-less, so rejected, with credentials before the host
    error = _validate_proxy_config({"https-proxy": "user:password@squid.example.com:3128"})
    assert error is not None
    assert "password" not in error
    assert "***@squid.example.com:3128" in error
    # valid scheme but rejected port, with credentials
    error = _validate_proxy_config({"https-proxy": "http://user:password@squid:99999"})
    assert error is not None
    assert "password" not in error
    assert "http://***@squid:99999" in error
    # a URL without credentials is shown as-is
    error = _validate_proxy_config({"https-proxy": "http://squid:3128/path"})
    assert error is not None
    assert "http://squid:3128/path" in error


def proxy_writes(mock_snap):
    """The proxy configs the charm wrote to the snap.

    The proxy sync is the only code path that uses a typed `snap set`, so the typed
    calls unambiguously identify proxy writes.
    """
    return [call.args[0] for call in mock_snap.set.call_args_list if call.kwargs.get("typed")]


def test_proxy_settings_are_written_to_the_snap(ctx, mock_snap, proxy_env):
    """Model proxy settings are written to the snap, with local addresses in no-proxy."""
    # GIVEN the snap has no proxy options set
    mock_snap.get.return_value = {}

    # WHEN a hook runs with model proxy settings in the environment
    state_out = ctx.run(ctx.on.update_status(), State())

    # THEN the proxy options are written in one call, with local addresses appended
    # to no-proxy (and "localhost", already present, not duplicated)
    assert proxy_writes(mock_snap) == [EXPECTED_CONFIG]
    assert state_out.unit_status.name == "active"


def test_no_proxy_settings_means_no_snap_options(ctx, mock_snap):
    """Without model proxy settings, no proxy options are written to the snap."""
    # GIVEN no model proxy settings in the environment and a snap without proxy options
    mock_snap.get.return_value = {}

    # WHEN a hook runs
    ctx.run(ctx.on.update_status(), State())

    # THEN no proxy options were written
    assert proxy_writes(mock_snap) == []
    mock_snap.unset.assert_not_called()


def test_proxy_settings_removal_clears_the_snap_options(ctx, mock_snap):
    """Removing the model proxy settings clears the snap's proxy options."""
    # GIVEN the snap still has proxy options set from a previous reconcile
    mock_snap.get.return_value = dict(EXPECTED_CONFIG)

    # WHEN a hook runs after the proxy settings were removed from the model
    ctx.run(ctx.on.update_status(), State())

    # THEN the proxy options were cleared in one call
    assert proxy_writes(mock_snap) == [CLEARED_CONFIG]
    mock_snap.unset.assert_not_called()


def test_unchanged_proxy_settings_are_not_written_again(ctx, mock_snap, proxy_env):
    """Unchanged proxy options are not written again, so the collector is not restarted."""
    # GIVEN the snap already has the desired proxy options
    mock_snap.get.return_value = dict(EXPECTED_CONFIG)

    # WHEN a hook runs with the same model proxy settings
    ctx.run(ctx.on.update_status(), State())

    # THEN the proxy options were not written again
    assert proxy_writes(mock_snap) == []
    mock_snap.unset.assert_not_called()


def test_invalid_proxy_scheme_blocks_the_unit(ctx, mock_snap, monkeypatch):
    """A model proxy without a scheme is rejected: nothing is written, the unit blocks."""
    # GIVEN a model https-proxy without a scheme
    monkeypatch.setenv("JUJU_CHARM_HTTPS_PROXY", "squid.example.com:3128")
    mock_snap.get.return_value = {}

    # WHEN a hook runs
    state_out = ctx.run(ctx.on.update_status(), State())

    # THEN the unit is blocked with a message naming the offending model setting
    assert state_out.unit_status.name == "blocked"
    assert "Invalid juju-https-proxy" in state_out.unit_status.message
    # AND nothing was written to the snap
    assert proxy_writes(mock_snap) == []


def test_invalid_proxy_keeps_the_last_good_settings(ctx, mock_snap, monkeypatch):
    """An invalid model proxy value leaves the previously applied proxy settings in place."""
    # GIVEN the snap has valid proxy options from a previous reconcile
    mock_snap.get.return_value = dict(EXPECTED_CONFIG)
    # AND the model now has an https-proxy without a scheme
    monkeypatch.setenv("JUJU_CHARM_HTTPS_PROXY", "squid.example.com:3128")

    # WHEN a hook runs
    state_out = ctx.run(ctx.on.update_status(), State())

    # THEN the unit is blocked
    assert state_out.unit_status.name == "blocked"
    assert "Invalid juju-https-proxy" in state_out.unit_status.message
    # AND the last good proxy settings were left untouched
    assert proxy_writes(mock_snap) == []


def test_snap_rejected_proxy_value_blocks_the_unit(ctx, mock_snap, proxy_env):
    """Validation drift: a snap-rejected value blocks the unit instead of erroring it."""
    # GIVEN a snap without proxy options and a model proxy the charm considers valid
    mock_snap.get.return_value = {}

    # AND the snap's configure hook rejects the charm's write (e.g. stricter rules)
    def reject_typed_set(config, typed=False, **kwargs):
        if typed:
            raise SnapError("snap change 'configure' failed with status Error")

    mock_snap.set.side_effect = reject_typed_set

    # WHEN a hook runs
    state_out = ctx.run(ctx.on.update_status(), State())

    # THEN the proxy write was attempted exactly once: a failed snapd change is
    # deterministic, so it is not retried
    assert len(proxy_writes(mock_snap)) == 1
    # AND the unit is blocked, not in error, naming the proxy settings
    assert state_out.unit_status.name == "blocked"
    assert "model proxy settings" in state_out.unit_status.message
