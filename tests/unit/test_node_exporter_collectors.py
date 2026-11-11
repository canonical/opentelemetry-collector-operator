# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: node-exporter collectors are selected by the node_exporter_collectors option."""

import dataclasses
import logging
from unittest.mock import patch

import pytest
from config_builder import parse_node_exporter_collectors
from ops.testing import Relation, State, SubordinateRelation
from scenario import BlockedStatus

TEXTFILE_DIR_PREFIX = "textfile.directory="
UNKNOWN_LOG = "Ignoring unknown node-exporter collectors"


@pytest.mark.parametrize(
    "value, enabled, unknown",
    [
        pytest.param(
            "",
            {"drm", "mountstats", "processes", "sysctl", "textfile"},
            [],
            id="empty-input-enables-default-set",
        ),
        pytest.param(
            " , ",
            {"drm", "mountstats", "processes", "sysctl", "textfile"},
            [],
            id="commas-and-whitespace-equal-empty-input",
        ),
        pytest.param(
            "logind,systemd,bogus,drm,",
            {"drm", "logind", "systemd", "textfile"},
            ["bogus"],
            id="unknown-names-dropped-rest-applied",
        ),
        pytest.param(
            "bogus",
            {"textfile"},
            ["bogus"],
            id="only-unknown-names-do-not-use-default-set",
        ),
        pytest.param(
            "Logind",
            {"textfile"},
            ["Logind"],
            id="matching-is-case-sensitive",
        ),
        pytest.param(
            "logind,logind,bogus,bogus",
            {"logind", "textfile"},
            ["bogus"],
            id="duplicates-collapse-unknown-reported-once",
        ),
        pytest.param(
            "logind",
            {"logind", "textfile"},
            [],
            id="textfile-enabled-when-omitted",
        ),
        pytest.param(
            " logind , systemd ",
            {"logind", "systemd", "textfile"},
            [],
            id="whitespace-around-tokens-stripped",
        ),
    ],
)
def test_parse_node_exporter_collectors(value, enabled, unknown):
    """Parse the option value into enabled managed collectors and unknown names."""
    # GIVEN a node_exporter_collectors option value
    # WHEN it is parsed
    result_enabled, result_unknown = parse_node_exporter_collectors(value)
    # THEN the enabled collectors and the unknown names match the expectation
    assert result_enabled == enabled
    assert result_unknown == unknown


def test_parse_returns_new_set_not_shared_constant():
    """Mutating a returned set must not leak into later calls."""
    # GIVEN a set returned for the empty input
    enabled, _ = parse_node_exporter_collectors("")
    # WHEN a member is removed from that set
    enabled.discard("drm")
    # THEN a fresh call still enables drm
    again, _ = parse_node_exporter_collectors("")
    assert "drm" in again


@pytest.fixture
def snap_configs():
    """Capture the configs sent to the node-exporter snap."""
    with patch("charm.OpenTelemetryCollectorCharm._set_snap_configs_with_retry") as mock:
        yield mock


def _node_exporter_tokens(snap_configs):
    """Return enabled collectors (without the textfile.directory token) and disabled collectors."""
    configs = snap_configs.call_args.args[1]
    tokens = configs["collectors"].split()
    directory_tokens = [t for t in tokens if t.startswith(TEXTFILE_DIR_PREFIX)]
    assert len(directory_tokens) == 1
    enabled = set(tokens) - set(directory_tokens)
    disabled = set(configs["no-collectors"].split())
    return enabled, disabled


def _unknown_collector_warnings(caplog):
    """Return WARNING records that report unknown node-exporter collectors."""
    return [
        record
        for record in caplog.records
        if record.levelno == logging.WARNING and UNKNOWN_LOG in record.getMessage()
    ]


def test_explicit_empty_value_enables_default_set(ctx, snap_configs, caplog):
    """An explicit empty value enables the default collectors and no warning is logged."""
    # GIVEN the option is set to an empty string
    state = State(config={"node_exporter_collectors": ""})
    # WHEN a config_changed hook runs
    ctx.run(ctx.on.config_changed(), state)
    # THEN the default collectors are enabled and logind and systemd are disabled
    enabled, disabled = _node_exporter_tokens(snap_configs)
    assert enabled == {"drm", "mountstats", "processes", "sysctl", "textfile"}
    assert disabled == {"logind", "systemd"}
    # AND no unknown-collector warning is logged
    assert _unknown_collector_warnings(caplog) == []


def test_managed_subset_enables_listed_collectors(ctx, snap_configs, caplog):
    """Listed managed collectors are enabled and upstream collectors are not touched."""
    # GIVEN a managed subset of collectors
    state = State(config={"node_exporter_collectors": "drm,logind,systemd"})
    # WHEN a config_changed hook runs
    ctx.run(ctx.on.config_changed(), state)
    # THEN the listed collectors and textfile are enabled
    enabled, disabled = _node_exporter_tokens(snap_configs)
    assert enabled == {"drm", "logind", "systemd", "textfile"}
    # AND the unlisted managed collectors are disabled
    assert disabled == {"mountstats", "processes", "sysctl"}
    # AND upstream collectors appear in neither set
    assert "cpu" not in enabled | disabled
    assert "diskstats" not in enabled | disabled
    # AND no unknown-collector warning is logged
    assert _unknown_collector_warnings(caplog) == []


def test_unknown_names_block_unit_and_log_warning(ctx, snap_configs, caplog):
    """Unknown names are ignored, the rest applied, and the unit goes Blocked with a warning."""
    # GIVEN a value with unknown names, including a case mismatch
    state = State(
        config={"node_exporter_collectors": "logind,bogus,Systemd"},
        relations=[SubordinateRelation("cos-agent"), Relation("send-remote-write")],
    )
    # WHEN a config_changed hook runs
    state_out = ctx.run(ctx.on.config_changed(), state)
    # THEN the known collector is applied and the unknown names are not
    enabled, disabled = _node_exporter_tokens(snap_configs)
    assert enabled == {"logind", "textfile"}
    assert disabled == {"drm", "mountstats", "processes", "sysctl", "systemd"}
    # AND the unit is Blocked with a message naming the unknown collectors
    assert isinstance(state_out.unit_status, BlockedStatus)
    assert "bogus" in state_out.unit_status.message
    assert "Systemd" in state_out.unit_status.message
    # AND exactly one WARNING names both unknown collectors
    warnings = _unknown_collector_warnings(caplog)
    assert len(warnings) == 1
    assert "bogus" in warnings[0].getMessage()
    assert "Systemd" in warnings[0].getMessage()


def test_unknown_warning_logged_even_when_relation_check_blocks(ctx, caplog):
    """The warning is logged even when a later relation check replaces the Blocked status."""
    # GIVEN a value with an unknown name and a cos-agent relation with no sink
    state = State(
        config={"node_exporter_collectors": "logind,bogus"},
        relations=[SubordinateRelation("cos-agent")],
    )
    # WHEN a config_changed hook runs
    state_out = ctx.run(ctx.on.config_changed(), state)
    # THEN the unit is Blocked by the missing mandatory relation
    assert isinstance(state_out.unit_status, BlockedStatus)
    assert "] for cos-agent" in state_out.unit_status.message
    # AND the warning still names the unknown collector
    warnings = _unknown_collector_warnings(caplog)
    assert len(warnings) == 1
    assert "bogus" in warnings[0].getMessage()


def test_fixing_unknown_names_clears_blocked_status(ctx, snap_configs):
    """Removing unknown names from the option recovers the unit and applies the new set."""
    # GIVEN a unit blocked by an unknown collector name
    relations = [SubordinateRelation("cos-agent"), Relation("send-remote-write")]
    blocked_state = ctx.run(
        ctx.on.config_changed(),
        State(config={"node_exporter_collectors": "logind,bogus,Systemd"}, relations=relations),
    )
    assert isinstance(blocked_state.unit_status, BlockedStatus)
    # WHEN the option is corrected to known names only
    recovered_state = ctx.run(
        ctx.on.config_changed(),
        dataclasses.replace(
            blocked_state, config={"node_exporter_collectors": "logind,systemd"}
        ),
    )
    # THEN the unit is no longer Blocked
    assert not isinstance(recovered_state.unit_status, BlockedStatus)
    # AND the corrected collector set is applied
    enabled, disabled = _node_exporter_tokens(snap_configs)
    assert enabled == {"logind", "systemd", "textfile"}
    assert disabled == {"drm", "mountstats", "processes", "sysctl"}
