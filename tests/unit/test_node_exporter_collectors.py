# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: node-exporter collectors are disabled through the node_exporter_disabled_collectors option."""

import dataclasses
import logging
from unittest.mock import patch

import pytest
from config_builder import parse_node_exporter_disabled_collectors
from ops.testing import Relation, State, SubordinateRelation
from scenario import BlockedStatus

TEXTFILE_DIR_PREFIX = "textfile.directory="


@pytest.mark.parametrize(
    "value, disabled, invalid",
    [
        pytest.param("", set(), [], id="empty-input-disables-nothing"),
        pytest.param(" , ", set(), [], id="commas-and-whitespace-equal-empty-input"),
        pytest.param("logind,systemd", {"logind", "systemd"}, [], id="managed-names-disabled"),
        pytest.param(
            "logind,bogus,systemd,drm,",
            {"logind", "systemd", "drm"},
            ["bogus"],
            id="invalid-names-ignored-rest-applied",
        ),
        pytest.param("bogus", set(), ["bogus"], id="only-invalid-names-disable-nothing"),
        pytest.param("Logind", set(), ["Logind"], id="matching-is-case-sensitive"),
        pytest.param(
            "logind,logind,bogus,bogus",
            {"logind"},
            ["bogus"],
            id="duplicates-collapse-invalid-reported-once",
        ),
        pytest.param("textfile", set(), ["textfile"], id="textfile-cannot-be-disabled"),
        pytest.param(
            "textfile,logind",
            {"logind"},
            ["textfile"],
            id="textfile-rejected-others-applied",
        ),
        pytest.param("cpu", set(), ["cpu"], id="upstream-collector-not-managed"),
        pytest.param(
            " logind , systemd ",
            {"logind", "systemd"},
            [],
            id="whitespace-around-tokens-stripped",
        ),
    ],
)
def test_parse_node_exporter_disabled_collectors(value, disabled, invalid):
    """Parse the option value into managed collectors to disable and invalid names."""
    # GIVEN a node_exporter_disabled_collectors option value
    # WHEN it is parsed
    result_disabled, result_invalid = parse_node_exporter_disabled_collectors(value)
    # THEN the collectors to disable and the invalid names match the expectation
    assert result_disabled == disabled
    assert result_invalid == invalid


def test_parse_returns_new_set_not_shared_constant():
    """Mutating a returned set must not leak into later calls."""
    # GIVEN a set returned for the empty input
    disabled, _ = parse_node_exporter_disabled_collectors("")
    # WHEN a member is added to that set
    disabled.add("drm")
    # THEN a fresh call still disables nothing
    again, _ = parse_node_exporter_disabled_collectors("")
    assert again == set()


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


def _warnings_naming(caplog, *names):
    """Return WARNING records whose message mentions any of the given names."""
    return [
        record
        for record in caplog.records
        if record.levelno == logging.WARNING and any(name in record.getMessage() for name in names)
    ]


def test_empty_value_leaves_every_managed_collector_enabled(ctx, snap_configs):
    """With nothing disabled, all managed collectors are enabled, including logind and systemd."""
    # GIVEN the option is set to an empty string
    state = State(config={"node_exporter_disabled_collectors": ""})
    # WHEN a config_changed hook runs
    ctx.run(ctx.on.config_changed(), state)
    # THEN every managed collector is enabled and none is sent as disabled
    enabled, disabled = _node_exporter_tokens(snap_configs)
    assert enabled == {
        "drm",
        "logind",
        "mountstats",
        "processes",
        "sysctl",
        "systemd",
        "textfile",
    }
    assert disabled == set()


def test_disabled_collectors_are_sent_as_no_collectors(ctx, snap_configs):
    """Listed managed collectors are disabled and the rest stay enabled."""
    # GIVEN two managed collectors listed as disabled
    state = State(config={"node_exporter_disabled_collectors": "logind,systemd"})
    # WHEN a config_changed hook runs
    ctx.run(ctx.on.config_changed(), state)
    # THEN the listed collectors are sent as disabled
    enabled, disabled = _node_exporter_tokens(snap_configs)
    assert disabled == {"logind", "systemd"}
    # AND the unlisted managed collectors and textfile remain enabled
    assert enabled == {"drm", "mountstats", "processes", "sysctl", "textfile"}
    # AND upstream collectors appear in neither set
    assert "cpu" not in enabled | disabled
    assert "diskstats" not in enabled | disabled


def test_invalid_names_block_unit_and_are_skipped(ctx, snap_configs, caplog):
    """Invalid names are ignored, the rest applied, and the unit goes Blocked with a warning."""
    # GIVEN a value with invalid names, including a case mismatch
    state = State(
        config={"node_exporter_disabled_collectors": "logind,bogus,Systemd"},
        relations=[SubordinateRelation("cos-agent"), Relation("send-remote-write")],
    )
    # WHEN a config_changed hook runs
    state_out = ctx.run(ctx.on.config_changed(), state)
    # THEN only the valid name is disabled
    enabled, disabled = _node_exporter_tokens(snap_configs)
    assert disabled == {"logind"}
    assert enabled == {"drm", "mountstats", "processes", "sysctl", "systemd", "textfile"}
    # AND the unit is Blocked with a message naming the invalid collectors
    assert isinstance(state_out.unit_status, BlockedStatus)
    assert "bogus" in state_out.unit_status.message
    assert "Systemd" in state_out.unit_status.message
    # AND exactly one WARNING names both invalid collectors
    warnings = _warnings_naming(caplog, "bogus", "Systemd")
    assert len(warnings) == 1
    assert "bogus" in warnings[0].getMessage()
    assert "Systemd" in warnings[0].getMessage()


def test_textfile_cannot_be_disabled(ctx, snap_configs, caplog):
    """Textfile stays enabled and is reported as invalid when listed."""
    # GIVEN textfile and logind listed as disabled
    state = State(
        config={"node_exporter_disabled_collectors": "textfile,logind"},
        relations=[SubordinateRelation("cos-agent"), Relation("send-remote-write")],
    )
    # WHEN a config_changed hook runs
    state_out = ctx.run(ctx.on.config_changed(), state)
    # THEN textfile is still enabled and only logind is disabled
    enabled, disabled = _node_exporter_tokens(snap_configs)
    assert "textfile" in enabled
    assert "textfile" not in disabled
    assert disabled == {"logind"}
    # AND the unit is Blocked and a WARNING names textfile
    assert isinstance(state_out.unit_status, BlockedStatus)
    assert "textfile" in state_out.unit_status.message
    assert len(_warnings_naming(caplog, "textfile")) == 1


def test_invalid_warning_logged_even_when_relation_check_blocks(ctx, caplog):
    """The warning is logged even when a later relation check replaces the Blocked status."""
    # GIVEN a value with an invalid name and a cos-agent relation with no sink
    state = State(
        config={"node_exporter_disabled_collectors": "logind,bogus"},
        relations=[SubordinateRelation("cos-agent")],
    )
    # WHEN a config_changed hook runs
    state_out = ctx.run(ctx.on.config_changed(), state)
    # THEN the unit is Blocked by the missing mandatory relation
    assert isinstance(state_out.unit_status, BlockedStatus)
    assert "] for cos-agent" in state_out.unit_status.message
    # AND the warning still names the invalid collector
    warnings = _warnings_naming(caplog, "bogus")
    assert len(warnings) == 1


def test_fixing_invalid_names_clears_blocked_status(ctx, snap_configs):
    """Removing invalid names from the option recovers the unit and applies the new set."""
    # GIVEN a unit blocked by an invalid collector name
    relations = [SubordinateRelation("cos-agent"), Relation("send-remote-write")]
    blocked_state = ctx.run(
        ctx.on.config_changed(),
        State(
            config={"node_exporter_disabled_collectors": "logind,bogus,Systemd"},
            relations=relations,
        ),
    )
    assert isinstance(blocked_state.unit_status, BlockedStatus)
    # WHEN the option is corrected to valid names only
    recovered_state = ctx.run(
        ctx.on.config_changed(),
        dataclasses.replace(
            blocked_state, config={"node_exporter_disabled_collectors": "logind"}
        ),
    )
    # THEN the unit is no longer Blocked
    assert not isinstance(recovered_state.unit_status, BlockedStatus)
    # AND the corrected set is applied
    enabled, disabled = _node_exporter_tokens(snap_configs)
    assert disabled == {"logind"}
    assert enabled == {"drm", "mountstats", "processes", "sysctl", "systemd", "textfile"}
