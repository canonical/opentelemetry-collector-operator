# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Step definitions for memory_limiter.feature."""

from unittest.mock import patch

import pytest
from ops.testing import State
from pytest_bdd import given, parsers, scenarios, then, when
from scenario import BlockedStatus

from helpers import get_otelcol_config_file
from src.config_manager import ConfigManager

scenarios("features/memory_limiter.feature")


@pytest.fixture
def context():
    """Mutable dict shared across steps within a single scenario."""
    return {}


# --- Given ---


@given(parsers.parse("total available memory is {memory:d} MiB"))
def given_total_memory(context, memory):
    context["total_memory"] = memory


@given(parsers.parse("the spike percentage is {spike:d}"))
def given_spike_percentage(context, spike):
    context["spike_percentage"] = spike


@given(parsers.parse("a user requested hard limit percentage of {user_input:d}"))
def given_user_requested_limit(context, user_input):
    context["user_input"] = user_input


@given("a user provides no value for the memory_limit_percentage config option")
def given_no_config(context):
    context["state"] = State(leader=True)


@given(parsers.parse('a user provides {value:d} for the memory_limit_percentage config option'))
def given_config_value(context, value):
    context["state"] = State(leader=True, config={"memory_limit_percentage": value})


@given('a user provides a memory_limiter in the processors config option')
def given_processors_config_value(context):
    context["state"] = State(
        leader=True,
        config={"processors": "memory_limiter:\n  limit_mib: 9999\n"},
    )


@given("no config options are set")
def given_no_config_options(context):
    context["state"] = State(leader=True)


# --- When ---


@when("the memory limiter processor is added to the config")
def when_add_memory_limiter(context):
    with patch("src.config_manager.total_memory_mib", return_value=context["total_memory"]):
        config_manager = ConfigManager("otelcol/0", "otelcol", "", "")
        config_manager.add_memory_limiter_processor(context["user_input"])
    context["config_manager"] = config_manager
    ml = config_manager.config._config["processors"]["memory_limiter"]
    context["limit_mib"] = ml["limit_mib"]
    context["spike_limit_mib"] = ml["spike_limit_mib"]


@when("any event executes the reconciler")
def when_reconciler_runs(context, ctx, unit_name, config_folder):
    with patch("config_manager.total_memory_mib", return_value=context["total_memory"]):
        state_out = ctx.run(ctx.on.update_status(), state=context["state"])
    context["state_out"] = state_out
    cfg = get_otelcol_config_file(unit_name, config_folder)
    context["cfg"] = cfg
    processor = cfg.get("processors", {}).get("memory_limiter", {})
    context["limit_mib"] = processor.get("limit_mib")
    context["spike_limit_mib"] = processor.get("spike_limit_mib")


# --- Then ---


@then(parsers.parse("the hard limit is {clamped_percentage:d}% of total memory"))
def then_hard_limit_is(context, clamped_percentage):
    expected = clamped_percentage * context["total_memory"] // 100
    limit_mib = context["limit_mib"]
    assert limit_mib == expected
    assert limit_mib >= 0
    assert limit_mib <= context["total_memory"]


@then(parsers.parse("the spike limit is {percentage:d} percent of the hard limit"))
def then_spike_limit(context, percentage):
    limit_mib = context["limit_mib"]
    spike_limit_mib = context["spike_limit_mib"]
    assert spike_limit_mib == limit_mib * percentage // 100
    assert spike_limit_mib >= 0
    assert limit_mib >= spike_limit_mib


@then(parsers.parse("the hard limit in the generated config is {percentage:d}% of total memory"))
def then_generated_hard_limit(context, percentage):
    expected = percentage * context["total_memory"] // 100
    assert context["limit_mib"] == expected


@then("the charm is in BlockedStatus")
def then_blocked_status(context):
    assert type(context["state_out"].unit_status) is BlockedStatus


@then("memory_limiter is the first processor in all pipelines")
def then_memory_limiter_first(context):
    pipelines = context["cfg"].get("service", {}).get("pipelines", {})
    assert pipelines, "No pipelines found in config"
    for pipeline in pipelines.values():
        processors = pipeline.get("processors", [])
        assert processors, "No processors found in pipeline"
        assert processors[0] == "memory_limiter"


@then("only the custom memory_limiter processor is in the pipelines")
def then_only_custom_memory_limiter(context):
    pipelines = context["cfg"].get("service", {}).get("pipelines", {})
    assert pipelines, "No pipelines found in config"
    for pipeline in pipelines.values():
        processors = pipeline.get("processors", [])
        memory_limiters = [p for p in processors if "memory_limiter" in p]
        assert len(memory_limiters) == 1
        assert "_custom" in memory_limiters[0]
