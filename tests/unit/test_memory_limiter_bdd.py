# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Step definitions for memory_limiter.feature."""

from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import patch

from ops.testing import State
from pytest_bdd import given, parsers, scenarios, then, when
from scenario import BlockedStatus

from helpers import get_otelcol_config_file
from src.config_manager import ConfigManager

scenarios("features/memory_limiter.feature")


@dataclass
class Result:
    """Values produced by a When step and consumed by Then steps."""

    limit_mib: Optional[int] = None
    spike_limit_mib: Optional[int] = None
    state_out: Optional[State] = None
    cfg: dict = field(default_factory=dict)


# --- Given ---


@given(parsers.parse("total available memory is {memory:d} MiB"), target_fixture="total_memory")
def given_total_memory(memory):
    return memory


@given(parsers.parse("the spike percentage is {spike:d}"), target_fixture="spike_percentage")
def given_spike_percentage(spike):
    return spike


@given(parsers.parse("a user requested hard limit percentage of {user_input:d}"), target_fixture="user_input")
def given_user_requested_limit(user_input):
    return user_input


@given("a user provides no value for the memory_limit_percentage config option", target_fixture="state")
def given_no_config():
    return State(leader=True)


@given(parsers.parse('a user provides {value:d} for the memory_limit_percentage config option'), target_fixture="state")
def given_config_value(value):
    return State(leader=True, config={"memory_limit_percentage": value})


@given('a user provides a memory_limiter in the processors config option', target_fixture="state")
def given_processors_config_value():
    return State(
        leader=True,
        config={"processors": "memory_limiter:\n  limit_mib: 9999\n"},
    )


@given("no config options are set", target_fixture="state")
def given_no_config_options():
    return State(leader=True)


# --- When ---


@when("the memory limiter processor is added to the config", target_fixture="result")
def when_add_memory_limiter(total_memory, user_input):
    with patch("src.config_manager.total_memory_mib", return_value=total_memory):
        config_manager = ConfigManager("otelcol/0", "otelcol", "", "")
        config_manager.add_memory_limiter_processor(user_input)
    ml = config_manager.config._config["processors"]["memory_limiter"]
    return Result(limit_mib=ml["limit_mib"], spike_limit_mib=ml["spike_limit_mib"])


@when("any event executes the reconciler", target_fixture="result")
def when_reconciler_runs(total_memory, state, ctx, unit_name, config_folder):
    with patch("config_manager.total_memory_mib", return_value=total_memory):
        state_out = ctx.run(ctx.on.update_status(), state=state)
    cfg = get_otelcol_config_file(unit_name, config_folder)
    processor = cfg.get("processors", {}).get("memory_limiter", {})
    return Result(
        limit_mib=processor.get("limit_mib"),
        spike_limit_mib=processor.get("spike_limit_mib"),
        state_out=state_out,
        cfg=cfg,
    )


# --- Then ---


@then(parsers.parse("the hard limit is {clamped_percentage:d}% of total memory"))
def then_hard_limit_is(result, total_memory, clamped_percentage):
    expected = clamped_percentage * total_memory // 100
    assert result.limit_mib == expected
    assert result.limit_mib >= 0
    assert result.limit_mib <= total_memory


@then(parsers.parse("the spike limit is {percentage:d} percent of the hard limit"))
def then_spike_limit(result, percentage):
    assert result.spike_limit_mib == result.limit_mib * percentage // 100
    assert result.spike_limit_mib >= 0
    assert result.limit_mib >= result.spike_limit_mib


@then(parsers.parse("the hard limit in the generated config is {percentage:d}% of total memory"))
def then_generated_hard_limit(result, total_memory, percentage):
    expected = percentage * total_memory // 100
    assert result.limit_mib == expected


@then("the charm is in BlockedStatus")
def then_blocked_status(result):
    assert type(result.state_out.unit_status) is BlockedStatus


@then("memory_limiter is the first processor in all pipelines")
def then_memory_limiter_first(result):
    pipelines = result.cfg.get("service", {}).get("pipelines", {})
    assert pipelines, "No pipelines found in config"
    for pipeline in pipelines.values():
        processors = pipeline.get("processors", [])
        assert processors, "No processors found in pipeline"
        assert processors[0] == "memory_limiter"


@then("only the custom memory_limiter processor is in the pipelines")
def then_only_custom_memory_limiter(result):
    pipelines = result.cfg.get("service", {}).get("pipelines", {})
    assert pipelines, "No pipelines found in config"
    for pipeline in pipelines.values():
        processors = pipeline.get("processors", [])
        memory_limiters = [p for p in processors if "memory_limiter" in p]
        assert len(memory_limiters) == 1
        assert "_custom" in memory_limiters[0]
