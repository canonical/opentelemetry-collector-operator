# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Node exporter info metric file."""

from unittest.mock import patch

from ops.testing import State, SubordinateRelation
from pytest_bdd import given, parsers, scenarios, then, when


scenarios("features/test_node_exporter_info_metric.feature")


# --- GIVEN ---


@given("the charm is deployed", target_fixture="state")
def state_deployed():
    return State()


@given(
    parsers.parse('a {relation_name} relation to a principal app named "{app_name}"'),
    target_fixture="state",
)
def state_with_relation(relation_name, app_name):
    rel = SubordinateRelation(relation_name, remote_app_name=app_name, remote_unit_id=0)
    return State(relations=[rel])


@given(
    parsers.parse('also a {relation_name} relation to a principal app named "{app_name}"'),
    target_fixture="state",
)
def state_with_additional_relation(state, relation_name, app_name):
    rel = SubordinateRelation(relation_name, remote_app_name=app_name, remote_unit_id=0)
    return State(relations=[*state.relations, rel])


@given("the info metric file exists", target_fixture="state")
def state_with_existing_metric_file(tmp_path):
    prom_file = tmp_path / "textfile-collector.d" / "otelcol_0.prom"
    prom_file.write_text("existing content")
    return State()


@given("the info metric file does not exist", target_fixture="state")
def state_without_metric_file(tmp_path):
    prom_file = tmp_path / "textfile-collector.d" / "otelcol_0.prom"
    assert not prom_file.exists()
    return State()


# --- WHEN ---


@when(parsers.parse('a "{hook}" hook runs'), target_fixture="state_out")
def run_hook(ctx, state, hook):
    event_method = getattr(ctx.on, hook.replace("-", "_"))
    return ctx.run(event_method(), state)


@when("the remove hook runs", target_fixture="state_out")
def run_remove(ctx, state):
    with patch("singleton_snap.SingletonSnapManager.unregister_all_for_unit"):
        return ctx.run(ctx.on.remove(), state)


# --- THEN ---


@then(parsers.parse('the info metric file "{path}" exists'))
def info_metric_file_exists(tmp_path, path):
    assert (tmp_path / path).exists()


@then(parsers.parse('the file "{path}" contains "{content}"'))
def file_contains(tmp_path, path, content):
    assert content in (tmp_path / path).read_text()


@then(parsers.parse("the info metric file contains the related unit {related_unit}"))
def file_contains_related_unit(tmp_path, related_unit):
    content = (tmp_path / "textfile-collector.d" / "otelcol_0.prom").read_text()
    assert f'related_unit="{related_unit}"' in content


@then(parsers.parse("the info metric file contains the related app {related_app}"))
def file_contains_related_app(tmp_path, related_app):
    content = (tmp_path / "textfile-collector.d" / "otelcol_0.prom").read_text()
    assert f'related_app="{related_app}"' in content


@then(parsers.parse('the info metric file "{path}" does not exist'))
def info_metric_file_does_not_exist(tmp_path, path):
    assert not (tmp_path / path).exists()
