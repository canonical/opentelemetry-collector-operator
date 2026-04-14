# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Feature: Node exporter info metric file."""

from unittest.mock import patch

from ops.testing import State, SubordinateRelation
from pytest_bdd import given, parsers, scenario, then, when


@scenario("features/test_node_exporter_info_metric.feature", "Info metric file is written when charm runs")
def test_info_metric_file_is_written():
    pass


@scenario(
    "features/test_node_exporter_info_metric.feature",
    "Info metric contains principal unit from subordinate relation",
)
def test_info_metric_contains_principal_unit():
    pass


@scenario("features/test_node_exporter_info_metric.feature", "Info metric file is removed on charm removal")
def test_info_metric_file_removed_on_remove():
    pass


@scenario(
    "features/test_node_exporter_info_metric.feature",
    "Removing info metric file is a no-op when it does not exist",
)
def test_info_metric_file_remove_is_noop_when_missing():
    pass


# --- GIVEN ---


@given("the charm is deployed", target_fixture="state")
def state_deployed():
    return State()


@given(
    parsers.parse("a {relation_name} relation to a principal app named {app_name}"),
    target_fixture="state",
)
def state_with_relation(relation_name, app_name):
    rel = SubordinateRelation(relation_name, remote_app_name=app_name, remote_unit_id=0)
    return State(relations=[rel])


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


@when("an update-status hook runs", target_fixture="state_out")
def run_update_status(ctx, state):
    return ctx.run(ctx.on.update_status(), state)


@when("the remove hook runs", target_fixture="state_out")
def run_remove(ctx, state):
    with patch("singleton_snap.SingletonSnapManager.unregister"):
        return ctx.run(ctx.on.remove(), state)


# --- THEN ---


@then("the info metric file exists")
def info_metric_file_exists(tmp_path):
    assert (tmp_path / "textfile-collector.d" / "otelcol_0.prom").exists()


@then("the file contains the subordinate unit name")
def file_contains_subordinate_unit(tmp_path, unit_name):
    content = (tmp_path / "textfile-collector.d" / "otelcol_0.prom").read_text()
    assert f'subordinate_unit="{unit_name}"' in content


@then(parsers.parse("the info metric file contains the principal unit {principal_unit}"))
def file_contains_principal_unit(tmp_path, principal_unit):
    content = (tmp_path / "textfile-collector.d" / "otelcol_0.prom").read_text()
    assert f'principal_unit="{principal_unit}"' in content


@then(parsers.parse("the info metric file contains the principal app {principal_app}"))
def file_contains_principal_app(tmp_path, principal_app):
    content = (tmp_path / "textfile-collector.d" / "otelcol_0.prom").read_text()
    assert f'principal_app="{principal_app}"' in content


@then("the info metric file does not exist")
def info_metric_file_does_not_exist(tmp_path):
    assert not (tmp_path / "textfile-collector.d" / "otelcol_0.prom").exists()
