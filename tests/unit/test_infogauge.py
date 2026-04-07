from pytest_bdd import given, when, then, scenarios
from pytest_bdd.parsers import parse
import ast
from utils import InfoGauge
from collections import Counter


scenarios("features/infogauge.feature")


@given("an InfoGauge dataclass with fields", target_fixture="infogauge")
def _(datatable):
    test_data = dict(datatable)
    info_gauge = InfoGauge(name=test_data["name"], help_=test_data["help"])
    return info_gauge

@when("I add a timeseries without labels")
def _(infogauge):
    infogauge.add({})

@when(parse("I add a timeseries with labels '{labels}'"))
def _(infogauge, labels):
    labels = ast.literal_eval(labels) if labels else {}
    infogauge.add(labels)

@when("I call str() on the InfoGauge instance", target_fixture="metrics_entry")
def _(infogauge):
    return str(infogauge)

@then("The output should be an empty string")
def _(metrics_entry):
    assert metrics_entry == ""

@then(parse('The output should contain the line "{line}"'))
def _(metrics_entry, line):
    assert line in metrics_entry

@then(parse('The output should contain the line "{line}" exactly once'))
def _(metrics_entry, line):
    assert Counter(metrics_entry.splitlines())[line] == 1
