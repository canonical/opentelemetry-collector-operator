Feature: Node exporter info metric file

  Scenario: Info metric file is written when charm runs
    Given the charm is deployed
    When a "update-status" hook runs
    Then the info metric file "textfile-collector.d/otelcol_0.prom" exists
    And the file "textfile-collector.d/otelcol_0.prom" contains "# HELP otelcol_subordinate_charm_info"

  Scenario Outline: Info metric contains related unit from subordinate relation
    Given a <relation_name> relation to a principal app named "<app_name>"
    When a "update-status" hook runs
    Then the file "textfile-collector.d/otelcol_0.prom" contains "<unit_name>"
    And the file "textfile-collector.d/otelcol_0.prom" contains "<app_name>"

    Examples:
      | relation_name | app_name  | unit_name   |
      | juju-info     | ubuntu    | ubuntu/0    |
      | cos-agent     | zookeeper | zookeeper/0 |

  Scenario: Info metric contains one line per related unit when related to multiple apps
    Given a juju-info relation to a principal app named "ubuntu"
    And a "cos-agent" relation to a principal app named "hardware-observer"
    When a "update-status" hook runs
    Then the file "textfile-collector.d/otelcol_0.prom" contains "ubuntu/0"
    And the file "textfile-collector.d/otelcol_0.prom" contains "hardware-observer/0"

  Scenario: Info metric file is removed on charm removal
    Given the file "textfile-collector.d/otelcol_0.prom" exists
    When the "remove hook" runs
    Then the file "textfile-collector.d/otelcol_0.prom" does not exist

  Scenario: Removing info metric file is a no-op when it does not exist
    Given the info metric file does not exist
    When the remove hook runs
    Then the info metric file "textfile-collector.d/otelcol_0.prom" does not exist
