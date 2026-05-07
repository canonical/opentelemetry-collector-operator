Feature: Node exporter info metric file

  Scenario: Info metric file is written when charm runs
    Given the charm is deployed
    When a "update-status" hook runs
    Then the info metric file "textfile-collector.d/otelcol_0.prom" exists
    And the file "textfile-collector.d/otelcol_0.prom" contains "# HELP otelcol_subordinate_charm_info"

  Scenario Outline: Info metric contains related unit from subordinate relation
    Given a <relation_name> relation to a principal app named "ubuntu"
    When a "update-status" hook runs
    Then the info metric file contains the related unit ubuntu/0
    And the info metric file contains the related app ubuntu

    Examples:
      | relation_name |
      | juju-info     |
      | cos-agent     |

  Scenario: Info metric contains one line per related unit when related to multiple apps
    Given a juju-info relation to a principal app named "ubuntu"
    And also a cos-agent relation to a principal app named "hardware-observer"
    When a "update-status" hook runs
    Then the info metric file contains the related unit ubuntu/0
    And the info metric file contains the related unit hardware-observer/0

  Scenario: Info metric file is removed on charm removal
    Given the info metric file exists
    When the remove hook runs
    Then the info metric file "textfile-collector.d/otelcol_0.prom" does not exist

  Scenario: Removing info metric file is a no-op when it does not exist
    Given the info metric file does not exist
    When the remove hook runs
    Then the info metric file "textfile-collector.d/otelcol_0.prom" does not exist
