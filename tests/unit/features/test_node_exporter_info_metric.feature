Feature: Node exporter info metric file

  Scenario: Info metric file is written when charm runs
    Given the charm is deployed
    When an update-status hook runs
    Then the info metric file exists
    And the file contains the subordinate unit name

  Scenario Outline: Info metric contains principal unit from subordinate relation
    Given a <relation_name> relation to a principal app named ubuntu
    When an update-status hook runs
    Then the info metric file contains the principal unit ubuntu/0

    Examples:
      | relation_name |
      | juju-info     |
      | cos-agent     |

  Scenario: Info metric file is removed on charm removal
    Given the info metric file exists
    When the remove hook runs
    Then the info metric file does not exist

  Scenario: Removing info metric file is a no-op when it does not exist
    Given the info metric file does not exist
    When the remove hook runs
    Then the info metric file does not exist
