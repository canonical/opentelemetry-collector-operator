Feature: InfoGauge __str__ representation
  As a developer
  I want the InfoGauge dataclass __str__ to produce a valid metrics endpoint representation.

  Background:
    Given an InfoGauge dataclass with fields
      | name   | my_metric               |
      | help   | Description of metric   |

  Scenario: No labels added
    When I call str() on the InfoGauge instance
    Then The output should be an empty string

  Scenario: No labels provided
    When I add a timeseries without labels
    And I call str() on the InfoGauge instance
    Then The output should contain the line "HELP my_metric Description of metric"
    And The output should contain the line "TYPE my_metric gauge"
    And The output should contain the line "my_metric 1"

  Scenario: Deterministic ordering of labels (sorted by key)
    When I add a timeseries with labels '{"z": "3", "a": "1", "m": "2"}'
    And I call str() on the InfoGauge instance
    Then The output should contain the line "HELP my_metric Description of metric"
    And The output should contain the line "TYPE my_metric gauge"
    And The output should contain the line "my_metric{a="1",m="2",z="3"} 1"

  Scenario: Multiple timeseries provided
    When I add a timeseries with labels '{"z": "3", "a": "1", "m": "2"}'
    And I add a timeseries with labels '{"zz": "3", "aa": "1", "mm": "2"}'
    And I call str() on the InfoGauge instance
    Then The output should contain the line "HELP my_metric Description of metric" exactly once
    And The output should contain the line "TYPE my_metric gauge" exactly once
    And The output should contain the line "my_metric{a="1",m="2",z="3"} 1" exactly once
    And The output should contain the line "my_metric{aa="1",mm="2",zz="3"} 1" exactly once