Feature: Memory limiter processor configuration
  The opentelemetry-collector charm configures a memory limiter processor
  to prevent out-of-memory scenarios. The user sets a hard limit as a
  percentage of total memory via the memory_limit_percentage Juju config
  option. The soft limit is always 80% of the hard limit (spike = 20%).

  Background:
    Given total available memory is "1024" MiB
    And the spike percentage is "20"

  # --- Config manager unit tests ---

  Scenario Outline: Hard limit is clamped to [0, 100] and spike is a percentage of hard limit
    Given a user requested hard limit percentage of <user_input>
    When the memory limiter processor is added to the config
    Then the hard limit is <clamped_percentage> percent of total memory
    And the spike limit is "20" percent of the hard limit
    And the charm status is <charm_status>

    Examples:
      | user_input | clamped_percentage | charm_status |
      | -10        | 0                  | blocked      |
      | 0          | 0                  | active       |
      | 60         | 60                 | active       |
      | 100        | 100                | active       |
      | 110        | 100                | blocked      |


  # --- Charm-level integration tests ---

  Scenario: Default config sets hard limit to 100%
    Given a user provides no value for the memory_limit_percentage config option
    When any event executes the reconciler
    Then the hard limit in the generated config is "100" percent of total memory
    And the spike limit is "20" percent of the hard limit

  Scenario: Memory limiter is the first processor in every pipeline
    Given no config options are set
    When any event executes the reconciler
    Then memory_limiter is the first processor in all pipelines

  Scenario: User-provided memory_limiter overrides the default
    Given a user provides a memory_limiter in the processors config option
    When any event executes the reconciler
    Then only the custom memory_limiter processor is in the pipelines
