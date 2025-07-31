from ops.testing import State
import pytest


@pytest.mark.parametrize(
    "value",
    [
        "",  # Missing value and unit
        "1",  # Missing unit
        "s",  # Missing value
        "1x",  # Incorrect unit
        "1sec",  # Incorrect unit
    ],
)
@pytest.mark.parametrize(
    "global_scrape_config", ["global_scrape_interval", "global_scrape_timeout"]
)
def test_invalid_global_scrape_config(ctx, global_scrape_config, value):
    # GIVEN the charm has an invalid global_scrape_config set
    state = State(config={global_scrape_config: value})

    # WHEN any event is emitted
    state_out = ctx.run(ctx.on.update_status(), state)

    # THEN the charm enters BlockedStatus
    assert state_out.unit_status.name == "blocked"
    # AND the correct config is identified to the admin
    assert (
        state_out.unit_status.message
        == f"The {global_scrape_config} config requires format: '\\d+[ywdhms]'."
    )
