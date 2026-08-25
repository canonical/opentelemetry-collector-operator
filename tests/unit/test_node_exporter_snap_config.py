# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

from unittest.mock import MagicMock, patch

from ops.testing import State

from charm import OpenTelemetryCollectorCharm
from constants import NODE_EXPORTER_DISABLED_COLLECTORS, NODE_EXPORTER_ENABLED_COLLECTORS


def _node_exporter_config(port: int = 9100):
    return {
        "collectors": " ".join(sorted(NODE_EXPORTER_ENABLED_COLLECTORS)),
        "no-collectors": " ".join(sorted(NODE_EXPORTER_DISABLED_COLLECTORS)),
        "web.listen-address": f":{port}",
    }


def _node_exporter_snap_get_config(port: int = 9100):
    return {
        "collectors": " ".join(sorted(NODE_EXPORTER_ENABLED_COLLECTORS)),
        "no-collectors": " ".join(sorted(NODE_EXPORTER_DISABLED_COLLECTORS)),
        "web": {
            "listen-address": f":{port}",
        },
    }


def test_update_status_does_not_set_matching_node_exporter_config(ctx):
    node_exporter = MagicMock()
    node_exporter.get.return_value = _node_exporter_snap_get_config()
    otelcol = MagicMock()

    def snap(name):
        return {
            "node-exporter": node_exporter,
            "opentelemetry-collector": otelcol,
        }[name]

    with (
        patch("charm.event", return_value="update-status"),
        patch.object(OpenTelemetryCollectorCharm, "snap", side_effect=snap),
        patch.object(OpenTelemetryCollectorCharm, "_restart_snap"),
    ):
        ctx.run(ctx.on.update_status(), State())

    node_exporter.set.assert_not_called()


def test_update_status_sets_drifted_node_exporter_config(ctx):
    node_exporter = MagicMock()
    node_exporter.get.return_value = _node_exporter_snap_get_config(port=9200)
    otelcol = MagicMock()

    def snap(name):
        return {
            "node-exporter": node_exporter,
            "opentelemetry-collector": otelcol,
        }[name]

    with (
        patch("charm.event", return_value="update-status"),
        patch.object(OpenTelemetryCollectorCharm, "snap", side_effect=snap),
        patch.object(OpenTelemetryCollectorCharm, "_restart_snap"),
    ):
        ctx.run(ctx.on.update_status(), State())

    node_exporter.set.assert_called_once_with(_node_exporter_config())
