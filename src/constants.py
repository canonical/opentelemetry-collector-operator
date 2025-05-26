"""Charm constants, for better testability."""

from typing import Final

RECV_CA_CERT_FOLDER_PATH: Final[str] = "/usr/local/share/ca-certificates/juju_receive-ca-cert"
SERVER_CERT_PATH: Final[str] = "/usr/local/share/ca-certificates/juju_tls-certificates/otelcol-server.crt"
SERVER_CERT_PRIVATE_KEY_PATH: Final[str] = "/etc/otelcol/private.key"
CONFIG_PATH: Final[str] = "/etc/otelcol/config.yaml"
SERVICE_NAME: Final[str] = "otelcol"
