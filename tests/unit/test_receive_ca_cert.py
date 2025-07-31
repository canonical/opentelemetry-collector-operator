from ops.testing import State, Relation
from unittest.mock import patch
import json


def test_no_recv_ca_cert_relations_present(ctx, recv_ca_folder_path):
    # GIVEN the charm is deployed in isolation
    state = State(leader=True)

    # WHEN any event is emitted
    with patch("integrations._add_alerts"):
        ctx.run(ctx.on.update_status(), state)

    # THEN no recv_ca_cert-associated certs are present
    assert not recv_ca_folder_path.exists()


def test_ca_forwarded_over_rel_data(ctx, recv_ca_folder_path):
    # Relation 1
    cert1a = "-----BEGIN CERTIFICATE-----\n ... cert1a ... \n-----END CERTIFICATE-----"
    cert1b = "-----BEGIN CERTIFICATE-----\n ... cert1b ... \n-----END CERTIFICATE-----"

    # Relation 2
    cert2a = "-----BEGIN CERTIFICATE-----\n ... cert2a ... \n-----END CERTIFICATE-----"
    cert2b = "-----BEGIN CERTIFICATE-----\n ... cert2b ... \n-----END CERTIFICATE-----"

    # GIVEN the charm is related to a CA
    state = State(
        leader=True,
        relations=[
            Relation(
                "receive-ca-cert", remote_app_data={"certificates": json.dumps([cert1a, cert1b])}
            ),
            Relation(
                "receive-ca-cert", remote_app_data={"certificates": json.dumps([cert2a, cert2b])}
            ),
        ],
    )

    # WHEN any event is emitted
    with patch("integrations._add_alerts"):
        ctx.run(ctx.on.update_status(), state)

    # THEN recv_ca_cert-associated certs are present
    certs_dir = recv_ca_folder_path
    assert certs_dir.exists()
    certs = {file.read_text() for file in certs_dir.glob("*.crt")}
    assert certs == {cert1a, cert1b, cert2a, cert2b}
