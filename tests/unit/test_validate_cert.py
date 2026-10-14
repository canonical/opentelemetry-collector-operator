# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for charm.validate_cert.

Ref: https://github.com/canonical/opentelemetry-collector-operator/issues/136
"""

from charm import validate_cert

VALID_CERT = """\
-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUIhzxKRChM6KISvH6MLrDjWOJcF8wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJVGVzdCBDQSBBMCAXDTI2MDYxOTEyNTk0NVoYDzIxMjYw
NTI2MTI1OTQ1WjAUMRIwEAYDVQQDDAlUZXN0IENBIEEwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC9lTLz3GaIzSHq5CaJLfHbQyOPTdMcFJmPDMcHFzrK
4+p7C2ghgWqszx1fGZLp3gWvOXtIFtXEUDmqVyFGeLXMbY1Tuj4uohT6cOmlq0eS
2BGXiMQtojJr/JSyuVVgGmclqr2rpCPJoZCuisf07GxJHip5gca8toW2LF42XazI
L2MkbeFxDTsnzkFZMUjYtYvHMQ9RvGAIOY+ZcYpDEfXE0otfW9FjvE0ovmgp6KgE
s8VYJ36N8y8zDCW1jVcA0KfN8yms+PRa07B4CHbPOpvnCBwqViNnA5K1DKAaT8eM
8p1UHh7GtP1Dnq/ohecFNCIIl4hmV6S2TVp6/IEb8FZ1AgMBAAGjUzBRMB0GA1Ud
DgQWBBSoYMuDm9+gI1y9edMUY+cyabsihzAfBgNVHSMEGDAWgBSoYMuDm9+gI1y9
edMUY+cyabsihzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQC0
zpE5zadj/rLEku+MLTHhzpNUGhJ5M9ITLB2u4i/FgDr5iq8DSRG+V40s/IC6gFQw
cr+phjP2KLQJ5u9kXcPd0SJjnczLpkUjDhk1DvKRtkpuKEyephefrZLbN8LL5GXX
ZH761BGCp2zUIZdKrgUTLD7+v/yOjLUXCtdg2SuEINULL6t3YZWNmSCax/Aj5Spb
98ZYuaWter2HDVxZ0sEVoOSywVLu2fklmd0LPwG4YNRXnPDLBZdM9tr6ZK/pQYrx
5r42RNTyp23PZz9gwvVxOgp0cuo4gQ0OPrhhMpQzl0FoLxneKlZioz8nxRPt9Eyv
PRvWM1nd7HRBMf+jka/M
-----END CERTIFICATE-----
"""

ANOTHER_VALID_CERT = """\
-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUD/28AVaqN7iZyT0eZVUdcgjLazIwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJVGVzdCBDQSBCMCAXDTI2MDYxOTEyNTk0NVoYDzIxMjYw
NTI2MTI1OTQ1WjAUMRIwEAYDVQQDDAlUZXN0IENBIEIwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQC/r0HhqilLd+27vxGS9wr4vrQncvSe6wh6FbZkcPuX
K0swT3iJJs1KKxHED6gSDC4KmNstB/PxKMRue7cV/omfUzfDWst1kVZ8YnuiHyTN
Xh54v5gPDeQY8qaHtYcuqVSFXEdLkW5fkKaodLGxwCzvC4HGSUfWcU0amVpmszsP
iEnz/yGOhj1i3r3+qFZp4z8iiUvSUUOqtVf2mCRxAes1Bi3nHlmxnI4n1oEl/4Vd
EQP1Ll1gfoQpfBGr9wlM43HaZUT2HYkpxxN+pvZtHOHC+ca5kvp/A/Nq59BW/Ain
ZuSrL/nsMkNK6bl/bc/x4HvPkdSqpKQODqzNofhQhzZtAgMBAAGjUzBRMB0GA1Ud
DgQWBBSFvVOvHAk1/fKC9bdKmHw/MzlhtjAfBgNVHSMEGDAWgBSFvVOvHAk1/fKC
9bdKmHw/MzlhtjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCz
JP5Mwv1HREglqFtqcskxqRnHeZthfgWo8L7Iai8Bu3OuusEgDVFVk2otWWsXx2I1
Eakl2UdnuJCCOldNQEaTHCwo2PHI3utDp3iMGSygvTt7Jwgt9qFWCn6pIYiBTvZj
F3nJXK871X/WiH92hWWNQbr8tU1tTFX7t27Ws+ZNhB3lp+2+JW1frr8C7b0RL9IK
5BobSVPbs4ZWZD+V9C1hkxnqq/bSU9/BZUEiBG7YF1IS/YQIyRo2x5LHWTpzcAan
4/bWpeG7Wm1IKOrNmRy8lE+ShTNu7ysOhw5tHqB/6uax7EIwlddNFDtjSg3rl1sD
BexQoqWvdoDZdSWulk7n
-----END CERTIFICATE-----
"""

GARBAGE_CERT = """\
-----BEGIN CERTIFICATE-----
not a real certificate
-----END CERTIFICATE-----
"""

INVALID_BASE64_CERT = """\
-----BEGIN CERTIFICATE-----
%%% invalid base64 %%%
-----END CERTIFICATE-----
"""


def test_valid_single_cert():
    assert validate_cert(VALID_CERT) is True


def test_garbage_body_rejected():
    assert validate_cert(GARBAGE_CERT) is False


def test_invalid_base64_body_rejected():
    assert validate_cert(INVALID_BASE64_CERT) is False


def test_missing_markers_rejected():
    assert validate_cert("hello world") is False


def test_empty_string_rejected():
    assert validate_cert("") is False


def test_private_key_is_not_a_cert():
    assert (
        validate_cert("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----")
        is False
    )


def test_bundle_of_valid_certs_accepted():
    assert validate_cert(VALID_CERT + ANOTHER_VALID_CERT) is True


def test_bundle_with_bad_block_rejected():
    assert validate_cert(VALID_CERT + GARBAGE_CERT) is False
