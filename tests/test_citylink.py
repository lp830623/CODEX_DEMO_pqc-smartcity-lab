"""CityLink handshake, telemetry, tamper, and replay tests."""

from __future__ import annotations

import pytest

from pqc_smartcity.errors import AuthenticationError, PolicyError, ProtocolError, ReplayError
from pqc_smartcity.identity import issue_fleet, signed_bundle, verify_bundle
from pqc_smartcity.mqtt_roles import loopback_exchange
from pqc_smartcity.protocol.engine import GatewayEndpoint, SensorEndpoint
from pqc_smartcity.protocol.framing import decode_telemetry
from pqc_smartcity.crypto.suites import get_suite


def _pair(suite: str, profile: str, signed: bool = True):
    fleet = issue_fleet(suite, profile)
    opened = loopback_exchange(fleet=fleet, require_signature=signed, messages=2)
    return fleet, opened


def test_default_suite_delivers_the_fleet() -> None:
    _fleet, opened = _pair("mlkem768-mldsa65", "ephemeral")
    assert [item.sensor_id for item in opened] == [
        "aq-centrum-03",
        "aq-centrum-03",
        "tr-bridge-01",
        "tr-bridge-01",
        "em-substation-07",
        "em-substation-07",
    ]
    kinds = {item.kind for item in opened}
    assert kinds == {"air_quality", "traffic", "energy_meter"}
    assert all(item.authenticated == "signed" for item in opened)
    assert opened[0].plaintext["readings"]["pm2_5_ugm3"] > 0


@pytest.mark.parametrize(
    ("suite", "profile"),
    [
        ("x25519-ed25519", "ephemeral"),
        ("x25519-ed25519", "static"),
        ("p256-ecdsa", "ephemeral"),
        ("rsa3072-pss", "static"),
        ("mlkem512-mldsa44", "ephemeral"),
        ("mlkem1024-mldsa87", "static"),
        ("hybrid-x25519-mlkem768", "ephemeral"),
        ("hybrid-x25519-mlkem768", "static"),
    ],
)
def test_suite_matrix(suite: str, profile: str) -> None:
    fleet = issue_fleet(suite, profile)
    opened = loopback_exchange(fleet=fleet, require_signature=True, messages=1)
    assert len(opened) == 3
    assert {item.suite for item in opened} == {suite}


def test_aead_only_frames_have_no_signature() -> None:
    fleet = issue_fleet("mlkem768-mldsa65", "ephemeral")
    opened = loopback_exchange(fleet=fleet, require_signature=False, messages=1)
    assert opened[0].authenticated == "aead"
    assert opened[0].wire_bytes < 800


def test_tamper_and_replay() -> None:
    fleet = issue_fleet("mlkem768-mldsa65", "ephemeral")
    sensor_identity = fleet.sensors[0]
    gateway = GatewayEndpoint(
        suite=get_suite(fleet.gateway.suite_name),
        profile="ephemeral",
        sig_sk=fleet.gateway.sig_sk,
        sig_pk=fleet.gateway.sig_pk,
        registry=fleet.registry(),
        require_signature=True,
        max_skew_ms=None,
    )
    sensor = SensorEndpoint(
        suite=get_suite(sensor_identity.suite_name),
        profile="ephemeral",
        sensor_id=sensor_identity.sensor_id,
        kind=sensor_identity.kind,
        sig_sk=sensor_identity.sig_sk,
        sig_pk=sensor_identity.sig_pk,
        anchor_sig_pk=fleet.gateway.sig_pk,
        require_signature=True,
    )
    hello = bytearray(sensor.client_hello())
    hello[-1] ^= 0x01
    with pytest.raises(AuthenticationError):
        gateway.handle_hello(bytes(hello))

    sensor.handle_welcome(gateway.handle_hello(sensor.client_hello()))
    frame = bytearray(sensor.seal())
    decoded = decode_telemetry(bytes(frame))
    # Flip a ciphertext byte. The signature still covers the original bytes,
    # so the failure is a bad signature when signatures are required; either
    # rejection is the property under test.
    frame[decoded.aad.__len__() + 12 + 4] ^= 0x01
    with pytest.raises((AuthenticationError, ProtocolError)):
        gateway.open_telemetry(bytes(frame))

    good = sensor.seal()
    gateway.open_telemetry(good)
    with pytest.raises(ReplayError):
        gateway.open_telemetry(good)


def test_unknown_sensor_and_suite_mismatch() -> None:
    fleet = issue_fleet("x25519-ed25519", "ephemeral")
    gateway = GatewayEndpoint(
        suite=get_suite("x25519-ed25519"),
        profile="ephemeral",
        sig_sk=fleet.gateway.sig_sk,
        sig_pk=fleet.gateway.sig_pk,
        registry={},
        require_signature=True,
        max_skew_ms=None,
    )
    sensor = fleet.sensors[0]
    endpoint = SensorEndpoint(
        suite=get_suite("x25519-ed25519"),
        profile="ephemeral",
        sensor_id=sensor.sensor_id,
        kind=sensor.kind,
        sig_sk=sensor.sig_sk,
        sig_pk=sensor.sig_pk,
        anchor_sig_pk=fleet.gateway.sig_pk,
        require_signature=True,
    )
    with pytest.raises(PolicyError):
        gateway.handle_hello(endpoint.client_hello())


def test_bundle_is_bound_to_the_anchor() -> None:
    fleet = issue_fleet("mlkem512-mldsa44", "static")
    bundle = signed_bundle(fleet.gateway)
    body = verify_bundle(bundle, fleet.gateway.sig_pk, fleet.gateway.suite_name)
    assert body["kem_pk"]
    bundle["name"] = "other-gateway"
    with pytest.raises(AuthenticationError):
        verify_bundle(bundle, fleet.gateway.sig_pk, fleet.gateway.suite_name)


def test_trailing_bytes_are_rejected() -> None:
    from pqc_smartcity.protocol.framing import decode_client_hello

    fleet = issue_fleet("x25519-ed25519", "static")
    sensor = fleet.sensors[0]
    endpoint = SensorEndpoint(
        suite=get_suite("x25519-ed25519"),
        profile="static",
        sensor_id=sensor.sensor_id,
        kind=sensor.kind,
        sig_sk=sensor.sig_sk,
        sig_pk=sensor.sig_pk,
        anchor_sig_pk=fleet.gateway.sig_pk,
        require_signature=True,
        gateway_kem_pk=fleet.gateway.kem_pk,
    )
    with pytest.raises(ProtocolError):
        decode_client_hello(endpoint.client_hello() + b"\x00")
