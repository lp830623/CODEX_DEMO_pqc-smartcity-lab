"""Commissioning material: gateway identity, device registry, trust anchor.

Secrets are ordinary JSON files with mode 0600. That is honest about this
being a lab. A deployment would use a TPM, a secure element, or a remote
signing service, and would not mount raw signing keys into a container.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path

from pqc_smartcity.crypto.suites import get_suite
from pqc_smartcity.errors import AuthenticationError, PolicyError
from pqc_smartcity.telemetry import FLEET

ANCHOR_NAME = "gateway.anchor.json"
REGISTRY_NAME = "registry.json"
GATEWAY_SECRET_NAME = "gateway.secret.json"


@dataclass
class GatewayIdentity:
    name: str
    suite_name: str
    profile: str
    sig_sk: bytes
    sig_pk: bytes
    kem_sk: bytes | None
    kem_pk: bytes | None


@dataclass
class SensorIdentity:
    sensor_id: str
    kind: str
    suite_name: str
    sig_sk: bytes
    sig_pk: bytes


@dataclass
class Fleet:
    gateway: GatewayIdentity
    sensors: list[SensorIdentity]

    def registry(self) -> dict[str, bytes]:
        return {sensor.sensor_id: sensor.sig_pk for sensor in self.sensors}


def issue_fleet(suite_name: str, profile: str, name: str = "city-gateway") -> Fleet:
    if profile not in ("ephemeral", "static"):
        raise PolicyError(f"unknown profile {profile}")
    suite = get_suite(suite_name)
    if suite.spec.static_only and profile == "ephemeral":
        raise PolicyError(f"{suite_name} only supports the static profile")
    sig_sk, sig_pk = suite.generate_sig_keypair()
    kem_sk: bytes | None = None
    kem_pk: bytes | None = None
    if profile == "static":
        kem_sk, kem_pk = suite.generate_kem_keypair()
    gateway = GatewayIdentity(name, suite_name, profile, sig_sk, sig_pk, kem_sk, kem_pk)
    sensors: list[SensorIdentity] = []
    for sensor_id, kind in FLEET:
        sensor_suite = get_suite(suite_name)
        sensor_sk, sensor_pk = sensor_suite.generate_sig_keypair()
        sensors.append(SensorIdentity(sensor_id, kind, suite_name, sensor_sk, sensor_pk))
    return Fleet(gateway, sensors)


def save_fleet(fleet: Fleet, *, gateway_secret: Path, sensor_dir: Path, trust_dir: Path) -> None:
    _write_json(gateway_secret, _gateway_secret_doc(fleet.gateway), secret=True)
    sensor_dir.mkdir(parents=True, exist_ok=True)
    for sensor in fleet.sensors:
        _write_json(sensor_dir / f"{sensor.sensor_id}.secret.json", _sensor_doc(sensor), secret=True)
    trust_dir.mkdir(parents=True, exist_ok=True)
    _write_json(trust_dir / ANCHOR_NAME, anchor_doc(fleet.gateway), secret=False)
    _write_json(trust_dir / REGISTRY_NAME, signed_registry(fleet), secret=False)


def load_gateway(path: Path) -> GatewayIdentity:
    return _gateway_from_doc(_read_json(path))


def load_sensor(path: Path) -> SensorIdentity:
    return _sensor_from_doc(_read_json(path))


def load_sensors(directory: Path) -> list[SensorIdentity]:
    paths = sorted(directory.glob("*.secret.json"))
    if not paths:
        raise FileNotFoundError(f"no sensor secrets in {directory}")
    return [load_sensor(path) for path in paths]


def load_anchor(path: Path) -> dict:
    doc = _read_json(path)
    _need(doc, "v", "name", "suite", "profile", "sig_pk")
    if doc["v"] != 1:
        raise PolicyError("unsupported anchor version")
    return doc


def signed_bundle(gateway: GatewayIdentity) -> dict:
    suite = get_suite(gateway.suite_name)
    body = {
        "v": 1,
        "name": gateway.name,
        "suite": gateway.suite_name,
        "profile": gateway.profile,
        "sig_pk": _b64(gateway.sig_pk),
        "kem_pk": _b64(gateway.kem_pk) if gateway.kem_pk else None,
    }
    signature = suite.sign(gateway.sig_sk, _canonical(body))
    return {**body, "sig": _b64(signature)}


def verify_bundle(bundle: dict, anchor_sig_pk: bytes, suite_name: str) -> dict:
    if not isinstance(bundle, dict) or "sig" not in bundle:
        raise AuthenticationError("gateway bundle is missing a signature")
    body = {key: value for key, value in bundle.items() if key != "sig"}
    suite = get_suite(suite_name)
    try:
        signature = _unb64(bundle["sig"])
        advertised = _unb64(body["sig_pk"])
    except (KeyError, ValueError) as exc:
        raise AuthenticationError("gateway bundle is malformed") from exc
    if not suite.verify(anchor_sig_pk, _canonical(body), signature):
        raise AuthenticationError("gateway bundle signature rejected")
    if advertised != anchor_sig_pk:
        raise AuthenticationError("bundle key is not the pinned anchor")
    if body.get("suite") != suite_name:
        raise PolicyError("bundle advertises a different suite")
    return body


def signed_registry(fleet: Fleet) -> dict:
    suite = get_suite(fleet.gateway.suite_name)
    body = {
        "v": 1,
        "name": fleet.gateway.name,
        "suite": fleet.gateway.suite_name,
        "profile": fleet.gateway.profile,
        "sensors": [
            {"sensor_id": sensor.sensor_id, "kind": sensor.kind, "sig_pk": _b64(sensor.sig_pk)}
            for sensor in sorted(fleet.sensors, key=lambda item: item.sensor_id)
        ],
    }
    signature = suite.sign(fleet.gateway.sig_sk, _canonical(body))
    return {**body, "sig": _b64(signature)}


def verify_registry(doc: dict, anchor_sig_pk: bytes) -> dict[str, bytes]:
    if not isinstance(doc, dict) or "sig" not in doc:
        raise AuthenticationError("registry is missing a signature")
    body = {key: value for key, value in doc.items() if key != "sig"}
    suite = get_suite(str(body.get("suite")))
    try:
        signature = _unb64(doc["sig"])
    except ValueError as exc:
        raise AuthenticationError("registry signature is malformed") from exc
    if not suite.verify(anchor_sig_pk, _canonical(body), signature):
        raise AuthenticationError("registry signature rejected")
    registry: dict[str, bytes] = {}
    for entry in body.get("sensors", []):
        registry[entry["sensor_id"]] = _unb64(entry["sig_pk"])
    if not registry:
        raise PolicyError("registry has no sensors")
    return registry


def anchor_doc(gateway: GatewayIdentity) -> dict:
    return {
        "v": 1,
        "name": gateway.name,
        "suite": gateway.suite_name,
        "profile": gateway.profile,
        "sig_pk": _b64(gateway.sig_pk),
    }


def anchor_sig_pk(doc: dict) -> bytes:
    return _unb64(doc["sig_pk"])


def _gateway_secret_doc(gateway: GatewayIdentity) -> dict:
    return {
        "v": 1,
        "name": gateway.name,
        "suite": gateway.suite_name,
        "profile": gateway.profile,
        "sig_sk": _b64(gateway.sig_sk),
        "sig_pk": _b64(gateway.sig_pk),
        "kem_sk": _b64(gateway.kem_sk) if gateway.kem_sk else None,
        "kem_pk": _b64(gateway.kem_pk) if gateway.kem_pk else None,
    }


def _gateway_from_doc(doc: dict) -> GatewayIdentity:
    _need(doc, "v", "name", "suite", "profile", "sig_sk", "sig_pk", "kem_sk", "kem_pk")
    if doc["v"] != 1:
        raise PolicyError("unsupported gateway secret version")
    return GatewayIdentity(
        name=doc["name"],
        suite_name=doc["suite"],
        profile=doc["profile"],
        sig_sk=_unb64(doc["sig_sk"]),
        sig_pk=_unb64(doc["sig_pk"]),
        kem_sk=_unb64(doc["kem_sk"]) if doc["kem_sk"] else None,
        kem_pk=_unb64(doc["kem_pk"]) if doc["kem_pk"] else None,
    )


def _sensor_doc(sensor: SensorIdentity) -> dict:
    return {
        "v": 1,
        "sensor_id": sensor.sensor_id,
        "kind": sensor.kind,
        "suite": sensor.suite_name,
        "sig_sk": _b64(sensor.sig_sk),
        "sig_pk": _b64(sensor.sig_pk),
    }


def _sensor_from_doc(doc: dict) -> SensorIdentity:
    _need(doc, "v", "sensor_id", "kind", "suite", "sig_sk", "sig_pk")
    if doc["v"] != 1:
        raise PolicyError("unsupported sensor secret version")
    return SensorIdentity(
        sensor_id=doc["sensor_id"],
        kind=doc["kind"],
        suite_name=doc["suite"],
        sig_sk=_unb64(doc["sig_sk"]),
        sig_pk=_unb64(doc["sig_pk"]),
    )


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:
        raise ValueError("invalid base64") from exc


def _need(doc: dict, *keys: str) -> None:
    missing = [key for key in keys if key not in doc]
    if missing:
        raise PolicyError(f"missing fields: {', '.join(missing)}")


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise
    except json.JSONDecodeError as exc:
        raise PolicyError(f"{path} is not JSON") from exc


def _write_json(path: Path, doc: dict, *, secret: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(payload)
    os.chmod(temporary, 0o600 if secret else 0o644)
    temporary.replace(path)
