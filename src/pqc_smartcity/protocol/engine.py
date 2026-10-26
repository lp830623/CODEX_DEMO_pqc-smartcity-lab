"""In-memory CityLink sessions.

The MQTT adapters are thin. All cryptographic checks happen here so they can
be tested without a broker.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from pqc_smartcity.catalog import SUITE_BY_ID
from pqc_smartcity.errors import (
    AuthenticationError,
    PolicyError,
    ProtocolError,
    ReplayError,
)
from pqc_smartcity.protocol.framing import (
    FLAG_SIGNED_TELEMETRY,
    ClientHello,
    client_signed_region,
    counter_nonce,
    decode_client_hello,
    decode_server_hello,
    decode_telemetry,
    encode_client_hello,
    encode_server_hello,
    encode_telemetry,
    server_signed_region,
    telemetry_aad,
    telemetry_covered,
)
from pqc_smartcity.telemetry import canonical_reading, make_reading, parse_reading

_NONCE_CACHE = 4096


@dataclass
class OpenedReading:
    sensor_id: str
    kind: str
    seq: int
    authenticated: str
    plaintext: dict
    wire_bytes: int
    suite: str
    profile: str

    def summary(self) -> dict:
        return {
            "sensor_id": self.sensor_id,
            "kind": self.kind,
            "seq": self.seq,
            "auth": self.authenticated,
            "suite": self.suite,
            "profile": self.profile,
            "wire_bytes": self.wire_bytes,
            "readings": self.plaintext["readings"],
            "ts": self.plaintext["ts"],
        }


@dataclass
class _SessionKeys:
    sensor_id: str
    sensor_pk: bytes
    traffic_key: bytes
    session_id: bytes
    last_seq: int = 0


class SensorEndpoint:
    """One commissioned field device."""

    def __init__(
        self,
        *,
        suite,
        profile: str,
        sensor_id: str,
        kind: str,
        sig_sk: bytes,
        sig_pk: bytes,
        anchor_sig_pk: bytes,
        require_signature: bool,
        gateway_kem_pk: bytes | None = None,
        now_ms=None,
    ) -> None:
        self.suite = suite
        self.profile = _profile(profile)
        self.profile_name = profile
        self.sensor_id = sensor_id
        self.kind = kind
        self.sig_sk = sig_sk
        self.sig_pk = sig_pk
        self.anchor_sig_pk = anchor_sig_pk
        self.require_signature = require_signature
        self.gateway_kem_pk = gateway_kem_pk
        self.now_ms = now_ms or _wall_ms
        self._lock = threading.Lock()
        self._ephemeral_sk: bytes | None = None
        self._static_shared: bytes | None = None
        self._pending_signed: bytes | None = None
        self._traffic_key: bytes | None = None
        self._session_id: bytes | None = None
        self._seq = 0
        _reject_unsupported(suite, self.profile_name)

    def client_hello(self) -> bytes:
        with self._lock:
            flags = FLAG_SIGNED_TELEMETRY if self.require_signature else 0
            nonce = os.urandom(16)
            unix_ms = int(self.now_ms())
            if self.profile_name == "ephemeral":
                secret, public = self.suite.generate_kem_keypair()
                self._ephemeral_sk = secret
                self._static_shared = None
                kem_material = public
            else:
                if not self.gateway_kem_pk:
                    raise PolicyError("static profile requires the gateway encapsulation key")
                self._ephemeral_sk = None
                kem_material, shared = self.suite.encaps(self.gateway_kem_pk)
                self._static_shared = shared
            signed_region = client_signed_region(
                profile=self.profile,
                suite_id=self.suite.spec.suite_id,
                flags=flags,
                sensor_id=self.sensor_id,
                unix_ms=unix_ms,
                client_nonce=nonce,
                kem_material=kem_material,
            )
            signature = self.suite.sign(self.sig_sk, signed_region)
            message = encode_client_hello(
                profile=self.profile,
                suite_id=self.suite.spec.suite_id,
                flags=flags,
                sensor_id=self.sensor_id,
                unix_ms=unix_ms,
                client_nonce=nonce,
                kem_material=kem_material,
                signature=signature,
            )
            decoded = decode_client_hello(message)
            if decoded.signed_region != signed_region:
                raise ProtocolError("client hello signature coverage mismatch")
            self._pending_signed = signed_region
            self._traffic_key = None
            self._session_id = None
            return message

    def handle_welcome(self, raw: bytes) -> None:
        with self._lock:
            if self._pending_signed is None:
                raise PolicyError("welcome arrived with no outstanding hello")
            welcome = decode_server_hello(raw)
            self._check_peer(welcome.profile, welcome.suite_id, welcome.flags)
            if welcome.flags & ~FLAG_SIGNED_TELEMETRY:
                raise ProtocolError("unknown handshake flags")
            if welcome.client_hash != hashlib.sha256(self._pending_signed).digest():
                raise AuthenticationError("server hello is not bound to this client hello")
            if not self.suite.verify(self.anchor_sig_pk, welcome.signed_region, welcome.signature):
                raise AuthenticationError("gateway signature rejected")
            if self.profile_name == "ephemeral":
                if self._ephemeral_sk is None:
                    raise PolicyError("missing ephemeral key")
                shared = self.suite.decaps(self._ephemeral_sk, welcome.kem_material)
            else:
                if welcome.kem_material:
                    raise ProtocolError("static server hello must not carry KEM material")
                shared = self._static_shared
            key, transcript = derive_traffic_key(
                shared,
                self._pending_signed,
                welcome.signed_region,
                self.suite.spec.name,
                self.profile_name,
                hybrid=self.suite.spec.family == "hybrid",
            )
            self._traffic_key = key
            self._session_id = transcript[:8]
            self._seq = 0
            self._pending_signed = None
            self._ephemeral_sk = None
            self._static_shared = None

    def seal(self, ts_ms: int | None = None) -> bytes:
        with self._lock:
            if self._traffic_key is None or self._session_id is None:
                raise PolicyError("handshake is not complete")
            self._seq += 1
            stamp = int(self.now_ms() if ts_ms is None else ts_ms)
            reading = make_reading(self.sensor_id, self.kind, self._seq, stamp)
            plaintext = canonical_reading(reading)
            nonce = counter_nonce(self._seq)
            aad = telemetry_aad(
                suite_id=self.suite.spec.suite_id,
                sensor_id=self.sensor_id,
                session_id=self._session_id,
                seq=self._seq,
                unix_ms=stamp,
            )
            ciphertext = AESGCM(self._traffic_key).encrypt(nonce, plaintext, aad)
            signature = b""
            if self.require_signature:
                signature = self.suite.sign(
                    self.sig_sk,
                    telemetry_covered(
                        suite_id=self.suite.spec.suite_id,
                        sensor_id=self.sensor_id,
                        session_id=self._session_id,
                        seq=self._seq,
                        unix_ms=stamp,
                        nonce=nonce,
                        ciphertext=ciphertext,
                    ),
                )
            return encode_telemetry(
                suite_id=self.suite.spec.suite_id,
                sensor_id=self.sensor_id,
                session_id=self._session_id,
                seq=self._seq,
                unix_ms=stamp,
                nonce=nonce,
                ciphertext=ciphertext,
                signature=signature,
            )

    def _check_peer(self, profile: int, suite_id: int, flags: int) -> None:
        if profile != self.profile or suite_id != self.suite.spec.suite_id:
            raise PolicyError("gateway negotiated a different suite or profile")
        signed = bool(flags & FLAG_SIGNED_TELEMETRY)
        if signed != self.require_signature:
            raise PolicyError("telemetry authentication flag mismatch")


class GatewayEndpoint:
    """City gateway. Holds long-term keys and the commissioned-device registry."""

    def __init__(
        self,
        *,
        suite,
        profile: str,
        sig_sk: bytes,
        sig_pk: bytes,
        registry: dict[str, bytes],
        require_signature: bool,
        kem_sk: bytes | None = None,
        max_skew_ms: int | None = 300_000,
        now_ms=None,
    ) -> None:
        self.suite = suite
        self.profile = _profile(profile)
        self.profile_name = profile
        self.sig_sk = sig_sk
        self.sig_pk = sig_pk
        self.registry = dict(registry)
        self.require_signature = require_signature
        self.kem_sk = kem_sk
        self.max_skew_ms = max_skew_ms
        self.now_ms = now_ms or _wall_ms
        self._lock = threading.Lock()
        self._sessions: dict[str, _SessionKeys] = {}
        self._nonces: OrderedDict[bytes, None] = OrderedDict()
        _reject_unsupported(suite, self.profile_name)
        if profile == "static" and not kem_sk:
            raise PolicyError("static profile requires a gateway decapsulation key")

    def handle_hello(self, raw: bytes) -> bytes:
        with self._lock:
            hello = decode_client_hello(raw)
            self._check_peer(hello)
            public = self.registry.get(hello.sensor_id)
            if public is None:
                raise PolicyError(f"unknown sensor {hello.sensor_id}")
            if not self.suite.verify(public, hello.signed_region, hello.signature):
                raise AuthenticationError("sensor signature rejected")
            self._check_time(hello.unix_ms)
            self._remember_nonce(hello.client_nonce)
            if self.profile_name == "ephemeral":
                kem_material, shared = self.suite.encaps(hello.kem_material)
            else:
                if not self.kem_sk:
                    raise PolicyError("missing gateway decapsulation key")
                kem_material = b""
                shared = self.suite.decaps(self.kem_sk, hello.kem_material)
            flags = FLAG_SIGNED_TELEMETRY if self.require_signature else 0
            gateway_nonce = os.urandom(16)
            client_hash = hashlib.sha256(hello.signed_region).digest()
            signed_region = server_signed_region(
                profile=self.profile,
                suite_id=self.suite.spec.suite_id,
                flags=flags,
                gateway_nonce=gateway_nonce,
                client_hash=client_hash,
                kem_material=kem_material,
            )
            signature = self.suite.sign(self.sig_sk, signed_region)
            welcome = encode_server_hello(
                profile=self.profile,
                suite_id=self.suite.spec.suite_id,
                flags=flags,
                gateway_nonce=gateway_nonce,
                client_hash=client_hash,
                kem_material=kem_material,
                signature=signature,
            )
            key, transcript = derive_traffic_key(
                shared,
                hello.signed_region,
                signed_region,
                self.suite.spec.name,
                self.profile_name,
                hybrid=self.suite.spec.family == "hybrid",
            )
            self._sessions[hello.sensor_id] = _SessionKeys(
                sensor_id=hello.sensor_id,
                sensor_pk=public,
                traffic_key=key,
                session_id=transcript[:8],
            )
            return welcome

    def open_telemetry(self, raw: bytes) -> OpenedReading:
        with self._lock:
            frame = decode_telemetry(raw)
            if frame.suite_id != self.suite.spec.suite_id:
                raise PolicyError("telemetry used a different suite")
            session = self._sessions.get(frame.sensor_id)
            if session is None or session.session_id != frame.session_id:
                raise PolicyError("telemetry does not match an active session")
            if frame.signature:
                if not self.suite.verify(session.sensor_pk, frame.signed_region, frame.signature):
                    raise AuthenticationError("telemetry signature rejected")
                authenticated = "signed"
            elif self.require_signature:
                raise PolicyError("telemetry signature required")
            else:
                authenticated = "aead"
            if frame.nonce != counter_nonce(frame.seq):
                raise ProtocolError("nonce is not the sequence counter")
            if frame.seq <= session.last_seq:
                raise ReplayError("telemetry sequence replayed")
            try:
                plaintext = AESGCM(session.traffic_key).decrypt(
                    frame.nonce, frame.ciphertext, frame.aad
                )
            except Exception as exc:
                raise AuthenticationError("AEAD rejected the telemetry") from exc
            reading = parse_reading(plaintext)
            if reading["sensor_id"] != frame.sensor_id or int(reading["seq"]) != frame.seq:
                raise ProtocolError("plaintext identity does not match the header")
            session.last_seq = frame.seq
            return OpenedReading(
                sensor_id=frame.sensor_id,
                kind=str(reading["kind"]),
                seq=frame.seq,
                authenticated=authenticated,
                plaintext=reading,
                wire_bytes=len(raw),
                suite=self.suite.spec.name,
                profile=self.profile_name,
            )

    def _check_peer(self, hello: ClientHello) -> None:
        if hello.profile != self.profile or hello.suite_id != self.suite.spec.suite_id:
            raise PolicyError("client offered a different suite or profile")
        signed = bool(hello.flags & FLAG_SIGNED_TELEMETRY)
        if signed != self.require_signature:
            raise PolicyError("telemetry authentication flag mismatch")
        if hello.flags & ~FLAG_SIGNED_TELEMETRY:
            raise ProtocolError("unknown handshake flags")

    def _check_time(self, unix_ms: int) -> None:
        if self.max_skew_ms is None:
            return
        delta = abs(int(self.now_ms()) - unix_ms)
        if delta > self.max_skew_ms:
            raise PolicyError("client hello timestamp is outside the skew window")

    def _remember_nonce(self, nonce: bytes) -> None:
        if nonce in self._nonces:
            raise ReplayError("client nonce reused")
        self._nonces[nonce] = None
        while len(self._nonces) > _NONCE_CACHE:
            self._nonces.popitem(last=False)


def derive_traffic_key(
    shared: bytes,
    client_signed: bytes,
    server_signed: bytes,
    suite_name: str,
    profile_name: str,
    *,
    hybrid: bool = False,
) -> tuple[bytes, bytes]:
    expected = 64 if hybrid or suite_name.startswith("hybrid-") else 32
    if len(shared) != expected:
        raise ProtocolError("shared secret has an unexpected length")
    transcript = hashlib.sha256(client_signed + server_signed).digest()
    info = f"citylink-v1 traffic-key|{suite_name}|{profile_name}".encode()
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=transcript, info=info).derive(shared)
    return key, transcript


def _profile(name: str) -> int:
    if name == "ephemeral":
        return 1
    if name == "static":
        return 2
    raise PolicyError(f"unknown profile {name}")


def _reject_unsupported(suite, profile_name: str) -> None:
    if suite.spec.static_only and profile_name == "ephemeral":
        raise PolicyError(
            f"{suite.spec.name} has no ephemeral profile; RSA here is long-term key transport"
        )
    if suite.spec.suite_id not in SUITE_BY_ID:
        raise PolicyError("suite id is not in the catalogue")


def _wall_ms() -> int:
    return int(time.time() * 1000)
