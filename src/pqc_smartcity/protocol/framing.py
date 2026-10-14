"""CityLink v1 message bytes.

The signed region is everything before the trailing signature. A signature
covers that region and nothing else, so a peer can verify before it does
decapsulation or AEAD.

ClientHello signed region
    magic ``CLH1`` | version | profile | suite | flags | sensor_id |
    unix_ms u64 | client_nonce 16 | kem_material u16-prefixed

ServerHello signed region
    magic ``CLS1`` | version | profile | suite | flags | gateway_nonce 16 |
    client_hash 32 | kem_material u16-prefixed

Telemetry
    magic ``CLT1`` | version | suite | sensor_id | session_id 8 | seq u64 |
    unix_ms u64 | nonce 12 | ciphertext u32-prefixed | signature u16-prefixed

The AEAD additional data is the header before the nonce. The nonce itself is
the 12-byte counter ``seq`` (big-endian). An empty signature means AEAD-only
telemetry; a present signature is over the header, nonce, and ciphertext.
"""

from __future__ import annotations

from dataclasses import dataclass

from pqc_smartcity.errors import ProtocolError
from pqc_smartcity.protocol.codec import read_exact, read_lp, write_lp

VERSION = 1
MAGIC_CLIENT = b"CLH1"
MAGIC_SERVER = b"CLS1"
MAGIC_TELEMETRY = b"CLT1"
FLAG_SIGNED_TELEMETRY = 0x01
MAX_KEM = 8000
MAX_SIG = 12000
MAX_CIPHERTEXT = 8192
SENSOR_ID_MAX = 32


@dataclass(frozen=True)
class ClientHello:
    profile: int
    suite_id: int
    flags: int
    sensor_id: str
    unix_ms: int
    client_nonce: bytes
    kem_material: bytes
    signature: bytes
    signed_region: bytes


@dataclass(frozen=True)
class ServerHello:
    profile: int
    suite_id: int
    flags: int
    gateway_nonce: bytes
    client_hash: bytes
    kem_material: bytes
    signature: bytes
    signed_region: bytes


@dataclass(frozen=True)
class TelemetryFrame:
    suite_id: int
    sensor_id: str
    session_id: bytes
    seq: int
    unix_ms: int
    nonce: bytes
    ciphertext: bytes
    signature: bytes
    aad: bytes
    signed_region: bytes


def encode_client_hello(
    *,
    profile: int,
    suite_id: int,
    flags: int,
    sensor_id: str,
    unix_ms: int,
    client_nonce: bytes,
    kem_material: bytes,
    signature: bytes,
) -> bytes:
    signed = _client_signed(
        profile, suite_id, flags, sensor_id, unix_ms, client_nonce, kem_material
    )
    return signed + write_lp(signature)


def decode_client_hello(raw: bytes) -> ClientHello:
    try:
        signed_end, fields = _parse_client_signed(raw, 0)
        signature, offset = read_lp(raw, signed_end)
    except ValueError as exc:
        raise ProtocolError("malformed client hello") from exc
    if offset != len(raw):
        raise ProtocolError("trailing bytes in client hello")
    if len(signature) > MAX_SIG:
        raise ProtocolError("signature too long")
    return ClientHello(*fields, signature=signature, signed_region=raw[:signed_end])


def encode_server_hello(
    *,
    profile: int,
    suite_id: int,
    flags: int,
    gateway_nonce: bytes,
    client_hash: bytes,
    kem_material: bytes,
    signature: bytes,
) -> bytes:
    signed = _server_signed(
        profile, suite_id, flags, gateway_nonce, client_hash, kem_material
    )
    return signed + write_lp(signature)


def decode_server_hello(raw: bytes) -> ServerHello:
    try:
        if len(raw) < 4 or raw[:4] != MAGIC_SERVER:
            raise ProtocolError("bad server-hello magic")
        offset = 4
        version, offset = _u8(raw, offset)
        profile, offset = _u8(raw, offset)
        suite_id, offset = _u8(raw, offset)
        flags, offset = _u8(raw, offset)
        gateway_nonce, offset = read_exact(raw, offset, 16)
        client_hash, offset = read_exact(raw, offset, 32)
        kem_material, offset = read_lp(raw, offset)
        signed_end = offset
        signature, offset = read_lp(raw, offset)
    except ProtocolError:
        raise
    except ValueError as exc:
        raise ProtocolError("malformed server hello") from exc
    if offset != len(raw):
        raise ProtocolError("trailing bytes in server hello")
    if version != VERSION:
        raise ProtocolError(f"unsupported version {version}")
    if len(kem_material) > MAX_KEM or len(signature) > MAX_SIG:
        raise ProtocolError("field too long")
    return ServerHello(
        profile=profile,
        suite_id=suite_id,
        flags=flags,
        gateway_nonce=gateway_nonce,
        client_hash=client_hash,
        kem_material=kem_material,
        signature=signature,
        signed_region=raw[:signed_end],
    )


def encode_telemetry(
    *,
    suite_id: int,
    sensor_id: str,
    session_id: bytes,
    seq: int,
    unix_ms: int,
    nonce: bytes,
    ciphertext: bytes,
    signature: bytes,
) -> bytes:
    header = _telemetry_header(suite_id, sensor_id, session_id, seq, unix_ms)
    if len(nonce) != 12:
        raise ProtocolError("nonce must be 12 bytes")
    body = header + nonce + write_lp(ciphertext, width=4)
    return body + write_lp(signature)


def decode_telemetry(raw: bytes) -> TelemetryFrame:
    try:
        if len(raw) < 4 or raw[:4] != MAGIC_TELEMETRY:
            raise ProtocolError("bad telemetry magic")
        offset = 4
        version, offset = _u8(raw, offset)
        suite_id, offset = _u8(raw, offset)
        sensor_raw, offset = read_lp(raw, offset, width=1)
        session_id, offset = read_exact(raw, offset, 8)
        seq_bytes, offset = read_exact(raw, offset, 8)
        unix_bytes, offset = read_exact(raw, offset, 8)
        aad = raw[:offset]
        nonce, offset = read_exact(raw, offset, 12)
        ciphertext, offset = read_lp(raw, offset, width=4)
        signed_end = offset
        signature, offset = read_lp(raw, offset)
    except ProtocolError:
        raise
    except ValueError as exc:
        raise ProtocolError("malformed telemetry") from exc
    if offset != len(raw):
        raise ProtocolError("trailing bytes in telemetry")
    if version != VERSION:
        raise ProtocolError(f"unsupported version {version}")
    if len(ciphertext) > MAX_CIPHERTEXT or len(signature) > MAX_SIG:
        raise ProtocolError("field too long")
    sensor_id = _sensor_id(sensor_raw)
    return TelemetryFrame(
        suite_id=suite_id,
        sensor_id=sensor_id,
        session_id=session_id,
        seq=int.from_bytes(seq_bytes, "big"),
        unix_ms=int.from_bytes(unix_bytes, "big"),
        nonce=nonce,
        ciphertext=ciphertext,
        signature=signature,
        aad=aad,
        signed_region=raw[:signed_end],
    )


def counter_nonce(seq: int) -> bytes:
    if not 0 < seq < 2**64:
        raise ProtocolError("sequence out of range")
    return seq.to_bytes(12, "big")


def client_signed_region(
    *,
    profile: int,
    suite_id: int,
    flags: int,
    sensor_id: str,
    unix_ms: int,
    client_nonce: bytes,
    kem_material: bytes,
) -> bytes:
    return _client_signed(profile, suite_id, flags, sensor_id, unix_ms, client_nonce, kem_material)


def server_signed_region(
    *,
    profile: int,
    suite_id: int,
    flags: int,
    gateway_nonce: bytes,
    client_hash: bytes,
    kem_material: bytes,
) -> bytes:
    return _server_signed(profile, suite_id, flags, gateway_nonce, client_hash, kem_material)


def telemetry_aad(
    *, suite_id: int, sensor_id: str, session_id: bytes, seq: int, unix_ms: int
) -> bytes:
    return _telemetry_header(suite_id, sensor_id, session_id, seq, unix_ms)


def telemetry_covered(
    *,
    suite_id: int,
    sensor_id: str,
    session_id: bytes,
    seq: int,
    unix_ms: int,
    nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    if len(nonce) != 12:
        raise ProtocolError("nonce must be 12 bytes")
    return telemetry_aad(
        suite_id=suite_id,
        sensor_id=sensor_id,
        session_id=session_id,
        seq=seq,
        unix_ms=unix_ms,
    ) + nonce + write_lp(ciphertext, width=4)


def _client_signed(
    profile: int,
    suite_id: int,
    flags: int,
    sensor_id: str,
    unix_ms: int,
    client_nonce: bytes,
    kem_material: bytes,
) -> bytes:
    if len(client_nonce) != 16:
        raise ProtocolError("client nonce must be 16 bytes")
    if len(kem_material) > MAX_KEM:
        raise ProtocolError("KEM material too long")
    return b"".join(
        (
            MAGIC_CLIENT,
            bytes((VERSION, profile & 0xFF, suite_id & 0xFF, flags & 0xFF)),
            write_lp(sensor_id.encode("ascii"), width=1),
            unix_ms.to_bytes(8, "big"),
            client_nonce,
            write_lp(kem_material),
        )
    )


def _parse_client_signed(raw: bytes, offset: int) -> tuple[int, tuple]:
    if len(raw) < 4 or raw[:4] != MAGIC_CLIENT:
        raise ProtocolError("bad client-hello magic")
    offset = 4
    version, offset = _u8(raw, offset)
    profile, offset = _u8(raw, offset)
    suite_id, offset = _u8(raw, offset)
    flags, offset = _u8(raw, offset)
    sensor_raw, offset = read_lp(raw, offset, width=1)
    unix_bytes, offset = read_exact(raw, offset, 8)
    client_nonce, offset = read_exact(raw, offset, 16)
    kem_material, offset = read_lp(raw, offset)
    if version != VERSION:
        raise ProtocolError(f"unsupported version {version}")
    if len(kem_material) > MAX_KEM:
        raise ProtocolError("KEM material too long")
    fields = (
        profile,
        suite_id,
        flags,
        _sensor_id(sensor_raw),
        int.from_bytes(unix_bytes, "big"),
        client_nonce,
        kem_material,
    )
    return offset, fields


def _server_signed(
    profile: int,
    suite_id: int,
    flags: int,
    gateway_nonce: bytes,
    client_hash: bytes,
    kem_material: bytes,
) -> bytes:
    if len(gateway_nonce) != 16 or len(client_hash) != 32:
        raise ProtocolError("server hello fields have the wrong length")
    if len(kem_material) > MAX_KEM:
        raise ProtocolError("KEM material too long")
    return b"".join(
        (
            MAGIC_SERVER,
            bytes((VERSION, profile & 0xFF, suite_id & 0xFF, flags & 0xFF)),
            gateway_nonce,
            client_hash,
            write_lp(kem_material),
        )
    )


def _telemetry_header(
    suite_id: int, sensor_id: str, session_id: bytes, seq: int, unix_ms: int
) -> bytes:
    if len(session_id) != 8:
        raise ProtocolError("session id must be 8 bytes")
    return b"".join(
        (
            MAGIC_TELEMETRY,
            bytes((VERSION, suite_id & 0xFF)),
            write_lp(sensor_id.encode("ascii"), width=1),
            session_id,
            seq.to_bytes(8, "big"),
            unix_ms.to_bytes(8, "big"),
        )
    )


def _u8(buf: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(buf):
        raise ValueError("truncated")
    return buf[offset], offset + 1


def _sensor_id(raw: bytes) -> str:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProtocolError("sensor id is not ascii") from exc
    if not text or len(text) > SENSOR_ID_MAX:
        raise ProtocolError("sensor id has an illegal length")
    if text[0] == "-" or not all(ch.islower() or ch.isdigit() or ch == "-" for ch in text):
        raise ProtocolError("sensor id has illegal characters")
    return text
