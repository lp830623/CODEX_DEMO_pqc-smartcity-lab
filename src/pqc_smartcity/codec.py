"""Shared length-prefix codec.

Lives above both the crypto suites and the CityLink framing so neither layer
has to import the other for a two-byte length.
"""

from __future__ import annotations


def write_lp(payload: bytes, width: int = 2) -> bytes:
    if len(payload) >= 256**width:
        raise ValueError("field does not fit in the length prefix")
    return len(payload).to_bytes(width, "big") + payload


def read_lp(buf: bytes, offset: int, width: int = 2) -> tuple[bytes, int]:
    if offset + width > len(buf):
        raise ValueError("truncated length")
    length = int.from_bytes(buf[offset : offset + width], "big")
    start = offset + width
    end = start + length
    if end > len(buf):
        raise ValueError("truncated field")
    return buf[start:end], end


def read_exact(buf: bytes, offset: int, length: int) -> tuple[bytes, int]:
    end = offset + length
    if end > len(buf):
        raise ValueError("truncated field")
    return buf[offset:end], end
