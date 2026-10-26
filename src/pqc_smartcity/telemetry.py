"""Simulated smart-city sensors.

The physical process is a deterministic function of the sensor id and the
sequence number. Cryptography uses the operating system's CSPRNG; only the
fake environment is seeded, so two runs of the benchmark encrypt the same
plaintext and the sizes stay comparable.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

FLEET: tuple[tuple[str, str], ...] = (
    ("aq-centrum-03", "air_quality"),
    ("tr-bridge-01", "traffic"),
    ("em-substation-07", "energy_meter"),
)

_KINDS = {sensor_id: kind for sensor_id, kind in FLEET}


def kind_of(sensor_id: str) -> str:
    try:
        return _KINDS[sensor_id]
    except KeyError as exc:
        raise ValueError(f"unknown sensor {sensor_id}") from exc


def make_reading(sensor_id: str, kind: str, seq: int, unix_ms: int) -> dict:
    if seq < 1:
        raise ValueError("sequence starts at 1")
    digest = hashlib.sha256(f"{sensor_id}:{seq}".encode()).digest()

    def unit(index: int, lo: float, hi: float) -> float:
        span = hi - lo
        raw = int.from_bytes(digest[index : index + 2], "big") / 65535
        return round(lo + span * raw, 2)

    if kind == "air_quality":
        readings = {
            "pm2_5_ugm3": unit(0, 4.0, 38.0),
            "pm10_ugm3": unit(2, 8.0, 62.0),
            "no2_ppb": unit(4, 6.0, 48.0),
            "o3_ppb": unit(6, 10.0, 70.0),
            "temperature_c": unit(8, -2.0, 34.0),
            "relative_humidity_pct": unit(10, 25.0, 95.0),
        }
    elif kind == "traffic":
        readings = {
            "volume_veh_per_min": int(unit(0, 2, 55)),
            "avg_speed_kmh": unit(2, 8.0, 72.0),
            "occupancy_pct": unit(4, 1.0, 80.0),
            "queue_m": unit(6, 0.0, 120.0),
        }
    elif kind == "energy_meter":
        readings = {
            "active_power_kw": unit(0, 40.0, 480.0),
            "reactive_power_kvar": unit(2, 5.0, 90.0),
            "voltage_v": unit(4, 225.0, 240.0),
            "frequency_hz": unit(6, 49.90, 50.10),
            "energy_kwh_total": round(150_000 + seq * 0.25 + unit(8, 0.0, 0.24), 2),
        }
    else:
        raise ValueError(f"unknown sensor kind {kind}")
    return {
        "v": 1,
        "sensor_id": sensor_id,
        "kind": kind,
        "ts": _iso(unix_ms),
        "seq": seq,
        "readings": readings,
    }


def canonical_reading(reading: dict) -> bytes:
    return json.dumps(reading, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def parse_reading(raw: bytes) -> dict:
    try:
        reading = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("telemetry plaintext is not JSON") from exc
    if canonical_reading(reading) != raw:
        raise ValueError("telemetry plaintext is not canonical JSON")
    for key in ("v", "sensor_id", "kind", "ts", "seq", "readings"):
        if key not in reading:
            raise ValueError(f"telemetry is missing {key}")
    if reading["v"] != 1 or not isinstance(reading["readings"], dict):
        raise ValueError("telemetry payload rejected")
    return reading


def _iso(unix_ms: int) -> str:
    stamp = datetime.fromtimestamp(unix_ms / 1000, timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{unix_ms % 1000:03d}Z"
