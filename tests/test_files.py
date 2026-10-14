"""Commissioning files and the benchmark harness."""

from __future__ import annotations

import csv
import json
import stat
from pathlib import Path

from pqc_smartcity.bench.charts import render_charts
from pqc_smartcity.bench.runner import run_benchmark
from pqc_smartcity.identity import (
    anchor_sig_pk,
    issue_fleet,
    load_anchor,
    load_gateway,
    load_sensors,
    save_fleet,
    verify_registry,
)

ROOT = Path(__file__).resolve().parents[1]


def test_secret_files_are_mode_0600(tmp_path: Path) -> None:
    fleet = issue_fleet("x25519-ed25519", "ephemeral")
    secret = tmp_path / "gateway.secret.json"
    save_fleet(
        fleet,
        gateway_secret=secret,
        sensor_dir=tmp_path / "sensors",
        trust_dir=tmp_path / "trust",
    )
    assert stat.S_IMODE(secret.stat().st_mode) == 0o600
    loaded = load_gateway(secret)
    assert loaded.sig_pk == fleet.gateway.sig_pk
    assert loaded.kem_sk is None
    sensors = load_sensors(tmp_path / "sensors")
    assert {sensor.sensor_id for sensor in sensors} == {item.sensor_id for item in fleet.sensors}
    anchor = load_anchor(tmp_path / "trust" / "gateway.anchor.json")
    registry = verify_registry(
        json.loads((tmp_path / "trust" / "registry.json").read_text()),
        anchor_sig_pk(anchor),
    )
    assert set(registry) == {sensor.sensor_id for sensor in sensors}


def test_benchmark_smoke_and_charts(tmp_path: Path) -> None:
    run_benchmark(
        output=tmp_path,
        iterations=2,
        warmup=1,
        suites=["x25519-ed25519", "mlkem768-mldsa65"],
    )
    charts = render_charts(tmp_path)
    assert charts[0].read_bytes().startswith(b"\x89PNG")
    timings = list(csv.DictReader((tmp_path / "timings.csv").open()))
    assert any(
        row["operation"] == "handshake_wall" and row["suite"] == "mlkem768-mldsa65" for row in timings
    )
    assert "mlkem768-mldsa65" in (tmp_path / "summary.md").read_text()


def test_published_results_match_the_schema() -> None:
    results = ROOT / "results"
    env = json.loads((results / "environment.json").read_text())
    assert "liboqs" in env and env["iterations"] >= 30
    with (results / "timings.csv").open() as handle:
        rows = list(csv.DictReader(handle))
    assert {"suite", "profile", "operation", "median", "p95", "n"} <= rows[0].keys()
    suites = {row["suite"] for row in rows}
    assert {"hybrid-x25519-mlkem768", "rsa3072-pss", "mlkem768-mldsa65"} <= suites
    for name in (
        "handshake_latency.png",
        "artifact_sizes.png",
        "telemetry_overhead.png",
        "primitive_latency.png",
    ):
        blob = (results / "charts" / name).read_bytes()
        assert blob.startswith(b"\x89PNG") and len(blob) > 5000
