"""One broker, one gateway, three sensors."""

from __future__ import annotations

import json
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

from pqc_smartcity.identity import (
    anchor_sig_pk,
    issue_fleet,
    load_anchor,
    save_fleet,
    verify_registry,
)
from pqc_smartcity.mqtt_roles import run_gateway, run_sensors


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_mqtt_fleet_roundtrip(tmp_path: Path) -> None:
    mosquitto = subprocess.run(["bash", "-lc", "command -v mosquitto"], capture_output=True, text=True)
    if mosquitto.returncode != 0:
        pytest.skip("mosquitto is not installed")
    port = _free_port()
    config = tmp_path / "mosquitto.conf"
    config.write_text(
        "\n".join(
            [
                f"listener {port} 127.0.0.1",
                "allow_anonymous true",
                "persistence false",
                "log_type error",
                "",
            ]
        )
    )
    broker = subprocess.Popen(
        ["mosquitto", "-c", str(config)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stop = threading.Event()
    thread: threading.Thread | None = None
    try:
        _wait_port(port)
        fleet = issue_fleet("mlkem768-mldsa65", "ephemeral")
        save_fleet(
            fleet,
            gateway_secret=tmp_path / "gateway.secret.json",
            sensor_dir=tmp_path / "sensors",
            trust_dir=tmp_path / "trust",
        )
        anchor = load_anchor(tmp_path / "trust" / "gateway.anchor.json")
        registry = verify_registry(
            json.loads((tmp_path / "trust" / "registry.json").read_text()),
            anchor_sig_pk(anchor),
        )
        received: list[dict] = []
        ready = threading.Event()

        def serve() -> None:
            run_gateway(
                identity=fleet.gateway,
                registry=registry,
                host="127.0.0.1",
                port=port,
                require_signature=True,
                stop_event=stop,
                on_reading=lambda opened: received.append(opened.summary()),
                ready_event=ready,
            )

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        assert ready.wait(15), "gateway did not become ready"
        finished = run_sensors(
            sensors=fleet.sensors,
            anchor=anchor,
            host="127.0.0.1",
            port=port,
            require_signature=True,
            count=2,
            interval=0.05,
        )
        deadline = time.time() + 10
        while len(received) < 6 and time.time() < deadline:
            time.sleep(0.05)
        assert finished == [sensor.sensor_id for sensor in fleet.sensors]
        assert len(received) == 6
        assert {item["kind"] for item in received} == {"air_quality", "traffic", "energy_meter"}
        assert all(item["auth"] == "signed" for item in received)
    finally:
        stop.set()
        if thread is not None:
            thread.join(timeout=5)
        broker.terminate()
        try:
            broker.wait(timeout=5)
        except subprocess.TimeoutExpired:
            broker.kill()


def _wait_port(port: int) -> None:
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"mosquitto did not listen on {port}")
