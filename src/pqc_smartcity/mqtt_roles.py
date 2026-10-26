"""MQTT transport for CityLink.

The broker is an untrusted pipe. It sees topics, packet sizes, and timing,
and it never sees a traffic key. Payloads are CityLink bytes or one signed
JSON bundle.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time

import paho.mqtt.client as mqtt

from pqc_smartcity.crypto.suites import get_suite
from pqc_smartcity.errors import CityLinkError
from pqc_smartcity.identity import (
    GatewayIdentity,
    SensorIdentity,
    anchor_sig_pk,
    signed_bundle,
    verify_bundle,
)
from pqc_smartcity.protocol.engine import GatewayEndpoint, OpenedReading, SensorEndpoint

logger = logging.getLogger("citylink.mqtt")

BUNDLE_TOPIC = "citylink/v1/bundle"


def hello_topic(sensor_id: str) -> str:
    return f"citylink/v1/hello/{sensor_id}"


def welcome_topic(sensor_id: str) -> str:
    return f"citylink/v1/welcome/{sensor_id}"


def telemetry_topic(sensor_id: str) -> str:
    return f"citylink/v1/telemetry/{sensor_id}"


def run_gateway(
    *,
    identity: GatewayIdentity,
    registry: dict[str, bytes],
    host: str,
    port: int,
    require_signature: bool,
    stop_event: threading.Event,
    on_reading=None,
    ready_event: threading.Event | None = None,
) -> None:
    suite = get_suite(identity.suite_name)
    endpoint = GatewayEndpoint(
        suite=suite,
        profile=identity.profile,
        sig_sk=identity.sig_sk,
        sig_pk=identity.sig_pk,
        registry=registry,
        require_signature=require_signature,
        kem_sk=identity.kem_sk,
    )
    bundle = json.dumps(signed_bundle(identity)).encode()

    def on_message(client, userdata, message) -> None:
        topic = message.topic
        try:
            if topic.startswith("citylink/v1/hello/"):
                sensor_id = topic.rsplit("/", 1)[1]
                welcome = endpoint.handle_hello(message.payload)
                client.publish(welcome_topic(sensor_id), welcome, qos=1)
            elif topic.startswith("citylink/v1/telemetry/"):
                opened = endpoint.open_telemetry(message.payload)
                if on_reading is not None:
                    on_reading(opened)
                else:
                    print(json.dumps(opened.summary()), flush=True)
        except CityLinkError as exc:
            logger.warning("rejected %s: %s", topic, exc)

    client = connect_client(f"citylink-gw-{os.urandom(3).hex()}", host, port, on_message)
    try:
        client.subscribe("citylink/v1/hello/+", qos=1)
        client.subscribe("citylink/v1/telemetry/+", qos=1)
        client.publish(BUNDLE_TOPIC, bundle, qos=1, retain=True)
        if ready_event is not None:
            ready_event.set()
        logger.info(
            "gateway %s online suite=%s profile=%s",
            identity.name,
            identity.suite_name,
            identity.profile,
        )
        while not stop_event.is_set():
            stop_event.wait(0.25)
    finally:
        client.disconnect()
        client.loop_stop()


def run_sensors(
    *,
    sensors: list[SensorIdentity],
    anchor: dict,
    host: str,
    port: int,
    require_signature: bool,
    count: int,
    interval: float,
) -> list[str]:
    """Publish readings from each sensor.

    ``count`` is the number of readings per sensor. Zero means run until the
    process is interrupted. Returns the sensor ids that completed a handshake.
    """

    if count < 0:
        raise ValueError("count must be zero (run forever) or positive")
    anchor_pk = anchor_sig_pk(anchor)
    suite_name = anchor["suite"]
    profile = anchor["profile"]
    for sensor in sensors:
        if sensor.suite_name != suite_name:
            raise ValueError(f"{sensor.sensor_id} was commissioned for {sensor.suite_name}")

    pending: dict[str, SensorEndpoint] = {}
    ready: dict[str, threading.Event] = {sensor.sensor_id: threading.Event() for sensor in sensors}
    bundle_holder: dict[str, dict] = {}
    bundle_event = threading.Event()

    def on_message(client, userdata, message) -> None:
        if message.topic == BUNDLE_TOPIC:
            try:
                body = verify_bundle(json.loads(message.payload), anchor_pk, suite_name)
            except (CityLinkError, json.JSONDecodeError) as exc:
                logger.warning("bundle rejected: %s", exc)
                return
            if body.get("profile") != profile or body.get("name") != anchor["name"]:
                logger.warning("bundle does not match the local anchor")
                return
            bundle_holder["body"] = body
            bundle_event.set()
            return
        if not message.topic.startswith("citylink/v1/welcome/"):
            return
        sensor_id = message.topic.rsplit("/", 1)[1]
        endpoint = pending.get(sensor_id)
        if endpoint is None:
            return
        try:
            endpoint.handle_welcome(message.payload)
        except CityLinkError as exc:
            logger.warning("welcome rejected for %s: %s", sensor_id, exc)
            return
        ready[sensor_id].set()

    client = connect_client(f"citylink-sensors-{os.urandom(3).hex()}", host, port, on_message)
    try:
        client.subscribe(BUNDLE_TOPIC, qos=1)
        client.subscribe("citylink/v1/welcome/+", qos=1)
        if not bundle_event.wait(20):
            raise TimeoutError("timed out waiting for the signed gateway bundle")
        body = bundle_holder["body"]
        kem_pk = None
        if profile == "static":
            if not body.get("kem_pk"):
                raise ValueError("static bundle is missing the encapsulation key")
            import base64

            kem_pk = base64.b64decode(body["kem_pk"], validate=True)
        endpoints = []
        for sensor in sensors:
            endpoint = SensorEndpoint(
                suite=get_suite(sensor.suite_name),
                profile=profile,
                sensor_id=sensor.sensor_id,
                kind=sensor.kind,
                sig_sk=sensor.sig_sk,
                sig_pk=sensor.sig_pk,
                anchor_sig_pk=anchor_pk,
                require_signature=require_signature,
                gateway_kem_pk=kem_pk,
            )
            pending[sensor.sensor_id] = endpoint
            endpoints.append(endpoint)
            client.publish(hello_topic(sensor.sensor_id), endpoint.client_hello(), qos=1)
        deadline = time.time() + 20
        for sensor in sensors:
            remaining = deadline - time.time()
            if remaining <= 0 or not ready[sensor.sensor_id].wait(remaining):
                raise TimeoutError(f"no welcome for {sensor.sensor_id}")
        finished = 0
        while count == 0 or finished < count:
            for endpoint in endpoints:
                client.publish(telemetry_topic(endpoint.sensor_id), endpoint.seal(), qos=1)
            finished += 1
            if interval and (count == 0 or finished < count):
                time.sleep(interval)
        # Give the broker a moment to deliver the last QoS 1 publishes.
        time.sleep(1.0)
        return [sensor.sensor_id for sensor in sensors]
    finally:
        client.disconnect()
        client.loop_stop()


def connect_client(client_id: str, host: str, port: int, on_message) -> mqtt.Client:
    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=client_id,
        protocol=mqtt.MQTTv311,
    )
    connected = threading.Event()
    failed: list[str] = []

    def on_connect(client, userdata, flags, reason_code, properties) -> None:
        failure = getattr(reason_code, "is_failure", None)
        if failure is None:
            failure = int(reason_code) != 0
        if failure:
            failed.append(str(reason_code))
            return
        connected.set()

    client.on_connect = on_connect
    client.on_message = on_message
    deadline = time.time() + 30
    while True:
        try:
            client.connect(host, port, keepalive=30)
            break
        except OSError:
            if time.time() > deadline:
                raise
            time.sleep(0.3)
    client.loop_start()
    if not connected.wait(10):
        client.loop_stop()
        detail = failed[0] if failed else "no CONNACK"
        raise TimeoutError(f"MQTT connection to {host}:{port} failed ({detail})")
    return client


def loopback_exchange(
    *,
    fleet,
    require_signature: bool,
    messages: int,
    timestamp_ms: int | None = None,
) -> list[OpenedReading]:
    """Run the fleet through CityLink in one process, with no broker."""

    gateway = GatewayEndpoint(
        suite=get_suite(fleet.gateway.suite_name),
        profile=fleet.gateway.profile,
        sig_sk=fleet.gateway.sig_sk,
        sig_pk=fleet.gateway.sig_pk,
        registry=fleet.registry(),
        require_signature=require_signature,
        kem_sk=fleet.gateway.kem_sk,
    )
    opened: list[OpenedReading] = []
    for sensor in fleet.sensors:
        endpoint = SensorEndpoint(
            suite=get_suite(sensor.suite_name),
            profile=fleet.gateway.profile,
            sensor_id=sensor.sensor_id,
            kind=sensor.kind,
            sig_sk=sensor.sig_sk,
            sig_pk=sensor.sig_pk,
            anchor_sig_pk=fleet.gateway.sig_pk,
            require_signature=require_signature,
            gateway_kem_pk=fleet.gateway.kem_pk,
        )
        endpoint.handle_welcome(gateway.handle_hello(endpoint.client_hello()))
        for _ in range(messages):
            opened.append(gateway.open_telemetry(endpoint.seal(timestamp_ms)))
    return opened
