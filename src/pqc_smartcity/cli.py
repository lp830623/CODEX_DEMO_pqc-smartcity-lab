"""Command line for the lab."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

from pqc_smartcity import __version__
from pqc_smartcity.catalog import SUITE_ORDER, require_suite


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pqc-smartcity",
        description="CityLink: a post-quantum smart-city telemetry lab over MQTT.",
    )
    parser.add_argument("--version", action="version", version=f"pqc-smartcity {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="print a loopback exchange, or one pass over every suite")
    _add_suite(demo)
    demo.add_argument("--messages", type=int, default=2)
    demo.add_argument("--telemetry", choices=("signed", "aead"), default="signed")
    demo.add_argument("--all-suites", action="store_true")
    demo.set_defaults(func=_demo)

    bench = sub.add_parser("bench", help="write timing and size CSVs")
    bench.add_argument("--iterations", type=int, default=100)
    bench.add_argument("--warmup", type=int, default=10)
    bench.add_argument("--output", type=Path, default=Path("results"))
    bench.add_argument("--suites", default="", help="comma-separated suite names; default is the full catalogue")
    bench.set_defaults(func=_bench)

    charts = sub.add_parser("charts", help="render figures from a benchmark directory")
    charts.add_argument("--results", type=Path, default=Path("results"))
    charts.set_defaults(func=_charts)

    provision = sub.add_parser("provision", help="write gateway, sensor, and trust files")
    _add_suite(provision)
    _add_paths(provision)
    provision.add_argument("--name", default=os.environ.get("CITYLINK_NAME", "city-gateway"))
    provision.add_argument("--force", action="store_true")
    provision.set_defaults(func=_provision)

    gateway = sub.add_parser("gateway", help="subscribe to CityLink and print accepted readings")
    _add_mqtt(gateway)
    _add_paths(gateway)
    gateway.set_defaults(func=_gateway)

    sensors = sub.add_parser("sensors", help="publish the commissioned fleet")
    _add_mqtt(sensors)
    _add_paths(sensors)
    sensors.add_argument("--count", type=int, default=int(os.environ.get("CITYLINK_COUNT", "0")))
    sensors.add_argument("--interval", type=float, default=float(os.environ.get("CITYLINK_INTERVAL", "2")))
    sensors.set_defaults(func=_sensors)

    versions = sub.add_parser("versions", help="print the crypto library versions")
    versions.set_defaults(func=_versions)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130


def _add_suite(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--suite",
        default=os.environ.get("CITYLINK_SUITE", "mlkem768-mldsa65"),
    )
    parser.add_argument(
        "--profile",
        choices=("ephemeral", "static"),
        default=os.environ.get("CITYLINK_PROFILE", "ephemeral"),
    )


def _add_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--gateway-secret",
        type=Path,
        default=Path(os.environ.get("CITYLINK_GATEWAY_SECRET", "runtime/gateway.secret.json")),
    )
    parser.add_argument(
        "--sensor-dir",
        type=Path,
        default=Path(os.environ.get("CITYLINK_SENSOR_DIR", "runtime/sensors")),
    )
    parser.add_argument(
        "--trust-dir",
        type=Path,
        default=Path(os.environ.get("CITYLINK_TRUST_DIR", "runtime/trust")),
    )


def _add_mqtt(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mqtt-host", default=os.environ.get("CITYLINK_MQTT_HOST", "127.0.0.1"))
    parser.add_argument("--mqtt-port", type=int, default=int(os.environ.get("CITYLINK_MQTT_PORT", "1883")))
    parser.add_argument(
        "--telemetry",
        choices=("signed", "aead"),
        default=os.environ.get("CITYLINK_TELEMETRY", "signed"),
    )


def _demo(args: argparse.Namespace) -> int:
    from pqc_smartcity.catalog import SUITES
    from pqc_smartcity.identity import issue_fleet
    from pqc_smartcity.mqtt_roles import loopback_exchange

    require_suite(args.suite)
    names = list(SUITE_ORDER) if args.all_suites else [args.suite]
    signed = args.telemetry == "signed"
    if args.all_suites:
        print(
            f"{'suite':<28} {'profile':<12} {'first_frame_B':>14} {'exchange_ms':>12}  "
            "(exchange_ms includes commissioning, not the benchmark)"
        )
    for name in names:
        info = SUITES[name]
        profile = "static" if info.static_only else args.profile
        started = time.perf_counter()
        fleet = issue_fleet(name, profile)
        opened = loopback_exchange(fleet=fleet, require_signature=signed, messages=args.messages)
        elapsed = (time.perf_counter() - started) * 1000
        if args.all_suites:
            print(f"{name:<28} {profile:<12} {opened[0].wire_bytes:>14} {elapsed:>12.1f}")
        else:
            for item in opened:
                print(json.dumps(item.summary()))
            print(
                f"# {len(opened)} readings, suite {name}, profile {profile}, "
                f"{args.telemetry} telemetry, {elapsed:.1f} ms including key generation",
                file=sys.stderr,
            )
    return 0


def _bench(args: argparse.Namespace) -> int:
    from pqc_smartcity.bench.runner import run_benchmark

    selected = [part.strip() for part in args.suites.split(",") if part.strip()] or None
    if selected:
        for name in selected:
            require_suite(name)
    run_benchmark(
        output=args.output,
        iterations=args.iterations,
        warmup=args.warmup,
        suites=selected,
    )
    return 0


def _charts(args: argparse.Namespace) -> int:
    from pqc_smartcity.bench.charts import render_charts

    for path in render_charts(args.results):
        print(path)
    return 0


def _provision(args: argparse.Namespace) -> int:
    from pqc_smartcity.identity import issue_fleet, load_gateway, save_fleet

    require_suite(args.suite)
    if args.gateway_secret.exists() and not args.force:
        existing = load_gateway(args.gateway_secret)
        if existing.suite_name != args.suite or existing.profile != args.profile:
            raise SystemExit(
                "existing keys were commissioned for "
                f"{existing.suite_name}/{existing.profile}; pass --force to rotate"
            )
        print(f"keys already present for {existing.suite_name} / {existing.profile}")
        return 0
    fleet = issue_fleet(args.suite, args.profile, args.name)
    save_fleet(
        fleet,
        gateway_secret=args.gateway_secret,
        sensor_dir=args.sensor_dir,
        trust_dir=args.trust_dir,
    )
    print(f"commissioned {args.suite} / {args.profile}")
    print(f"  gateway secret: {args.gateway_secret}")
    print(f"  sensor secrets: {args.sensor_dir}")
    print(f"  trust anchor:   {args.trust_dir / 'gateway.anchor.json'}")
    return 0


def _gateway(args: argparse.Namespace) -> int:
    from pqc_smartcity.identity import anchor_sig_pk, load_anchor, load_gateway, verify_registry
    from pqc_smartcity.mqtt_roles import run_gateway

    _wait(args.trust_dir / "gateway.anchor.json")
    _wait(args.trust_dir / "registry.json")
    _wait(args.gateway_secret)
    identity = load_gateway(args.gateway_secret)
    anchor = load_anchor(args.trust_dir / "gateway.anchor.json")
    registry = verify_registry(
        json.loads((args.trust_dir / "registry.json").read_text()),
        anchor_sig_pk(anchor),
    )
    stop = _stop_event()
    run_gateway(
        identity=identity,
        registry=registry,
        host=args.mqtt_host,
        port=args.mqtt_port,
        require_signature=args.telemetry == "signed",
        stop_event=stop,
    )
    return 0


def _sensors(args: argparse.Namespace) -> int:
    from pqc_smartcity.identity import load_anchor, load_sensors
    from pqc_smartcity.mqtt_roles import run_sensors

    _wait(args.trust_dir / "gateway.anchor.json")
    anchor = load_anchor(args.trust_dir / "gateway.anchor.json")
    sensors = load_sensors(args.sensor_dir)
    run_sensors(
        sensors=sensors,
        anchor=anchor,
        host=args.mqtt_host,
        port=args.mqtt_port,
        require_signature=args.telemetry == "signed",
        count=args.count,
        interval=args.interval,
    )
    return 0


def _versions(_args: argparse.Namespace) -> int:
    import cryptography
    import oqs

    print(f"pqc-smartcity {__version__}")
    print(f"python {sys.version.split()[0]}")
    print(f"liboqs {oqs.oqs_version()}")
    print(f"liboqs-python {oqs.oqs_python_version()}")
    print(f"cryptography {cryptography.__version__}")
    return 0


def _wait(path: Path, timeout: float = 60) -> None:
    deadline = time.time() + timeout
    while not path.exists():
        if time.time() > deadline:
            raise SystemExit(f"timed out waiting for {path}")
        time.sleep(0.25)


def _stop_event() -> threading.Event:
    stop = threading.Event()

    def _handle(signum, _frame) -> None:
        stop.set()

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)
    return stop
