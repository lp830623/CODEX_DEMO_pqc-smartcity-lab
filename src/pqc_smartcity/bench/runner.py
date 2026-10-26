"""Reproducible CityLink measurements.

Timings are in-process. They include the Python wrapper and exclude MQTT and
the network. That is the number this harness can stand behind; it is not a
claim about a C TLS stack.
"""

from __future__ import annotations

import csv
import json
import math
import os
import platform
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from pqc_smartcity.catalog import SUITE_ORDER, SuiteInfo, require_suite
from pqc_smartcity.crypto.classical import (
    EcdsaP256Signer,
    Ed25519Signer,
    P256Kem,
    RsaOaepKem,
    RsaPssSigner,
    X25519Kem,
)
from pqc_smartcity.crypto.fips import ML_DSA, ML_KEM
from pqc_smartcity.crypto.pq import PqKem, PqSigner
from pqc_smartcity.crypto.suites import get_suite
from pqc_smartcity.identity import Fleet, issue_fleet
from pqc_smartcity.protocol.engine import GatewayEndpoint, SensorEndpoint
from pqc_smartcity.protocol.framing import decode_client_hello, decode_server_hello
from pqc_smartcity.telemetry import canonical_reading, make_reading

# Fixed probe so plaintext length does not depend on the wall clock.
PROBE_TS_MS = 1_760_443_200_000
PROBE_SENSOR = "aq-centrum-03"
_SIGN_MESSAGE = b"citylink-primitive-probe|" + (b"M" * 232)
_RSA_KEYGEN_CAP = 8

_TIMING_FIELDS = (
    "suite",
    "profile",
    "operation",
    "unit",
    "n",
    "median",
    "mean",
    "stdev",
    "p95",
    "min",
    "max",
)
_SAMPLE_FIELDS = ("suite", "profile", "operation", "iteration", "milliseconds")
_SIZE_FIELDS = (
    "suite",
    "profile",
    "kem_public_bytes",
    "kem_secret_bytes",
    "kem_ciphertext_bytes",
    "sig_public_bytes",
    "sig_secret_bytes",
    "signature_bytes_max",
    "client_hello_bytes_max",
    "server_hello_bytes_max",
    "plaintext_bytes",
    "telemetry_aead_bytes",
    "telemetry_signed_bytes",
)
_PRIMITIVE_FIELDS = (
    "algorithm",
    "role",
    "public_bytes",
    "secret_bytes",
    "artifact_bytes",
    "artifact",
    "shared_secret_bytes",
    "standard_public_bytes",
    "standard_secret_bytes",
    "standard_artifact_bytes",
)


def run_benchmark(
    *,
    output: Path,
    iterations: int = 100,
    warmup: int = 10,
    suites: list[str] | None = None,
) -> Path:
    if iterations < 1:
        raise ValueError("iterations must be positive")
    if warmup < 0:
        raise ValueError("warmup must be zero or positive")
    selected = [require_suite(name) for name in (suites or SUITE_ORDER)]
    output.mkdir(parents=True, exist_ok=True)
    env = _environment(iterations, warmup)
    (output / "environment.json").write_text(json.dumps(env, indent=2) + "\n")

    timing_rows: list[dict] = []
    sample_rows: list[dict] = []
    size_rows: list[dict] = []
    for info in selected:
        print(f"measuring {info.name}", flush=True)
        primitive_rows, primitive_samples = _time_primitives(info, iterations, warmup)
        timing_rows.extend(primitive_rows)
        sample_rows.extend(primitive_samples)
        for profile in _profiles(info):
            print(f"  handshake {profile}", flush=True)
            rows, samples, sizes = _time_handshake(info, profile, iterations, warmup)
            timing_rows.extend(rows)
            sample_rows.extend(samples)
            size_rows.append(sizes)

    _write_csv(output / "timings.csv", _TIMING_FIELDS, timing_rows)
    _write_csv(output / "samples.csv", _SAMPLE_FIELDS, sample_rows)
    _write_csv(output / "sizes.csv", _SIZE_FIELDS, size_rows)
    _write_csv(output / "primitives.csv", _PRIMITIVE_FIELDS, _measure_primitives())
    _write_summary(output, env)
    print(f"wrote {output}", flush=True)
    return output


def _profiles(info: SuiteInfo) -> tuple[str, ...]:
    if info.static_only:
        return ("static",)
    return ("ephemeral", "static")


def _time_primitives(info: SuiteInfo, iterations: int, warmup: int) -> tuple[list[dict], list[dict]]:
    suite = get_suite(info.name)
    kem_sk, kem_pk = suite.generate_kem_keypair()
    ciphertext, _shared = suite.encaps(kem_pk)
    sig_sk, sig_pk = suite.generate_sig_keypair()
    signature = suite.sign(sig_sk, _SIGN_MESSAGE)
    keygen_iters = min(iterations, _RSA_KEYGEN_CAP) if info.name == "rsa3072-pss" else iterations
    operations = {
        "kem_keygen": (lambda: suite.generate_kem_keypair(), keygen_iters),
        "kem_encaps": (lambda: suite.encaps(kem_pk), iterations),
        "kem_decaps": (lambda: suite.decaps(kem_sk, ciphertext), iterations),
        "sig_keygen": (lambda: suite.generate_sig_keypair(), keygen_iters),
        "sig_sign": (lambda: suite.sign(sig_sk, _SIGN_MESSAGE), iterations),
        "sig_verify": (lambda: suite.verify(sig_pk, _SIGN_MESSAGE, signature), iterations),
    }
    rows: list[dict] = []
    samples: list[dict] = []
    for name, (fn, count) in operations.items():
        wall, cpu = _time_call(fn, count, warmup)
        rows.append(_row(info.name, "primitive", name + "_wall", wall))
        rows.append(_row(info.name, "primitive", name + "_cpu", cpu))
        if name in {"sig_sign", "sig_verify", "kem_encaps", "kem_decaps", "kem_keygen"}:
            samples.extend(_samples(info.name, "primitive", name + "_wall", wall))
    return rows, samples


def _time_handshake(
    info: SuiteInfo, profile: str, iterations: int, warmup: int
) -> tuple[list[dict], list[dict], dict]:
    fleet = issue_fleet(info.name, profile)
    gateway, sensor = _endpoints(fleet, profile, require_signature=True)
    aead_gateway, aead_sensor = _endpoints(fleet, profile, require_signature=False)

    def handshake() -> None:
        sensor.handle_welcome(gateway.handle_hello(sensor.client_hello()))

    for _ in range(warmup):
        handshake()
    wall: list[float] = []
    cpu: list[float] = []
    client_sizes: list[int] = []
    server_sizes: list[int] = []
    signature_sizes: list[int] = []
    for index in range(iterations):
        cpu0 = time.process_time_ns()
        start = time.perf_counter_ns()
        hello = sensor.client_hello()
        welcome = gateway.handle_hello(hello)
        sensor.handle_welcome(welcome)
        wall.append((time.perf_counter_ns() - start) / 1e6)
        cpu.append((time.process_time_ns() - cpu0) / 1e6)
        client_sizes.append(len(hello))
        server_sizes.append(len(welcome))
        signature_sizes.append(len(decode_client_hello(hello).signature))
        signature_sizes.append(len(decode_server_hello(welcome).signature))
        if index == iterations - 1:
            signed_frame = sensor.seal(PROBE_TS_MS)
    aead_sensor.handle_welcome(aead_gateway.handle_hello(aead_sensor.client_hello()))
    aead_frame = aead_sensor.seal(PROBE_TS_MS)

    kem_sk, kem_pk = sensor.suite.generate_kem_keypair()
    kem_ct, _shared = sensor.suite.encaps(kem_pk)
    sensor_identity = next(item for item in fleet.sensors if item.sensor_id == PROBE_SENSOR)
    plaintext = canonical_reading(make_reading(PROBE_SENSOR, "air_quality", 1, PROBE_TS_MS))
    # seal() above used whatever sequence the loop reached, so the signed frame's
    # plaintext is not the probe document. Size the probe itself, and keep the
    # wire sizes from the frames we actually built.
    sizes = {
        "suite": info.name,
        "profile": profile,
        "kem_public_bytes": len(kem_pk),
        "kem_secret_bytes": len(kem_sk),
        "kem_ciphertext_bytes": len(kem_ct),
        "sig_public_bytes": len(sensor_identity.sig_pk),
        "sig_secret_bytes": len(sensor_identity.sig_sk),
        "signature_bytes_max": max(signature_sizes),
        "client_hello_bytes_max": max(client_sizes),
        "server_hello_bytes_max": max(server_sizes),
        "plaintext_bytes": len(plaintext),
        "telemetry_aead_bytes": len(aead_frame),
        "telemetry_signed_bytes": len(signed_frame),
    }
    rows = [
        _row(info.name, profile, "handshake_wall", wall),
        _row(info.name, profile, "handshake_cpu", cpu),
    ]
    samples = _samples(info.name, profile, "handshake_wall", wall)
    samples.extend(_samples(info.name, profile, "handshake_cpu", cpu))
    return rows, samples, sizes


def _endpoints(fleet: Fleet, profile: str, require_signature: bool):
    sensor_identity = next(item for item in fleet.sensors if item.sensor_id == PROBE_SENSOR)
    gateway = GatewayEndpoint(
        suite=get_suite(fleet.gateway.suite_name),
        profile=profile,
        sig_sk=fleet.gateway.sig_sk,
        sig_pk=fleet.gateway.sig_pk,
        registry={sensor_identity.sensor_id: sensor_identity.sig_pk},
        require_signature=require_signature,
        kem_sk=fleet.gateway.kem_sk,
        max_skew_ms=None,
    )
    sensor = SensorEndpoint(
        suite=get_suite(fleet.gateway.suite_name),
        profile=profile,
        sensor_id=sensor_identity.sensor_id,
        kind=sensor_identity.kind,
        sig_sk=sensor_identity.sig_sk,
        sig_pk=sensor_identity.sig_pk,
        anchor_sig_pk=fleet.gateway.sig_pk,
        require_signature=require_signature,
        gateway_kem_pk=fleet.gateway.kem_pk,
    )
    return gateway, sensor


def _measure_primitives() -> list[dict]:
    rows = []
    classical = (
        ("X25519", "kem", X25519Kem()),
        ("ECDH-P-256", "kem", P256Kem()),
        ("RSA-3072-OAEP", "kem", RsaOaepKem()),
        ("Ed25519", "sig", Ed25519Signer()),
        ("ECDSA-P-256", "sig", EcdsaP256Signer()),
        ("RSA-3072-PSS", "sig", RsaPssSigner()),
    )
    for name, role, primitive in classical:
        rows.append(_primitive_row(name, role, primitive, None))
    for algorithm, standard in ML_KEM.items():
        rows.append(
            _primitive_row(
                algorithm,
                "kem",
                PqKem(algorithm),
                {
                    "public": standard["encapsulation_key"],
                    "secret": standard["decapsulation_key"],
                    "artifact": standard["ciphertext"],
                },
            )
        )
    for algorithm, standard in ML_DSA.items():
        rows.append(
            _primitive_row(
                algorithm,
                "sig",
                PqSigner(algorithm),
                {
                    "public": standard["public_key"],
                    "secret": standard["secret_key"],
                    "artifact": standard["signature"],
                },
            )
        )
    return rows


def _primitive_row(name: str, role: str, primitive, standard: dict | None) -> dict:
    secret, public = primitive.generate()
    if role == "kem":
        artifact, shared = primitive.encaps(public)
        artifact_name = "ciphertext"
        shared_len: int | str = len(shared)
    else:
        artifact = primitive.sign(secret, _SIGN_MESSAGE)
        artifact_name = "signature"
        shared_len = ""
    return {
        "algorithm": name,
        "role": role,
        "public_bytes": len(public),
        "secret_bytes": len(secret),
        "artifact_bytes": len(artifact),
        "artifact": artifact_name,
        "shared_secret_bytes": shared_len,
        "standard_public_bytes": "" if standard is None else standard["public"],
        "standard_secret_bytes": "" if standard is None else standard["secret"],
        "standard_artifact_bytes": "" if standard is None else standard["artifact"],
    }


def _time_call(fn, iterations: int, warmup: int) -> tuple[list[float], list[float]]:
    for _ in range(warmup):
        fn()
    wall: list[float] = []
    cpu: list[float] = []
    for _ in range(iterations):
        cpu0 = time.process_time_ns()
        start = time.perf_counter_ns()
        fn()
        wall.append((time.perf_counter_ns() - start) / 1e6)
        cpu.append((time.process_time_ns() - cpu0) / 1e6)
    return wall, cpu


def _row(suite: str, profile: str, operation: str, samples: list[float]) -> dict:
    return {"suite": suite, "profile": profile, "operation": operation, "unit": "ms", **_stats(samples)}


def _samples(suite: str, profile: str, operation: str, samples: list[float]) -> list[dict]:
    return [
        {
            "suite": suite,
            "profile": profile,
            "operation": operation,
            "iteration": index,
            "milliseconds": f"{value:.6f}",
        }
        for index, value in enumerate(samples)
    ]


def _stats(samples: list[float]) -> dict:
    ordered = sorted(samples)
    count = len(ordered)
    return {
        "n": count,
        "median": f"{statistics.median(ordered):.6f}",
        "mean": f"{statistics.fmean(ordered):.6f}",
        "stdev": f"{(statistics.stdev(ordered) if count > 1 else 0.0):.6f}",
        "p95": f"{ordered[max(0, math.ceil(0.95 * count) - 1)]:.6f}",
        "min": f"{ordered[0]:.6f}",
        "max": f"{ordered[-1]:.6f}",
    }


def _environment(iterations: int, warmup: int) -> dict:
    import cryptography

    cpu = _cpu_model()
    flags = _cpu_flags()
    document = {
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or cpu,
        "cpu_model": cpu,
        "cpu_count": os.cpu_count(),
        "cpu_flags_of_interest": [flag for flag in ("aes", "avx2", "avx512f", "sha_ni") if flag in flags],
        "cryptography": cryptography.__version__,
        "iterations": iterations,
        "warmup": warmup,
        "rsa_keygen_iteration_cap": _RSA_KEYGEN_CAP,
        "probe_timestamp_ms": PROBE_TS_MS,
        "sign_probe_bytes": len(_SIGN_MESSAGE),
        "method": (
            "Single-threaded CPython. Wall time is time.perf_counter_ns and CPU time is "
            "time.process_time_ns, both converted to milliseconds. Warmup calls are discarded. "
            "The p95 is the nearest-rank statistic at ceil(0.95*n). Handshake time is the sum "
            "of the initiator and the responder in one process, with no MQTT hop. "
            "DH-style encapsulation includes ephemeral key generation; ML-KEM encapsulation does not. "
            "RSA-3072 key generation is capped because it is a commissioning cost, not a per-packet cost."
        ),
    }
    try:
        import oqs

        document["liboqs"] = oqs.oqs_version()
        document["liboqs_python"] = oqs.oqs_python_version()
    except Exception as exc:  # pragma: no cover - the lab always ships with liboqs
        document["liboqs_error"] = str(exc)
    return document


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _cpu_flags() -> set[str]:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("flags"):
                return set(line.split(":", 1)[1].split())
    except OSError:
        pass
    return set()


def _write_csv(path: Path, fields: tuple[str, ...], rows: list[dict]) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _write_summary(output: Path, env: dict) -> None:
    timings = _index_timings(output / "timings.csv")
    sizes = list(csv.DictReader((output / "sizes.csv").open()))
    lines = [
        "# Benchmark summary",
        "",
        "Generated by `python -m pqc_smartcity bench`. Do not edit by hand.",
        "",
        f"- When: {env['generated_at_utc']}",
        f"- Host: {env['cpu_model']} ({env['cpu_count']} threads), Python {env['python']}",
        (
            f"- Libraries: liboqs {env.get('liboqs', 'n/a')}, "
            f"liboqs-python {env.get('liboqs_python', 'n/a')}, cryptography {env['cryptography']}"
        ),
        f"- Iterations: {env['iterations']} after {env['warmup']} warmup calls",
        "",
        "| Suite | Profile | Handshake median (ms) | p95 (ms) | CPU median (ms) | ClientHello (B) | ServerHello (B) | Signature (B) | Plaintext (B) | AEAD telemetry (B) | Signed telemetry (B) |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for size in sizes:
        wall = timings[(size["suite"], size["profile"], "handshake_wall")]
        cpu = timings[(size["suite"], size["profile"], "handshake_cpu")]
        lines.append(
            "| {suite} | {profile} | {median} | {p95} | {cpu} | {hello} | {welcome} | {sig} | {plain} | {aead} | {signed} |".format(
                suite=size["suite"],
                profile=size["profile"],
                median=_ms(wall["median"]),
                p95=_ms(wall["p95"]),
                cpu=_ms(cpu["median"]),
                hello=size["client_hello_bytes_max"],
                welcome=size["server_hello_bytes_max"],
                sig=size["signature_bytes_max"],
                plain=size["plaintext_bytes"],
                aead=size["telemetry_aead_bytes"],
                signed=size["telemetry_signed_bytes"],
            )
        )
    lines.extend(
        [
            "",
            "Primitive wall-clock medians. Sign and verify use a fixed "
            f"{env['sign_probe_bytes']}-byte message.",
            "X25519 and P-256 encapsulation includes ephemeral key generation. ML-KEM encapsulation does not.",
            "",
            "| Suite | KEM keygen (ms) | Encaps (ms) | Decaps (ms) | Sign (ms) | Verify (ms) |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    seen: list[str] = []
    for size in sizes:
        if size["suite"] not in seen:
            seen.append(size["suite"])
    for name in seen:
        def cell(operation: str, suite: str = name) -> str:
            return _ms(timings[(suite, "primitive", operation)]["median"])

        lines.append(
            f"| {name} | {cell('kem_keygen_wall')} | {cell('kem_encaps_wall')} | "
            f"{cell('kem_decaps_wall')} | {cell('sig_sign_wall')} | {cell('sig_verify_wall')} |"
        )
    lines.append("")
    (output / "summary.md").write_text("\n".join(lines))
    (output / "README.md").write_text(
        "\n".join(
            [
                "# Results",
                "",
                "These files were produced by the benchmark harness in this repository.",
                "Regenerate them with `python -m pqc_smartcity bench --output results` and",
                "`python -m pqc_smartcity charts --results results`.",
                "",
                "| File | Contents |",
                "| --- | --- |",
                "| `environment.json` | Host, library versions, iteration count, method note |",
                "| `timings.csv` | Median, mean, stdev, p95, min, max for each operation |",
                "| `samples.csv` | Per-iteration samples behind the summaries |",
                "| `sizes.csv` | Handshake and telemetry sizes by suite and profile |",
                "| `primitives.csv` | Measured object sizes, with the FIPS 203/204 lengths beside ML-KEM and ML-DSA |",
                "| `summary.md` | The tables quoted by the main README |",
                "| `charts/` | Matplotlib figures |",
                "",
                "Absolute milliseconds belong to this machine and to CPython. The comparison",
                "across suites is the result the harness is built to support.",
                "",
            ]
        )
    )


def _index_timings(path: Path) -> dict[tuple[str, str, str], dict]:
    indexed = {}
    for row in csv.DictReader(path.open()):
        indexed[(row["suite"], row["profile"], row["operation"])] = row
    return indexed


def _ms(text: str) -> str:
    return f"{float(text):.3f}"
