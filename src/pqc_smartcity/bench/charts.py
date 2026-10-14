"""Publication-style figures for the committed benchmark tables.

Matplotlib only, Agg backend, Okabe-Ito colors. Re-running this module on the
same CSVs is how the README figures are produced.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from pqc_smartcity.catalog import SUITES, SUITE_ORDER

_EPHEMERAL = "#0072B2"
_STATIC = "#E69F00"
_PUBLIC = "#0072B2"
_CIPHERTEXT = "#E69F00"
_SIGNATURE = "#D55E00"
_PLAIN = "#7F7F7F"
_AEAD = "#0072B2"
_SIGNED = "#D55E00"
_OPS = {
    "kem_keygen_wall": ("#009E73", "KEM keygen"),
    "kem_encaps_wall": ("#0072B2", "Encapsulate"),
    "kem_decaps_wall": ("#56B4E9", "Decapsulate"),
    "sig_sign_wall": ("#D55E00", "Sign"),
    "sig_verify_wall": ("#CC79A7", "Verify"),
}


def render_charts(results: Path) -> list[Path]:
    results = Path(results)
    sizes = list(csv.DictReader((results / "sizes.csv").open()))
    timings = list(csv.DictReader((results / "timings.csv").open()))
    samples = list(csv.DictReader((results / "samples.csv").open()))
    env_path = results / "environment.json"
    subtitle = ""
    if env_path.exists():
        env = json.loads(env_path.read_text())
        subtitle = (
            f"{env.get('cpu_model', 'unknown CPU')}, Python {env.get('python', '')}, "
            f"liboqs {env.get('liboqs', 'n/a')}, n={env.get('iterations', '?')}"
        )
    out = results / "charts"
    out.mkdir(parents=True, exist_ok=True)
    _style()
    written = [
        _handshake(out, sizes, timings, samples, subtitle),
        _artifacts(out, sizes, subtitle),
        _telemetry(out, sizes, subtitle),
        _operations(out, timings, subtitle),
    ]
    return written


def _style() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 11,
            "axes.titlesize": 13,
            "axes.labelsize": 11,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "axes.grid.axis": "x",
            "grid.alpha": 0.35,
            "legend.frameon": False,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.bbox": "tight",
            "savefig.facecolor": "white",
        }
    )


def _handshake(out: Path, sizes, timings, samples, subtitle: str) -> Path:
    names = [name for name in _present(sizes) if name != "rsa3072-pss"]
    labels = [_label(name) for name in names]
    y = list(range(len(names)))
    rsa = _lookup(timings, "rsa3072-pss", "static", "handshake_wall", "median")
    if rsa is not None:
        subtitle = (
            f"{subtitle}. RSA-3072 static median {rsa:.1f} ms "
            "(~1000× ML-KEM-768 ephemeral) is off this axis"
        )
    fig, axes = plt.subplots(
        1, 2, figsize=(11.4, 5.6), gridspec_kw={"width_ratios": [1.2, 1]}
    )
    ephemeral = [_lookup(timings, name, "ephemeral", "handshake_wall", "median") for name in names]
    static = [_lookup(timings, name, "static", "handshake_wall", "median") for name in names]
    _grouped(axes[0], y, labels, ephemeral, static, "Milliseconds, median")
    axes[0].set_title("Handshake wall time")
    axes[0].invert_yaxis()
    box_data = []
    box_labels = []
    for name in names:
        values = [
            float(row["milliseconds"])
            for row in samples
            if row["suite"] == name and row["operation"] == "handshake_wall" and row["profile"] == "ephemeral"
        ]
        if values:
            box_data.append(values)
            box_labels.append(_label(name))
    axes[1].boxplot(
        box_data,
        orientation="horizontal",
        patch_artist=True,
        medianprops={"color": "black"},
        boxprops={"facecolor": "#D6E4F0", "edgecolor": "#333333"},
        whiskerprops={"color": "#333333"},
        capprops={"color": "#333333"},
        flierprops={"marker": "o", "markersize": 3, "markerfacecolor": "#333333"},
    )
    axes[1].set_yticklabels(box_labels)
    axes[1].invert_yaxis()
    axes[1].set_xlabel("Milliseconds")
    axes[1].set_title("Ephemeral handshake samples")
    _finish(fig, axes[0], "In-process CityLink handshake", subtitle)
    path = out / "handshake_latency.png"
    fig.savefig(path, dpi=160)
    fig.savefig(out / "handshake_latency.svg")
    plt.close(fig)
    return path


def _artifacts(out: Path, sizes, subtitle: str) -> Path:
    # Object sizes do not depend on the profile. Prefer the ephemeral row.
    chosen = {}
    for row in sizes:
        chosen.setdefault(row["suite"], row)
        if row["profile"] == "ephemeral":
            chosen[row["suite"]] = row
    names = [name for name in SUITE_ORDER if name in chosen]
    labels = [_label(name) for name in names]
    y = list(range(len(names)))
    fig, ax = plt.subplots(figsize=(10.2, 5.2))
    height = 0.24
    series = (
        ("kem_public_bytes", _PUBLIC, "Encapsulation key"),
        ("kem_ciphertext_bytes", _CIPHERTEXT, "Ciphertext or DH share"),
        ("signature_bytes_max", _SIGNATURE, "Signature"),
    )
    for offset, (column, color, legend) in zip((-height, 0, height), series):
        values = [int(chosen[name][column]) for name in names]
        positions = [index + offset for index in y]
        ax.barh(positions, values, height=height, color=color, label=legend)
        if column == "signature_bytes_max":
            for position, value in zip(positions, values):
                ax.text(value, position, f" {value}", va="center", fontsize=8, color="#333333")
            ax.set_xlim(0, max(values) * 1.16)
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.set_xlabel("Bytes")
    _legend(ax, ncol=3)
    _finish(fig, ax, "Object sizes carried by a suite", subtitle)
    path = out / "artifact_sizes.png"
    fig.savefig(path, dpi=160)
    fig.savefig(out / "artifact_sizes.svg")
    plt.close(fig)
    return path


def _telemetry(out: Path, sizes, subtitle: str) -> Path:
    chosen = {}
    for row in sizes:
        chosen.setdefault(row["suite"], row)
        if row["profile"] == "ephemeral":
            chosen[row["suite"]] = row
    names = [name for name in SUITE_ORDER if name in chosen]
    labels = [_label(name) for name in names]
    y = list(range(len(names)))
    fig, ax = plt.subplots(figsize=(10.2, 5.2))
    height = 0.24
    series = (
        ("plaintext_bytes", _PLAIN, "Canonical JSON"),
        ("telemetry_aead_bytes", _AEAD, "AEAD frame"),
        ("telemetry_signed_bytes", _SIGNED, "AEAD + signature"),
    )
    for offset, (column, color, legend) in zip((-height, 0, height), series):
        values = [int(chosen[name][column]) for name in names]
        positions = [index + offset for index in y]
        ax.barh(positions, values, height=height, color=color, label=legend)
        if column == "telemetry_signed_bytes":
            for position, value in zip(positions, values):
                ax.text(value, position, f" {value}", va="center", fontsize=8, color="#333333")
            ax.set_xlim(0, max(values) * 1.16)
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.set_xlabel("Bytes on the sensor-to-gateway message")
    _legend(ax, ncol=3)
    _finish(fig, ax, "One air-quality reading on the wire", subtitle)
    path = out / "telemetry_overhead.png"
    fig.savefig(path, dpi=160)
    fig.savefig(out / "telemetry_overhead.svg")
    plt.close(fig)
    return path


def _operations(out: Path, timings, subtitle: str) -> Path:
    names = [name for name in SUITE_ORDER if _lookup(timings, name, "primitive", "sig_sign_wall", "median") is not None]
    labels = [_label(name) for name in names]
    y = list(range(len(names)))
    fig, ax = plt.subplots(figsize=(10.4, 5.6))
    keys = list(_OPS)
    span = 0.16
    start = -((len(keys) - 1) / 2) * span
    for index, key in enumerate(keys):
        color, legend = _OPS[key]
        values = [_lookup(timings, name, "primitive", key, "median") or float("nan") for name in names]
        positions = [item + start + index * span for item in y]
        ax.scatter(values, positions, s=32, color=color, label=legend, zorder=3)
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.set_xscale("log")
    ax.set_xlabel("Milliseconds, median, logarithmic scale")
    ax.grid(True, axis="x", which="both", alpha=0.3)
    _legend(ax, ncol=3)
    _finish(fig, ax, "Primitive wall time", subtitle + " — DH encaps includes an ephemeral keygen")
    path = out / "primitive_latency.png"
    fig.savefig(path, dpi=160)
    fig.savefig(out / "primitive_latency.svg")
    plt.close(fig)
    return path


def _grouped(ax, y, labels, ephemeral, static, xlabel: str) -> None:
    height = 0.36
    e_pos, e_val, s_pos, s_val = [], [], [], []
    for index, (left, right) in enumerate(zip(ephemeral, static)):
        if left is not None:
            e_pos.append(index + height / 2)
            e_val.append(left)
        if right is not None:
            s_pos.append(index - height / 2)
            s_val.append(right)
    ax.barh(e_pos, e_val, height=height, color=_EPHEMERAL, label="Ephemeral KEM (forward secret)")
    ax.barh(s_pos, s_val, height=height, color=_STATIC, label="Static gateway key (no forward secrecy)")
    ax.set_yticks(y, labels)
    ax.set_xlabel(xlabel)
    _legend(ax, ncol=2)
    for position, value in list(zip(e_pos, e_val)) + list(zip(s_pos, s_val)):
        ax.text(value, position, f" {_fmt(value)}", va="center", ha="left", fontsize=8, color="#333333")
    finite = [value for value in e_val + s_val if value is not None]
    if finite:
        ax.set_xlim(0, max(finite) * 1.22)


def _legend(ax, ncol: int) -> None:
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.16), ncol=ncol)


def _finish(fig, ax, title: str, subtitle: str) -> None:
    ax.set_title(title, loc="left")
    if subtitle:
        fig.text(0.01, 0.01, subtitle, fontsize=8, color="#555555")
    fig.tight_layout(rect=(0, 0.08, 1, 1))


def _present(sizes) -> list[str]:
    found = {row["suite"] for row in sizes}
    return [name for name in SUITE_ORDER if name in found]


def _label(name: str) -> str:
    return SUITES[name].label


def _lookup(rows, suite: str, profile: str, operation: str, field: str):
    for row in rows:
        if row["suite"] == suite and row["profile"] == profile and row["operation"] == operation:
            return float(row[field])
    return None


def _fmt(value: float) -> str:
    if value >= 10:
        return f"{value:.1f}"
    if value >= 1:
        return f"{value:.2f}"
    return f"{value:.3f}"
