"""Suite catalogue.

This module is intentionally free of native libraries so charts and the CLI
help text can be imported without building liboqs.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SuiteInfo:
    suite_id: int
    name: str
    label: str
    family: str
    kem_algorithm: str
    sig_algorithm: str
    security: str
    static_only: bool
    blurb: str


# NIST PQC security categories are not bit strengths. ML-DSA has no category-1
# parameter set: ML-DSA-44 is category 2, so the smallest pair below is mixed.
SUITES: dict[str, SuiteInfo] = {
    "x25519-ed25519": SuiteInfo(
        suite_id=1,
        name="x25519-ed25519",
        label="X25519 + Ed25519",
        family="classical",
        kem_algorithm="X25519",
        sig_algorithm="Ed25519",
        security="Classical ~128-bit. Shor's algorithm breaks both.",
        static_only=False,
        blurb="Modern classical baseline. X25519 is modeled as a KEM: the ciphertext is an ephemeral public key.",
    ),
    "p256-ecdsa": SuiteInfo(
        suite_id=2,
        name="p256-ecdsa",
        label="P-256 ECDH + ECDSA",
        family="classical",
        kem_algorithm="ECDH-P-256",
        sig_algorithm="ECDSA-P-256-SHA256",
        security="Classical ~128-bit. Shor's algorithm breaks both.",
        static_only=False,
        blurb="The NIST-curve stack still common in OT gateways. ECDSA signatures are DER-encoded.",
    ),
    "rsa3072-pss": SuiteInfo(
        suite_id=3,
        name="rsa3072-pss",
        label="RSA-3072 OAEP + PSS",
        family="classical",
        kem_algorithm="RSA-3072-OAEP-SHA256",
        sig_algorithm="RSA-3072-PSS-SHA256",
        security="Classical ~128-bit (SP 800-57). Shor's algorithm breaks both.",
        static_only=True,
        blurb="Legacy meter-style key transport to a long-term RSA key. No ephemeral profile: RSA key generation is not an ECDHE analogue.",
    ),
    "mlkem512-mldsa44": SuiteInfo(
        suite_id=4,
        name="mlkem512-mldsa44",
        label="ML-KEM-512 + ML-DSA-44",
        family="post-quantum",
        kem_algorithm="ML-KEM-512",
        sig_algorithm="ML-DSA-44",
        security="ML-KEM-512 is NIST category 1; ML-DSA-44 is NIST category 2.",
        static_only=False,
        blurb="Smallest FIPS parameter pair. The categories do not match; it is included because constrained devices will be tempted by it.",
    ),
    "mlkem768-mldsa65": SuiteInfo(
        suite_id=5,
        name="mlkem768-mldsa65",
        label="ML-KEM-768 + ML-DSA-65",
        family="post-quantum",
        kem_algorithm="ML-KEM-768",
        sig_algorithm="ML-DSA-65",
        security="Both parameters are NIST category 3.",
        static_only=False,
        blurb="Recommended default in this lab. Matches the ML-KEM parameter used in the TLS hybrid group X25519MLKEM768.",
    ),
    "mlkem1024-mldsa87": SuiteInfo(
        suite_id=6,
        name="mlkem1024-mldsa87",
        label="ML-KEM-1024 + ML-DSA-87",
        family="post-quantum",
        kem_algorithm="ML-KEM-1024",
        sig_algorithm="ML-DSA-87",
        security="Both parameters are NIST category 5.",
        static_only=False,
        blurb="Highest standardized ML-KEM / ML-DSA pair. Largest signatures and encapsulation keys.",
    ),
    "hybrid-x25519-mlkem768": SuiteInfo(
        suite_id=7,
        name="hybrid-x25519-mlkem768",
        label="Hybrid X25519+ML-KEM-768",
        family="hybrid",
        kem_algorithm="X25519 || ML-KEM-768",
        sig_algorithm="Ed25519 || ML-DSA-65",
        security="Classical ~128-bit and NIST category 3, concatenated then HKDF'd.",
        static_only=False,
        blurb="Dual KEM and dual signature. Stricter than today's TLS hybrid, which hybrids the KEM and still uses classical certificates.",
    ),
}

SUITE_ORDER: tuple[str, ...] = tuple(SUITES)

SUITE_BY_ID: dict[int, SuiteInfo] = {info.suite_id: info for info in SUITES.values()}


def require_suite(name: str) -> SuiteInfo:
    try:
        return SUITES[name]
    except KeyError as exc:
        known = ", ".join(SUITE_ORDER)
        raise ValueError(f"unknown suite {name!r}; choose one of: {known}") from exc
