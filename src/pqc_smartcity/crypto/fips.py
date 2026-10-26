"""FIPS 203 / FIPS 204 parameter sizes.

Secret-key lengths are the standardized decapsulation and signing keys.
liboqs is expected to match them; tests check the public objects either way,
because those are what appears on the wire.
"""

from __future__ import annotations

# FIPS 203, Table 3.
ML_KEM: dict[str, dict[str, int]] = {
    "ML-KEM-512": {
        "encapsulation_key": 800,
        "decapsulation_key": 1632,
        "ciphertext": 768,
        "shared_secret": 32,
    },
    "ML-KEM-768": {
        "encapsulation_key": 1184,
        "decapsulation_key": 2400,
        "ciphertext": 1088,
        "shared_secret": 32,
    },
    "ML-KEM-1024": {
        "encapsulation_key": 1568,
        "decapsulation_key": 3168,
        "ciphertext": 1568,
        "shared_secret": 32,
    },
}

# FIPS 204, Table 2 (public key, secret key, signature).
ML_DSA: dict[str, dict[str, int]] = {
    "ML-DSA-44": {"public_key": 1312, "secret_key": 2560, "signature": 2420},
    "ML-DSA-65": {"public_key": 1952, "secret_key": 4032, "signature": 3309},
    "ML-DSA-87": {"public_key": 2592, "secret_key": 4896, "signature": 4627},
}

CONTEXT = b"citylink-v1"
