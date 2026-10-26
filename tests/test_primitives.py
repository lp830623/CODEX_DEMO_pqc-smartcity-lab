"""Primitive round trips and the FIPS 203/204 size catalogue."""

from __future__ import annotations

import pytest

from pqc_smartcity.crypto.classical import Ed25519Signer, X25519Kem
from pqc_smartcity.crypto.fips import ML_DSA, ML_KEM
from pqc_smartcity.crypto.pq import PqKem, PqSigner
from pqc_smartcity.crypto.suites import get_suite
from pqc_smartcity.errors import PolicyError


def test_x25519_and_ed25519_roundtrip() -> None:
    kem = X25519Kem()
    secret, public = kem.generate()
    ciphertext, left = kem.encaps(public)
    right = kem.decaps(secret, ciphertext)
    assert left == right
    assert len(public) == 32 and len(ciphertext) == 32 and len(left) == 32
    signer = Ed25519Signer()
    sk, pk = signer.generate()
    message = b"meter"
    signature = signer.sign(sk, message)
    assert signer.verify(pk, message, signature)
    assert not signer.verify(pk, b"other", signature)


@pytest.mark.parametrize("algorithm", list(ML_KEM))
def test_mlkem_matches_fips_203(algorithm: str) -> None:
    kem = PqKem(algorithm)
    secret, public = kem.generate()
    ciphertext, left = kem.encaps(public)
    right = kem.decaps(secret, ciphertext)
    assert left == right
    standard = ML_KEM[algorithm]
    assert len(public) == standard["encapsulation_key"]
    assert len(secret) == standard["decapsulation_key"]
    assert len(ciphertext) == standard["ciphertext"]
    assert len(left) == standard["shared_secret"]


@pytest.mark.parametrize("algorithm", list(ML_DSA))
def test_mldsa_matches_fips_204(algorithm: str) -> None:
    signer = PqSigner(algorithm)
    secret, public = signer.generate()
    message = b"citylink-v1"
    signature = signer.sign(secret, message)
    assert signer.verify(public, message, signature)
    assert not signer.verify(public, message + b"!", signature)
    standard = ML_DSA[algorithm]
    assert len(public) == standard["public_key"]
    assert len(secret) == standard["secret_key"]
    assert len(signature) == standard["signature"]


def test_context_separates_ml_dsa_signatures() -> None:
    import oqs

    assert oqs.sig_supports_context("ML-DSA-65")
    signer = PqSigner("ML-DSA-65")
    secret, public = signer.generate()
    message = b"same-bytes"
    signature = signer.sign(secret, message)
    with oqs.Signature("ML-DSA-65") as bare:
        assert not bare.verify(message, signature, public)


def test_every_suite_agrees_on_a_shared_secret() -> None:
    from pqc_smartcity.catalog import SUITES

    for name, info in SUITES.items():
        suite = get_suite(name)
        secret, public = suite.generate_kem_keypair()
        ciphertext, left = suite.encaps(public)
        right = suite.decaps(secret, ciphertext)
        assert left == right
        sig_secret, sig_public = suite.generate_sig_keypair()
        signature = suite.sign(sig_secret, b"probe")
        assert suite.verify(sig_public, b"probe", signature)
        assert not suite.verify(sig_public, b"probe", signature[:-1] + bytes([signature[-1] ^ 0x01]))
        if info.family == "hybrid":
            assert len(left) == 64
        else:
            assert len(left) == 32


def test_rsa_ephemeral_profile_is_rejected() -> None:
    from pqc_smartcity.identity import issue_fleet

    with pytest.raises(PolicyError):
        issue_fleet("rsa3072-pss", "ephemeral")
