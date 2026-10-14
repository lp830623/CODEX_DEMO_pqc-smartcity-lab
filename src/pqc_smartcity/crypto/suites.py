"""Suite objects used by CityLink.

A suite is one KEM plus one signature, or a hybrid of two of each. Hybrid
shared secrets are concatenated ML-KEM first, then X25519, matching the order
in RFC 10024. The bytes are then passed through CityLink's own HKDF. Hybrid
public keys, ciphertexts, and signatures are length-prefixed pairs so the lab
parser does not depend on a particular liboqs secret-key encoding. That
framing is deliberately not the TLS key-share layout.
"""

from __future__ import annotations

from dataclasses import dataclass

from pqc_smartcity.catalog import SUITES, SuiteInfo, require_suite
from pqc_smartcity.crypto.classical import (
    EcdsaP256Signer,
    Ed25519Signer,
    P256Kem,
    RsaOaepKem,
    RsaPssSigner,
    X25519Kem,
)
from pqc_smartcity.crypto.pq import PqKem, PqSigner
from pqc_smartcity.codec import read_lp, write_lp
from pqc_smartcity.errors import CryptoError


@dataclass
class CompositeSuite:
    info: SuiteInfo
    kem: object
    signer: object

    @property
    def spec(self) -> SuiteInfo:
        return self.info

    def generate_sig_keypair(self) -> tuple[bytes, bytes]:
        return self.signer.generate()

    def generate_kem_keypair(self) -> tuple[bytes, bytes]:
        return self.kem.generate()

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        return self.signer.sign(secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return self.signer.verify(public_key, message, signature)

    def encaps(self, public_key: bytes) -> tuple[bytes, bytes]:
        return self.kem.encaps(public_key)

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return self.kem.decaps(secret_key, ciphertext)


class HybridSuite:
    """X25519 + ML-KEM-768 and Ed25519 + ML-DSA-65."""

    def __init__(self) -> None:
        self.info = SUITES["hybrid-x25519-mlkem768"]
        self._classical_kem = X25519Kem()
        self._pq_kem = PqKem("ML-KEM-768")
        self._classical_sig = Ed25519Signer()
        self._pq_sig = PqSigner("ML-DSA-65")

    @property
    def spec(self) -> SuiteInfo:
        return self.info

    def generate_kem_keypair(self) -> tuple[bytes, bytes]:
        c_sk, c_pk = self._classical_kem.generate()
        q_sk, q_pk = self._pq_kem.generate()
        # ML-KEM first, then X25519, as in RFC 10024's shared-secret order.
        return write_lp(q_sk) + write_lp(c_sk), write_lp(q_pk) + write_lp(c_pk)

    def generate_sig_keypair(self) -> tuple[bytes, bytes]:
        c_sk, c_pk = self._classical_sig.generate()
        q_sk, q_pk = self._pq_sig.generate()
        return write_lp(q_sk) + write_lp(c_sk), write_lp(q_pk) + write_lp(c_pk)

    def encaps(self, public_key: bytes) -> tuple[bytes, bytes]:
        q_pk, c_pk = _split_pair(public_key)
        q_ct, q_ss = self._pq_kem.encaps(q_pk)
        c_ct, c_ss = self._classical_kem.encaps(c_pk)
        if len(q_ss) != 32 or len(c_ss) != 32:
            raise CryptoError("hybrid shared secret is not 32 || 32")
        return write_lp(q_ct) + write_lp(c_ct), q_ss + c_ss

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        q_sk, c_sk = _split_pair(secret_key)
        q_ct, c_ct = _split_pair(ciphertext)
        q_ss = self._pq_kem.decaps(q_sk, q_ct)
        c_ss = self._classical_kem.decaps(c_sk, c_ct)
        if len(q_ss) != 32 or len(c_ss) != 32:
            raise CryptoError("hybrid shared secret is not 32 || 32")
        return q_ss + c_ss

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        q_sk, c_sk = _split_pair(secret_key)
        q_sig = self._pq_sig.sign(q_sk, message)
        c_sig = self._classical_sig.sign(c_sk, message)
        return write_lp(q_sig) + write_lp(c_sig)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            q_pk, c_pk = _split_pair(public_key)
            q_sig, c_sig = _split_pair(signature)
        except CryptoError:
            return False
        return self._pq_sig.verify(q_pk, message, q_sig) and self._classical_sig.verify(
            c_pk, message, c_sig
        )


def _split_pair(blob: bytes) -> tuple[bytes, bytes]:
    try:
        first, offset = read_lp(blob, 0)
        second, offset = read_lp(blob, offset)
    except ValueError as exc:
        raise CryptoError("malformed hybrid blob") from exc
    if offset != len(blob):
        raise CryptoError("malformed hybrid blob")
    return first, second


def get_suite(name: str) -> CompositeSuite | HybridSuite:
    """Return a fresh suite. Callers must not share one instance across threads."""

    info = require_suite(name)
    if info.name == "x25519-ed25519":
        return CompositeSuite(info, X25519Kem(), Ed25519Signer())
    if info.name == "p256-ecdsa":
        return CompositeSuite(info, P256Kem(), EcdsaP256Signer())
    if info.name == "rsa3072-pss":
        return CompositeSuite(info, RsaOaepKem(), RsaPssSigner())
    if info.name == "mlkem512-mldsa44":
        return CompositeSuite(info, PqKem("ML-KEM-512"), PqSigner("ML-DSA-44"))
    if info.name == "mlkem768-mldsa65":
        return CompositeSuite(info, PqKem("ML-KEM-768"), PqSigner("ML-DSA-65"))
    if info.name == "mlkem1024-mldsa87":
        return CompositeSuite(info, PqKem("ML-KEM-1024"), PqSigner("ML-DSA-87"))
    if info.name == "hybrid-x25519-mlkem768":
        return HybridSuite()
    raise CryptoError(f"suite {name} is not implemented")
