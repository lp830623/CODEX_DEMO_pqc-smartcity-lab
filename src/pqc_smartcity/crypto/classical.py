"""Classical KEMs and signatures used as the pre-quantum baseline.

X25519 and P-256 are modeled as KEMs in the style of HPKE's DHKEM (RFC 9180):
the ciphertext is an ephemeral public key, and the peer's public key is the
encapsulation key. CityLink then runs its own HKDF. This is not HPKE, and it
is not TLS.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from pqc_smartcity.errors import CryptoError

RSA_BITS = 3072
RSA_BYTES = RSA_BITS // 8
RSA_E = 65537
_OAEP_LABEL = b"citylink-v1"


def _raw_public_x(key: x25519.X25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _raw_private_x(key: x25519.X25519PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


class X25519Kem:
    name = "X25519"
    public_bytes = 32
    secret_bytes = 32
    ciphertext_bytes = 32
    shared_secret_bytes = 32

    def generate(self) -> tuple[bytes, bytes]:
        secret = x25519.X25519PrivateKey.generate()
        return _raw_private_x(secret), _raw_public_x(secret.public_key())

    def encaps(self, peer_public: bytes) -> tuple[bytes, bytes]:
        try:
            peer = x25519.X25519PublicKey.from_public_bytes(peer_public)
        except Exception as exc:
            raise CryptoError("malformed X25519 encapsulation key") from exc
        ephemeral = x25519.X25519PrivateKey.generate()
        ciphertext = _raw_public_x(ephemeral.public_key())
        shared = ephemeral.exchange(peer)
        return ciphertext, shared

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        try:
            mine = x25519.X25519PrivateKey.from_private_bytes(secret_key)
            peer = x25519.X25519PublicKey.from_public_bytes(ciphertext)
        except Exception as exc:
            raise CryptoError("malformed X25519 decapsulation input") from exc
        return mine.exchange(peer)


class P256Kem:
    name = "ECDH-P-256"
    public_bytes = 65
    secret_bytes = 32
    ciphertext_bytes = 65
    shared_secret_bytes = 32

    def generate(self) -> tuple[bytes, bytes]:
        secret = ec.generate_private_key(ec.SECP256R1())
        scalar = secret.private_numbers().private_value.to_bytes(32, "big")
        public = secret.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        return scalar, public

    def encaps(self, peer_public: bytes) -> tuple[bytes, bytes]:
        peer = _load_p256_public(peer_public)
        ephemeral = ec.generate_private_key(ec.SECP256R1())
        ciphertext = ephemeral.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        shared = ephemeral.exchange(ec.ECDH(), peer)
        if len(shared) != 32:
            raise CryptoError("unexpected P-256 shared-secret length")
        return ciphertext, shared

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        if len(secret_key) != 32:
            raise CryptoError("malformed P-256 secret scalar")
        mine = ec.derive_private_key(int.from_bytes(secret_key, "big"), ec.SECP256R1())
        peer = _load_p256_public(ciphertext)
        shared = mine.exchange(ec.ECDH(), peer)
        if len(shared) != 32:
            raise CryptoError("unexpected P-256 shared-secret length")
        return shared


class RsaOaepKem:
    """RSA-3072 OAEP as a KEM: encapsulate 32 random bytes to a long-term key."""

    name = "RSA-3072-OAEP-SHA256"
    public_bytes = RSA_BYTES
    ciphertext_bytes = RSA_BYTES
    shared_secret_bytes = 32

    def generate(self) -> tuple[bytes, bytes]:
        private = rsa.generate_private_key(public_exponent=RSA_E, key_size=RSA_BITS)
        secret = private.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        modulus = private.public_key().public_numbers().n.to_bytes(RSA_BYTES, "big")
        return secret, modulus

    def encaps(self, peer_public: bytes) -> tuple[bytes, bytes]:
        public = _load_rsa_public(peer_public)
        shared = os.urandom(32)
        ciphertext = public.encrypt(shared, _oaep())
        return ciphertext, shared

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        try:
            private = serialization.load_der_private_key(secret_key, password=None)
            shared = private.decrypt(ciphertext, _oaep())
        except Exception as exc:
            raise CryptoError("RSA decapsulation failed") from exc
        if not isinstance(shared, bytes) or len(shared) != 32:
            raise CryptoError("RSA decapsulation failed")
        return shared


class Ed25519Signer:
    name = "Ed25519"
    public_bytes = 32
    secret_bytes = 32
    signature_bytes = 64

    def generate(self) -> tuple[bytes, bytes]:
        secret = ed25519.Ed25519PrivateKey.generate()
        sk = secret.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        pk = secret.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return sk, pk

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        try:
            return ed25519.Ed25519PrivateKey.from_private_bytes(secret_key).sign(message)
        except Exception as exc:
            raise CryptoError("Ed25519 signing failed") from exc

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        except Exception:
            return False


class EcdsaP256Signer:
    name = "ECDSA-P-256-SHA256"
    public_bytes = 65
    secret_bytes = 32

    def generate(self) -> tuple[bytes, bytes]:
        secret = ec.generate_private_key(ec.SECP256R1())
        scalar = secret.private_numbers().private_value.to_bytes(32, "big")
        public = secret.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        return scalar, public

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        if len(secret_key) != 32:
            raise CryptoError("malformed P-256 signing key")
        key = ec.derive_private_key(int.from_bytes(secret_key, "big"), ec.SECP256R1())
        return key.sign(message, ec.ECDSA(hashes.SHA256()))

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            _load_p256_public(public_key).verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


class RsaPssSigner:
    name = "RSA-3072-PSS-SHA256"
    public_bytes = RSA_BYTES
    signature_bytes = RSA_BYTES

    def generate(self) -> tuple[bytes, bytes]:
        private = rsa.generate_private_key(public_exponent=RSA_E, key_size=RSA_BITS)
        secret = private.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        modulus = private.public_key().public_numbers().n.to_bytes(RSA_BYTES, "big")
        return secret, modulus

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        try:
            private = serialization.load_der_private_key(secret_key, password=None)
            return private.sign(message, _pss(), hashes.SHA256())
        except Exception as exc:
            raise CryptoError("RSA-PSS signing failed") from exc

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            _load_rsa_public(public_key).verify(signature, message, _pss(), hashes.SHA256())
            return True
        except Exception:
            return False


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=_OAEP_LABEL,
    )


def _pss() -> padding.PSS:
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def _load_p256_public(raw: bytes) -> EllipticCurvePublicKey:
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except Exception as exc:
        raise CryptoError("malformed P-256 point") from exc


def _load_rsa_public(modulus: bytes) -> rsa.RSAPublicKey:
    if len(modulus) != RSA_BYTES:
        raise CryptoError("malformed RSA-3072 modulus")
    try:
        return rsa.RSAPublicNumbers(RSA_E, int.from_bytes(modulus, "big")).public_key()
    except Exception as exc:
        raise CryptoError("malformed RSA-3072 modulus") from exc
