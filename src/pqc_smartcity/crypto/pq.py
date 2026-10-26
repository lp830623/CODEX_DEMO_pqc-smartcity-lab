"""liboqs adapters for ML-KEM (FIPS 203) and ML-DSA (FIPS 204).

Handles are cached per secret key so a long-lived gateway does not reconstruct
an OQS object on every packet. A fresh ephemeral key still pays for one object
construction, because that key did not exist before the handshake.
"""

from __future__ import annotations

import oqs

from pqc_smartcity.crypto.fips import CONTEXT
from pqc_smartcity.errors import CryptoError


class PqKem:
    def __init__(self, algorithm: str) -> None:
        if not oqs.is_kem_enabled(algorithm):
            raise CryptoError(f"{algorithm} is not enabled in this liboqs build")
        self.name = algorithm
        self._encap = oqs.KeyEncapsulation(algorithm)
        self._keygen = oqs.KeyEncapsulation(algorithm)
        self._decap: oqs.KeyEncapsulation | None = None
        self._decap_sk: bytes | None = None

    def generate(self) -> tuple[bytes, bytes]:
        public = self._keygen.generate_keypair()
        secret = self._keygen.export_secret_key()
        return bytes(secret), bytes(public)

    def encaps(self, peer_public: bytes) -> tuple[bytes, bytes]:
        try:
            ciphertext, shared = self._encap.encap_secret(peer_public)
        except Exception as exc:
            raise CryptoError(f"{self.name} encapsulation failed") from exc
        return bytes(ciphertext), bytes(shared)

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        handle = self._decap_handle(secret_key)
        try:
            shared = handle.decap_secret(ciphertext)
        except Exception as exc:
            raise CryptoError(f"{self.name} decapsulation failed") from exc
        return bytes(shared)

    def _decap_handle(self, secret_key: bytes) -> oqs.KeyEncapsulation:
        if self._decap is not None and self._decap_sk == secret_key:
            return self._decap
        if self._decap is not None:
            self._decap.free()
        try:
            self._decap = oqs.KeyEncapsulation(self.name, secret_key=secret_key)
        except Exception as exc:
            self._decap = None
            self._decap_sk = None
            raise CryptoError(f"{self.name} secret key rejected") from exc
        self._decap_sk = secret_key
        return self._decap


class PqSigner:
    def __init__(self, algorithm: str) -> None:
        if not oqs.is_sig_enabled(algorithm):
            raise CryptoError(f"{algorithm} is not enabled in this liboqs build")
        self.name = algorithm
        self._use_context = bool(oqs.sig_supports_context(algorithm))
        self._verifier = oqs.Signature(algorithm)
        self._keygen = oqs.Signature(algorithm)
        self._signer: oqs.Signature | None = None
        self._signer_sk: bytes | None = None

    def generate(self) -> tuple[bytes, bytes]:
        public = self._keygen.generate_keypair()
        secret = self._keygen.export_secret_key()
        return bytes(secret), bytes(public)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        signer = self._signer_handle(secret_key)
        try:
            if self._use_context:
                signature = signer.sign_with_ctx_str(message, CONTEXT)
            else:
                signature = signer.sign(message)
        except Exception as exc:
            raise CryptoError(f"{self.name} signing failed") from exc
        return bytes(signature)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        try:
            if self._use_context:
                return bool(
                    self._verifier.verify_with_ctx_str(message, signature, CONTEXT, public_key)
                )
            return bool(self._verifier.verify(message, signature, public_key))
        except Exception:
            return False

    def _signer_handle(self, secret_key: bytes) -> oqs.Signature:
        if self._signer is not None and self._signer_sk == secret_key:
            return self._signer
        if self._signer is not None:
            self._signer.free()
        try:
            self._signer = oqs.Signature(self.name, secret_key=secret_key)
        except Exception as exc:
            self._signer = None
            self._signer_sk = None
            raise CryptoError(f"{self.name} secret key rejected") from exc
        self._signer_sk = secret_key
        return self._signer
