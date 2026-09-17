"""Ed25519 signing and verification of published artifact metadata.

Mirrors the shape of ``crypto.py``: pure functions, no I/O, no global state,
dependencies passed explicitly, and a single exception type. Ed25519 signing
is deterministic (RFC 8032), so signing the same payload twice with the same
key always yields the same signature bytes, unlike ECDSA schemes that depend
on a fresh per-signature nonce. Keys are exchanged as PEM (PKCS#8 for private
keys, SubjectPublicKeyInfo for public keys) rather than raw bytes, so that a
key of the wrong type is rejected as a parse error at load time instead of
being silently accepted.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class SignatureError(Exception):
    """Raised when key loading or signature verification fails."""


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 key pair and return it as ``(private_pem, public_pem)``.

    The private key is encoded as unencrypted PKCS#8 PEM and the public key
    as SubjectPublicKeyInfo PEM.
    """
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def load_private_key(pem: bytes) -> Ed25519PrivateKey:
    """Parse ``pem`` as a PKCS#8-encoded Ed25519 private key.

    Raises :class:`SignatureError` if ``pem`` is not a valid unencrypted PEM
    private key, or if it decodes to a key of a type other than Ed25519 (for
    example a mismatched public key or a key from a different algorithm).
    """
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError) as exc:
        raise SignatureError("could not parse PEM as a private key") from exc

    if not isinstance(key, Ed25519PrivateKey):
        raise SignatureError(f"expected an Ed25519 private key, got {type(key).__name__}")
    return key


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    """Parse ``pem`` as a SubjectPublicKeyInfo-encoded Ed25519 public key.

    Raises :class:`SignatureError` if ``pem`` is not a valid PEM public key,
    or if it decodes to a key of a type other than Ed25519 (for example a
    mismatched private key or a key from a different algorithm).
    """
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError) as exc:
        raise SignatureError("could not parse PEM as a public key") from exc

    if not isinstance(key, Ed25519PublicKey):
        raise SignatureError(f"expected an Ed25519 public key, got {type(key).__name__}")
    return key


def sign(payload: bytes, private_key: Ed25519PrivateKey) -> bytes:
    """Sign ``payload`` with ``private_key`` and return the raw 64-byte Ed25519 signature."""
    return private_key.sign(payload)


def verify(payload: bytes, signature: bytes, public_key: Ed25519PublicKey) -> None:
    """Verify that ``signature`` is a valid Ed25519 signature of ``payload`` by ``public_key``.

    Raises :class:`SignatureError` on any verification failure — a wrong
    key, a tampered payload, or a malformed, truncated, or oversized
    signature — rather than returning a boolean that could be ignored.
    """
    try:
        public_key.verify(signature, payload)
    except InvalidSignature as exc:
        raise SignatureError("signature verification failed") from exc


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    """Compute the hex SHA-256 fingerprint of the raw 32-byte encoding of ``public_key``.

    Hashing the raw encoding, rather than its DER or PEM form, keeps the
    fingerprint stable regardless of how the key happens to be serialized.
    """
    return hashlib.sha256(public_key.public_bytes_raw()).hexdigest()
