"""Tests for Ed25519 signing and verification.

These tests exist to demonstrate the security properties claimed for the
signing module: authenticated round-trips, deterministic signatures,
rejection of a wrong public key, detection of payload and signature
tampering, rejection of cross-payload replay, and rejection of key
confusion between symmetric and asymmetric, or private and public, key
material.
"""

import base64
from collections.abc import Callable

import pytest
import tests.constants as test_const
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from model_pipeline import signing


def test_round_trip_sign_and_verify() -> None:
    """Signing a payload and verifying it with the matching public key must succeed."""
    private_key = signing.load_private_key(test_const.TEST_SIGNING_PRIVATE_KEY_PEM)
    public_key = signing.load_public_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)

    signature = signing.sign(b"a model artifact manifest", private_key)

    assert signing.verify(b"a model artifact manifest", signature, public_key) is None


def test_sign_is_deterministic_and_matches_known_answer() -> None:
    """Ed25519 signing must be deterministic: same key and payload, identical bytes every time."""
    private_key = signing.load_private_key(test_const.TEST_SIGNING_PRIVATE_KEY_PEM)

    first = signing.sign(test_const.KNOWN_ANSWER_PAYLOAD, private_key)
    second = signing.sign(test_const.KNOWN_ANSWER_PAYLOAD, private_key)

    assert first == second == test_const.KNOWN_ANSWER_SIGNATURE


def test_verify_with_wrong_public_key_fails() -> None:
    """A signature produced with one key must not verify against an unrelated public key."""
    private_key = signing.load_private_key(test_const.TEST_SIGNING_PRIVATE_KEY_PEM)
    wrong_public_key = signing.load_public_key(test_const.OTHER_SIGNING_PUBLIC_KEY_PEM)

    signature = signing.sign(b"payload", private_key)

    with pytest.raises(signing.SignatureError, match="^signature verification failed$"):
        signing.verify(b"payload", signature, wrong_public_key)


def test_verify_tampered_payload_fails() -> None:
    """Flipping a single bit anywhere in the payload must invalidate the signature."""
    private_key = signing.load_private_key(test_const.TEST_SIGNING_PRIVATE_KEY_PEM)
    public_key = signing.load_public_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)

    payload = bytearray(b"a model artifact manifest")
    signature = signing.sign(bytes(payload), private_key)
    payload[0] ^= 0x01

    with pytest.raises(signing.SignatureError, match="^signature verification failed$"):
        signing.verify(bytes(payload), signature, public_key)


def _flip_last_bit(signature: bytes) -> bytes:
    """Return ``signature`` with the last bit of its final byte flipped."""
    tampered = bytearray(signature)
    tampered[-1] ^= 0x01
    return bytes(tampered)


@pytest.mark.parametrize(
    "make_signature",
    [
        pytest.param(_flip_last_bit, id="flipped-bit"),
        pytest.param(lambda sig: sig[:-1], id="truncated"),
        pytest.param(lambda sig: b"", id="empty"),
        pytest.param(lambda sig: sig + b"\x00", id="oversized"),
        pytest.param(lambda sig: b"\x99" * 64, id="random-64-bytes"),
    ],
)
def test_verify_rejects_malformed_or_tampered_signatures(
    make_signature: Callable[[bytes], bytes],
) -> None:
    """Any malformed or tampered signature must raise SignatureError, never crash or pass."""
    private_key = signing.load_private_key(test_const.TEST_SIGNING_PRIVATE_KEY_PEM)
    public_key = signing.load_public_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)
    payload = b"a model artifact manifest"

    signature = signing.sign(payload, private_key)
    tampered_signature = make_signature(signature)

    with pytest.raises(signing.SignatureError, match="^signature verification failed$"):
        signing.verify(payload, tampered_signature, public_key)


def test_cross_payload_replay_fails() -> None:
    """A signature over one payload (e.g. one manifest version) must not verify another."""
    private_key = signing.load_private_key(test_const.TEST_SIGNING_PRIVATE_KEY_PEM)
    public_key = signing.load_public_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)

    signature_for_version_a = signing.sign(b'{"artifact.version": "1.0.0"}', private_key)

    with pytest.raises(signing.SignatureError, match="^signature verification failed$"):
        signing.verify(b'{"artifact.version": "1.1.0"}', signature_for_version_a, public_key)


def test_load_private_key_rejects_base64_aes_master_key() -> None:
    """The base64-encoded AES master key must be rejected as a private signing key."""
    confused_value = base64.b64encode(test_const.TEST_MASTER_KEY)

    with pytest.raises(signing.SignatureError, match="^could not parse PEM as a private key$"):
        signing.load_private_key(confused_value)


def test_load_public_key_rejects_base64_aes_master_key() -> None:
    """The base64-encoded AES master key must be rejected as a public verification key."""
    confused_value = base64.b64encode(test_const.TEST_MASTER_KEY)

    with pytest.raises(signing.SignatureError, match="^could not parse PEM as a public key$"):
        signing.load_public_key(confused_value)


def test_load_private_key_rejects_a_public_key_pem() -> None:
    """A public key PEM offered where a private key is expected must be rejected."""
    with pytest.raises(signing.SignatureError, match="^could not parse PEM as a private key$"):
        signing.load_private_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)


def test_load_public_key_rejects_a_private_key_pem() -> None:
    """A private key PEM offered where a public key is expected must be rejected."""
    with pytest.raises(signing.SignatureError, match="^could not parse PEM as a public key$"):
        signing.load_public_key(test_const.TEST_SIGNING_PRIVATE_KEY_PEM)


def test_load_private_key_rejects_a_non_ed25519_private_key() -> None:
    """A syntactically valid private key PEM of a different algorithm (EC) must be rejected."""
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with pytest.raises(
        signing.SignatureError,
        match=r"^expected an Ed25519 private key, got ECPrivateKey$",
    ):
        signing.load_private_key(ec_pem)


def test_load_public_key_rejects_a_non_ed25519_public_key() -> None:
    """A syntactically valid public key PEM of a different algorithm (EC) must be rejected."""
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = ec_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with pytest.raises(
        signing.SignatureError,
        match=r"^expected an Ed25519 public key, got ECPublicKey$",
    ):
        signing.load_public_key(ec_pem)


def test_load_private_key_rejects_malformed_pem() -> None:
    """Garbage bytes that are not PEM at all must be rejected, not crash."""
    with pytest.raises(signing.SignatureError, match="^could not parse PEM as a private key$"):
        signing.load_private_key(b"not a pem file")


def test_load_public_key_rejects_malformed_pem() -> None:
    """Garbage bytes that are not PEM at all must be rejected, not crash."""
    with pytest.raises(signing.SignatureError, match="^could not parse PEM as a public key$"):
        signing.load_public_key(b"not a pem file")


def test_generate_keypair_produces_a_usable_ed25519_pair() -> None:
    """A freshly generated key pair must round-trip through sign/verify."""
    private_pem, public_pem = signing.generate_keypair()

    private_key = signing.load_private_key(private_pem)
    public_key = signing.load_public_key(public_pem)
    signature = signing.sign(b"payload", private_key)

    assert signing.verify(b"payload", signature, public_key) is None


def test_generate_keypair_yields_distinct_pairs_each_call() -> None:
    """Successive calls to generate_keypair must not reuse the same key material."""
    first_private_pem, _ = signing.generate_keypair()
    second_private_pem, _ = signing.generate_keypair()

    assert first_private_pem != second_private_pem


def test_fingerprint_is_stable_across_pem_round_trips() -> None:
    """The fingerprint of a public key must not depend on how it was loaded or re-encoded."""
    public_key = signing.load_public_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)

    reloaded_public_key = signing.load_public_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)

    assert signing.public_key_fingerprint(public_key) == signing.public_key_fingerprint(
        reloaded_public_key
    )


def test_fingerprint_differs_between_distinct_keys() -> None:
    """Distinct public keys must have distinct fingerprints."""
    public_key = signing.load_public_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)
    other_public_key = signing.load_public_key(test_const.OTHER_SIGNING_PUBLIC_KEY_PEM)

    assert signing.public_key_fingerprint(public_key) != signing.public_key_fingerprint(
        other_public_key
    )


def test_fingerprint_matches_the_private_keys_own_public_half() -> None:
    """The fingerprint computed from a loaded public key must match the key pair's own half."""
    private_key = signing.load_private_key(test_const.TEST_SIGNING_PRIVATE_KEY_PEM)
    public_key = signing.load_public_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)

    assert signing.public_key_fingerprint(
        private_key.public_key()
    ) == signing.public_key_fingerprint(public_key)
