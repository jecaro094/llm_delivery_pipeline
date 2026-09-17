"""Tests for loading and validating key material from a file or a raw value.

Covers both the AES-256 master key and the Ed25519 signing key pair.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
import tests.constants as test_const

from model_pipeline import keys, signing


def _b64(key_bytes: bytes) -> str:
    """Base64-encode raw key bytes the same way `keygen` would."""
    return base64.b64encode(key_bytes).decode("ascii")


def test_load_key_from_file(tmp_path: Path) -> None:
    """A key file containing the base64-encoded key must decode to the original bytes."""
    key_file = tmp_path / "encryption-key"
    key_file.write_text(_b64(test_const.TEST_MASTER_KEY), encoding="utf-8")

    assert keys.load_key_from_file(key_file) == test_const.TEST_MASTER_KEY


def test_load_key_from_file_tolerates_trailing_newline(tmp_path: Path) -> None:
    """A trailing newline, as added by `kubectl create secret --from-file`, must be tolerated."""
    key_file = tmp_path / "encryption-key"
    key_file.write_text(_b64(test_const.TEST_MASTER_KEY) + "\n", encoding="utf-8")

    assert keys.load_key_from_file(key_file) == test_const.TEST_MASTER_KEY


def test_decode_key_from_raw_value() -> None:
    """A raw base64 value (as from an environment variable) must decode correctly."""
    assert keys.decode_key(_b64(test_const.TEST_MASTER_KEY)) == test_const.TEST_MASTER_KEY


def test_decode_key_rejects_invalid_base64() -> None:
    """Non-base64 content must raise KeyLoadError instead of an unrelated exception."""
    with pytest.raises(keys.KeyLoadError):
        keys.decode_key("not-valid-base64!!!")


def test_decode_key_rejects_wrong_length() -> None:
    """A key that decodes to something other than 32 bytes must be rejected."""
    with pytest.raises(keys.KeyLoadError):
        keys.decode_key(_b64(test_const.WRONG_LENGTH_KEY_BYTES))


def test_resolve_key_prefers_file_over_value(tmp_path: Path) -> None:
    """When both a key file and a raw value are given, the file must take precedence."""
    key_file = tmp_path / "encryption-key"
    key_file.write_text(_b64(test_const.TEST_MASTER_KEY), encoding="utf-8")

    resolved = keys.resolve_key(key_file=key_file, key_value=_b64(test_const.OTHER_MASTER_KEY))

    assert resolved == test_const.TEST_MASTER_KEY


def test_resolve_key_falls_back_to_value_when_no_file() -> None:
    """When no key file is given, the raw value must be used."""
    resolved = keys.resolve_key(key_file=None, key_value=_b64(test_const.TEST_MASTER_KEY))

    assert resolved == test_const.TEST_MASTER_KEY


def test_resolve_key_raises_when_nothing_provided() -> None:
    """Resolving with neither a file nor a value must fail explicitly."""
    with pytest.raises(keys.KeyLoadError):
        keys.resolve_key(key_file=None, key_value=None)


def test_resolve_signing_private_key_from_file(tmp_path: Path) -> None:
    """A private signing key PEM file must resolve to a usable Ed25519 private key."""
    key_file = tmp_path / "signing-key.pem"
    key_file.write_bytes(test_const.TEST_SIGNING_PRIVATE_KEY_PEM)

    resolved = keys.resolve_signing_private_key(key_file=key_file, key_value=None)

    assert (
        resolved.private_bytes_raw()
        == signing.load_private_key(test_const.TEST_SIGNING_PRIVATE_KEY_PEM).private_bytes_raw()
    )


def test_resolve_signing_private_key_from_value() -> None:
    """A private signing key PEM given as a raw environment-style value must resolve correctly."""
    resolved = keys.resolve_signing_private_key(
        key_file=None, key_value=test_const.TEST_SIGNING_PRIVATE_KEY_PEM.decode("ascii")
    )

    assert (
        resolved.private_bytes_raw()
        == signing.load_private_key(test_const.TEST_SIGNING_PRIVATE_KEY_PEM).private_bytes_raw()
    )


def test_resolve_signing_private_key_prefers_file_over_value(tmp_path: Path) -> None:
    """When both a key file and a raw value are given, the file must take precedence."""
    key_file = tmp_path / "signing-key.pem"
    key_file.write_bytes(test_const.TEST_SIGNING_PRIVATE_KEY_PEM)

    resolved = keys.resolve_signing_private_key(
        key_file=key_file, key_value=test_const.OTHER_SIGNING_PRIVATE_KEY_PEM.decode("ascii")
    )

    assert (
        resolved.private_bytes_raw()
        == signing.load_private_key(test_const.TEST_SIGNING_PRIVATE_KEY_PEM).private_bytes_raw()
    )


def test_resolve_signing_private_key_tolerates_trailing_whitespace(tmp_path: Path) -> None:
    """A trailing newline, as added by `kubectl create secret --from-file`, must be tolerated."""
    key_file = tmp_path / "signing-key.pem"
    key_file.write_bytes(test_const.TEST_SIGNING_PRIVATE_KEY_PEM + b"\n\n  \n")

    resolved = keys.resolve_signing_private_key(key_file=key_file, key_value=None)

    assert (
        resolved.private_bytes_raw()
        == signing.load_private_key(test_const.TEST_SIGNING_PRIVATE_KEY_PEM).private_bytes_raw()
    )


def test_resolve_signing_private_key_raises_when_nothing_provided() -> None:
    """Resolving with neither a file nor a value must fail explicitly."""
    with pytest.raises(keys.KeyLoadError):
        keys.resolve_signing_private_key(key_file=None, key_value=None)


def test_resolve_signing_private_key_rejects_malformed_pem() -> None:
    """A malformed PEM value must be rejected as a KeyLoadError, not a raw SignatureError."""
    with pytest.raises(keys.KeyLoadError):
        keys.resolve_signing_private_key(key_file=None, key_value="not a pem file")


def test_resolve_signing_private_key_rejects_a_public_key_pem() -> None:
    """A public key PEM offered where a private key is expected must be rejected structurally."""
    with pytest.raises(keys.KeyLoadError):
        keys.resolve_signing_private_key(
            key_file=None, key_value=test_const.TEST_SIGNING_PUBLIC_KEY_PEM.decode("ascii")
        )


def test_resolve_signing_public_key_from_file(tmp_path: Path) -> None:
    """A public verification key PEM file must resolve to a usable Ed25519 public key."""
    key_file = tmp_path / "signing-public-key.pem"
    key_file.write_bytes(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)

    resolved = keys.resolve_signing_public_key(key_file=key_file, key_value=None)

    assert (
        resolved.public_bytes_raw()
        == signing.load_public_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM).public_bytes_raw()
    )


def test_resolve_signing_public_key_from_value() -> None:
    """A public verification key PEM given as a raw environment-style value must resolve."""
    resolved = keys.resolve_signing_public_key(
        key_file=None, key_value=test_const.TEST_SIGNING_PUBLIC_KEY_PEM.decode("ascii")
    )

    assert (
        resolved.public_bytes_raw()
        == signing.load_public_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM).public_bytes_raw()
    )


def test_resolve_signing_public_key_prefers_file_over_value(tmp_path: Path) -> None:
    """When both a key file and a raw value are given, the file must take precedence."""
    key_file = tmp_path / "signing-public-key.pem"
    key_file.write_bytes(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)

    resolved = keys.resolve_signing_public_key(
        key_file=key_file, key_value=test_const.OTHER_SIGNING_PUBLIC_KEY_PEM.decode("ascii")
    )

    assert (
        resolved.public_bytes_raw()
        == signing.load_public_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM).public_bytes_raw()
    )


def test_resolve_signing_public_key_tolerates_trailing_whitespace(tmp_path: Path) -> None:
    """A trailing newline, as added by `kubectl create secret --from-file`, must be tolerated."""
    key_file = tmp_path / "signing-public-key.pem"
    key_file.write_bytes(test_const.TEST_SIGNING_PUBLIC_KEY_PEM + b"\n\n  \n")

    resolved = keys.resolve_signing_public_key(key_file=key_file, key_value=None)

    assert (
        resolved.public_bytes_raw()
        == signing.load_public_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM).public_bytes_raw()
    )


def test_resolve_signing_public_key_raises_when_nothing_provided() -> None:
    """Resolving with neither a file nor a value must fail explicitly."""
    with pytest.raises(keys.KeyLoadError):
        keys.resolve_signing_public_key(key_file=None, key_value=None)


def test_resolve_signing_public_key_rejects_malformed_pem() -> None:
    """A malformed PEM value must be rejected as a KeyLoadError, not a raw SignatureError."""
    with pytest.raises(keys.KeyLoadError):
        keys.resolve_signing_public_key(key_file=None, key_value="not a pem file")


def test_resolve_signing_public_key_rejects_a_private_key_pem() -> None:
    """A private key PEM offered where a public key is expected must be rejected structurally."""
    with pytest.raises(keys.KeyLoadError):
        keys.resolve_signing_public_key(
            key_file=None, key_value=test_const.TEST_SIGNING_PRIVATE_KEY_PEM.decode("ascii")
        )
