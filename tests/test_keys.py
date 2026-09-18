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
    with pytest.raises(keys.KeyLoadError, match="not valid base64"):
        keys.decode_key("not-valid-base64!!!")


def test_decode_key_rejects_wrong_length() -> None:
    """A key that decodes to something other than 32 bytes must be rejected."""
    with pytest.raises(keys.KeyLoadError, match="must be .* bytes"):
        keys.decode_key(_b64(test_const.WRONG_LENGTH_KEY_BYTES))


def test_load_key_from_file_translates_a_missing_file_to_key_load_error(tmp_path: Path) -> None:
    """load_key_from_file must raise KeyLoadError, not a raw OSError, for a missing file."""
    with pytest.raises(keys.KeyLoadError, match="could not read key file"):
        keys.load_key_from_file(tmp_path / "does-not-exist")


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
    with pytest.raises(keys.KeyLoadError, match="no key material provided"):
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


def test_resolve_signing_private_key_translates_a_missing_file_to_key_load_error(
    tmp_path: Path,
) -> None:
    """A non-existent key file must raise KeyLoadError naming the path, not a raw OSError."""
    missing_file = tmp_path / "does-not-exist.pem"
    with pytest.raises(keys.KeyLoadError, match="could not read key file") as exc_info:
        keys.resolve_signing_private_key(key_file=missing_file, key_value=None)
    assert str(missing_file) in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, OSError)


def test_resolve_signing_private_key_translates_an_unreadable_file_to_key_load_error(
    tmp_path: Path,
) -> None:
    """A key file that exists but cannot be read must raise KeyLoadError, not PermissionError."""
    key_file = tmp_path / "signing-key.pem"
    key_file.write_bytes(test_const.TEST_SIGNING_PRIVATE_KEY_PEM)
    key_file.chmod(0o000)
    try:
        with pytest.raises(keys.KeyLoadError, match="could not read key file") as exc_info:
            keys.resolve_signing_private_key(key_file=key_file, key_value=None)
        assert isinstance(exc_info.value.__cause__, OSError)
    finally:
        key_file.chmod(0o644)


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


def test_resolve_signing_public_key_translates_a_missing_file_to_key_load_error(
    tmp_path: Path,
) -> None:
    """A non-existent key file must raise KeyLoadError naming the path, not a raw OSError."""
    missing_file = tmp_path / "does-not-exist.pem"
    with pytest.raises(keys.KeyLoadError, match="could not read key file") as exc_info:
        keys.resolve_signing_public_key(key_file=missing_file, key_value=None)
    assert str(missing_file) in str(exc_info.value)
    assert isinstance(exc_info.value.__cause__, OSError)


def test_resolve_signing_public_key_translates_an_unreadable_file_to_key_load_error(
    tmp_path: Path,
) -> None:
    """A key file that exists but cannot be read must raise KeyLoadError, not PermissionError."""
    key_file = tmp_path / "signing-public-key.pem"
    key_file.write_bytes(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)
    key_file.chmod(0o000)
    try:
        with pytest.raises(keys.KeyLoadError, match="could not read key file") as exc_info:
            keys.resolve_signing_public_key(key_file=key_file, key_value=None)
        assert isinstance(exc_info.value.__cause__, OSError)
    finally:
        key_file.chmod(0o644)


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


def test_load_token_from_file_strips_the_trailing_newline(tmp_path: Path) -> None:
    """load_token_from_file must strip whitespace, as kubectl's --from-file appends a newline."""
    token_file = tmp_path / "hf-token"
    token_file.write_text("hf_abc123\n", encoding="utf-8")

    assert keys.load_token_from_file(token_file) == "hf_abc123"


def test_load_token_from_file_translates_a_missing_file_to_key_load_error(
    tmp_path: Path,
) -> None:
    """load_token_from_file must raise KeyLoadError, not a raw OSError, for a missing file."""
    with pytest.raises(keys.KeyLoadError, match="could not read token file"):
        keys.load_token_from_file(tmp_path / "does-not-exist")


def test_load_token_from_file_rejects_an_empty_file(tmp_path: Path) -> None:
    """load_token_from_file must reject a file that is empty (or only whitespace)."""
    token_file = tmp_path / "hf-token"
    token_file.write_text("   \n", encoding="utf-8")

    with pytest.raises(keys.KeyLoadError, match="is empty"):
        keys.load_token_from_file(token_file)


def test_resolve_hf_token_prefers_file_over_value_over_fallback(tmp_path: Path) -> None:
    """token_file must win over token_value, which must win over fallback_token."""
    token_file = tmp_path / "hf-token"
    token_file.write_text("from-file", encoding="utf-8")

    resolved = keys.resolve_hf_token(
        token_file=token_file,
        token_value="from-value",  # noqa: S106
        fallback_token="from-fallback",  # noqa: S106
    )

    assert resolved == "from-file"


def test_resolve_hf_token_falls_back_to_value_when_no_file() -> None:
    """token_value must be used, and fallback_token ignored, when no file is given."""
    resolved = keys.resolve_hf_token(
        token_file=None,
        token_value="from-value",  # noqa: S106
        fallback_token="from-fallback",  # noqa: S106
    )

    assert resolved == "from-value"


def test_resolve_hf_token_falls_back_to_cached_login_last() -> None:
    """fallback_token (a cached `hf auth login`) must be used only when nothing else is given."""
    resolved = keys.resolve_hf_token(
        token_file=None,
        token_value=None,
        fallback_token="cached",  # noqa: S106
    )

    assert resolved == "cached"


def test_resolve_hf_token_raises_when_nothing_is_available() -> None:
    """Resolving with no file, value, or cached login must fail explicitly."""
    with pytest.raises(keys.KeyLoadError, match="no Hugging Face token available"):
        keys.resolve_hf_token(token_file=None, token_value=None, fallback_token=None)


def test_resolve_hf_token_never_leaks_a_token_into_a_raised_error(tmp_path: Path) -> None:
    """An error raised while resolving must never embed any candidate token's value."""
    secret_from_value = "hf_secret-from-value"  # noqa: S105
    secret_from_fallback = "hf_secret-from-fallback"  # noqa: S105

    with pytest.raises(keys.KeyLoadError) as exc_info:
        keys.resolve_hf_token(
            token_file=tmp_path / "does-not-exist",
            token_value=secret_from_value,
            fallback_token=secret_from_fallback,
        )

    message = str(exc_info.value)
    assert secret_from_value not in message
    assert secret_from_fallback not in message
