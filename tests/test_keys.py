"""Tests for loading and validating the AES-256 master key from a file or a raw value."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
import tests.constants as test_const

from model_pipeline import keys


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
