"""Loading and validation of key material from a file or an environment value.

The AES-256 master key at rest (in the Kubernetes Secret, or in a local
shell for `docker run`) is the base64 string produced by `keygen`. This
module is the single place that decodes and validates it, tolerating the
trailing newline that `kubectl create secret --from-file` appends to any
text file it reads. It also loads the Ed25519 signing key pair using the
same precedence and whitespace tolerance, since it is delivered the same
way, as PEM text instead of base64.
"""

from __future__ import annotations

import base64
import binascii
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import model_pipeline.constants as const
from model_pipeline.signing import SignatureError, load_private_key, load_public_key


class KeyLoadError(Exception):
    """Raised when key material is missing, not valid base64, or the wrong length once decoded."""


def load_key_from_file(path: Path) -> bytes:
    """Read and decode the base64-encoded master key stored at path.

    Raises KeyLoadError, instead of a raw OSError, when path does not
    exist or cannot be read -- a real, previously observed failure mode: a
    key file mounted from a Kubernetes Secret was unreadable until the
    pod's ``fsGroup`` was set.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise KeyLoadError(f"could not read key file {path}: {exc}") from exc
    return decode_key(raw)


def decode_key(raw: str) -> bytes:
    """Decode a base64-encoded key string, tolerating surrounding whitespace, and validate it."""
    stripped = raw.strip()
    try:
        key = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KeyLoadError("key material is not valid base64") from exc
    _require_key_size(key)
    return key


def resolve_key(*, key_file: Path | None, key_value: str | None) -> bytes:
    """Resolve the master key from a mounted key file, falling back to a raw value.

    A key file takes precedence over a raw value when both are given, since
    the file is how the key is normally delivered (a mounted Kubernetes
    Secret); the raw value exists for local, file-less execution.
    """
    if key_file is not None:
        return load_key_from_file(key_file)
    if key_value is not None:
        return decode_key(key_value)
    raise KeyLoadError("no key material provided: neither key_file nor key_value was set")


def load_token_from_file(path: Path) -> str:
    """Read and strip the Hugging Face token stored at path.

    Raises KeyLoadError, instead of a raw OSError, on the same
    fsGroup-related failure mode :func:`load_key_from_file` guards against.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise KeyLoadError(f"could not read token file {path}: {exc}") from exc
    stripped = raw.strip()
    if not stripped:
        raise KeyLoadError(f"token file {path} is empty")
    return stripped


def resolve_hf_token(
    *, token_file: Path | None, token_value: str | None, fallback_token: str | None = None
) -> str:
    """Resolve the Hugging Face token from a mounted file, a raw value, or a cached login.

    Precedence: token_file (HF_TOKEN_FILE) takes priority over token_value
    (HF_TOKEN), which takes priority over fallback_token -- the token
    ``huggingface_hub.get_token()`` reports from a prior ``hf auth login``,
    passed in by the caller since this module stays free of any
    ``huggingface_hub`` dependency. Raises KeyLoadError when none of the
    three yields a token, so an operator who has neither set HF_TOKEN nor
    logged in gets one clear error instead of an opaque 401 later.
    """
    if token_file is not None:
        return load_token_from_file(token_file)
    if token_value is not None:
        return token_value.strip()
    if fallback_token is not None:
        return fallback_token.strip()
    raise KeyLoadError(
        "no Hugging Face token available: set HF_TOKEN, HF_TOKEN_FILE, or run `hf auth login`"
    )


def _require_key_size(key: bytes) -> None:
    """Raise KeyLoadError unless the decoded key has the required AES-256 length."""
    if len(key) != const.KEY_SIZE:
        raise KeyLoadError(f"key must be {const.KEY_SIZE} bytes after decoding, got {len(key)}")


def _resolve_pem_text(*, key_file: Path | None, key_value: str | None, missing_message: str) -> str:
    """Resolve raw PEM text from a mounted key file, falling back to a raw value.

    Shares the same precedence as :func:`resolve_key`: a key file takes
    precedence over a raw value when both are given. Raises KeyLoadError,
    instead of a raw OSError, when key_file cannot be read -- the same
    fsGroup-related failure mode :func:`load_key_from_file` guards against.
    """
    if key_file is not None:
        try:
            return key_file.read_text(encoding="utf-8")
        except OSError as exc:
            raise KeyLoadError(f"could not read key file {key_file}: {exc}") from exc
    if key_value is not None:
        return key_value
    raise KeyLoadError(missing_message)


def _normalize_pem(raw: str) -> bytes:
    """Encode PEM text to bytes, tolerating surrounding whitespace.

    Trailing whitespace or a missing final newline, as can happen when PEM
    text passes through an environment variable or a file written by hand,
    is normalized away before parsing rather than passed through as-is.
    """
    return raw.strip().encode("utf-8") + b"\n"


def resolve_signing_private_key(
    *, key_file: Path | None, key_value: str | None
) -> Ed25519PrivateKey:
    """Resolve the Ed25519 private signing key from a mounted key file or a raw PEM value.

    Follows the same file-over-value precedence as :func:`resolve_key`, and
    wraps any :class:`~model_pipeline.signing.SignatureError` raised while
    parsing the PEM into a :class:`KeyLoadError`, so callers only ever
    handle one exception type for key material problems.
    """
    raw = _resolve_pem_text(
        key_file=key_file,
        key_value=key_value,
        missing_message=(
            "no signing private key material provided: neither key_file nor key_value was set"
        ),
    )
    try:
        return load_private_key(_normalize_pem(raw))
    except SignatureError as exc:
        raise KeyLoadError(f"could not load signing private key: {exc}") from exc


def resolve_signing_public_key(*, key_file: Path | None, key_value: str | None) -> Ed25519PublicKey:
    """Resolve the Ed25519 public verification key from a mounted key file or a raw PEM value.

    Follows the same file-over-value precedence as :func:`resolve_key`, and
    wraps any :class:`~model_pipeline.signing.SignatureError` raised while
    parsing the PEM into a :class:`KeyLoadError`, so callers only ever
    handle one exception type for key material problems.
    """
    raw = _resolve_pem_text(
        key_file=key_file,
        key_value=key_value,
        missing_message=(
            "no signing public key material provided: neither key_file nor key_value was set"
        ),
    )
    try:
        return load_public_key(_normalize_pem(raw))
    except SignatureError as exc:
        raise KeyLoadError(f"could not load signing public key: {exc}") from exc
