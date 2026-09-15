"""Loading and validation of the AES-256 master key from a file or an environment value.

The key at rest (in the Kubernetes Secret, or in a local shell for `docker
run`) is the base64 string produced by `keygen`. This module is the single
place that decodes and validates it, tolerating the trailing newline that
`kubectl create secret --from-file` appends to any text file it reads.
"""

from __future__ import annotations

import base64
import binascii
from pathlib import Path

import model_pipeline.constants as const


class KeyLoadError(Exception):
    """Raised when key material is missing, not valid base64, or the wrong length once decoded."""


def load_key_from_file(path: Path) -> bytes:
    """Read and decode the base64-encoded master key stored at path."""
    raw = path.read_text(encoding="utf-8")
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


def _require_key_size(key: bytes) -> None:
    """Raise KeyLoadError unless the decoded key has the required AES-256 length."""
    if len(key) != const.KEY_SIZE:
        raise KeyLoadError(f"key must be {const.KEY_SIZE} bytes after decoding, got {len(key)}")
