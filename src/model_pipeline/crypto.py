"""Chunked AES-256-GCM container for model artifacts.

The container format is a self-describing envelope: an 8-byte magic (a 7-byte
tag plus a 1-byte format version), a length-prefixed JSON header, and a
sequence of length-prefixed GCM chunks. The master key is never used to
encrypt data directly; a per-artifact ``file_key`` is derived via
HKDF-SHA256 from a random salt stored in the header, which allows chunk
nonces to be a simple big-endian counter without any risk of nonce reuse
across artifacts. Each chunk is authenticated with additional data (AAD)
binding it to the header and to its position in the sequence, so that
truncation, reordering, or header tampering are all detected as
authentication failures rather than producing corrupted plaintext.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import model_pipeline.constants as const


class DecryptionError(Exception):
    """Raised when a container fails structural, integrity, or authenticity checks."""


def _derive_file_key(master_key: bytes, salt: bytes) -> bytes:
    """Derive the per-artifact file key from the master key and a random salt via HKDF-SHA256."""
    return HKDF(algorithm=SHA256(), length=const.KEY_SIZE, salt=salt, info=const.HKDF_INFO).derive(
        master_key
    )


def _nonce_for_chunk(index: int) -> bytes:
    """Build the deterministic, non-repeating GCM nonce for the chunk at ``index``."""
    return index.to_bytes(const.NONCE_SIZE, "big")


def _build_header(salt: bytes, chunk_size: int) -> bytes:
    """Serialize the container header (algorithm, KDF, salt, chunk size) as canonical JSON."""
    header = {
        "format_version": const.FORMAT_VERSION,
        "algorithm": const.ALGORITHM_LABEL,
        "kdf": const.KDF_LABEL,
        "salt": salt.hex(),
        "chunk_size": chunk_size,
    }
    return json.dumps(header, sort_keys=True).encode("utf-8")


def _aad_for_chunk(header_bytes: bytes, index: int, is_last: bool) -> bytes:
    """Build the additional authenticated data binding a chunk to the header and its position."""
    return (
        hashlib.sha256(header_bytes).digest()
        + index.to_bytes(4, "big")
        + (b"\x01" if is_last else b"\x00")
    )


def _iter_plaintext_chunks(data: bytes, chunk_size: int) -> Iterator[bytes]:
    """Split ``data`` into ``chunk_size`` pieces; yield one empty chunk when ``data`` is empty."""
    if not data:
        yield b""
        return
    for start in range(0, len(data), chunk_size):
        yield data[start : start + chunk_size]


def _require_key_size(master_key: bytes) -> None:
    """Raise ``ValueError`` unless ``master_key`` has the required AES-256 key length."""
    if len(master_key) != const.KEY_SIZE:
        raise ValueError(f"master key must be {const.KEY_SIZE} bytes, got {len(master_key)}")


def _split_header(container: bytes) -> tuple[bytes, int]:
    """Parse and validate the magic, format version, and length-prefixed header of ``container``.

    Returns the raw header bytes and the offset of the first byte after the header.
    Raises :class:`DecryptionError` on any structural inconsistency.
    """
    min_len = len(const.MAGIC) + 1 + const.HEADER_LEN_SIZE
    if len(container) < min_len:
        raise DecryptionError("container is too short to contain a valid header")

    offset = 0
    magic = container[offset : offset + len(const.MAGIC)]
    offset += len(const.MAGIC)
    if magic != const.MAGIC:
        raise DecryptionError("invalid magic bytes")

    format_version = container[offset]
    offset += 1
    if format_version != const.FORMAT_VERSION:
        raise DecryptionError(f"unsupported format version {format_version}")

    header_len = int.from_bytes(container[offset : offset + const.HEADER_LEN_SIZE], "big")
    offset += const.HEADER_LEN_SIZE
    if offset + header_len > len(container):
        raise DecryptionError("truncated header")
    header_bytes = container[offset : offset + header_len]
    offset += header_len

    return header_bytes, offset


def _parse_header_salt(header_bytes: bytes) -> bytes:
    """Parse the header JSON and return the decoded salt, validating format_version and shape."""
    try:
        header = json.loads(header_bytes)
    except json.JSONDecodeError as exc:
        raise DecryptionError("invalid header JSON") from exc

    try:
        salt = bytes.fromhex(header["salt"])
        header_format_version = header["format_version"]
    except (KeyError, TypeError, ValueError) as exc:
        raise DecryptionError("invalid or missing header fields") from exc

    if header_format_version != const.FORMAT_VERSION:
        raise DecryptionError(f"unsupported header format_version {header_format_version}")

    return salt


def _split_chunk_ciphertexts(container: bytes, offset: int) -> list[bytes]:
    """Split the length-prefixed chunk ciphertexts out of ``container`` starting at ``offset``."""
    chunk_ciphertexts: list[bytes] = []
    while offset < len(container):
        if offset + const.CHUNK_LEN_SIZE > len(container):
            raise DecryptionError("truncated chunk length prefix")
        chunk_len = int.from_bytes(container[offset : offset + const.CHUNK_LEN_SIZE], "big")
        offset += const.CHUNK_LEN_SIZE
        if offset + chunk_len > len(container):
            raise DecryptionError("truncated chunk data")
        chunk_ciphertexts.append(container[offset : offset + chunk_len])
        offset += chunk_len

    if not chunk_ciphertexts:
        raise DecryptionError("container has no chunks")

    return chunk_ciphertexts


def encrypt(
    plaintext: bytes, master_key: bytes, *, chunk_size: int = const.DEFAULT_CHUNK_SIZE
) -> bytes:
    """Encrypt ``plaintext`` into a self-describing container.

    A fresh random salt is drawn for every call, so encrypting the same
    plaintext twice with the same key yields different ciphertexts.
    """
    _require_key_size(master_key)
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    salt = os.urandom(const.SALT_SIZE)
    file_key = _derive_file_key(master_key, salt)
    aesgcm = AESGCM(file_key)
    header_bytes = _build_header(salt, chunk_size)

    chunks = list(_iter_plaintext_chunks(plaintext, chunk_size))
    last_index = len(chunks) - 1

    out = bytearray()
    out += const.MAGIC
    out += const.FORMAT_VERSION.to_bytes(1, "big")
    out += len(header_bytes).to_bytes(const.HEADER_LEN_SIZE, "big")
    out += header_bytes

    for index, chunk in enumerate(chunks):
        aad = _aad_for_chunk(header_bytes, index, index == last_index)
        ciphertext = aesgcm.encrypt(_nonce_for_chunk(index), chunk, aad)
        out += len(ciphertext).to_bytes(const.CHUNK_LEN_SIZE, "big")
        out += ciphertext

    return bytes(out)


def decrypt(container: bytes, master_key: bytes) -> bytes:
    """Decrypt a container produced by :func:`encrypt`.

    Raises :class:`DecryptionError` on any structural inconsistency, wrong
    key, or tampering (bit flips, chunk reordering, truncation, or header
    modification) — never on silently returning partial or corrupted data.
    """
    _require_key_size(master_key)

    header_bytes, offset = _split_header(container)
    salt = _parse_header_salt(header_bytes)
    chunk_ciphertexts = _split_chunk_ciphertexts(container, offset)

    file_key = _derive_file_key(master_key, salt)
    aesgcm = AESGCM(file_key)
    last_index = len(chunk_ciphertexts) - 1

    plaintext_parts: list[bytes] = []
    for index, ciphertext in enumerate(chunk_ciphertexts):
        aad = _aad_for_chunk(header_bytes, index, index == last_index)
        try:
            plaintext_parts.append(aesgcm.decrypt(_nonce_for_chunk(index), ciphertext, aad))
        except InvalidTag as exc:
            raise DecryptionError(f"authentication failed on chunk {index}") from exc

    return b"".join(plaintext_parts)
