"""Tests for the chunked AES-256-GCM container.

These tests exist to demonstrate the security properties claimed for the
container format: authenticated round-trips, rejection of a wrong key,
detection of ciphertext tampering, truncation, chunk reordering, and header
manipulation, plus non-determinism of the ciphertext and non-repetition of
nonces within an artifact.
"""

import json
import os
import struct

import pytest
import tests.constants as test_const
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import model_pipeline.constants as const
from model_pipeline import crypto


@pytest.mark.parametrize(
    "size",
    [
        0,
        1,
        test_const.SMALL_TEST_CHUNK_SIZE - 1,
        test_const.SMALL_TEST_CHUNK_SIZE,
        test_const.SMALL_TEST_CHUNK_SIZE * 3,
        test_const.SMALL_TEST_CHUNK_SIZE * 3 + 1,
    ],
)
def test_round_trip_for_various_sizes(size: int) -> None:
    """Encrypting then decrypting must return the original plaintext for boundary sizes."""
    plaintext = os.urandom(size)
    container = crypto.encrypt(
        plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )
    assert crypto.decrypt(container, test_const.TEST_MASTER_KEY) == plaintext


def test_wrong_key_fails_authentication_not_garbage() -> None:
    """Decrypting with the wrong master key must raise, never return garbage plaintext."""
    plaintext = b"a" * (test_const.SMALL_TEST_CHUNK_SIZE * 2)
    container = crypto.encrypt(
        plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )
    with pytest.raises(crypto.DecryptionError, match="authentication failed"):
        crypto.decrypt(container, test_const.OTHER_MASTER_KEY)


def test_ciphertext_bit_flip_is_detected() -> None:
    """Flipping a single bit in a chunk's ciphertext must be caught by GCM authentication."""
    plaintext = b"b" * (test_const.SMALL_TEST_CHUNK_SIZE * 2)
    container = bytearray(
        crypto.encrypt(
            plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
        )
    )
    header_len = _read_header_len(bytes(container))
    tamper_offset = len(const.MAGIC) + 1 + const.HEADER_LEN_SIZE + header_len + const.CHUNK_LEN_SIZE
    container[tamper_offset] ^= 0x01
    with pytest.raises(crypto.DecryptionError, match="authentication failed"):
        crypto.decrypt(bytes(container), test_const.TEST_MASTER_KEY)


def test_truncation_of_last_chunk_is_detected() -> None:
    """Dropping the trailing chunk must be detected rather than silently accepted."""
    plaintext = b"c" * (test_const.SMALL_TEST_CHUNK_SIZE * 3)
    container = crypto.encrypt(
        plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )

    last_ciphertext_len = test_const.SMALL_TEST_CHUNK_SIZE + const.TAG_SIZE
    length_prefix_start = -(last_ciphertext_len + const.CHUNK_LEN_SIZE)
    length_prefix_end = -last_ciphertext_len
    last_chunk_len = struct.unpack(">I", container[length_prefix_start:length_prefix_end])[0]
    truncated = container[: -(last_chunk_len + const.CHUNK_LEN_SIZE)]

    with pytest.raises(crypto.DecryptionError, match="authentication failed"):
        crypto.decrypt(truncated, test_const.TEST_MASTER_KEY)


def test_chunk_reordering_is_detected() -> None:
    """Swapping the order of two chunks must be detected via the per-chunk AAD."""
    plaintext = b"d" * (test_const.SMALL_TEST_CHUNK_SIZE * 3)
    container = crypto.encrypt(
        plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )

    header_end = _header_end_offset(container)
    chunks = _split_chunks(container, header_end)
    assert len(chunks) == 3

    reordered = container[:header_end] + b"".join([chunks[1], chunks[0], chunks[2]])
    with pytest.raises(crypto.DecryptionError, match="authentication failed"):
        crypto.decrypt(reordered, test_const.TEST_MASTER_KEY)


def test_header_tampering_is_detected() -> None:
    """Modifying a value inside the JSON header must invalidate every chunk's AAD."""
    plaintext = b"e" * (test_const.SMALL_TEST_CHUNK_SIZE * 2)
    container = bytearray(
        crypto.encrypt(
            plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
        )
    )
    header_len_offset = len(const.MAGIC) + 1
    header_len = _read_header_len(bytes(container))
    header_start = header_len_offset + const.HEADER_LEN_SIZE
    header = bytearray(container[header_start : header_start + header_len])

    target = str(test_const.SMALL_TEST_CHUNK_SIZE).encode()
    idx = header.find(target)
    assert idx != -1
    header[idx] = ord("9") if header[idx : idx + 1] != b"9" else ord("1")
    container[header_start : header_start + header_len] = header

    with pytest.raises(crypto.DecryptionError, match="authentication failed"):
        crypto.decrypt(bytes(container), test_const.TEST_MASTER_KEY)


def test_same_plaintext_encrypts_differently_and_both_decrypt() -> None:
    """Two encryptions of the same plaintext must differ (random salt) but both must decrypt."""
    plaintext = b"f" * (test_const.SMALL_TEST_CHUNK_SIZE * 2)
    container_a = crypto.encrypt(
        plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )
    container_b = crypto.encrypt(
        plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )

    assert container_a != container_b
    assert crypto.decrypt(container_a, test_const.TEST_MASTER_KEY) == plaintext
    assert crypto.decrypt(container_b, test_const.TEST_MASTER_KEY) == plaintext


def test_nonces_never_repeat_within_an_artifact() -> None:
    """The counter-based nonces generated for one artifact's chunks must all be distinct."""
    plaintext = os.urandom(test_const.SMALL_TEST_CHUNK_SIZE * 5)
    container = crypto.encrypt(
        plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )

    header_end = _header_end_offset(container)
    chunks = _split_chunks(container, header_end)
    nonces = [crypto._nonce_for_chunk(i) for i in range(len(chunks))]
    assert len(nonces) == len(set(nonces))


def test_invalid_magic_is_rejected() -> None:
    """A container whose magic bytes do not match the format tag must be rejected."""
    plaintext = b"g" * test_const.SMALL_TEST_CHUNK_SIZE
    container = crypto.encrypt(
        plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )
    corrupted = b"XXXXXXX\x00" + container[len(const.MAGIC) :]
    with pytest.raises(crypto.DecryptionError, match="invalid magic bytes"):
        crypto.decrypt(corrupted, test_const.TEST_MASTER_KEY)


def test_rejects_wrong_key_size() -> None:
    """Both encrypt and decrypt must reject a master key that is not exactly 32 bytes."""
    with pytest.raises(ValueError, match="master key must be"):
        crypto.encrypt(b"data", b"too-short")
    with pytest.raises(ValueError, match="master key must be"):
        crypto.decrypt(b"anything", b"too-short")


def test_decrypt_raises_on_empty_container() -> None:
    """Decrypting an empty byte string must raise, not crash with an unrelated exception."""
    with pytest.raises(crypto.DecryptionError, match="too short to contain a valid header"):
        crypto.decrypt(b"", test_const.TEST_MASTER_KEY)


def test_encrypt_rejects_non_positive_chunk_size() -> None:
    """A zero or negative chunk_size must be rejected before any encryption work happens."""
    with pytest.raises(ValueError, match="chunk_size must be positive"):
        crypto.encrypt(b"data", test_const.TEST_MASTER_KEY, chunk_size=0)


def test_decrypt_rejects_unsupported_outer_format_version() -> None:
    """A container whose format-version byte does not match the supported version is rejected."""
    plaintext = b"g" * test_const.SMALL_TEST_CHUNK_SIZE
    container = bytearray(
        crypto.encrypt(
            plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
        )
    )
    container[len(const.MAGIC)] = const.FORMAT_VERSION + 1
    with pytest.raises(crypto.DecryptionError, match="unsupported format version"):
        crypto.decrypt(bytes(container), test_const.TEST_MASTER_KEY)


def test_decrypt_rejects_truncated_header() -> None:
    """A container cut off in the middle of its declared header must be rejected."""
    plaintext = b"g" * test_const.SMALL_TEST_CHUNK_SIZE
    container = crypto.encrypt(
        plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )
    header_start = len(const.MAGIC) + 1 + const.HEADER_LEN_SIZE
    truncated = container[: header_start + 1]
    with pytest.raises(crypto.DecryptionError, match="truncated header"):
        crypto.decrypt(truncated, test_const.TEST_MASTER_KEY)


def test_decrypt_rejects_invalid_header_json() -> None:
    """A header that is not valid JSON must be rejected with a clear error, not crash."""
    plaintext = b"g" * test_const.SMALL_TEST_CHUNK_SIZE
    container = crypto.encrypt(
        plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )
    header_len = _read_header_len(container)
    header_start = len(const.MAGIC) + 1 + const.HEADER_LEN_SIZE
    broken_header = b"{not json" + b" " * (header_len - len(b"{not json"))
    corrupted = container[:header_start] + broken_header + container[header_start + header_len :]
    with pytest.raises(crypto.DecryptionError, match="invalid header JSON"):
        crypto.decrypt(corrupted, test_const.TEST_MASTER_KEY)


def test_decrypt_rejects_header_missing_salt_field() -> None:
    """A syntactically valid header JSON missing the required 'salt' field must be rejected."""
    plaintext = b"g" * test_const.SMALL_TEST_CHUNK_SIZE
    container = crypto.encrypt(
        plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )
    header_len = _read_header_len(container)
    header_start = len(const.MAGIC) + 1 + const.HEADER_LEN_SIZE
    new_header = json.dumps({"format_version": const.FORMAT_VERSION}).encode("utf-8")
    assert len(new_header) <= header_len
    padded = new_header + b" " * (header_len - len(new_header))
    corrupted = container[:header_start] + padded + container[header_start + header_len :]
    with pytest.raises(crypto.DecryptionError, match="invalid or missing header fields"):
        crypto.decrypt(corrupted, test_const.TEST_MASTER_KEY)


def test_decrypt_rejects_unsupported_header_format_version() -> None:
    """A header whose JSON 'format_version' field disagrees with the outer magic is rejected."""
    plaintext = b"g" * test_const.SMALL_TEST_CHUNK_SIZE
    container = crypto.encrypt(
        plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )
    header_len = _read_header_len(container)
    header_start = len(const.MAGIC) + 1 + const.HEADER_LEN_SIZE
    original_header = json.loads(container[header_start : header_start + header_len])
    original_header["format_version"] = const.FORMAT_VERSION + 1
    new_header = json.dumps(original_header, sort_keys=True).encode("utf-8")
    assert len(new_header) <= header_len
    padded = new_header + b" " * (header_len - len(new_header))
    corrupted = container[:header_start] + padded + container[header_start + header_len :]
    with pytest.raises(crypto.DecryptionError, match="unsupported header format_version"):
        crypto.decrypt(corrupted, test_const.TEST_MASTER_KEY)


def test_decrypt_rejects_truncated_chunk_length_prefix() -> None:
    """A container cut off inside a chunk's length prefix must be rejected."""
    plaintext = b"g" * test_const.SMALL_TEST_CHUNK_SIZE
    container = crypto.encrypt(
        plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )
    header_end = _header_end_offset(container)
    truncated = container[: header_end + const.CHUNK_LEN_SIZE - 1]
    with pytest.raises(crypto.DecryptionError, match="truncated chunk length prefix"):
        crypto.decrypt(truncated, test_const.TEST_MASTER_KEY)


def test_decrypt_rejects_truncated_chunk_data() -> None:
    """A container whose declared chunk length exceeds the remaining bytes must be rejected."""
    plaintext = b"g" * test_const.SMALL_TEST_CHUNK_SIZE
    container = crypto.encrypt(
        plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )
    header_end = _header_end_offset(container)
    truncated = container[: header_end + const.CHUNK_LEN_SIZE + 1]
    with pytest.raises(crypto.DecryptionError, match="truncated chunk data"):
        crypto.decrypt(truncated, test_const.TEST_MASTER_KEY)


def test_decrypt_rejects_container_with_no_chunks() -> None:
    """A structurally valid container with zero chunks after the header must be rejected."""
    plaintext = b"g" * test_const.SMALL_TEST_CHUNK_SIZE
    container = crypto.encrypt(
        plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )
    header_end = _header_end_offset(container)
    with pytest.raises(crypto.DecryptionError, match="no chunks"):
        crypto.decrypt(container[:header_end], test_const.TEST_MASTER_KEY)


def test_decrypt_low_level_matches_aesgcm_reference() -> None:
    """The derived file_key/nonce/AAD scheme must be consistent with direct AESGCM usage."""
    plaintext = b"h" * test_const.SMALL_TEST_CHUNK_SIZE
    container = crypto.encrypt(
        plaintext, test_const.TEST_MASTER_KEY, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )

    header_len = _read_header_len(container)
    header_start = len(const.MAGIC) + 1 + const.HEADER_LEN_SIZE
    header_bytes = container[header_start : header_start + header_len]
    header = json.loads(header_bytes)
    salt = bytes.fromhex(header["salt"])
    file_key = crypto._derive_file_key(test_const.TEST_MASTER_KEY, salt)

    chunk_start = header_start + header_len
    chunk_len = struct.unpack(">I", container[chunk_start : chunk_start + const.CHUNK_LEN_SIZE])[0]
    ciphertext_start = chunk_start + const.CHUNK_LEN_SIZE
    ciphertext = container[ciphertext_start : ciphertext_start + chunk_len]

    aad = crypto._aad_for_chunk(header_bytes, 0, True)
    aesgcm = AESGCM(file_key)
    assert aesgcm.decrypt(crypto._nonce_for_chunk(0), ciphertext, aad) == plaintext


def _read_header_len(container: bytes) -> int:
    """Read the big-endian header-length prefix that follows the magic and format version."""
    offset = len(const.MAGIC) + 1
    return int(struct.unpack(">I", container[offset : offset + const.HEADER_LEN_SIZE])[0])


def _header_end_offset(container: bytes) -> int:
    """Compute the byte offset where the JSON header ends and the chunk sequence begins."""
    header_len = _read_header_len(container)
    return len(const.MAGIC) + 1 + const.HEADER_LEN_SIZE + header_len


def _split_chunks(container: bytes, start: int) -> list[bytes]:
    """Split the length-prefixed chunk records out of ``container``, each including its prefix."""
    chunks = []
    offset = start
    while offset < len(container):
        chunk_len = struct.unpack(">I", container[offset : offset + const.CHUNK_LEN_SIZE])[0]
        end = offset + const.CHUNK_LEN_SIZE + chunk_len
        chunks.append(container[offset:end])
        offset = end
    return chunks
