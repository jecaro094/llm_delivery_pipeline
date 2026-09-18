"""Tests for manifest construction, serialization, and integrity verification."""

from __future__ import annotations

import base64
import json
from typing import get_args

import pydantic
import pytest
import tests.constants as test_const

import model_pipeline.constants as const
from model_pipeline import manifest


def _build_sample_manifest(artifact_bytes: bytes, plaintext_bytes: bytes) -> manifest.Manifest:
    """Build a manifest whose recorded hashes match the given artifact and plaintext bytes."""
    return manifest.build_manifest(
        created_at="2026-09-15T10:00:00Z",
        model=manifest.ModelInfo(
            source_repo="prajjwal1/bert-tiny",
            source_revision="deadbeef",
            task_hint="fill-mask",
        ),
        artifact=manifest.ArtifactInfo(
            version="1.0.0",
            path="versions/1.0.0/model.tar.enc",
            size_bytes=len(artifact_bytes),
            sha256=manifest.compute_sha256(artifact_bytes),
            plaintext_sha256=manifest.compute_sha256(plaintext_bytes),
            plaintext_size_bytes=len(plaintext_bytes),
        ),
        encryption=manifest.EncryptionInfo(
            algorithm="AES-256-GCM",
            kdf="HKDF-SHA256",
            chunk_size_bytes=4 * 1024 * 1024,
            format_version=1,
            key_id="model-encryption-key",
        ),
        producer=manifest.ProducerInfo(tool="model_pipeline", tool_version="0.1.0"),
    )


def test_build_serialize_deserialize_round_trip() -> None:
    """A manifest must survive serialization and deserialization unchanged."""
    artifact_bytes = b"ciphertext-bytes"
    plaintext_bytes = b"plaintext-bytes"
    original = _build_sample_manifest(artifact_bytes, plaintext_bytes)

    restored = manifest.deserialize_manifest(manifest.serialize_manifest(original))

    assert restored == original


def test_verify_artifact_and_plaintext_hashes_pass_for_matching_bytes() -> None:
    """Verification must succeed when the manifest's hashes match the actual bytes."""
    artifact_bytes = b"ciphertext-bytes"
    plaintext_bytes = b"plaintext-bytes"
    sample_manifest = _build_sample_manifest(artifact_bytes, plaintext_bytes)

    manifest.verify_artifact_sha256(sample_manifest, artifact_bytes)
    manifest.verify_plaintext_sha256(sample_manifest, plaintext_bytes)


def test_verify_artifact_sha256_detects_mismatch() -> None:
    """A tampered or corrupted artifact must fail sha256 verification."""
    sample_manifest = _build_sample_manifest(b"ciphertext-bytes", b"plaintext-bytes")

    with pytest.raises(manifest.ManifestError, match="artifact sha256 mismatch"):
        manifest.verify_artifact_sha256(sample_manifest, b"different-ciphertext-bytes")


def test_verify_plaintext_sha256_detects_mismatch() -> None:
    """An incorrect or incomplete decryption must fail plaintext_sha256 verification."""
    sample_manifest = _build_sample_manifest(b"ciphertext-bytes", b"plaintext-bytes")

    with pytest.raises(manifest.ManifestError, match="plaintext sha256 mismatch"):
        manifest.verify_plaintext_sha256(sample_manifest, b"different-plaintext-bytes")


def test_serialized_manifest_never_contains_the_encryption_key() -> None:
    """The manifest is a plaintext, public document and must never embed key material."""
    sample_manifest = _build_sample_manifest(b"ciphertext-bytes", b"plaintext-bytes")
    serialized = manifest.serialize_manifest(sample_manifest)

    key_b64 = base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    assert test_const.TEST_MASTER_KEY.hex() not in serialized.decode("utf-8")
    assert key_b64 not in serialized.decode("utf-8")


def _tampered_bytes(**overrides: object) -> bytes:
    """Serialize a sample manifest as a plain dict with overrides applied, bypassing Manifest."""
    sample_manifest = _build_sample_manifest(b"ciphertext-bytes", b"plaintext-bytes")
    as_dict = json.loads(manifest.serialize_manifest(sample_manifest))
    as_dict.update(overrides)
    return json.dumps(as_dict).encode("utf-8")


def test_deserialize_rejects_unknown_manifest_version() -> None:
    """A manifest with an unrecognized manifest_version must be rejected, not silently accepted."""
    with pytest.raises(manifest.ManifestError, match="manifest_version"):
        manifest.deserialize_manifest(_tampered_bytes(manifest_version="99.0"))


def test_deserialize_rejects_invalid_json() -> None:
    """Malformed JSON must raise ManifestError rather than an unrelated exception."""
    with pytest.raises(manifest.ManifestError, match="invalid manifest"):
        manifest.deserialize_manifest(b"not json")


def test_deserialize_rejects_a_missing_field() -> None:
    """A manifest missing a required field must be rejected with that field named."""
    as_dict = json.loads(manifest.serialize_manifest(_build_sample_manifest(b"c", b"p")))
    del as_dict["artifact"]["sha256"]

    with pytest.raises(manifest.ManifestError, match="sha256"):
        manifest.deserialize_manifest(json.dumps(as_dict).encode("utf-8"))


def test_deserialize_rejects_a_wrong_type() -> None:
    """A manifest with a field of the wrong type must be rejected."""
    with pytest.raises(manifest.ManifestError, match="size_bytes"):
        manifest.deserialize_manifest(_tampered_bytes(artifact={"size_bytes": "not-an-int"}))


def test_deserialize_rejects_an_unexpected_extra_field() -> None:
    """A manifest carrying a field outside the schema must be rejected, not silently ignored."""
    with pytest.raises(manifest.ManifestError, match="unexpected"):
        manifest.deserialize_manifest(_tampered_bytes(unexpected_field="surprise"))


def test_manifest_is_immutable_once_built() -> None:
    """Assigning to a field of a built manifest must raise, not silently succeed."""
    sample_manifest = _build_sample_manifest(b"ciphertext-bytes", b"plaintext-bytes")

    with pytest.raises(pydantic.ValidationError):
        sample_manifest.created_at = "2099-01-01T00:00:00Z"


def test_serialized_manifest_bytes_match_a_committed_fixture() -> None:
    """The serialized byte format must not drift, since a future signature would cover it."""
    fixed_manifest = manifest.build_manifest(
        created_at="2026-09-15T10:00:00Z",
        model=manifest.ModelInfo(
            source_repo="prajjwal1/bert-tiny", source_revision="deadbeef", task_hint="fill-mask"
        ),
        artifact=manifest.ArtifactInfo(
            version="1.0.0",
            path="versions/1.0.0/model.tar.enc",
            size_bytes=16,
            sha256="a" * 64,
            plaintext_sha256="b" * 64,
            plaintext_size_bytes=15,
        ),
        encryption=manifest.EncryptionInfo(
            algorithm="AES-256-GCM",
            kdf="HKDF-SHA256",
            chunk_size_bytes=4194304,
            format_version=1,
            key_id="model-encryption-key",
        ),
        producer=manifest.ProducerInfo(tool="model_pipeline", tool_version="0.1.0"),
    )

    expected = (
        b"{\n"
        b'  "artifact": {\n'
        b'    "path": "versions/1.0.0/model.tar.enc",\n'
        b'    "plaintext_sha256": "' + b"b" * 64 + b'",\n'
        b'    "plaintext_size_bytes": 15,\n'
        b'    "sha256": "' + b"a" * 64 + b'",\n'
        b'    "size_bytes": 16,\n'
        b'    "version": "1.0.0"\n'
        b"  },\n"
        b'  "created_at": "2026-09-15T10:00:00Z",\n'
        b'  "encryption": {\n'
        b'    "algorithm": "AES-256-GCM",\n'
        b'    "chunk_size_bytes": 4194304,\n'
        b'    "format_version": 1,\n'
        b'    "kdf": "HKDF-SHA256",\n'
        b'    "key_id": "model-encryption-key"\n'
        b"  },\n"
        b'  "manifest_version": "1.0",\n'
        b'  "model": {\n'
        b'    "source_repo": "prajjwal1/bert-tiny",\n'
        b'    "source_revision": "deadbeef",\n'
        b'    "task_hint": "fill-mask"\n'
        b"  },\n"
        b'  "producer": {\n'
        b'    "tool": "model_pipeline",\n'
        b'    "tool_version": "0.1.0"\n'
        b"  }\n"
        b"}"
    )

    assert manifest.serialize_manifest(fixed_manifest) == expected


def test_manifest_version_literal_matches_constant() -> None:
    """The Manifest.manifest_version Literal must stay in sync with const.MANIFEST_VERSION."""
    annotation = manifest.Manifest.model_fields["manifest_version"].annotation
    assert get_args(annotation) == (const.MANIFEST_VERSION,)
