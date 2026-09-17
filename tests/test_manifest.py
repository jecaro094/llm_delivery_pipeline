"""Tests for manifest construction, serialization, and integrity verification."""

from __future__ import annotations

import base64

import pytest
import tests.constants as test_const

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
        signature=manifest.SignatureInfo(
            algorithm="Ed25519",
            public_key_sha256="ab" * 32,
            signature_path="versions/1.0.0/manifest.json.sig",
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

    with pytest.raises(manifest.ManifestError):
        manifest.verify_artifact_sha256(sample_manifest, b"different-ciphertext-bytes")


def test_verify_plaintext_sha256_detects_mismatch() -> None:
    """An incorrect or incomplete decryption must fail plaintext_sha256 verification."""
    sample_manifest = _build_sample_manifest(b"ciphertext-bytes", b"plaintext-bytes")

    with pytest.raises(manifest.ManifestError):
        manifest.verify_plaintext_sha256(sample_manifest, b"different-plaintext-bytes")


def test_serialized_manifest_never_contains_the_encryption_key() -> None:
    """The manifest is a plaintext, public document and must never embed key material."""
    sample_manifest = _build_sample_manifest(b"ciphertext-bytes", b"plaintext-bytes")
    serialized = manifest.serialize_manifest(sample_manifest)

    key_b64 = base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    assert test_const.TEST_MASTER_KEY.hex() not in serialized.decode("utf-8")
    assert key_b64 not in serialized.decode("utf-8")


def test_manifest_has_a_well_formed_signature_section_with_no_signature_bytes() -> None:
    """The signature section carries only labels: no private key and no signature bytes.

    The manifest is the payload a signature covers, so a field containing
    its own signature would be circular; the signature is published as a
    separate, detached file instead.
    """
    sample_manifest = _build_sample_manifest(b"ciphertext-bytes", b"plaintext-bytes")
    serialized = manifest.serialize_manifest(sample_manifest)

    assert sample_manifest["signature"]["algorithm"] == "Ed25519"
    assert len(sample_manifest["signature"]["public_key_sha256"]) == 64
    assert test_const.TEST_SIGNING_PRIVATE_KEY_PEM not in serialized
    assert test_const.TEST_SIGNING_PUBLIC_KEY_PEM not in serialized


def test_deserialize_rejects_unknown_manifest_version() -> None:
    """A manifest with an unrecognized manifest_version must be rejected, not silently accepted."""
    sample_manifest = _build_sample_manifest(b"ciphertext-bytes", b"plaintext-bytes")
    tampered = dict(sample_manifest)
    tampered["manifest_version"] = "99.0"
    tampered_bytes = manifest.serialize_manifest(tampered)  # type: ignore[arg-type]

    with pytest.raises(manifest.ManifestError):
        manifest.deserialize_manifest(tampered_bytes)


def test_deserialize_rejects_the_pre_signing_manifest_version() -> None:
    """A Layer 1 manifest (manifest_version 1.0, no signature section) must be rejected.

    A signing-aware consumer must refuse to fall back to an unsigned
    manifest rather than silently skip verification.
    """
    sample_manifest = _build_sample_manifest(b"ciphertext-bytes", b"plaintext-bytes")
    tampered = dict(sample_manifest)
    tampered["manifest_version"] = "1.0"
    tampered_bytes = manifest.serialize_manifest(tampered)  # type: ignore[arg-type]

    with pytest.raises(manifest.ManifestError):
        manifest.deserialize_manifest(tampered_bytes)


def test_deserialize_rejects_invalid_json() -> None:
    """Malformed JSON must raise ManifestError rather than an unrelated exception."""
    with pytest.raises(manifest.ManifestError):
        manifest.deserialize_manifest(b"not json")
