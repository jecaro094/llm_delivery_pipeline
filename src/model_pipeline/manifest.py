"""Construction, serialization, and integrity verification of the artifact manifest.

The manifest is published alongside the encrypted artifact on Hugging Face
Hub and never contains any cryptographic material: no key, no derived key,
and no nonce, only labels and hashes. A consumer verifies the artifact's
``sha256`` before decrypting (catching corruption or tampering in transit)
and the ``plaintext_sha256`` after decrypting (catching an incorrect or
incomplete decryption).
"""

from __future__ import annotations

import hashlib
import json
from typing import TypedDict, cast

import model_pipeline.constants as const


class ManifestError(Exception):
    """Raised when a manifest fails schema validation or an integrity check."""


class ModelInfo(TypedDict):
    """Provenance of the plaintext model that was packaged into the artifact."""

    source_repo: str
    source_revision: str
    task_hint: str


class ArtifactInfo(TypedDict):
    """Identity, location, and integrity hashes of one published artifact version."""

    version: str
    path: str
    size_bytes: int
    sha256: str
    plaintext_sha256: str
    plaintext_size_bytes: int


class EncryptionInfo(TypedDict):
    """Labels describing how the artifact was encrypted, without any key material."""

    algorithm: str
    kdf: str
    chunk_size_bytes: int
    format_version: int
    key_id: str


class ProducerInfo(TypedDict):
    """Identity of the tool that produced the manifest."""

    tool: str
    tool_version: str


class SignatureInfo(TypedDict):
    """Labels describing how the manifest itself was signed, without the signature bytes.

    The signature cannot live in this section: the manifest is the signed
    payload, so a field containing its own signature would be circular. The
    signature is published as a separate, detached file instead (see
    ``constants.SIGNATURE_FILENAME``).
    """

    algorithm: str
    public_key_sha256: str
    signature_path: str


class Manifest(TypedDict):
    """Full manifest published next to an encrypted artifact."""

    manifest_version: str
    created_at: str
    model: ModelInfo
    artifact: ArtifactInfo
    encryption: EncryptionInfo
    signature: SignatureInfo
    producer: ProducerInfo


def compute_sha256(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of data."""
    return hashlib.sha256(data).hexdigest()


def build_manifest(
    *,
    created_at: str,
    model: ModelInfo,
    artifact: ArtifactInfo,
    encryption: EncryptionInfo,
    signature: SignatureInfo,
    producer: ProducerInfo,
) -> Manifest:
    """Assemble a manifest from its sections, stamping the current manifest schema version."""
    return Manifest(
        manifest_version=const.MANIFEST_VERSION,
        created_at=created_at,
        model=model,
        artifact=artifact,
        encryption=encryption,
        signature=signature,
        producer=producer,
    )


def serialize_manifest(manifest: Manifest) -> bytes:
    """Serialize a manifest to canonical, sorted-key, indented JSON bytes."""
    return json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8")


def deserialize_manifest(data: bytes) -> Manifest:
    """Parse manifest JSON bytes, rejecting invalid JSON or an unsupported manifest_version."""
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ManifestError("invalid manifest JSON") from exc

    manifest_version = parsed.get("manifest_version")
    if manifest_version != const.MANIFEST_VERSION:
        raise ManifestError(f"unsupported manifest_version {manifest_version!r}")

    return cast(Manifest, parsed)


def verify_artifact_sha256(manifest: Manifest, artifact_bytes: bytes) -> None:
    """Raise ManifestError unless artifact_bytes matches the manifest's recorded sha256.

    Intended to run before decryption, to catch corruption or tampering of
    the encrypted artifact in transit.
    """
    expected = manifest["artifact"]["sha256"]
    actual = compute_sha256(artifact_bytes)
    if actual != expected:
        raise ManifestError(f"artifact sha256 mismatch: expected {expected}, got {actual}")


def verify_plaintext_sha256(manifest: Manifest, plaintext_bytes: bytes) -> None:
    """Raise ManifestError unless plaintext_bytes matches the manifest's recorded plaintext_sha256.

    Intended to run after decryption, to catch an incorrect or incomplete
    decryption that would otherwise pass silently.
    """
    expected = manifest["artifact"]["plaintext_sha256"]
    actual = compute_sha256(plaintext_bytes)
    if actual != expected:
        raise ManifestError(f"plaintext sha256 mismatch: expected {expected}, got {actual}")
