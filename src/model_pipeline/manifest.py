"""Construction, serialization, and integrity verification of the artifact manifest.

The manifest is published alongside the encrypted artifact on Hugging Face
Hub and never contains any cryptographic material: no key, no derived key,
and no nonce, only labels and hashes. A consumer verifies the artifact's
``sha256`` before decrypting (catching corruption or tampering in transit)
and the ``plaintext_sha256`` after decrypting (catching an incorrect or
incomplete decryption).

The manifest is the one place in this project that parses externally
supplied structured data -- a file downloaded from a public Hugging Face
repo -- so it is modeled with ``pydantic`` rather than a hand-rolled
``TypedDict`` + ``cast``: a malformed or tampered manifest is rejected at
parse time, with a message naming the offending field, instead of failing
later as an opaque ``KeyError``/``TypeError`` deep inside the consumer flow.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

_MODEL_CONFIG = ConfigDict(extra="forbid", frozen=True)


class ManifestError(Exception):
    """Raised when a manifest fails schema validation or an integrity check."""


class ModelInfo(BaseModel):
    """Provenance of the plaintext model that was packaged into the artifact."""

    model_config = _MODEL_CONFIG

    source_repo: str
    source_revision: str
    task_hint: str


class ArtifactInfo(BaseModel):
    """Identity, location, and integrity hashes of one published artifact version."""

    model_config = _MODEL_CONFIG

    version: str
    path: str
    size_bytes: int
    sha256: str
    plaintext_sha256: str
    plaintext_size_bytes: int


class EncryptionInfo(BaseModel):
    """Labels describing how the artifact was encrypted, without any key material."""

    model_config = _MODEL_CONFIG

    algorithm: str
    kdf: str
    chunk_size_bytes: int
    format_version: int
    key_id: str


class ProducerInfo(BaseModel):
    """Identity of the tool that produced the manifest."""

    model_config = _MODEL_CONFIG

    tool: str
    tool_version: str


class SignatureInfo(BaseModel):
    """Labels describing how the manifest itself was signed, without the signature bytes.

    The signature cannot live in this section: the manifest is the signed
    payload, so a field containing its own signature would be circular. The
    signature is published as a separate, detached file instead (see
    ``constants.SIGNATURE_FILENAME``).
    """

    model_config = _MODEL_CONFIG

    algorithm: str
    public_key_sha256: str
    signature_path: str


class Manifest(BaseModel):
    """Full manifest published next to an encrypted artifact.

    Immutable (``frozen=True``) once parsed or built, since every caller
    already treats a manifest as a value it reads, never mutates, and
    rejects any unexpected top-level field (``extra="forbid"``) instead of
    silently ignoring it.
    """

    model_config = _MODEL_CONFIG

    # Kept in sync with const.MANIFEST_VERSION by test_manifest_version_literal_matches_constant.
    manifest_version: Literal["2.0"]
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
        manifest_version="2.0",
        created_at=created_at,
        model=model,
        artifact=artifact,
        encryption=encryption,
        signature=signature,
        producer=producer,
    )


def serialize_manifest(manifest: Manifest) -> bytes:
    """Serialize a manifest to canonical, sorted-key, indented JSON bytes."""
    return json.dumps(manifest.model_dump(mode="json"), sort_keys=True, indent=2).encode("utf-8")


def deserialize_manifest(data: bytes) -> Manifest:
    """Parse manifest JSON bytes, rejecting invalid JSON or a manifest that fails validation.

    Covers malformed JSON, a missing or mistyped field, an unexpected extra
    field, and an unsupported ``manifest_version`` -- every rejection names
    the offending field in the raised ManifestError.
    """
    try:
        return Manifest.model_validate_json(data)
    except ValidationError as exc:
        raise ManifestError(f"invalid manifest: {exc}") from exc


def verify_artifact_sha256(manifest: Manifest, artifact_bytes: bytes) -> None:
    """Raise ManifestError unless artifact_bytes matches the manifest's recorded sha256.

    Intended to run before decryption, to catch corruption or tampering of
    the encrypted artifact in transit.
    """
    expected = manifest.artifact.sha256
    actual = compute_sha256(artifact_bytes)
    if actual != expected:
        raise ManifestError(f"artifact sha256 mismatch: expected {expected}, got {actual}")


def verify_plaintext_sha256(manifest: Manifest, plaintext_bytes: bytes) -> None:
    """Raise ManifestError unless plaintext_bytes matches the manifest's recorded plaintext_sha256.

    Intended to run after decryption, to catch an incorrect or incomplete
    decryption that would otherwise pass silently.
    """
    expected = manifest.artifact.plaintext_sha256
    actual = compute_sha256(plaintext_bytes)
    if actual != expected:
        raise ManifestError(f"plaintext sha256 mismatch: expected {expected}, got {actual}")
