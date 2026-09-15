"""Producer orchestration: download the source model, encrypt it, and publish it.

Ties together ``hub`` (network I/O), ``packaging`` (tar), ``crypto``
(encryption), and ``manifest`` (integrity metadata) into the single flow the
enunciado describes for the producer side: download the open model, encrypt
it, upload the encrypted artifact to Hugging Face Hub, and hand back the
manifest that was published alongside it.
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path

import model_pipeline.constants as const
from model_pipeline import __version__, crypto, hub, packaging
from model_pipeline.manifest import (
    ArtifactInfo,
    EncryptionInfo,
    Manifest,
    ModelInfo,
    ProducerInfo,
    build_manifest,
    compute_sha256,
    serialize_manifest,
)


class ProducerError(Exception):
    """Raised when the producer flow cannot proceed, e.g. a version already exists."""


def produce(
    *,
    source_model: str,
    target_repo: str,
    version: str,
    master_key: bytes,
    hf_token: str,
    chunk_size: int = const.DEFAULT_CHUNK_SIZE,
    task_hint: str = const.DEFAULT_TASK_HINT,
) -> Manifest:
    """Run the full producer flow and return the manifest published for version.

    The target repo is created as a public repo if it does not exist yet,
    and publishing a version that already exists is refused: artifact
    versions are immutable once published.
    """
    hub.ensure_public_repo(target_repo, token=hf_token)
    if version in hub.list_versions(target_repo):
        raise ProducerError(f"version {version!r} already exists in {target_repo!r}")

    with tempfile.TemporaryDirectory(prefix="model-pipeline-produce-") as raw_workdir:
        workdir = Path(raw_workdir)
        resolved_revision = hub.resolve_model_revision(source_model)
        hub.download_model_snapshot(source_model, resolved_revision, workdir)
        plaintext_tar = packaging.pack_directory(workdir)

    encrypted_container = crypto.encrypt(plaintext_tar, master_key, chunk_size=chunk_size)

    artifact_manifest = build_manifest(
        created_at=datetime.now(UTC).isoformat(),
        model=ModelInfo(
            source_repo=source_model, source_revision=resolved_revision, task_hint=task_hint
        ),
        artifact=ArtifactInfo(
            version=version,
            path=f"{const.VERSIONS_PREFIX}/{version}/{const.ARTIFACT_FILENAME}",
            size_bytes=len(encrypted_container),
            sha256=compute_sha256(encrypted_container),
            plaintext_sha256=compute_sha256(plaintext_tar),
            plaintext_size_bytes=len(plaintext_tar),
        ),
        encryption=EncryptionInfo(
            algorithm=const.ALGORITHM_LABEL,
            kdf=const.KDF_LABEL,
            chunk_size_bytes=chunk_size,
            format_version=const.FORMAT_VERSION,
            key_id=const.DEFAULT_KEY_ID,
        ),
        producer=ProducerInfo(tool=const.TOOL_NAME, tool_version=__version__),
    )

    hub.upload_artifact(
        target_repo,
        version,
        artifact_bytes=encrypted_container,
        manifest_bytes=serialize_manifest(artifact_manifest),
        token=hf_token,
    )

    return artifact_manifest
