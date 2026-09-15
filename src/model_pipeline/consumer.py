"""Consumer orchestration: download, verify, decrypt, and unpack the model artifact.

Ties together ``hub`` (network I/O), ``manifest`` (integrity metadata),
``crypto`` (decryption), and ``packaging`` (tar) into the flow the enunciado
describes for the consumer side: download the encrypted artifact and its
manifest from Hugging Face Hub, verify the artifact hash before decrypting
and the plaintext hash after, and unpack the recovered model snapshot into a
working directory. Loading the model into memory and running an inference
smoke test are handled separately by :func:`load_and_predict`, so that the
network and cryptographic flow in :func:`consume` stays testable without
pulling ``transformers``/``torch`` into the test environment.
"""

from __future__ import annotations

from pathlib import Path

import model_pipeline.constants as const
from model_pipeline import crypto, hub, packaging
from model_pipeline.manifest import (
    Manifest,
    deserialize_manifest,
    verify_artifact_sha256,
    verify_plaintext_sha256,
)


class ConsumerError(Exception):
    """Raised when the consumer flow cannot proceed: a key_id mismatch or a failed decryption."""


def consume(
    *,
    repo_id: str,
    version: str,
    master_key: bytes,
    workdir: Path,
    expected_key_id: str = const.DEFAULT_KEY_ID,
) -> Manifest:
    """Download, verify, decrypt, and unpack the artifact for version into workdir.

    Returns the manifest once the recovered model snapshot has been fully
    unpacked into workdir. Raises ConsumerError on a key_id mismatch or a
    decryption failure (most likely the wrong key); a corrupted or tampered
    artifact instead raises ``manifest.ManifestError`` from the sha256 checks.
    """
    artifact_manifest = _fetch_and_check_manifest(repo_id, version, expected_key_id)
    plaintext_tar = _download_and_decrypt(repo_id, version, artifact_manifest, master_key)
    packaging.unpack_archive(plaintext_tar, workdir)
    return artifact_manifest


def _fetch_and_check_manifest(repo_id: str, version: str, expected_key_id: str) -> Manifest:
    """Download the manifest for version and reject it early if its key_id label is unexpected.

    This check runs before any network transfer of the (potentially large)
    encrypted artifact or any decryption attempt: a key_id mismatch means the
    consumer is looking at the wrong Secret, so failing fast here saves the
    cost of downloading and attempting to decrypt with a key that is already
    known to be the wrong one.
    """
    manifest_bytes = hub.download_manifest(repo_id, version)
    artifact_manifest = deserialize_manifest(manifest_bytes)
    actual_key_id = artifact_manifest["encryption"]["key_id"]
    if actual_key_id != expected_key_id:
        raise ConsumerError(
            f"key_id mismatch: manifest expects {actual_key_id!r}, consumer has {expected_key_id!r}"
        )
    return artifact_manifest


def _download_and_decrypt(
    repo_id: str, version: str, artifact_manifest: Manifest, master_key: bytes
) -> bytes:
    """Download the encrypted artifact, verify its hash, decrypt it, and verify the plaintext."""
    encrypted_container = hub.download_artifact(repo_id, version)
    verify_artifact_sha256(artifact_manifest, encrypted_container)
    try:
        plaintext_tar = crypto.decrypt(encrypted_container, master_key)
    except crypto.DecryptionError as exc:
        raise ConsumerError(f"decryption failed, likely the wrong key: {exc}") from exc
    verify_plaintext_sha256(artifact_manifest, plaintext_tar)
    return plaintext_tar


def load_and_predict(workdir: Path, task_hint: str) -> str:
    """Load the decrypted model from workdir and run a single smoke-test prediction.

    Only the "fill-mask" task hint is supported, matching the pipeline's
    default source model. ``transformers`` is imported lazily here, on the
    smoke-test path only, so that :func:`consume` never needs it installed.
    """
    if task_hint != const.DEFAULT_TASK_HINT:
        raise ConsumerError(f"unsupported task hint for smoke test: {task_hint!r}")

    from transformers import pipeline

    fill_mask = pipeline("fill-mask", model=str(workdir))
    mask_token = fill_mask.tokenizer.mask_token
    predictions = fill_mask(f"Paris is the {mask_token} of France.")
    return ", ".join(
        f"{prediction['token_str']!r} ({prediction['score']:.3f})" for prediction in predictions
    )
