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

import sys
from pathlib import Path

import model_pipeline.constants as const
from model_pipeline import crypto, hub, packaging
from model_pipeline.hub import HubError
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
    try:
        manifest_bytes = hub.download_manifest(repo_id, version)
    except HubError as exc:
        raise ConsumerError(str(exc)) from exc
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


def resolve_consume_version(repo_id: str, version: str, *, interactive: bool) -> str:
    """Return a version confirmed to be published under repo_id.

    Looks up the versions already published under repo_id. If version is
    among them, it is returned unchanged. If it is not, and interactive is
    True, prompts on the terminal for one of the published versions,
    looping until a published one is entered. If interactive is False --
    e.g. running unattended inside a Kubernetes Pod, or from
    scripts/demo.sh's preflight check -- raises ConsumerError describing
    the mismatch instead of blocking on input that will never arrive.
    """
    published_versions = hub.list_versions(repo_id)
    if version in published_versions:
        return version
    if not published_versions:
        raise ConsumerError(f"{repo_id!r} has no published artifact versions")

    message = (
        f"version {version!r} is not published in {repo_id!r}; "
        f"published versions: {', '.join(published_versions)}"
    )
    if not interactive:
        raise ConsumerError(message)

    print(message, file=sys.stderr)
    latest = published_versions[-1]
    while True:
        print(f"Enter a published version to consume [{latest}]: ", end="", file=sys.stderr)
        sys.stderr.flush()
        candidate = input().strip() or latest
        if candidate in published_versions:
            return candidate
        print(
            f"version {candidate!r} is not published in {repo_id!r}; try another",
            file=sys.stderr,
        )


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
