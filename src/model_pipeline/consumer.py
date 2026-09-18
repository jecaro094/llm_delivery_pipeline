"""Consumer orchestration: download, verify, decrypt, and unpack the model artifact.

Ties together ``hub`` (network I/O), ``signing`` (signature verification),
``manifest`` (integrity metadata), ``crypto`` (decryption), and ``packaging``
(tar) into the flow the consumer side follows: download the manifest and its
detached signature, verify the signature *before*
parsing the manifest or touching the decryption key, then download the
encrypted artifact, verify the artifact hash before decrypting and the
plaintext hash after, and unpack the recovered model snapshot into a working
directory. Loading the model into memory and running an inference smoke test
are handled separately by :func:`load_and_predict`, so that the network and
cryptographic flow in :func:`consume` stays testable without pulling
``transformers``/``torch`` into the test environment.
"""

from __future__ import annotations

import logging
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import model_pipeline.constants as const
from model_pipeline import crypto, hub, packaging, signing
from model_pipeline.hub import HubError
from model_pipeline.manifest import (
    Manifest,
    deserialize_manifest,
    verify_artifact_sha256,
    verify_plaintext_sha256,
)
from model_pipeline.prompt import PromptError, prompt_for_value
from model_pipeline.signing import SignatureError

logger = logging.getLogger(__name__)


class ConsumerError(Exception):
    """Raised when the consumer flow cannot proceed: a failed verification, a key_id mismatch,
    or a failed decryption."""


def consume(
    *,
    repo_id: str,
    version: str,
    master_key: bytes,
    public_key: Ed25519PublicKey,
    workdir: Path,
    expected_key_id: str = const.DEFAULT_KEY_ID,
) -> Manifest:
    """Verify, download, decrypt, and unpack the artifact for version into workdir.

    Returns the manifest once the recovered model snapshot has been fully
    unpacked into workdir. Raises ConsumerError on a failed signature
    verification, a key_id mismatch, or a decryption failure (most likely
    the wrong key); a corrupted or tampered artifact instead raises
    ``manifest.ManifestError`` from the sha256 checks. The signature is
    checked before the artifact is downloaded and before the decryption key
    is read, so a run against a tampered repo never touches either.
    """
    artifact_manifest = _download_and_verify_manifest(repo_id, version, public_key)
    actual_key_id = artifact_manifest.encryption.key_id
    if actual_key_id != expected_key_id:
        raise ConsumerError(
            f"key_id mismatch: manifest expects {actual_key_id!r}, consumer has {expected_key_id!r}"
        )
    logger.info("key_id checked: key_id=%s", actual_key_id)
    plaintext_tar = _download_and_decrypt(repo_id, version, artifact_manifest, master_key)
    packaging.unpack_archive(plaintext_tar, workdir)
    logger.info("unpacked model snapshot into %s", workdir)
    return artifact_manifest


def verify_published_version(
    *, repo_id: str, version: str, public_key: Ed25519PublicKey
) -> Manifest:
    """Verify a published version's signature, needing neither the decryption key nor a Hub token.

    This is the standalone counterpart of the signature check :func:`consume`
    performs internally, exposed so that anyone -- not only a party holding
    the decryption key -- can check that a published artifact's manifest was
    signed by the expected producer.
    """
    return _download_and_verify_manifest(repo_id, version, public_key)


def _download_and_verify_manifest(
    repo_id: str, version: str, public_key: Ed25519PublicKey
) -> Manifest:
    """Download the manifest and its detached signature, verify, and cross-check consistency.

    Verification runs on the raw downloaded bytes, before they are parsed as
    JSON: the signature covers the bytes as published, so there is no reason
    to accept the small extra attack surface of parsing attacker-supplied
    JSON before it is authenticated. Two cheap cross-checks run afterwards --
    the signed ``artifact.version`` against the version requested, and the
    signed ``signature.public_key_sha256`` against the fingerprint of the key
    that was actually used -- but neither of them ever chooses *which* key
    verifies the signature: that is always the mounted public_key, never a
    value read from the manifest itself.
    """
    try:
        manifest_bytes = hub.download_manifest(repo_id, version)
        signature_bytes = hub.download_signature(repo_id, version)
    except HubError as exc:
        raise ConsumerError(str(exc)) from exc
    logger.info("manifest and signature fetched: repo=%s version=%s", repo_id, version)

    try:
        signing.verify(manifest_bytes, signature_bytes, public_key)
    except SignatureError as exc:
        raise ConsumerError(f"signature verification failed: {exc}") from exc
    logger.info("signature verified: repo=%s version=%s", repo_id, version)

    artifact_manifest = deserialize_manifest(manifest_bytes)

    actual_version = artifact_manifest.artifact.version
    if actual_version != version:
        raise ConsumerError(
            f"version mismatch: manifest is signed for {actual_version!r}, requested {version!r}"
        )

    expected_fingerprint = signing.public_key_fingerprint(public_key)
    signed_fingerprint = artifact_manifest.signature.public_key_sha256
    if signed_fingerprint != expected_fingerprint:
        raise ConsumerError(
            "signing key fingerprint mismatch: the manifest names a different public key than "
            f"the one mounted (mounted key fingerprint {expected_fingerprint!r}, "
            f"manifest names {signed_fingerprint!r})"
        )

    return artifact_manifest


def _download_and_decrypt(
    repo_id: str, version: str, artifact_manifest: Manifest, master_key: bytes
) -> bytes:
    """Download the encrypted artifact, verify its hash, decrypt it, and verify the plaintext."""
    try:
        encrypted_container = hub.download_artifact(repo_id, version)
    except HubError as exc:
        raise ConsumerError(str(exc)) from exc
    verify_artifact_sha256(artifact_manifest, encrypted_container)
    logger.info("artifact sha256 verified: repo=%s version=%s", repo_id, version)
    try:
        plaintext_tar = crypto.decrypt(encrypted_container, master_key)
    except crypto.DecryptionError as exc:
        raise ConsumerError(f"decryption failed, likely the wrong key: {exc}") from exc
    logger.info("artifact decrypted: repo=%s version=%s", repo_id, version)
    verify_plaintext_sha256(artifact_manifest, plaintext_tar)
    logger.info("plaintext sha256 verified: repo=%s version=%s", repo_id, version)
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
    try:
        published_versions = hub.list_versions(repo_id)
    except HubError as exc:
        raise ConsumerError(str(exc)) from exc
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

    logger.warning(message)
    latest = published_versions[-1]

    def invalid_message(candidate: str) -> str:
        """Explain that candidate is not among published_versions."""
        return f"version {candidate!r} is not published in {repo_id!r}; try another"

    try:
        return prompt_for_value(
            prompt=f"Enter a published version to consume [{latest}]: ",
            default=latest,
            is_valid=lambda candidate: candidate in published_versions,
            invalid_message=invalid_message,
        )
    except PromptError as exc:
        raise ConsumerError(str(exc)) from exc


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
    assert fill_mask.tokenizer is not None  # noqa: S101 -- always set for a fill-mask pipeline
    mask_token = fill_mask.tokenizer.mask_token
    predictions = fill_mask(f"Paris is the {mask_token} of France.")
    return ", ".join(
        f"{prediction['token_str']!r} ({prediction['score']:.3f})" for prediction in predictions
    )
