"""Producer orchestration: download the source model, encrypt it, and publish it.

Ties together ``hub`` (network I/O), ``packaging`` (tar), ``crypto``
(encryption), and ``manifest`` (integrity metadata) into the single flow the
enunciado describes for the producer side: download the open model, encrypt
it, upload the encrypted artifact to Hugging Face Hub, and hand back the
manifest that was published alongside it.
"""

from __future__ import annotations

import json
import sys
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
    versions are immutable once published. The downloaded snapshot is also
    rejected before encryption if its architecture cannot be auto-detected
    (see :func:`_validate_model_type`).
    """
    hub.ensure_public_repo(target_repo, token=hf_token)
    existing_versions = hub.list_versions(target_repo)
    if version in existing_versions:
        raise ProducerError(_version_exists_message(version, target_repo, existing_versions))

    with tempfile.TemporaryDirectory(prefix="model-pipeline-produce-") as raw_workdir:
        workdir = Path(raw_workdir)
        resolved_revision = hub.resolve_model_revision(source_model)
        hub.download_model_snapshot(source_model, resolved_revision, workdir)
        _validate_model_type(workdir, source_model)
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


def resolve_produce_version(target_repo: str, version: str, *, interactive: bool) -> str:
    """Return a version confirmed not to already exist in target_repo.

    Looks up the versions already published under target_repo. If version
    is free, it is returned unchanged. If it is already taken and
    interactive is True, prompts on the terminal for a replacement
    (suggesting the next available version, see suggest_next_version),
    looping until a free one is entered. If interactive is False -- e.g.
    running unattended inside a Kubernetes Job, or from scripts/demo.sh's
    preflight check -- raises ProducerError describing the conflict instead
    of blocking on input that will never arrive, exactly like produce()
    itself already does.
    """
    existing_versions = hub.list_versions(target_repo)
    if version not in existing_versions:
        return version
    if not interactive:
        raise ProducerError(_version_exists_message(version, target_repo, existing_versions))

    print(_version_exists_message(version, target_repo, existing_versions), file=sys.stderr)
    suggestion = suggest_next_version(existing_versions)
    while True:
        hint = f" [{suggestion}]" if suggestion else ""
        print(f"Enter a version to publish under {target_repo!r}{hint}: ", end="", file=sys.stderr)
        sys.stderr.flush()
        candidate = input().strip() or suggestion
        if not candidate:
            print("a version is required", file=sys.stderr)
            continue
        if candidate not in existing_versions:
            return candidate
        print(
            f"version {candidate!r} already exists in {target_repo!r}; try another",
            file=sys.stderr,
        )


def _version_exists_message(version: str, target_repo: str, existing_versions: list[str]) -> str:
    """Build the error message for a rejected produce() call over an already-published version.

    Artifact versions are immutable once published (see PLAN.md, decision
    7), so this never resolves the conflict automatically; it only points
    the operator at a version they can pass explicitly on retry.
    """
    message = f"version {version!r} already exists in {target_repo!r}"
    suggestion = suggest_next_version(existing_versions)
    if suggestion is not None:
        message += f"; the next available version looks like {suggestion!r}"
    return message


def suggest_next_version(existing_versions: list[str]) -> str | None:
    """Return a patch-bump one past the highest dotted-integer version in existing_versions.

    Returns None when none of existing_versions parses as dotted integers
    (including an empty list), since guessing a bump from a versioning
    scheme this code does not understand would be misleading rather than
    helpful.
    """
    parsed_versions = []
    for candidate in existing_versions:
        parts = candidate.split(".")
        if parts and all(part.isdigit() for part in parts):
            parsed_versions.append(tuple(int(part) for part in parts))
    if not parsed_versions:
        return None

    latest = max(parsed_versions)
    bumped = (*latest[:-1], latest[-1] + 1)
    return ".".join(str(part) for part in bumped)


def _validate_model_type(workdir: Path, source_model: str) -> None:
    """Reject source_model if its downloaded config.json has no model_type key.

    Without model_type, transformers cannot auto-detect the model's
    architecture; that failure would otherwise only surface later, in the
    consumer, after the artifact has already been encrypted and published.
    Failing here, while the plaintext snapshot in workdir is still around
    to inspect, is cheaper and gives a clearer error than that.
    """
    config_path = workdir / const.MODEL_CONFIG_FILENAME
    if not config_path.is_file():
        raise ProducerError(
            f"{source_model!r} has no {const.MODEL_CONFIG_FILENAME}: "
            "cannot validate its architecture"
        )

    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ProducerError(
            f"{source_model!r}'s {const.MODEL_CONFIG_FILENAME} is not valid JSON"
        ) from exc

    if const.MODEL_TYPE_KEY not in config:
        raise ProducerError(
            f"{source_model!r}'s {const.MODEL_CONFIG_FILENAME} has no {const.MODEL_TYPE_KEY!r} "
            "key, so transformers cannot auto-detect its architecture; pick a different source "
            "model whose config.json declares it"
        )
