"""Thin wrapper around ``huggingface_hub`` for the source model and the target artifact repo.

Isolating every Hugging Face Hub call behind this module keeps the network
and authentication surface in one place, and is what lets the rest of the
pipeline be tested against a mocked ``HfApi``/``snapshot_download`` instead
of the real network. A repository token, when required, is only ever passed
through to ``huggingface_hub``; it is never logged or included in any
returned value or exception message.
"""

from __future__ import annotations

import logging
from pathlib import Path

from huggingface_hub import HfApi, snapshot_download

import model_pipeline.constants as const

logger = logging.getLogger(__name__)


class HubError(Exception):
    """Raised when a Hugging Face Hub operation fails or returns an unusable result."""


def resolve_model_revision(repo_id: str, revision: str | None = None) -> str:
    """Resolve repo_id (at an optional revision) to its immutable commit SHA."""
    info = HfApi().model_info(repo_id, revision=revision)
    if info.sha is None:
        raise HubError(f"could not resolve a commit sha for {repo_id!r}")
    return info.sha


def download_model_snapshot(repo_id: str, revision: str, local_dir: Path) -> None:
    """Download the full snapshot of repo_id at revision into local_dir."""
    logger.info("downloading model snapshot: repo=%s revision=%s", repo_id, revision)
    snapshot_download(repo_id=repo_id, revision=revision, local_dir=str(local_dir))


def ensure_public_repo(repo_id: str, token: str) -> None:
    """Create repo_id as a public model repo if it does not already exist."""
    logger.info("ensuring target repo exists: repo=%s", repo_id)
    HfApi().create_repo(repo_id=repo_id, token=token, private=False, exist_ok=True)


def list_versions(repo_id: str) -> list[str]:
    """Return the sorted list of artifact versions published under repo_id."""
    prefix = f"{const.VERSIONS_PREFIX}/"
    suffix = f"/{const.MANIFEST_FILENAME}"
    files = HfApi().list_repo_files(repo_id)
    versions = {
        f[len(prefix) : -len(suffix)] for f in files if f.startswith(prefix) and f.endswith(suffix)
    }
    return sorted(versions)


def upload_artifact(
    repo_id: str, version: str, *, artifact_bytes: bytes, manifest_bytes: bytes, token: str
) -> None:
    """Upload the encrypted artifact and its manifest for version under repo_id."""
    logger.info("uploading artifact: repo=%s version=%s", repo_id, version)
    api = HfApi()
    api.upload_file(
        path_or_fileobj=artifact_bytes,
        path_in_repo=f"{const.VERSIONS_PREFIX}/{version}/{const.ARTIFACT_FILENAME}",
        repo_id=repo_id,
        token=token,
    )
    api.upload_file(
        path_or_fileobj=manifest_bytes,
        path_in_repo=f"{const.VERSIONS_PREFIX}/{version}/{const.MANIFEST_FILENAME}",
        repo_id=repo_id,
        token=token,
    )
