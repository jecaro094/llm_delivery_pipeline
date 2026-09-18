"""Thin wrapper around ``huggingface_hub`` for the source model and the target artifact repo.

Isolating every Hugging Face Hub call behind this module keeps the network
and authentication surface in one place, and is what lets the rest of the
pipeline be tested against a mocked ``HfApi``/``snapshot_download``/
``hf_hub_download`` instead of the real network. A repository token, when
required, is only ever passed through to ``huggingface_hub``; it is never
logged or included in any returned value or exception message. The consumer
side never passes a token at all: the target artifact repo is public, so
downloading the manifest and the encrypted artifact needs no authentication.
"""

from __future__ import annotations

import logging
from pathlib import Path

from huggingface_hub import HfApi, get_token, hf_hub_download, snapshot_download
from huggingface_hub.errors import EntryNotFoundError, HfHubHTTPError, RepositoryNotFoundError

import model_pipeline.constants as const

logger = logging.getLogger(__name__)


class HubError(Exception):
    """Raised when a Hugging Face Hub operation fails or returns an unusable result."""


def get_cached_token() -> str | None:
    """Return the token cached locally by `hf auth login`, if any, or None.

    Isolated behind this module, like every other huggingface_hub call, so
    keys.py -- where the rest of the token/key resolution logic lives --
    stays free of any huggingface_hub dependency.
    """
    return get_token()


def resolve_model_revision(repo_id: str, revision: str | None = None) -> str:
    """Resolve repo_id (at an optional revision) to its immutable commit SHA."""
    try:
        info = HfApi().model_info(repo_id, revision=revision)
    except HfHubHTTPError as exc:
        raise HubError(f"could not resolve a revision for {repo_id!r}: {exc}") from exc
    if info.sha is None:
        raise HubError(f"could not resolve a commit sha for {repo_id!r}")
    return info.sha


def download_model_snapshot(repo_id: str, revision: str, local_dir: Path) -> None:
    """Download the full snapshot of repo_id at revision into local_dir."""
    logger.info("downloading model snapshot: repo=%s revision=%s", repo_id, revision)
    try:
        snapshot_download(repo_id=repo_id, revision=revision, local_dir=str(local_dir))
    except HfHubHTTPError as exc:
        raise HubError(
            f"could not download the snapshot for {repo_id!r} at {revision!r}: {exc}"
        ) from exc


def ensure_public_repo(repo_id: str, token: str) -> None:
    """Create repo_id as a public model repo if it does not already exist."""
    logger.info("ensuring target repo exists: repo=%s", repo_id)
    try:
        HfApi().create_repo(repo_id=repo_id, token=token, private=False, exist_ok=True)
    except HfHubHTTPError as exc:
        raise HubError(f"could not create or access the repo {repo_id!r}: {exc}") from exc


def list_versions(repo_id: str) -> list[str]:
    """Return the sorted list of artifact versions published under repo_id.

    Returns an empty list, rather than raising, when repo_id does not exist
    yet: every caller of this function treats "the repo was never created"
    the same as "nothing has been published there".
    """
    prefix = f"{const.VERSIONS_PREFIX}/"
    suffix = f"/{const.MANIFEST_FILENAME}"
    try:
        files = HfApi().list_repo_files(repo_id)
    except RepositoryNotFoundError:
        return []
    except HfHubHTTPError as exc:
        raise HubError(f"could not list published versions for {repo_id!r}: {exc}") from exc
    versions = {
        f[len(prefix) : -len(suffix)] for f in files if f.startswith(prefix) and f.endswith(suffix)
    }
    return sorted(versions)


def upload_artifact(
    repo_id: str,
    version: str,
    *,
    artifact_bytes: bytes,
    signature_bytes: bytes,
    manifest_bytes: bytes,
    token: str,
) -> None:
    """Upload the encrypted artifact, its signature, and its manifest for version under repo_id.

    Uploaded in that order deliberately: the manifest is what a consumer
    reads first and fails closed on if it, or its signature, is missing, so
    uploading it last means an upload interrupted partway through (these are
    three separate, non-atomic calls) looks like "version not published
    yet" rather than "version published but unverifiable".
    """
    logger.info("uploading artifact: repo=%s version=%s", repo_id, version)
    api = HfApi()
    try:
        api.upload_file(
            path_or_fileobj=artifact_bytes,
            path_in_repo=f"{const.VERSIONS_PREFIX}/{version}/{const.ARTIFACT_FILENAME}",
            repo_id=repo_id,
            token=token,
        )
        api.upload_file(
            path_or_fileobj=signature_bytes,
            path_in_repo=f"{const.VERSIONS_PREFIX}/{version}/{const.SIGNATURE_FILENAME}",
            repo_id=repo_id,
            token=token,
        )
        api.upload_file(
            path_or_fileobj=manifest_bytes,
            path_in_repo=f"{const.VERSIONS_PREFIX}/{version}/{const.MANIFEST_FILENAME}",
            repo_id=repo_id,
            token=token,
        )
    except HfHubHTTPError as exc:
        raise HubError(
            f"could not upload the artifact for {repo_id!r} version {version!r}: {exc}"
        ) from exc


def download_manifest(repo_id: str, version: str) -> bytes:
    """Download and return the raw manifest.json bytes published for version under repo_id.

    Raises HubError, instead of leaking the underlying huggingface_hub
    exception, when repo_id does not exist or has no manifest published for
    version: this is the one place callers need to handle "nothing
    published there", the same way every other Hub failure in this module
    is kept out of the rest of the pipeline.
    """
    logger.info("downloading manifest: repo=%s version=%s", repo_id, version)
    try:
        local_path = hf_hub_download(
            repo_id=repo_id,
            filename=f"{const.VERSIONS_PREFIX}/{version}/{const.MANIFEST_FILENAME}",
        )
    except (RepositoryNotFoundError, EntryNotFoundError) as exc:
        raise HubError(f"no manifest published for {repo_id!r} version {version!r}") from exc
    except HfHubHTTPError as exc:
        raise HubError(
            f"could not download the manifest for {repo_id!r} version {version!r}: {exc}"
        ) from exc
    return Path(local_path).read_bytes()


def download_signature(repo_id: str, version: str) -> bytes:
    """Download and return the raw manifest.json.sig bytes published for version under repo_id.

    Raises HubError, instead of leaking the underlying huggingface_hub
    exception, on the same not-found and transport failures download_manifest
    already guards against -- a manifest with no signature published
    alongside it must abort, not proceed unverified.
    """
    logger.info("downloading signature: repo=%s version=%s", repo_id, version)
    try:
        local_path = hf_hub_download(
            repo_id=repo_id,
            filename=f"{const.VERSIONS_PREFIX}/{version}/{const.SIGNATURE_FILENAME}",
        )
    except (RepositoryNotFoundError, EntryNotFoundError) as exc:
        raise HubError(f"no signature published for {repo_id!r} version {version!r}") from exc
    except HfHubHTTPError as exc:
        raise HubError(
            f"could not download the signature for {repo_id!r} version {version!r}: {exc}"
        ) from exc
    return Path(local_path).read_bytes()


def download_artifact(repo_id: str, version: str) -> bytes:
    """Download and return the raw encrypted artifact bytes published for version under repo_id.

    Raises HubError, instead of leaking the underlying huggingface_hub
    exception, on the same not-found and transport failures download_manifest
    already guards against.
    """
    logger.info("downloading artifact: repo=%s version=%s", repo_id, version)
    try:
        local_path = hf_hub_download(
            repo_id=repo_id,
            filename=f"{const.VERSIONS_PREFIX}/{version}/{const.ARTIFACT_FILENAME}",
        )
    except (RepositoryNotFoundError, EntryNotFoundError) as exc:
        raise HubError(f"no artifact published for {repo_id!r} version {version!r}") from exc
    except HfHubHTTPError as exc:
        raise HubError(
            f"could not download the artifact for {repo_id!r} version {version!r}: {exc}"
        ) from exc
    return Path(local_path).read_bytes()
