"""Tests for the huggingface_hub wrapper, mocking HfApi and snapshot_download."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from huggingface_hub.errors import EntryNotFoundError, HfHubHTTPError, RepositoryNotFoundError

from model_pipeline import hub

FAKE_TOKEN = "hf_super-secret-token"  # noqa: S105


def _http_error(message: str) -> HfHubHTTPError:
    """Build an HfHubHTTPError the same way huggingface_hub raises one, for test fixtures."""
    return HfHubHTTPError(message, response=MagicMock())


def test_resolve_model_revision_returns_commit_sha() -> None:
    """resolve_model_revision must return the sha reported by HfApi.model_info."""
    with patch("model_pipeline.hub.HfApi") as mock_api_cls:
        mock_api_cls.return_value.model_info.return_value = MagicMock(sha="deadbeef")
        revision = hub.resolve_model_revision("prajjwal1/bert-tiny")
    assert revision == "deadbeef"
    mock_api_cls.return_value.model_info.assert_called_once_with(
        "prajjwal1/bert-tiny", revision=None
    )


def test_resolve_model_revision_rejects_missing_sha() -> None:
    """resolve_model_revision must raise HubError if the Hub reports no commit sha."""
    with patch("model_pipeline.hub.HfApi") as mock_api_cls:
        mock_api_cls.return_value.model_info.return_value = MagicMock(sha=None)
        with pytest.raises(hub.HubError, match="could not resolve a commit sha"):
            hub.resolve_model_revision("prajjwal1/bert-tiny")


def test_resolve_model_revision_translates_an_http_error() -> None:
    """resolve_model_revision must translate an HfHubHTTPError into HubError, not leak it."""
    with patch("model_pipeline.hub.HfApi") as mock_api_cls:
        mock_api_cls.return_value.model_info.side_effect = _http_error("401 unauthorized")
        with pytest.raises(hub.HubError, match="prajjwal1/bert-tiny"):
            hub.resolve_model_revision("prajjwal1/bert-tiny")


def test_download_model_snapshot_calls_snapshot_download(tmp_path: Path) -> None:
    """download_model_snapshot must forward repo_id, revision, and local_dir."""
    with patch("model_pipeline.hub.snapshot_download") as mock_snapshot_download:
        hub.download_model_snapshot("prajjwal1/bert-tiny", "deadbeef", tmp_path)
    mock_snapshot_download.assert_called_once_with(
        repo_id="prajjwal1/bert-tiny", revision="deadbeef", local_dir=str(tmp_path)
    )


def test_download_model_snapshot_translates_an_http_error(tmp_path: Path) -> None:
    """download_model_snapshot must translate an HfHubHTTPError into HubError."""
    with patch("model_pipeline.hub.snapshot_download", side_effect=_http_error("503 unavailable")):
        with pytest.raises(hub.HubError, match="prajjwal1/bert-tiny"):
            hub.download_model_snapshot("prajjwal1/bert-tiny", "deadbeef", tmp_path)


def test_ensure_public_repo_creates_with_private_false() -> None:
    """ensure_public_repo must always request a public, idempotent repo creation."""
    with patch("model_pipeline.hub.HfApi") as mock_api_cls:
        hub.ensure_public_repo("me/bert-tiny-encrypted", token=FAKE_TOKEN)
    mock_api_cls.return_value.create_repo.assert_called_once_with(
        repo_id="me/bert-tiny-encrypted", token=FAKE_TOKEN, private=False, exist_ok=True
    )


def test_ensure_public_repo_translates_an_http_error_without_leaking_the_token() -> None:
    """ensure_public_repo must translate an HfHubHTTPError into HubError, never with the token."""
    with patch("model_pipeline.hub.HfApi") as mock_api_cls:
        mock_api_cls.return_value.create_repo.side_effect = _http_error("401 unauthorized")
        with pytest.raises(hub.HubError) as exc_info:
            hub.ensure_public_repo("me/bert-tiny-encrypted", token=FAKE_TOKEN)
    assert FAKE_TOKEN not in str(exc_info.value)


def test_list_versions_parses_manifest_paths() -> None:
    """list_versions must extract version identifiers from versions/<v>/manifest.json paths."""
    with patch("model_pipeline.hub.HfApi") as mock_api_cls:
        mock_api_cls.return_value.list_repo_files.return_value = [
            ".gitattributes",
            "versions/1.0.0/manifest.json",
            "versions/1.0.0/model.tar.enc",
            "versions/1.1.0/manifest.json",
            "versions/1.1.0/model.tar.enc",
        ]
        versions = hub.list_versions("me/bert-tiny-encrypted")
    assert versions == ["1.0.0", "1.1.0"]


def test_list_versions_returns_empty_for_a_fresh_repo() -> None:
    """list_versions must return an empty list when no version has been published yet."""
    with patch("model_pipeline.hub.HfApi") as mock_api_cls:
        mock_api_cls.return_value.list_repo_files.return_value = [".gitattributes"]
        versions = hub.list_versions("me/bert-tiny-encrypted")
    assert versions == []


def test_list_versions_returns_empty_when_the_repo_does_not_exist() -> None:
    """list_versions must return an empty list, not raise, for a never-created repo."""
    with patch("model_pipeline.hub.HfApi") as mock_api_cls:
        mock_api_cls.return_value.list_repo_files.side_effect = RepositoryNotFoundError(
            "not found", response=MagicMock()
        )
        versions = hub.list_versions("me/does-not-exist")
    assert versions == []


def test_list_versions_translates_other_http_errors() -> None:
    """list_versions must translate a non-404 HfHubHTTPError into HubError, not return []."""
    with patch("model_pipeline.hub.HfApi") as mock_api_cls:
        mock_api_cls.return_value.list_repo_files.side_effect = _http_error("503 unavailable")
        with pytest.raises(hub.HubError, match="me/bert-tiny-encrypted"):
            hub.list_versions("me/bert-tiny-encrypted")


def test_upload_artifact_uploads_both_files_under_the_version_prefix() -> None:
    """upload_artifact must upload the encrypted artifact and the manifest at the right paths."""
    with patch("model_pipeline.hub.HfApi") as mock_api_cls:
        hub.upload_artifact(
            "me/bert-tiny-encrypted",
            "1.0.0",
            artifact_bytes=b"ciphertext",
            manifest_bytes=b"{}",
            token=FAKE_TOKEN,
        )
    upload_calls = mock_api_cls.return_value.upload_file.call_args_list
    assert len(upload_calls) == 2
    assert upload_calls[0].kwargs["path_in_repo"] == "versions/1.0.0/model.tar.enc"
    assert upload_calls[0].kwargs["path_or_fileobj"] == b"ciphertext"
    assert upload_calls[1].kwargs["path_in_repo"] == "versions/1.0.0/manifest.json"
    assert upload_calls[1].kwargs["path_or_fileobj"] == b"{}"
    for call in upload_calls:
        assert call.kwargs["repo_id"] == "me/bert-tiny-encrypted"
        assert call.kwargs["token"] == FAKE_TOKEN


def test_upload_artifact_never_logs_the_token(caplog: pytest.LogCaptureFixture) -> None:
    """The token must never appear in any log record emitted while uploading."""
    with caplog.at_level("DEBUG"), patch("model_pipeline.hub.HfApi"):
        hub.upload_artifact(
            "me/bert-tiny-encrypted",
            "1.0.0",
            artifact_bytes=b"ciphertext",
            manifest_bytes=b"{}",
            token=FAKE_TOKEN,
        )
    assert all(FAKE_TOKEN not in record.getMessage() for record in caplog.records)


def test_upload_artifact_translates_an_http_error_without_leaking_the_token() -> None:
    """upload_artifact must translate an HfHubHTTPError into HubError, never with the token."""
    with patch("model_pipeline.hub.HfApi") as mock_api_cls:
        mock_api_cls.return_value.upload_file.side_effect = _http_error("401 unauthorized")
        with pytest.raises(hub.HubError) as exc_info:
            hub.upload_artifact(
                "me/bert-tiny-encrypted",
                "1.0.0",
                artifact_bytes=b"ciphertext",
                manifest_bytes=b"{}",
                token=FAKE_TOKEN,
            )
    assert FAKE_TOKEN not in str(exc_info.value)


def test_download_manifest_reads_the_downloaded_file(tmp_path: Path) -> None:
    """download_manifest must return the bytes of the file hf_hub_download reports."""
    local_file = tmp_path / "manifest.json"
    local_file.write_bytes(b'{"manifest_version": "1.0"}')
    with patch("model_pipeline.hub.hf_hub_download", return_value=str(local_file)) as mock_dl:
        content = hub.download_manifest("me/bert-tiny-encrypted", "1.0.0")
    mock_dl.assert_called_once_with(
        repo_id="me/bert-tiny-encrypted", filename="versions/1.0.0/manifest.json"
    )
    assert content == b'{"manifest_version": "1.0"}'


def test_download_manifest_raises_hub_error_for_a_missing_repo_or_version() -> None:
    """download_manifest must translate a not-found Hub error into HubError."""
    with patch(
        "model_pipeline.hub.hf_hub_download",
        side_effect=RepositoryNotFoundError("not found", response=MagicMock()),
    ):
        with pytest.raises(hub.HubError, match="me/bert-tiny-encrypted.*1.0.0"):
            hub.download_manifest("me/bert-tiny-encrypted", "1.0.0")

    with patch("model_pipeline.hub.hf_hub_download", side_effect=EntryNotFoundError("no entry")):
        with pytest.raises(hub.HubError, match="me/bert-tiny-encrypted.*1.0.0"):
            hub.download_manifest("me/bert-tiny-encrypted", "1.0.0")


def test_download_manifest_translates_other_http_errors() -> None:
    """download_manifest must translate a non-404 HfHubHTTPError into HubError."""
    with patch("model_pipeline.hub.hf_hub_download", side_effect=_http_error("503 unavailable")):
        with pytest.raises(hub.HubError, match="me/bert-tiny-encrypted.*1.0.0"):
            hub.download_manifest("me/bert-tiny-encrypted", "1.0.0")


def test_download_artifact_reads_the_downloaded_file(tmp_path: Path) -> None:
    """download_artifact must return the bytes of the file hf_hub_download reports."""
    local_file = tmp_path / "model.tar.enc"
    local_file.write_bytes(b"ciphertext")
    with patch("model_pipeline.hub.hf_hub_download", return_value=str(local_file)) as mock_dl:
        content = hub.download_artifact("me/bert-tiny-encrypted", "1.0.0")
    mock_dl.assert_called_once_with(
        repo_id="me/bert-tiny-encrypted", filename="versions/1.0.0/model.tar.enc"
    )
    assert content == b"ciphertext"


def test_download_artifact_raises_hub_error_for_a_missing_repo_or_version() -> None:
    """download_artifact must translate a not-found Hub error into HubError, like the manifest."""
    with patch(
        "model_pipeline.hub.hf_hub_download",
        side_effect=RepositoryNotFoundError("not found", response=MagicMock()),
    ):
        with pytest.raises(hub.HubError, match="me/bert-tiny-encrypted.*1.0.0"):
            hub.download_artifact("me/bert-tiny-encrypted", "1.0.0")


def test_download_artifact_translates_other_http_errors() -> None:
    """download_artifact must translate a non-404 HfHubHTTPError into HubError."""
    with patch("model_pipeline.hub.hf_hub_download", side_effect=_http_error("503 unavailable")):
        with pytest.raises(hub.HubError, match="me/bert-tiny-encrypted.*1.0.0"):
            hub.download_artifact("me/bert-tiny-encrypted", "1.0.0")


def test_download_manifest_and_artifact_never_pass_a_token() -> None:
    """The consumer's download calls must never pass a token: the target repo is public."""
    with patch("model_pipeline.hub.hf_hub_download", return_value="/dev/null") as mock_dl:
        hub.download_manifest("me/bert-tiny-encrypted", "1.0.0")
        hub.download_artifact("me/bert-tiny-encrypted", "1.0.0")
    for call in mock_dl.call_args_list:
        assert "token" not in call.kwargs
