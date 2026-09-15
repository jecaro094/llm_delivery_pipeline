"""Producer orchestration tests, against a fake Hugging Face Hub kept in tmp_path.

The fake hub stands in for ``model_pipeline.hub``: it "publishes" versions as
files under a directory and "downloads" the source model by copying a fixture
directory, so the full download -> pack -> encrypt -> manifest -> upload flow
runs end to end without any network access.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import tests.constants as test_const

from model_pipeline import manifest as manifest_module
from model_pipeline import producer
from model_pipeline.producer import ProducerError, produce

FAKE_TOKEN = "hf_super-secret-token"  # noqa: S105
SOURCE_MODEL = "prajjwal1/bert-tiny"
TARGET_REPO = "me/bert-tiny-encrypted"


class FakeHub:
    """In-memory-on-disk stand-in for model_pipeline.hub, backed by tmp_path."""

    def __init__(self, source_dir: Path, remote_dir: Path) -> None:
        """Store the fixture source model directory and the fake remote repo directory."""
        self.source_dir = source_dir
        self.remote_dir = remote_dir
        self.public_repos: set[str] = set()
        self.uploaded_tokens: list[str] = []

    def resolve_model_revision(self, repo_id: str, revision: str | None = None) -> str:
        """Return a fixed fake commit sha, ignoring the requested repo_id/revision."""
        return "deadbeef"

    def download_model_snapshot(self, repo_id: str, revision: str, local_dir: Path) -> None:
        """Copy the fixture source model directory into local_dir."""
        shutil.copytree(self.source_dir, local_dir, dirs_exist_ok=True)

    def ensure_public_repo(self, repo_id: str, token: str) -> None:
        """Record that repo_id was ensured to be public."""
        self.public_repos.add(repo_id)

    def list_versions(self, repo_id: str) -> list[str]:
        """List version directories already published under the fake remote repo."""
        repo_dir = self.remote_dir / repo_id
        if not repo_dir.is_dir():
            return []
        return sorted(p.name for p in repo_dir.iterdir() if p.is_dir())

    def upload_artifact(
        self,
        repo_id: str,
        version: str,
        *,
        artifact_bytes: bytes,
        manifest_bytes: bytes,
        token: str,
    ) -> None:
        """Write the artifact and manifest bytes under the fake remote repo."""
        self.uploaded_tokens.append(token)
        version_dir = self.remote_dir / repo_id / version
        version_dir.mkdir(parents=True)
        (version_dir / "model.tar.enc").write_bytes(artifact_bytes)
        (version_dir / "manifest.json").write_bytes(manifest_bytes)


@pytest.fixture
def fake_hub(monkeypatch: pytest.MonkeyPatch, fake_model_dir: Path, tmp_path: Path) -> FakeHub:
    """Patch model_pipeline.producer.hub with a FakeHub rooted at tmp_path."""
    fake = FakeHub(source_dir=fake_model_dir, remote_dir=tmp_path / "remote")
    monkeypatch.setattr(producer, "hub", fake)
    return fake


def test_produce_publishes_a_working_encrypted_artifact(fake_hub: FakeHub) -> None:
    """produce must publish an artifact and manifest that decrypt back to the source model."""
    from model_pipeline import crypto, packaging

    published_manifest = produce(
        source_model=SOURCE_MODEL,
        target_repo=TARGET_REPO,
        version="1.0.0",
        master_key=test_const.TEST_MASTER_KEY,
        hf_token=FAKE_TOKEN,
        chunk_size=test_const.SMALL_TEST_CHUNK_SIZE,
    )

    assert TARGET_REPO in fake_hub.public_repos
    assert fake_hub.uploaded_tokens == [FAKE_TOKEN]

    version_dir = fake_hub.remote_dir / TARGET_REPO / "1.0.0"
    encrypted_container = (version_dir / "model.tar.enc").read_bytes()
    remote_manifest = manifest_module.deserialize_manifest(
        (version_dir / "manifest.json").read_bytes()
    )
    assert remote_manifest == published_manifest

    manifest_module.verify_artifact_sha256(published_manifest, encrypted_container)
    decrypted_tar = crypto.decrypt(encrypted_container, test_const.TEST_MASTER_KEY)
    manifest_module.verify_plaintext_sha256(published_manifest, decrypted_tar)

    restored_dir = version_dir / "restored"
    packaging.unpack_archive(decrypted_tar, restored_dir)
    assert (restored_dir / "config.json").read_bytes() == (
        fake_hub.source_dir / "config.json"
    ).read_bytes()

    assert published_manifest["model"]["source_repo"] == SOURCE_MODEL
    assert published_manifest["model"]["source_revision"] == "deadbeef"


def test_produce_rejects_a_source_model_without_a_model_type(
    fake_hub: FakeHub, tmp_path: Path
) -> None:
    """produce must reject a source model whose config.json has no model_type key."""
    (fake_hub.source_dir / "config.json").write_text('{"hidden_size": 128}', encoding="utf-8")

    with pytest.raises(ProducerError, match="model_type"):
        produce(
            source_model=SOURCE_MODEL,
            target_repo=TARGET_REPO,
            version="1.0.0",
            master_key=test_const.TEST_MASTER_KEY,
            hf_token=FAKE_TOKEN,
            chunk_size=test_const.SMALL_TEST_CHUNK_SIZE,
        )
    assert fake_hub.uploaded_tokens == []


def test_produce_rejects_a_source_model_without_a_config_file(fake_hub: FakeHub) -> None:
    """produce must reject a source model whose snapshot has no config.json at all."""
    (fake_hub.source_dir / "config.json").unlink()

    with pytest.raises(ProducerError, match="config.json"):
        produce(
            source_model=SOURCE_MODEL,
            target_repo=TARGET_REPO,
            version="1.0.0",
            master_key=test_const.TEST_MASTER_KEY,
            hf_token=FAKE_TOKEN,
            chunk_size=test_const.SMALL_TEST_CHUNK_SIZE,
        )


def test_produce_rejects_a_source_model_with_invalid_json_config(fake_hub: FakeHub) -> None:
    """produce must reject a source model whose config.json is not valid JSON."""
    (fake_hub.source_dir / "config.json").write_text("not json", encoding="utf-8")

    with pytest.raises(ProducerError, match="not valid JSON"):
        produce(
            source_model=SOURCE_MODEL,
            target_repo=TARGET_REPO,
            version="1.0.0",
            master_key=test_const.TEST_MASTER_KEY,
            hf_token=FAKE_TOKEN,
            chunk_size=test_const.SMALL_TEST_CHUNK_SIZE,
        )


def test_produce_refuses_to_overwrite_an_existing_version(fake_hub: FakeHub) -> None:
    """produce must reject publishing a version that already exists in the target repo."""
    produce(
        source_model=SOURCE_MODEL,
        target_repo=TARGET_REPO,
        version="1.0.0",
        master_key=test_const.TEST_MASTER_KEY,
        hf_token=FAKE_TOKEN,
        chunk_size=test_const.SMALL_TEST_CHUNK_SIZE,
    )

    with pytest.raises(ProducerError):
        produce(
            source_model=SOURCE_MODEL,
            target_repo=TARGET_REPO,
            version="1.0.0",
            master_key=test_const.TEST_MASTER_KEY,
            hf_token=FAKE_TOKEN,
            chunk_size=test_const.SMALL_TEST_CHUNK_SIZE,
        )
