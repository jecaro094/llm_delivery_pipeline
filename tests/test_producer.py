"""Producer orchestration tests, against a fake Hugging Face Hub kept in tmp_path.

The fake hub stands in for ``model_pipeline.hub``: it "publishes" versions as
files under a directory and "downloads" the source model by copying a fixture
directory, so the full download -> pack -> encrypt -> manifest -> upload flow
runs end to end without any network access.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest
import tests.constants as test_const

from model_pipeline import manifest as manifest_module
from model_pipeline import producer, signing
from model_pipeline.producer import ProducerError, produce, resolve_produce_version

FAKE_TOKEN = "hf_super-secret-token"  # noqa: S105
SOURCE_MODEL = "prajjwal1/bert-tiny"
TARGET_REPO = "me/bert-tiny-encrypted"
SIGNING_PRIVATE_KEY = signing.load_private_key(test_const.TEST_SIGNING_PRIVATE_KEY_PEM)


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
        signature_bytes: bytes,
        manifest_bytes: bytes,
        token: str,
    ) -> None:
        """Write the artifact, signature, and manifest bytes under the fake remote repo."""
        self.uploaded_tokens.append(token)
        version_dir = self.remote_dir / repo_id / version
        version_dir.mkdir(parents=True)
        (version_dir / "model.tar.enc").write_bytes(artifact_bytes)
        (version_dir / "manifest.json.sig").write_bytes(signature_bytes)
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
        signing_private_key=SIGNING_PRIVATE_KEY,
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

    assert published_manifest.model.source_repo == SOURCE_MODEL
    assert published_manifest.model.source_revision == "deadbeef"


def test_produce_logs_every_milestone(fake_hub: FakeHub, caplog: pytest.LogCaptureFixture) -> None:
    """produce must log the revision, snapshot, archive/encrypted sizes, and upload completion."""
    with caplog.at_level(logging.INFO):
        produce(
            source_model=SOURCE_MODEL,
            target_repo=TARGET_REPO,
            version="1.0.0",
            master_key=test_const.TEST_MASTER_KEY,
            signing_private_key=SIGNING_PRIVATE_KEY,
            hf_token=FAKE_TOKEN,
            chunk_size=test_const.SMALL_TEST_CHUNK_SIZE,
        )
    messages = [record.getMessage() for record in caplog.records]
    assert any("resolved source model revision" in message for message in messages)
    assert any("downloaded model snapshot" in message for message in messages)
    assert any("packed model snapshot into archive" in message for message in messages)
    assert any("encrypted archive" in message for message in messages)
    assert any("upload complete" in message for message in messages)


def test_produce_never_logs_the_token(fake_hub: FakeHub, caplog: pytest.LogCaptureFixture) -> None:
    """No log record emitted by a full produce() run may contain the Hugging Face token."""
    with caplog.at_level(logging.DEBUG):
        produce(
            source_model=SOURCE_MODEL,
            target_repo=TARGET_REPO,
            version="1.0.0",
            master_key=test_const.TEST_MASTER_KEY,
            signing_private_key=SIGNING_PRIVATE_KEY,
            hf_token=FAKE_TOKEN,
            chunk_size=test_const.SMALL_TEST_CHUNK_SIZE,
        )
    assert all(FAKE_TOKEN not in record.getMessage() for record in caplog.records)


def test_produce_publishes_three_files_and_the_manifest_is_the_exact_signed_bytes(
    fake_hub: FakeHub,
) -> None:
    """produce must publish artifact, signature, and manifest, and sign the uploaded bytes exactly.

    The invariant that matters is that the manifest bytes verified against
    the published signature are byte-identical to the manifest bytes
    published as manifest.json -- never a re-serialization of the same
    logical content.
    """
    from model_pipeline import signing as signing_module

    published_manifest = produce(
        source_model=SOURCE_MODEL,
        target_repo=TARGET_REPO,
        version="1.0.0",
        master_key=test_const.TEST_MASTER_KEY,
        signing_private_key=SIGNING_PRIVATE_KEY,
        hf_token=FAKE_TOKEN,
        chunk_size=test_const.SMALL_TEST_CHUNK_SIZE,
    )

    version_dir = fake_hub.remote_dir / TARGET_REPO / "1.0.0"
    assert {p.name for p in version_dir.iterdir()} == {
        "model.tar.enc",
        "manifest.json.sig",
        "manifest.json",
    }

    manifest_bytes = (version_dir / "manifest.json").read_bytes()
    signature_bytes = (version_dir / "manifest.json.sig").read_bytes()
    signing_module.verify(manifest_bytes, signature_bytes, SIGNING_PRIVATE_KEY.public_key())
    expected_fingerprint = signing_module.public_key_fingerprint(SIGNING_PRIVATE_KEY.public_key())
    assert published_manifest.signature.public_key_sha256 == expected_fingerprint


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
            signing_private_key=SIGNING_PRIVATE_KEY,
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
            signing_private_key=SIGNING_PRIVATE_KEY,
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
            signing_private_key=SIGNING_PRIVATE_KEY,
            hf_token=FAKE_TOKEN,
            chunk_size=test_const.SMALL_TEST_CHUNK_SIZE,
        )


def test_produce_refuses_to_overwrite_an_existing_version(fake_hub: FakeHub) -> None:
    """produce must reject publishing a version that already exists, suggesting the next one."""
    produce(
        source_model=SOURCE_MODEL,
        target_repo=TARGET_REPO,
        version="1.0.0",
        master_key=test_const.TEST_MASTER_KEY,
        signing_private_key=SIGNING_PRIVATE_KEY,
        hf_token=FAKE_TOKEN,
        chunk_size=test_const.SMALL_TEST_CHUNK_SIZE,
    )

    with pytest.raises(ProducerError, match=r"already exists.*next available version.*1\.0\.1"):
        produce(
            source_model=SOURCE_MODEL,
            target_repo=TARGET_REPO,
            version="1.0.0",
            master_key=test_const.TEST_MASTER_KEY,
            signing_private_key=SIGNING_PRIVATE_KEY,
            hf_token=FAKE_TOKEN,
            chunk_size=test_const.SMALL_TEST_CHUNK_SIZE,
        )


def test_produce_error_omits_a_suggestion_when_no_version_is_dotted_integers(
    fake_hub: FakeHub,
) -> None:
    """produce's error must not guess a next version when existing ones aren't dotted integers."""
    (fake_hub.remote_dir / TARGET_REPO / "unstable").mkdir(parents=True)

    with pytest.raises(ProducerError) as exc_info:
        produce(
            source_model=SOURCE_MODEL,
            target_repo=TARGET_REPO,
            version="unstable",
            master_key=test_const.TEST_MASTER_KEY,
            signing_private_key=SIGNING_PRIVATE_KEY,
            hf_token=FAKE_TOKEN,
            chunk_size=test_const.SMALL_TEST_CHUNK_SIZE,
        )
    assert "next available version" not in str(exc_info.value)


def test_resolve_produce_version_returns_a_free_version_unchanged(fake_hub: FakeHub) -> None:
    """resolve_produce_version must return version as-is when it is not already published."""
    assert resolve_produce_version(TARGET_REPO, "1.0.0", interactive=False) == "1.0.0"
    assert resolve_produce_version(TARGET_REPO, "1.0.0", interactive=True) == "1.0.0"


def test_resolve_produce_version_raises_non_interactively_on_conflict(fake_hub: FakeHub) -> None:
    """resolve_produce_version must raise ProducerError, not prompt, when interactive is False."""
    fake_hub.remote_dir.joinpath(TARGET_REPO, "1.0.0").mkdir(parents=True)

    with pytest.raises(ProducerError, match=r"already exists.*next available version.*1\.0\.1"):
        resolve_produce_version(TARGET_REPO, "1.0.0", interactive=False)


def test_resolve_produce_version_prompts_until_a_free_version_is_given(fake_hub: FakeHub) -> None:
    """resolve_produce_version must reprompt on the terminal until a free version is entered."""
    fake_hub.remote_dir.joinpath(TARGET_REPO, "1.0.0").mkdir(parents=True)
    fake_hub.remote_dir.joinpath(TARGET_REPO, "1.0.1").mkdir(parents=True)

    with patch("builtins.input", side_effect=["1.0.1", "1.0.2"]):
        resolved = resolve_produce_version(TARGET_REPO, "1.0.0", interactive=True)
    assert resolved == "1.0.2"


def test_resolve_produce_version_prompt_blank_accepts_the_suggestion(fake_hub: FakeHub) -> None:
    """resolve_produce_version must use the suggested next version when the prompt is left blank."""
    fake_hub.remote_dir.joinpath(TARGET_REPO, "1.0.0").mkdir(parents=True)

    with patch("builtins.input", return_value=""):
        resolved = resolve_produce_version(TARGET_REPO, "1.0.0", interactive=True)
    assert resolved == "1.0.1"


def test_resolve_produce_version_reprompts_on_blank_input_without_a_suggestion(
    fake_hub: FakeHub,
) -> None:
    """With no bumpable suggestion, a blank prompt must reprompt instead of an empty version."""
    fake_hub.remote_dir.joinpath(TARGET_REPO, "abc").mkdir(parents=True)

    with patch("builtins.input", side_effect=["", "def"]):
        resolved = resolve_produce_version(TARGET_REPO, "abc", interactive=True)
    assert resolved == "def"


def test_resolve_produce_version_raises_when_operator_never_enters_a_free_version(
    fake_hub: FakeHub,
) -> None:
    """resolve_produce_version must raise ProducerError, not hang, after repeated conflicts."""
    fake_hub.remote_dir.joinpath(TARGET_REPO, "1.0.0").mkdir(parents=True)

    with (
        patch("builtins.input", return_value="1.0.0"),
        pytest.raises(ProducerError, match="no valid value entered"),
    ):
        resolve_produce_version(TARGET_REPO, "1.0.0", interactive=True)
