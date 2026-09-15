"""Consumer orchestration tests, against a fake Hugging Face Hub kept in tmp_path.

The fake hub stands in for ``model_pipeline.hub``: it "downloads" a manifest
and an encrypted artifact that were built beforehand, so the full
download -> verify -> decrypt -> verify -> unpack flow runs end to end
without any network access. ``transformers`` is mocked for the load_and_predict
tests so the suite never needs torch installed.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import tests.constants as test_const

from model_pipeline import consumer, crypto, packaging
from model_pipeline import manifest as manifest_module
from model_pipeline.consumer import ConsumerError, consume, load_and_predict

REPO_ID = "me/bert-tiny-encrypted"
VERSION = "1.0.0"


def _build_manifest_and_artifact(
    fake_model_dir: Path,
    *,
    key: bytes = test_const.TEST_MASTER_KEY,
    key_id: str = "model-encryption-key",
) -> tuple[manifest_module.Manifest, bytes]:
    """Build a real encrypted artifact for fake_model_dir and its matching manifest."""
    plaintext_tar = packaging.pack_directory(fake_model_dir)
    encrypted_container = crypto.encrypt(
        plaintext_tar, key, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )
    artifact_manifest = manifest_module.build_manifest(
        created_at="2026-09-15T10:00:00Z",
        model=manifest_module.ModelInfo(
            source_repo="prajjwal1/bert-tiny", source_revision="deadbeef", task_hint="fill-mask"
        ),
        artifact=manifest_module.ArtifactInfo(
            version=VERSION,
            path=f"versions/{VERSION}/model.tar.enc",
            size_bytes=len(encrypted_container),
            sha256=manifest_module.compute_sha256(encrypted_container),
            plaintext_sha256=manifest_module.compute_sha256(plaintext_tar),
            plaintext_size_bytes=len(plaintext_tar),
        ),
        encryption=manifest_module.EncryptionInfo(
            algorithm="AES-256-GCM",
            kdf="HKDF-SHA256",
            chunk_size_bytes=test_const.SMALL_TEST_CHUNK_SIZE,
            format_version=1,
            key_id=key_id,
        ),
        producer=manifest_module.ProducerInfo(tool="model_pipeline", tool_version="0.1.0"),
    )
    return artifact_manifest, encrypted_container


class FakeHub:
    """In-memory stand-in for model_pipeline.hub's download side."""

    def __init__(self, manifest_bytes: bytes, artifact_bytes: bytes) -> None:
        """Store the manifest and artifact bytes this fake hub will serve."""
        self.manifest_bytes = manifest_bytes
        self.artifact_bytes = artifact_bytes
        self.download_calls: list[tuple[str, str, str]] = []

    def download_manifest(self, repo_id: str, version: str) -> bytes:
        """Record the call and return the stored manifest bytes."""
        self.download_calls.append(("manifest", repo_id, version))
        return self.manifest_bytes

    def download_artifact(self, repo_id: str, version: str) -> bytes:
        """Record the call and return the stored artifact bytes."""
        self.download_calls.append(("artifact", repo_id, version))
        return self.artifact_bytes


@pytest.fixture
def fake_hub_with_valid_artifact(monkeypatch: pytest.MonkeyPatch, fake_model_dir: Path) -> FakeHub:
    """Patch model_pipeline.consumer.hub with a FakeHub serving a valid artifact/manifest pair."""
    artifact_manifest, encrypted_container = _build_manifest_and_artifact(fake_model_dir)
    fake = FakeHub(
        manifest_bytes=manifest_module.serialize_manifest(artifact_manifest),
        artifact_bytes=encrypted_container,
    )
    monkeypatch.setattr(consumer, "hub", fake)
    return fake


def test_consume_downloads_verifies_decrypts_and_unpacks(
    fake_hub_with_valid_artifact: FakeHub, fake_model_dir: Path, tmp_path: Path
) -> None:
    """consume must recover the exact original model files into workdir."""
    workdir = tmp_path / "restored-model"

    returned_manifest = consume(
        repo_id=REPO_ID,
        version=VERSION,
        master_key=test_const.TEST_MASTER_KEY,
        workdir=workdir,
    )

    assert returned_manifest["artifact"]["version"] == VERSION
    assert fake_hub_with_valid_artifact.download_calls == [
        ("manifest", REPO_ID, VERSION),
        ("artifact", REPO_ID, VERSION),
    ]
    for relative_path in ["config.json", "pytorch_model.bin", "tokenizer/vocab.txt"]:
        assert (workdir / relative_path).read_bytes() == (
            fake_model_dir / relative_path
        ).read_bytes()


def test_consume_rejects_key_id_mismatch(
    monkeypatch: pytest.MonkeyPatch, fake_model_dir: Path, tmp_path: Path
) -> None:
    """consume must refuse to proceed when the manifest's key_id does not match expected_key_id."""
    artifact_manifest, encrypted_container = _build_manifest_and_artifact(
        fake_model_dir, key_id="some-other-secret"
    )
    fake = FakeHub(
        manifest_bytes=manifest_module.serialize_manifest(artifact_manifest),
        artifact_bytes=encrypted_container,
    )
    monkeypatch.setattr(consumer, "hub", fake)

    with pytest.raises(ConsumerError, match="key_id mismatch"):
        consume(
            repo_id=REPO_ID,
            version=VERSION,
            master_key=test_const.TEST_MASTER_KEY,
            workdir=tmp_path / "restored-model",
            expected_key_id="model-encryption-key",
        )
    # The key_id check must run before the artifact itself is downloaded.
    assert fake.download_calls == [("manifest", REPO_ID, VERSION)]


def test_consume_rejects_the_wrong_key(
    fake_hub_with_valid_artifact: FakeHub, tmp_path: Path
) -> None:
    """consume must raise ConsumerError, not produce a corrupted model, with the wrong key."""
    with pytest.raises(ConsumerError, match="decryption failed"):
        consume(
            repo_id=REPO_ID,
            version=VERSION,
            master_key=test_const.OTHER_MASTER_KEY,
            workdir=tmp_path / "restored-model",
        )


def test_consume_rejects_a_tampered_artifact(
    monkeypatch: pytest.MonkeyPatch, fake_model_dir: Path, tmp_path: Path
) -> None:
    """consume must raise ManifestError when the downloaded artifact does not match its sha256."""
    artifact_manifest, encrypted_container = _build_manifest_and_artifact(fake_model_dir)
    tampered = bytearray(encrypted_container)
    tampered[-1] ^= 0xFF
    fake = FakeHub(
        manifest_bytes=manifest_module.serialize_manifest(artifact_manifest),
        artifact_bytes=bytes(tampered),
    )
    monkeypatch.setattr(consumer, "hub", fake)

    with pytest.raises(manifest_module.ManifestError):
        consume(
            repo_id=REPO_ID,
            version=VERSION,
            master_key=test_const.TEST_MASTER_KEY,
            workdir=tmp_path / "restored-model",
        )


def test_load_and_predict_rejects_an_unsupported_task_hint(tmp_path: Path) -> None:
    """load_and_predict must reject an unsupported task hint before importing transformers."""
    with pytest.raises(ConsumerError, match="unsupported task hint"):
        load_and_predict(tmp_path, "text-classification")


def test_load_and_predict_runs_a_fill_mask_pipeline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """load_and_predict must build a fill-mask pipeline from workdir and format its predictions.

    ``transformers`` is not a dependency of the test environment, so a fake
    module is injected into sys.modules instead of patching a real one: this
    exercises the same ``from transformers import pipeline`` import path
    without requiring torch/transformers to be installed to run the tests.
    """
    fake_pipeline = MagicMock()
    fake_pipeline.tokenizer.mask_token = "[MASK]"  # noqa: S105
    fake_pipeline.return_value = [
        {"token_str": "capital", "score": 0.987654},
        {"token_str": "heart", "score": 0.012},
    ]
    mock_pipeline_factory = MagicMock(return_value=fake_pipeline)
    fake_transformers_module = types.ModuleType("transformers")
    fake_transformers_module.pipeline = mock_pipeline_factory  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "transformers", fake_transformers_module)

    result = load_and_predict(tmp_path, "fill-mask")

    mock_pipeline_factory.assert_called_once_with("fill-mask", model=str(tmp_path))
    fake_pipeline.assert_called_once_with("Paris is the [MASK] of France.")
    assert result == "'capital' (0.988), 'heart' (0.012)"
