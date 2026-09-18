"""Consumer orchestration tests, against a fake Hugging Face Hub kept in tmp_path.

The fake hub stands in for ``model_pipeline.hub``: it "downloads" a manifest,
its detached signature, and an encrypted artifact that were built beforehand,
so the full verify -> download -> decrypt -> verify -> unpack flow runs end
to end without any network access. ``transformers`` is mocked for the
load_and_predict tests so the suite never needs torch installed.
"""

from __future__ import annotations

import logging
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import tests.constants as test_const

from model_pipeline import consumer, crypto, packaging, signing
from model_pipeline import manifest as manifest_module
from model_pipeline.consumer import (
    ConsumerError,
    consume,
    load_and_predict,
    resolve_consume_version,
    verify_published_version,
)
from model_pipeline.hub import HubError

REPO_ID = "me/bert-tiny-encrypted"
VERSION = "1.0.0"

SIGNING_PRIVATE_KEY = signing.load_private_key(test_const.TEST_SIGNING_PRIVATE_KEY_PEM)
SIGNING_PUBLIC_KEY = signing.load_public_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)
OTHER_SIGNING_PUBLIC_KEY = signing.load_public_key(test_const.OTHER_SIGNING_PUBLIC_KEY_PEM)


def _build_signed_manifest_and_artifact(
    fake_model_dir: Path,
    *,
    key: bytes = test_const.TEST_MASTER_KEY,
    key_id: str = "model-encryption-key",
    version: str = VERSION,
    signing_private_key=SIGNING_PRIVATE_KEY,
    fingerprint: str | None = None,
) -> tuple[bytes, bytes, bytes]:
    """Build a real encrypted artifact, its signed manifest bytes, and its signature bytes."""
    plaintext_tar = packaging.pack_directory(fake_model_dir)
    encrypted_container = crypto.encrypt(
        plaintext_tar, key, chunk_size=test_const.SMALL_TEST_CHUNK_SIZE
    )
    if fingerprint is None:
        fingerprint = signing.public_key_fingerprint(signing_private_key.public_key())
    artifact_manifest = manifest_module.build_manifest(
        created_at="2026-09-15T10:00:00Z",
        model=manifest_module.ModelInfo(
            source_repo="prajjwal1/bert-tiny", source_revision="deadbeef", task_hint="fill-mask"
        ),
        artifact=manifest_module.ArtifactInfo(
            version=version,
            path=f"versions/{version}/model.tar.enc",
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
        signature=manifest_module.SignatureInfo(
            algorithm="Ed25519",
            public_key_sha256=fingerprint,
            signature_path=f"versions/{version}/manifest.json.sig",
        ),
        producer=manifest_module.ProducerInfo(tool="model_pipeline", tool_version="0.1.0"),
    )
    manifest_bytes = manifest_module.serialize_manifest(artifact_manifest)
    signature_bytes = signing.sign(manifest_bytes, signing_private_key)
    return manifest_bytes, signature_bytes, encrypted_container


class FakeHub:
    """In-memory stand-in for model_pipeline.hub's download side."""

    def __init__(
        self,
        manifest_bytes: bytes,
        signature_bytes: bytes,
        artifact_bytes: bytes,
        published_versions: list[str] | None = None,
    ) -> None:
        """Store the manifest, signature, and artifact bytes this fake hub will serve."""
        self.manifest_bytes = manifest_bytes
        self.signature_bytes = signature_bytes
        self.artifact_bytes = artifact_bytes
        self.published_versions = published_versions or [VERSION]
        self.download_calls: list[tuple[str, str, str]] = []

    def download_manifest(self, repo_id: str, version: str) -> bytes:
        """Record the call and return the stored manifest bytes."""
        self.download_calls.append(("manifest", repo_id, version))
        return self.manifest_bytes

    def download_signature(self, repo_id: str, version: str) -> bytes:
        """Record the call and return the stored signature bytes."""
        self.download_calls.append(("signature", repo_id, version))
        return self.signature_bytes

    def download_artifact(self, repo_id: str, version: str) -> bytes:
        """Record the call and return the stored artifact bytes."""
        self.download_calls.append(("artifact", repo_id, version))
        return self.artifact_bytes

    def list_versions(self, repo_id: str) -> list[str]:
        """Return the fixed list of published versions this fake hub was built with."""
        return self.published_versions


@pytest.fixture
def fake_hub_with_valid_artifact(monkeypatch: pytest.MonkeyPatch, fake_model_dir: Path) -> FakeHub:
    """Patch model_pipeline.consumer.hub with a FakeHub serving a validly signed artifact."""
    manifest_bytes, signature_bytes, encrypted_container = _build_signed_manifest_and_artifact(
        fake_model_dir
    )
    fake = FakeHub(
        manifest_bytes=manifest_bytes,
        signature_bytes=signature_bytes,
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
        public_key=SIGNING_PUBLIC_KEY,
        workdir=workdir,
    )

    assert returned_manifest.artifact.version == VERSION
    assert fake_hub_with_valid_artifact.download_calls == [
        ("manifest", REPO_ID, VERSION),
        ("signature", REPO_ID, VERSION),
        ("artifact", REPO_ID, VERSION),
    ]
    for relative_path in ["config.json", "pytorch_model.bin", "tokenizer/vocab.txt"]:
        assert (workdir / relative_path).read_bytes() == (
            fake_model_dir / relative_path
        ).read_bytes()


def test_consume_logs_every_milestone(
    fake_hub_with_valid_artifact: FakeHub, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """consume must log the manifest fetch, key_id check, hash checks, decryption, and unpack."""
    with caplog.at_level(logging.INFO):
        consume(
            repo_id=REPO_ID,
            version=VERSION,
            master_key=test_const.TEST_MASTER_KEY,
            public_key=SIGNING_PUBLIC_KEY,
            workdir=tmp_path / "restored-model",
        )
    messages = [record.getMessage() for record in caplog.records]
    assert any("manifest and signature fetched" in message for message in messages)
    assert any("signature verified" in message for message in messages)
    assert any("key_id checked" in message for message in messages)
    assert any("artifact sha256 verified" in message for message in messages)
    assert any("artifact decrypted" in message for message in messages)
    assert any("plaintext sha256 verified" in message for message in messages)
    assert any("unpacked model snapshot" in message for message in messages)


def test_consume_rejects_an_invalid_signature_without_downloading_the_artifact(
    fake_hub_with_valid_artifact: FakeHub, tmp_path: Path
) -> None:
    """An invalid signature must abort before the artifact is downloaded or the key is read."""
    with pytest.raises(ConsumerError, match="signature verification failed"):
        consume(
            repo_id=REPO_ID,
            version=VERSION,
            master_key=test_const.TEST_MASTER_KEY,
            public_key=OTHER_SIGNING_PUBLIC_KEY,
            workdir=tmp_path / "restored-model",
        )
    assert fake_hub_with_valid_artifact.download_calls == [
        ("manifest", REPO_ID, VERSION),
        ("signature", REPO_ID, VERSION),
    ]


def test_consume_rejects_a_missing_signature_file(
    monkeypatch: pytest.MonkeyPatch, fake_model_dir: Path, tmp_path: Path
) -> None:
    """consume must abort when the repo has a manifest but no published signature."""
    manifest_bytes, _signature_bytes, encrypted_container = _build_signed_manifest_and_artifact(
        fake_model_dir
    )

    class NoSignatureHub:
        def download_manifest(self, repo_id: str, version: str) -> bytes:
            return manifest_bytes

        def download_signature(self, repo_id: str, version: str) -> bytes:
            raise HubError(f"no signature published for {repo_id!r} version {version!r}")

    monkeypatch.setattr(consumer, "hub", NoSignatureHub())

    with pytest.raises(ConsumerError, match="no signature published"):
        consume(
            repo_id=REPO_ID,
            version=VERSION,
            master_key=test_const.TEST_MASTER_KEY,
            public_key=SIGNING_PUBLIC_KEY,
            workdir=tmp_path / "restored-model",
        )


def test_consume_rejects_a_version_mismatch_between_request_and_signed_manifest(
    monkeypatch: pytest.MonkeyPatch, fake_model_dir: Path, tmp_path: Path
) -> None:
    """A manifest signed for a version other than the one requested must be rejected."""
    manifest_bytes, signature_bytes, encrypted_container = _build_signed_manifest_and_artifact(
        fake_model_dir, version="1.0.0"
    )
    fake = FakeHub(
        manifest_bytes=manifest_bytes,
        signature_bytes=signature_bytes,
        artifact_bytes=encrypted_container,
        published_versions=["1.0.0", "2.0.0"],
    )
    monkeypatch.setattr(consumer, "hub", fake)

    with pytest.raises(ConsumerError, match="version mismatch"):
        consume(
            repo_id=REPO_ID,
            version="2.0.0",
            master_key=test_const.TEST_MASTER_KEY,
            public_key=SIGNING_PUBLIC_KEY,
            workdir=tmp_path / "restored-model",
        )


def test_consume_rejects_a_manifest_naming_a_foreign_key_fingerprint(
    monkeypatch: pytest.MonkeyPatch, fake_model_dir: Path, tmp_path: Path
) -> None:
    """A manifest naming a fingerprint other than the mounted key's must be rejected.

    The manifest field is only ever compared against the mounted key; it can
    never redirect verification to a different key. This manifest is validly
    signed by SIGNING_PRIVATE_KEY but claims OTHER's fingerprint, so
    verification against the correct, mounted SIGNING_PUBLIC_KEY succeeds
    and only the cross-check should fail.
    """
    other_fingerprint = signing.public_key_fingerprint(OTHER_SIGNING_PUBLIC_KEY)
    manifest_bytes, signature_bytes, encrypted_container = _build_signed_manifest_and_artifact(
        fake_model_dir, fingerprint=other_fingerprint
    )
    fake = FakeHub(
        manifest_bytes=manifest_bytes,
        signature_bytes=signature_bytes,
        artifact_bytes=encrypted_container,
    )
    monkeypatch.setattr(consumer, "hub", fake)

    with pytest.raises(ConsumerError, match="fingerprint mismatch"):
        consume(
            repo_id=REPO_ID,
            version=VERSION,
            master_key=test_const.TEST_MASTER_KEY,
            public_key=SIGNING_PUBLIC_KEY,
            workdir=tmp_path / "restored-model",
        )


def test_consume_rejects_key_id_mismatch(
    monkeypatch: pytest.MonkeyPatch, fake_model_dir: Path, tmp_path: Path
) -> None:
    """consume must refuse to proceed when the manifest's key_id does not match expected_key_id."""
    manifest_bytes, signature_bytes, encrypted_container = _build_signed_manifest_and_artifact(
        fake_model_dir, key_id="some-other-secret"
    )
    fake = FakeHub(
        manifest_bytes=manifest_bytes,
        signature_bytes=signature_bytes,
        artifact_bytes=encrypted_container,
    )
    monkeypatch.setattr(consumer, "hub", fake)

    with pytest.raises(ConsumerError, match="key_id mismatch"):
        consume(
            repo_id=REPO_ID,
            version=VERSION,
            master_key=test_const.TEST_MASTER_KEY,
            public_key=SIGNING_PUBLIC_KEY,
            workdir=tmp_path / "restored-model",
            expected_key_id="model-encryption-key",
        )
    # The key_id check must run after signature verification but before the
    # artifact itself is downloaded.
    assert fake.download_calls == [
        ("manifest", REPO_ID, VERSION),
        ("signature", REPO_ID, VERSION),
    ]


def test_consume_rejects_the_wrong_key(
    fake_hub_with_valid_artifact: FakeHub, tmp_path: Path
) -> None:
    """consume must raise ConsumerError, not produce a corrupted model, with the wrong key."""
    with pytest.raises(ConsumerError, match="decryption failed"):
        consume(
            repo_id=REPO_ID,
            version=VERSION,
            master_key=test_const.OTHER_MASTER_KEY,
            public_key=SIGNING_PUBLIC_KEY,
            workdir=tmp_path / "restored-model",
        )


def test_consume_rejects_a_tampered_artifact(
    monkeypatch: pytest.MonkeyPatch, fake_model_dir: Path, tmp_path: Path
) -> None:
    """consume must raise ManifestError when the downloaded artifact does not match its sha256."""
    manifest_bytes, signature_bytes, encrypted_container = _build_signed_manifest_and_artifact(
        fake_model_dir
    )
    tampered = bytearray(encrypted_container)
    tampered[-1] ^= 0xFF
    fake = FakeHub(
        manifest_bytes=manifest_bytes,
        signature_bytes=signature_bytes,
        artifact_bytes=bytes(tampered),
    )
    monkeypatch.setattr(consumer, "hub", fake)

    with pytest.raises(manifest_module.ManifestError, match="artifact sha256 mismatch"):
        consume(
            repo_id=REPO_ID,
            version=VERSION,
            master_key=test_const.TEST_MASTER_KEY,
            public_key=SIGNING_PUBLIC_KEY,
            workdir=tmp_path / "restored-model",
        )


def test_consume_reports_a_missing_artifact_as_a_consumer_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """consume must raise ConsumerError, not leak HubError, when nothing is published."""

    class MissingHub:
        def download_manifest(self, repo_id: str, version: str) -> bytes:
            raise HubError(f"no manifest published for {repo_id!r} version {version!r}")

    monkeypatch.setattr(consumer, "hub", MissingHub())

    with pytest.raises(ConsumerError, match="no manifest published"):
        consume(
            repo_id=REPO_ID,
            version=VERSION,
            master_key=test_const.TEST_MASTER_KEY,
            public_key=SIGNING_PUBLIC_KEY,
            workdir=tmp_path / "restored-model",
        )


def test_verify_published_version_succeeds_with_no_master_key(
    fake_hub_with_valid_artifact: FakeHub,
) -> None:
    """verify_published_version must confirm a valid signature using only the public key."""
    artifact_manifest = verify_published_version(
        repo_id=REPO_ID, version=VERSION, public_key=SIGNING_PUBLIC_KEY
    )
    assert artifact_manifest.artifact.version == VERSION
    # No artifact was downloaded: verification never needed the decryption key.
    assert ("artifact", REPO_ID, VERSION) not in fake_hub_with_valid_artifact.download_calls


def test_verify_published_version_rejects_the_wrong_public_key(
    fake_hub_with_valid_artifact: FakeHub,
) -> None:
    """verify_published_version must reject a signature checked against the wrong public key."""
    with pytest.raises(ConsumerError, match="signature verification failed"):
        verify_published_version(
            repo_id=REPO_ID, version=VERSION, public_key=OTHER_SIGNING_PUBLIC_KEY
        )


def test_consume_reports_a_missing_encrypted_artifact_as_a_consumer_error(
    monkeypatch: pytest.MonkeyPatch, fake_model_dir: Path, tmp_path: Path
) -> None:
    """consume must raise ConsumerError, not leak HubError, when the artifact download fails."""
    manifest_bytes, signature_bytes, _ = _build_signed_manifest_and_artifact(fake_model_dir)

    class MissingArtifactHub:
        def download_manifest(self, repo_id: str, version: str) -> bytes:
            return manifest_bytes

        def download_signature(self, repo_id: str, version: str) -> bytes:
            return signature_bytes

        def download_artifact(self, repo_id: str, version: str) -> bytes:
            raise HubError(f"no artifact published for {repo_id!r} version {version!r}")

    monkeypatch.setattr(consumer, "hub", MissingArtifactHub())

    with pytest.raises(ConsumerError, match="no artifact published"):
        consume(
            repo_id=REPO_ID,
            version=VERSION,
            master_key=test_const.TEST_MASTER_KEY,
            public_key=SIGNING_PUBLIC_KEY,
            workdir=tmp_path / "restored-model",
        )


def test_resolve_consume_version_reports_a_list_failure_as_a_consumer_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """resolve_consume_version must raise ConsumerError, not leak HubError, on a lookup failure."""

    class BrokenHub:
        def list_versions(self, repo_id: str) -> list[str]:
            raise HubError(f"could not list versions for {repo_id!r}")

    monkeypatch.setattr(consumer, "hub", BrokenHub())

    with pytest.raises(ConsumerError, match="could not list versions"):
        resolve_consume_version(REPO_ID, VERSION, interactive=False)


def test_resolve_consume_version_returns_a_published_version_unchanged(
    fake_hub_with_valid_artifact: FakeHub,
) -> None:
    """resolve_consume_version must return version as-is when it is already published."""
    assert resolve_consume_version(REPO_ID, VERSION, interactive=False) == VERSION
    assert resolve_consume_version(REPO_ID, VERSION, interactive=True) == VERSION


def test_resolve_consume_version_raises_non_interactively_on_mismatch(
    monkeypatch: pytest.MonkeyPatch, fake_hub_with_valid_artifact: FakeHub
) -> None:
    """resolve_consume_version must raise ConsumerError, not prompt, when interactive is False."""
    with pytest.raises(ConsumerError, match="not published"):
        resolve_consume_version(REPO_ID, "9.9.9", interactive=False)


def test_resolve_consume_version_raises_when_nothing_is_published(
    monkeypatch: pytest.MonkeyPatch, fake_hub_with_valid_artifact: FakeHub
) -> None:
    """resolve_consume_version must raise ConsumerError when repo_id has no published versions."""
    fake_hub_with_valid_artifact.published_versions = []
    with pytest.raises(ConsumerError, match="no published artifact versions"):
        resolve_consume_version(REPO_ID, VERSION, interactive=True)


def test_resolve_consume_version_prompts_until_a_published_version_is_given(
    fake_hub_with_valid_artifact: FakeHub,
) -> None:
    """resolve_consume_version must reprompt on the terminal until a published version is given."""
    fake_hub_with_valid_artifact.published_versions = [VERSION, "1.1.0"]

    with patch("builtins.input", side_effect=["9.9.9", "1.1.0"]):
        resolved = resolve_consume_version(REPO_ID, "unpublished", interactive=True)
    assert resolved == "1.1.0"


def test_resolve_consume_version_prompt_blank_accepts_the_latest(
    fake_hub_with_valid_artifact: FakeHub,
) -> None:
    """resolve_consume_version must default to the latest published version when left blank."""
    fake_hub_with_valid_artifact.published_versions = [VERSION, "1.1.0"]

    with patch("builtins.input", return_value=""):
        resolved = resolve_consume_version(REPO_ID, "unpublished", interactive=True)
    assert resolved == "1.1.0"


def test_resolve_consume_version_raises_when_operator_never_enters_a_published_version(
    fake_hub_with_valid_artifact: FakeHub,
) -> None:
    """resolve_consume_version must raise ConsumerError, not hang, after repeated mismatches."""
    with (
        patch("builtins.input", return_value="9.9.9"),
        pytest.raises(ConsumerError, match="no valid value entered"),
    ):
        resolve_consume_version(REPO_ID, "unpublished", interactive=True)


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
