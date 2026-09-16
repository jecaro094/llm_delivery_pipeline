"""Tests for the keygen, produce, and list CLI subcommands."""

from __future__ import annotations

import base64
from pathlib import Path
from unittest.mock import patch

import pytest
import tests.constants as test_const

import model_pipeline.constants as const
from model_pipeline import cli
from model_pipeline.consumer import ConsumerError
from model_pipeline.manifest import (
    ArtifactInfo,
    EncryptionInfo,
    ModelInfo,
    ProducerInfo,
    build_manifest,
)
from model_pipeline.producer import ProducerError
from model_pipeline.settings import Settings


def test_keygen_prints_a_valid_base64_32_byte_key(capsys: pytest.CaptureFixture[str]) -> None:
    """keygen must print a base64 string that decodes to exactly 32 bytes."""
    exit_code = cli.main(["keygen"])
    assert exit_code == 0
    printed = capsys.readouterr().out.strip()
    assert len(base64.b64decode(printed, validate=True)) == const.KEY_SIZE


def test_keygen_generates_a_different_key_each_call(capsys: pytest.CaptureFixture[str]) -> None:
    """Two keygen calls must not print the same key."""
    cli.main(["keygen"])
    first = capsys.readouterr().out.strip()
    cli.main(["keygen"])
    second = capsys.readouterr().out.strip()
    assert first != second


def _fake_manifest() -> object:
    """Build a minimal, valid manifest for asserting the produce command's stdout."""
    return build_manifest(
        created_at="2026-09-15T10:00:00Z",
        model=ModelInfo(
            source_repo="prajjwal1/bert-tiny", source_revision="deadbeef", task_hint="fill-mask"
        ),
        artifact=ArtifactInfo(
            version="1.0.0",
            path="versions/1.0.0/model.tar.enc",
            size_bytes=1,
            sha256="a" * 64,
            plaintext_sha256="b" * 64,
            plaintext_size_bytes=1,
        ),
        encryption=EncryptionInfo(
            algorithm="AES-256-GCM",
            kdf="HKDF-SHA256",
            chunk_size_bytes=1,
            format_version=1,
            key_id="k",
        ),
        producer=ProducerInfo(tool="model_pipeline", tool_version="0.1.0"),
    )


def test_produce_requires_target_repo_and_version(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """produce must fail with a usage error when --target-repo/--version are unresolved."""
    monkeypatch.delenv("MODEL_REPO_ID", raising=False)
    monkeypatch.delenv("MODEL_VERSION", raising=False)
    exit_code = cli.main(["produce"])
    assert exit_code == 2
    assert "target-repo" in capsys.readouterr().err


def test_produce_requires_hf_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """produce must fail with a usage error when HF_TOKEN is not set."""
    monkeypatch.delenv("HF_TOKEN", raising=False)
    exit_code = cli.main(["produce", "--target-repo", "me/repo", "--version", "1.0.0"])
    assert exit_code == 2
    assert "HF_TOKEN" in capsys.readouterr().err


def test_produce_requires_encryption_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """produce must fail cleanly when no encryption key can be resolved."""
    monkeypatch.setenv("HF_TOKEN", "hf_token")  # noqa: S105
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("ENCRYPTION_KEY_FILE", raising=False)
    exit_code = cli.main(["produce", "--target-repo", "me/repo", "--version", "1.0.0"])
    assert exit_code == 2
    assert "encryption key" in capsys.readouterr().err


def test_produce_runs_the_producer_flow_and_prints_the_manifest(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """produce must resolve config/secrets, call producer.produce, and print its manifest."""
    monkeypatch.setenv("HF_TOKEN", "hf_token")  # noqa: S105
    monkeypatch.setenv(
        "ENCRYPTION_KEY", base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    )
    fake_manifest = _fake_manifest()
    with patch("model_pipeline.cli.produce", return_value=fake_manifest) as mock_produce:
        exit_code = cli.main(
            [
                "produce",
                "--source-model",
                "prajjwal1/bert-tiny",
                "--target-repo",
                "me/repo",
                "--version",
                "1.0.0",
            ]
        )
    assert exit_code == 0
    mock_produce.assert_called_once()
    call_kwargs = mock_produce.call_args.kwargs
    assert call_kwargs["source_model"] == "prajjwal1/bert-tiny"
    assert call_kwargs["target_repo"] == "me/repo"
    assert call_kwargs["version"] == "1.0.0"
    assert call_kwargs["master_key"] == test_const.TEST_MASTER_KEY
    assert call_kwargs["hf_token"] == "hf_token"  # noqa: S105
    assert '"manifest_version"' in capsys.readouterr().out


def test_produce_reports_a_producer_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """produce must return a non-zero exit code and print the reason on a ProducerError."""
    monkeypatch.setenv("HF_TOKEN", "hf_token")  # noqa: S105
    monkeypatch.setenv(
        "ENCRYPTION_KEY", base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    )
    with patch("model_pipeline.cli.produce", side_effect=ProducerError("version exists")):
        exit_code = cli.main(["produce", "--target-repo", "me/repo", "--version", "1.0.0"])
    assert exit_code == 1
    assert "version exists" in capsys.readouterr().err


def test_produce_check_only_prints_the_version_and_does_not_publish(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """produce --check-only must print the confirmed version and never call producer.produce."""
    with (
        patch("model_pipeline.cli.resolve_produce_version", return_value="1.0.0") as mock_resolve,
        patch("model_pipeline.cli.produce") as mock_produce,
    ):
        exit_code = cli.main(
            ["produce", "--target-repo", "me/repo", "--version", "1.0.0", "--check-only"]
        )
    assert exit_code == 0
    mock_resolve.assert_called_once_with("me/repo", "1.0.0", interactive=False)
    mock_produce.assert_not_called()
    assert capsys.readouterr().out.strip() == "1.0.0"


def test_produce_check_only_reports_a_conflict_without_publishing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """produce --check-only must report a version conflict and exit 1 without publishing."""
    with (
        patch(
            "model_pipeline.cli.resolve_produce_version",
            side_effect=ProducerError("version '1.0.0' already exists in 'me/repo'"),
        ),
        patch("model_pipeline.cli.produce") as mock_produce,
    ):
        exit_code = cli.main(
            ["produce", "--target-repo", "me/repo", "--version", "1.0.0", "--check-only"]
        )
    assert exit_code == 1
    mock_produce.assert_not_called()
    assert "already exists" in capsys.readouterr().err


def test_key_file_takes_precedence_over_key_value(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """_resolve_master_key must prefer ENCRYPTION_KEY_FILE over ENCRYPTION_KEY when both are set."""
    key_file = tmp_path / "encryption-key"
    key_file.write_text(
        base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii"), encoding="utf-8"
    )
    monkeypatch.setenv("ENCRYPTION_KEY_FILE", str(key_file))
    monkeypatch.setenv(
        "ENCRYPTION_KEY", base64.b64encode(test_const.OTHER_MASTER_KEY).decode("ascii")
    )
    assert cli._resolve_master_key(Settings()) == test_const.TEST_MASTER_KEY


def test_list_requires_repo(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """list must fail with a usage error when --repo/MODEL_REPO_ID are unresolved."""
    monkeypatch.delenv("MODEL_REPO_ID", raising=False)
    exit_code = cli.main(["list"])
    assert exit_code == 2
    assert "repo" in capsys.readouterr().err


def test_list_prints_published_versions(capsys: pytest.CaptureFixture[str]) -> None:
    """list must print every version reported by hub.list_versions, one per line."""
    with patch(
        "model_pipeline.cli.hub.list_versions", return_value=["1.0.0", "1.1.0"]
    ) as mock_list:
        exit_code = cli.main(["list", "--repo", "me/repo"])
    assert exit_code == 0
    mock_list.assert_called_once_with("me/repo")
    assert capsys.readouterr().out.splitlines() == ["1.0.0", "1.1.0"]


def test_consume_requires_repo_and_version(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """consume must fail with a usage error when --repo/--version are unresolved."""
    monkeypatch.delenv("MODEL_REPO_ID", raising=False)
    monkeypatch.delenv("MODEL_VERSION", raising=False)
    exit_code = cli.main(["consume"])
    assert exit_code == 2
    assert "--repo" in capsys.readouterr().err


def test_consume_requires_workdir(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """consume must fail with a usage error when --workdir/MODEL_WORKDIR is unresolved."""
    monkeypatch.delenv("MODEL_WORKDIR", raising=False)
    exit_code = cli.main(["consume", "--repo", "me/repo", "--version", "1.0.0"])
    assert exit_code == 2
    assert "workdir" in capsys.readouterr().err


def test_consume_requires_encryption_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """consume must fail cleanly when no encryption key can be resolved."""
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("ENCRYPTION_KEY_FILE", raising=False)
    exit_code = cli.main(
        [
            "consume",
            "--repo",
            "me/repo",
            "--version",
            "1.0.0",
            "--workdir",
            str(tmp_path / "model"),
        ]
    )
    assert exit_code == 2
    assert "encryption key" in capsys.readouterr().err


def test_consume_key_file_argument_takes_precedence_over_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """consume's --key-file argument must win over ENCRYPTION_KEY_FILE from the environment."""
    env_key_file = tmp_path / "env-key"
    env_key_file.write_text(
        base64.b64encode(test_const.OTHER_MASTER_KEY).decode("ascii"), encoding="utf-8"
    )
    arg_key_file = tmp_path / "arg-key"
    arg_key_file.write_text(
        base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii"), encoding="utf-8"
    )
    monkeypatch.setenv("ENCRYPTION_KEY_FILE", str(env_key_file))
    fake_manifest = _fake_manifest()

    with patch("model_pipeline.cli.consume", return_value=fake_manifest) as mock_consume:
        exit_code = cli.main(
            [
                "consume",
                "--repo",
                "me/repo",
                "--version",
                "1.0.0",
                "--workdir",
                str(tmp_path / "model"),
                "--key-file",
                str(arg_key_file),
            ]
        )
    assert exit_code == 0
    assert mock_consume.call_args.kwargs["master_key"] == test_const.TEST_MASTER_KEY


def test_consume_runs_the_consumer_flow_without_smoke_test(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """consume must resolve config/secrets, call consumer.consume, and skip load_and_predict."""
    monkeypatch.setenv(
        "ENCRYPTION_KEY", base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    )
    fake_manifest = _fake_manifest()
    workdir = tmp_path / "model"

    with (
        patch("model_pipeline.cli.consume", return_value=fake_manifest) as mock_consume,
        patch("model_pipeline.cli.load_and_predict") as mock_load_and_predict,
    ):
        exit_code = cli.main(
            [
                "consume",
                "--repo",
                "me/repo",
                "--version",
                "1.0.0",
                "--workdir",
                str(workdir),
            ]
        )

    assert exit_code == 0
    mock_consume.assert_called_once_with(
        repo_id="me/repo",
        version="1.0.0",
        master_key=test_const.TEST_MASTER_KEY,
        workdir=workdir,
    )
    mock_load_and_predict.assert_not_called()
    assert "me/repo" in capsys.readouterr().out


def test_consume_runs_the_smoke_test_when_requested(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """consume --smoke-test must call load_and_predict with the manifest's task hint."""
    monkeypatch.setenv(
        "ENCRYPTION_KEY", base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    )
    fake_manifest = _fake_manifest()
    workdir = tmp_path / "model"

    with (
        patch("model_pipeline.cli.consume", return_value=fake_manifest),
        patch(
            "model_pipeline.cli.load_and_predict", return_value="'capital' (0.988)"
        ) as mock_load_and_predict,
    ):
        exit_code = cli.main(
            [
                "consume",
                "--repo",
                "me/repo",
                "--version",
                "1.0.0",
                "--workdir",
                str(workdir),
                "--smoke-test",
            ]
        )

    assert exit_code == 0
    mock_load_and_predict.assert_called_once_with(workdir, "fill-mask")
    assert "'capital' (0.988)" in capsys.readouterr().out


def test_consume_check_only_prints_the_version_and_does_not_download(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """consume --check-only must print the confirmed version and never call consumer.consume."""
    with (
        patch("model_pipeline.cli.resolve_consume_version", return_value="1.0.0") as mock_resolve,
        patch("model_pipeline.cli.consume") as mock_consume,
    ):
        exit_code = cli.main(
            [
                "consume",
                "--repo",
                "me/repo",
                "--version",
                "1.0.0",
                "--workdir",
                str(tmp_path / "model"),
                "--check-only",
            ]
        )
    assert exit_code == 0
    mock_resolve.assert_called_once_with("me/repo", "1.0.0", interactive=False)
    mock_consume.assert_not_called()
    assert capsys.readouterr().out.strip() == "1.0.0"


def test_consume_check_only_reports_a_mismatch_without_downloading(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """consume --check-only must report a missing version and exit 1 without downloading."""
    with (
        patch(
            "model_pipeline.cli.resolve_consume_version",
            side_effect=ConsumerError("version '1.0.0' is not published in 'me/repo'"),
        ),
        patch("model_pipeline.cli.consume") as mock_consume,
    ):
        exit_code = cli.main(["consume", "--repo", "me/repo", "--version", "1.0.0", "--check-only"])
    assert exit_code == 1
    mock_consume.assert_not_called()
    assert "not published" in capsys.readouterr().err


def test_consume_reports_a_consumer_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """consume must return a non-zero exit code and print the reason on a ConsumerError."""
    monkeypatch.setenv(
        "ENCRYPTION_KEY", base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    )
    with patch("model_pipeline.cli.consume", side_effect=ConsumerError("decryption failed")):
        exit_code = cli.main(
            [
                "consume",
                "--repo",
                "me/repo",
                "--version",
                "1.0.0",
                "--workdir",
                str(tmp_path / "model"),
            ]
        )
    assert exit_code == 1
    assert "decryption failed" in capsys.readouterr().err
