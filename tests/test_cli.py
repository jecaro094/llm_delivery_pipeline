"""Tests for the keygen, produce, and list CLI subcommands."""

from __future__ import annotations

import argparse
import base64
import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest
import tests.constants as test_const

import model_pipeline.constants as const
from model_pipeline import cli, signing
from model_pipeline.consumer import ConsumerError
from model_pipeline.manifest import (
    ArtifactInfo,
    EncryptionInfo,
    ModelInfo,
    ProducerInfo,
    SignatureInfo,
    build_manifest,
)
from model_pipeline.producer import ProducerError
from model_pipeline.settings import Settings

SIGNING_PRIVATE_KEY_PEM = test_const.TEST_SIGNING_PRIVATE_KEY_PEM.decode("ascii")
SIGNING_PUBLIC_KEY_PEM = test_const.TEST_SIGNING_PUBLIC_KEY_PEM.decode("ascii")


def _set_signing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set both signing key env vars to the fixed test key pair."""
    monkeypatch.setenv("SIGNING_KEY", SIGNING_PRIVATE_KEY_PEM)
    monkeypatch.setenv("SIGNING_PUBLIC_KEY", SIGNING_PUBLIC_KEY_PEM)


def test_every_cli_argument_is_documented_with_help() -> None:
    """Every declared argument, on every subparser, must carry a non-empty help= string."""
    parser = cli.build_parser()
    subparsers_action = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    for sub_parser in subparsers_action.choices.values():
        for action in sub_parser._actions:
            if isinstance(action, argparse._HelpAction):
                continue
            assert action.help, (
                f"{sub_parser.prog!r} argument {action.option_strings} has no help text"
            )


def test_every_subcommand_has_a_description() -> None:
    """Every subcommand must carry a description= shown by `<command> --help`."""
    parser = cli.build_parser()
    subparsers_action = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    for sub_parser in subparsers_action.choices.values():
        assert sub_parser.description, f"{sub_parser.prog!r} has no description"


def test_setting_or_arg_prefers_the_cli_argument_when_given() -> None:
    """_setting_or_arg must return the CLI argument when it is not None."""
    assert cli._setting_or_arg("from-arg", "from-settings") == "from-arg"


def test_setting_or_arg_falls_back_to_settings_when_arg_is_none() -> None:
    """_setting_or_arg must return the settings value when the CLI argument is None."""
    assert cli._setting_or_arg(None, "from-settings") == "from-settings"


def test_require_returns_none_when_nothing_is_missing() -> None:
    """_require must return None when every value is present."""
    assert cli._require({"--repo": "me/repo", "--version": "1.0.0"}, "produce") is None


def test_require_reports_every_missing_value_together(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """_require must name every missing value in one log record and return exit code 2."""
    with caplog.at_level("ERROR"):
        exit_code = cli._require({"--target-repo": None, "--version": None}, "produce")
    assert exit_code == 2
    message = caplog.records[-1].getMessage()
    assert "--target-repo" in message
    assert "--version" in message


def test_fail_prints_the_command_and_reason_and_returns_one(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """_fail must log '<command> failed: <exc>' and return exit code 1."""
    with caplog.at_level("ERROR"):
        exit_code = cli._fail("produce", ProducerError("boom"))
    assert exit_code == 1
    assert "produce failed: boom" in caplog.records[-1].getMessage()


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
        signature=SignatureInfo(
            algorithm="Ed25519",
            public_key_sha256="ab" * 32,
            signature_path="versions/1.0.0/manifest.json.sig",
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


def test_produce_falls_back_to_a_cached_login_token_when_hf_token_is_unset(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """produce must use huggingface_hub.get_token()'s cached login when HF_TOKEN is unset."""
    monkeypatch.delenv("HF_TOKEN", raising=False)
    monkeypatch.setenv(
        "ENCRYPTION_KEY", base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    )
    _set_signing_env(monkeypatch)
    monkeypatch.setattr("model_pipeline.cli.hub.get_cached_token", lambda: "cached-token")
    fake_manifest = _fake_manifest()
    with patch("model_pipeline.cli.produce", return_value=fake_manifest) as mock_produce:
        exit_code = cli.main(["produce", "--target-repo", "me/repo", "--version", "1.0.0"])
    assert exit_code == 0
    assert mock_produce.call_args.kwargs["hf_token"] == "cached-token"  # noqa: S105


def test_produce_reads_the_token_from_hf_token_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """produce must prefer HF_TOKEN_FILE over HF_TOKEN when both are set."""
    token_file = tmp_path / "hf-token"
    token_file.write_text("from-file\n", encoding="utf-8")
    monkeypatch.setenv("HF_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("HF_TOKEN", "from-env-value")  # noqa: S105
    monkeypatch.setenv(
        "ENCRYPTION_KEY", base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    )
    _set_signing_env(monkeypatch)
    fake_manifest = _fake_manifest()
    with patch("model_pipeline.cli.produce", return_value=fake_manifest) as mock_produce:
        exit_code = cli.main(["produce", "--target-repo", "me/repo", "--version", "1.0.0"])
    assert exit_code == 0
    assert mock_produce.call_args.kwargs["hf_token"] == "from-file"  # noqa: S105


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


def test_produce_requires_signing_private_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """produce must fail cleanly when no signing private key can be resolved."""
    monkeypatch.setenv("HF_TOKEN", "hf_token")  # noqa: S105
    monkeypatch.setenv(
        "ENCRYPTION_KEY", base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    )
    monkeypatch.delenv("SIGNING_KEY", raising=False)
    monkeypatch.delenv("SIGNING_KEY_FILE", raising=False)
    exit_code = cli.main(["produce", "--target-repo", "me/repo", "--version", "1.0.0"])
    assert exit_code == 2
    assert "signing private key" in capsys.readouterr().err


def test_produce_runs_the_producer_flow_and_prints_the_manifest(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """produce must resolve config/secrets, call producer.produce, and print its manifest."""
    monkeypatch.setenv("HF_TOKEN", "hf_token")  # noqa: S105
    monkeypatch.setenv(
        "ENCRYPTION_KEY", base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    )
    _set_signing_env(monkeypatch)
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
    assert signing.public_key_fingerprint(
        call_kwargs["signing_private_key"].public_key()
    ) == signing.public_key_fingerprint(
        signing.load_private_key(test_const.TEST_SIGNING_PRIVATE_KEY_PEM).public_key()
    )
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
    _set_signing_env(monkeypatch)
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


def test_consume_requires_signing_public_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """consume must fail cleanly when no signing public key can be resolved."""
    monkeypatch.setenv(
        "ENCRYPTION_KEY", base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    )
    monkeypatch.delenv("SIGNING_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("SIGNING_PUBLIC_KEY_FILE", raising=False)
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
    assert "signing public key" in capsys.readouterr().err


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
    monkeypatch.setenv("SIGNING_PUBLIC_KEY", SIGNING_PUBLIC_KEY_PEM)
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


def test_consume_public_key_file_argument_takes_precedence_over_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """consume's --public-key-file argument must win over SIGNING_PUBLIC_KEY_FILE from the env."""
    env_key_file = tmp_path / "env-pubkey"
    env_key_file.write_bytes(test_const.OTHER_SIGNING_PUBLIC_KEY_PEM)
    arg_key_file = tmp_path / "arg-pubkey"
    arg_key_file.write_bytes(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)
    monkeypatch.setenv(
        "ENCRYPTION_KEY", base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    )
    monkeypatch.setenv("SIGNING_PUBLIC_KEY_FILE", str(env_key_file))
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
                "--public-key-file",
                str(arg_key_file),
            ]
        )
    assert exit_code == 0
    used_key = mock_consume.call_args.kwargs["public_key"]
    assert signing.public_key_fingerprint(used_key) == signing.public_key_fingerprint(
        signing.load_public_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)
    )


def test_consume_runs_the_consumer_flow_without_smoke_test(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """consume must resolve config/secrets, call consumer.consume, and skip load_and_predict."""
    monkeypatch.setenv(
        "ENCRYPTION_KEY", base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    )
    monkeypatch.setenv("SIGNING_PUBLIC_KEY", SIGNING_PUBLIC_KEY_PEM)
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
    mock_consume.assert_called_once()
    call_kwargs = mock_consume.call_args.kwargs
    assert call_kwargs["repo_id"] == "me/repo"
    assert call_kwargs["version"] == "1.0.0"
    assert call_kwargs["master_key"] == test_const.TEST_MASTER_KEY
    assert call_kwargs["workdir"] == workdir
    assert signing.public_key_fingerprint(
        call_kwargs["public_key"]
    ) == signing.public_key_fingerprint(
        signing.load_public_key(test_const.TEST_SIGNING_PUBLIC_KEY_PEM)
    )
    mock_load_and_predict.assert_not_called()
    assert "me/repo" in capsys.readouterr().err


def test_consume_runs_the_smoke_test_when_requested(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """consume --smoke-test must call load_and_predict with the manifest's task hint."""
    monkeypatch.setenv(
        "ENCRYPTION_KEY", base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    )
    monkeypatch.setenv("SIGNING_PUBLIC_KEY", SIGNING_PUBLIC_KEY_PEM)
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
    assert "'capital' (0.988)" in capsys.readouterr().err


def test_consume_reports_a_smoke_test_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """consume --smoke-test must report a ConsumerError from load_and_predict and exit 1."""
    monkeypatch.setenv(
        "ENCRYPTION_KEY", base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    )
    monkeypatch.setenv("SIGNING_PUBLIC_KEY", SIGNING_PUBLIC_KEY_PEM)
    fake_manifest = _fake_manifest()
    workdir = tmp_path / "model"

    with (
        patch("model_pipeline.cli.consume", return_value=fake_manifest),
        patch(
            "model_pipeline.cli.load_and_predict",
            side_effect=ConsumerError("failed to load the model"),
        ),
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

    assert exit_code == 1
    assert "smoke test failed" in capsys.readouterr().err


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
    monkeypatch.setenv("SIGNING_PUBLIC_KEY", SIGNING_PUBLIC_KEY_PEM)
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


def test_signing_keygen_prints_a_usable_key_pair(capsys: pytest.CaptureFixture[str]) -> None:
    """signing-keygen must print a private and a public PEM that parse and pair up."""
    exit_code = cli.main(["signing-keygen"])
    assert exit_code == 0
    output = capsys.readouterr().out

    private_pem = output[
        output.index("-----BEGIN PRIVATE KEY-----") : output.index("-----END PRIVATE KEY-----")
        + len("-----END PRIVATE KEY-----\n")
    ]
    public_pem = output[output.index("-----BEGIN PUBLIC KEY-----") :]

    private_key = signing.load_private_key(private_pem.encode("ascii"))
    public_key = signing.load_public_key(public_pem.encode("ascii"))
    assert signing.public_key_fingerprint(
        private_key.public_key()
    ) == signing.public_key_fingerprint(public_key)


def test_verify_requires_repo_and_version(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """verify must fail with a usage error when --repo/--version are unresolved."""
    monkeypatch.delenv("MODEL_REPO_ID", raising=False)
    monkeypatch.delenv("MODEL_VERSION", raising=False)
    exit_code = cli.main(["verify"])
    assert exit_code == 2
    assert "--repo" in capsys.readouterr().err


def test_verify_requires_signing_public_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """verify must fail cleanly when no signing public key can be resolved."""
    monkeypatch.delenv("SIGNING_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("SIGNING_PUBLIC_KEY_FILE", raising=False)
    exit_code = cli.main(["verify", "--repo", "me/repo", "--version", "1.0.0"])
    assert exit_code == 2
    assert "signing public key" in capsys.readouterr().err


def test_verify_reports_a_missing_public_key_file_as_a_configuration_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A non-existent --public-key-file must report a clean exit 2, not an unhandled traceback.

    Regression test: a missing signing key file used to escape
    resolve_signing_public_key as a raw OSError, past cmd_verify's `except
    KeyLoadError`, and be reported as an unexpected internal error (exit 3)
    by main()'s last-resort handler instead.
    """
    monkeypatch.delenv("SIGNING_PUBLIC_KEY", raising=False)
    missing_file = tmp_path / "does-not-exist.pem"

    exit_code = cli.main(
        [
            "verify",
            "--repo",
            "me/repo",
            "--version",
            "1.0.0",
            "--public-key-file",
            str(missing_file),
        ]
    )

    assert exit_code == 2
    assert "could not load the signing public key" in capsys.readouterr().err


def test_verify_succeeds_and_prints_the_key_fingerprint(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """verify must print the signature status and key fingerprint on success."""
    monkeypatch.setenv("SIGNING_PUBLIC_KEY", SIGNING_PUBLIC_KEY_PEM)
    fake_manifest = _fake_manifest()

    with patch(
        "model_pipeline.cli.verify_published_version", return_value=fake_manifest
    ) as mock_verify:
        exit_code = cli.main(["verify", "--repo", "me/repo", "--version", "1.0.0"])

    assert exit_code == 0
    mock_verify.assert_called_once()
    assert mock_verify.call_args.kwargs["repo_id"] == "me/repo"
    assert mock_verify.call_args.kwargs["version"] == "1.0.0"
    assert "signature OK" in capsys.readouterr().err


def test_verify_reports_a_consumer_error_and_exits_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """verify must return a non-zero exit code and print the reason on a failed verification."""
    monkeypatch.setenv("SIGNING_PUBLIC_KEY", SIGNING_PUBLIC_KEY_PEM)

    with patch(
        "model_pipeline.cli.verify_published_version",
        side_effect=ConsumerError("signature verification failed"),
    ):
        exit_code = cli.main(["verify", "--repo", "me/repo", "--version", "1.0.0"])

    assert exit_code == 1
    assert "signature verification failed" in capsys.readouterr().err


def test_main_reports_an_unexpected_exception_as_exit_code_three(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An exception a subcommand did not translate itself must be logged and exit 3."""

    def _boom(_args: argparse.Namespace) -> int:
        """Raise an exception no subcommand is expected to translate itself."""
        raise RuntimeError("boom")

    monkeypatch.setitem(cli._COMMANDS, "keygen", _boom)
    with caplog.at_level("ERROR"):
        exit_code = cli.main(["keygen"])
    assert exit_code == 3
    assert any("unexpected error" in record.getMessage() for record in caplog.records)


def test_main_lets_a_keyboard_interrupt_propagate(monkeypatch: pytest.MonkeyPatch) -> None:
    """A KeyboardInterrupt must not be swallowed by the top-level unexpected-error guard."""

    def _interrupt(_args: argparse.Namespace) -> int:
        """Raise KeyboardInterrupt, which the top-level guard must not catch."""
        raise KeyboardInterrupt

    monkeypatch.setitem(cli._COMMANDS, "keygen", _interrupt)
    with pytest.raises(KeyboardInterrupt):
        cli.main(["keygen"])


def test_log_level_debug_emits_debug_records_and_default_does_not(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """--log-level debug must let DEBUG records through; the default (info) must filter them."""

    def _log_debug(_args: argparse.Namespace) -> int:
        """Emit a single DEBUG record for the test to check propagation."""
        logging.getLogger("model_pipeline.cli").debug("debug marker")
        return 0

    monkeypatch.setitem(cli._COMMANDS, "keygen", _log_debug)
    caplog.set_level(logging.DEBUG)

    cli.main(["keygen"])
    assert not any("debug marker" in record.getMessage() for record in caplog.records)

    caplog.clear()
    cli.main(["--log-level", "debug", "keygen"])
    assert any("debug marker" in record.getMessage() for record in caplog.records)


def test_stdout_contains_only_the_key_for_keygen(capsys: pytest.CaptureFixture[str]) -> None:
    """keygen's stdout must be exactly one line: the base64 key, nothing else."""
    exit_code = cli.main(["keygen"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert out.count("\n") == 1
    assert len(base64.b64decode(out.strip(), validate=True)) == const.KEY_SIZE


def test_stdout_contains_only_the_versions_for_list(capsys: pytest.CaptureFixture[str]) -> None:
    """list's stdout must be exactly the published versions, one per line, nothing else."""
    with patch("model_pipeline.cli.hub.list_versions", return_value=["1.0.0", "1.1.0"]):
        exit_code = cli.main(["list", "--repo", "me/repo"])
    assert exit_code == 0
    assert capsys.readouterr().out == "1.0.0\n1.1.0\n"


def test_stdout_contains_only_the_version_for_produce_check_only(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """produce --check-only's stdout must be exactly the resolved version, nothing else."""
    with (
        patch("model_pipeline.cli.resolve_produce_version", return_value="1.0.0"),
        patch("model_pipeline.cli.produce") as mock_produce,
    ):
        exit_code = cli.main(
            ["produce", "--target-repo", "me/repo", "--version", "1.0.0", "--check-only"]
        )
    assert exit_code == 0
    mock_produce.assert_not_called()
    assert capsys.readouterr().out == "1.0.0\n"


def test_stdout_contains_only_the_manifest_json_for_produce(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """produce's stdout must be exactly the serialized manifest, nothing else."""
    monkeypatch.setenv("HF_TOKEN", "hf_token")  # noqa: S105
    monkeypatch.setenv(
        "ENCRYPTION_KEY", base64.b64encode(test_const.TEST_MASTER_KEY).decode("ascii")
    )
    _set_signing_env(monkeypatch)
    fake_manifest = _fake_manifest()
    with patch("model_pipeline.cli.produce", return_value=fake_manifest):
        exit_code = cli.main(["produce", "--target-repo", "me/repo", "--version", "1.0.0"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert out.endswith("\n")
    assert json.loads(out) == fake_manifest.model_dump(mode="json")
