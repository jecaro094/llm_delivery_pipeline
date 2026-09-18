"""Command-line interface: ``keygen``, ``produce``, ``list``, and ``consume`` subcommands.

Configuration follows the precedence documented in the project plan:
explicit CLI arguments win over environment variables, which win over
defaults. Environment variables (and an optional local ``.env`` file, see
``.env.example`` at the repository root) are resolved by
:class:`model_pipeline.settings.Settings`; an explicit CLI argument then
overrides the corresponding field. Secrets (the Hugging Face token and the
encryption key) are deliberately only ever accepted through environment
variables or a mounted key file, never as a CLI argument, so they cannot
leak into shell history or a process listing.

``produce`` and ``consume`` both resolve the requested version against the
target repo before doing anything else. On a real terminal, a version
conflict (already published for ``produce``, not published for
``consume``) prompts for a replacement instead of failing outright; in a
non-interactive context (a Kubernetes Job/Pod, a CI run) it fails fast
with no prompt, since no one is there to answer it. ``--check-only`` runs
just that resolution step, printing the confirmed version and exiting
without publishing or downloading anything -- what ``scripts/demo.sh``
uses to catch a version conflict before ever creating a Job or Pod.
"""

from __future__ import annotations

import argparse
import base64
import logging
import secrets
import sys
from collections.abc import Callable
from pathlib import Path

import model_pipeline.constants as const
from model_pipeline import hub
from model_pipeline.consumer import (
    ConsumerError,
    consume,
    load_and_predict,
    resolve_consume_version,
)
from model_pipeline.keys import KeyLoadError, resolve_key
from model_pipeline.logging_config import configure_logging
from model_pipeline.manifest import ManifestError, serialize_manifest
from model_pipeline.packaging import PackagingError
from model_pipeline.producer import ProducerError, produce, resolve_produce_version
from model_pipeline.settings import Settings

logger = logging.getLogger(__name__)


def _add_repo_argument(parser: argparse.ArgumentParser) -> None:
    """Add the shared --repo argument to parser."""
    parser.add_argument(
        "--repo",
        help="Hugging Face Hub repo holding the published artifact (default: MODEL_REPO_ID)",
    )


def _add_version_argument(parser: argparse.ArgumentParser) -> None:
    """Add the shared --version argument to parser."""
    parser.add_argument(
        "--version",
        help="artifact version, e.g. 1.0.0 (default: MODEL_VERSION)",
    )


def _add_check_only_argument(parser: argparse.ArgumentParser, *, repo_flag: str, verb: str) -> None:
    """Add the shared --check-only flag to parser, phrased for repo_flag and verb."""
    parser.add_argument(
        "--check-only",
        action="store_true",
        help=f"only resolve/validate --version against {repo_flag} and print it; {verb} nothing",
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser with its keygen/produce/list/consume subcommands."""
    parser = argparse.ArgumentParser(
        prog="model_pipeline",
        epilog="See .env.example at the repository root for the full reference of the "
        "environment variables named above. Exit codes: 0 success, 1 an expected failure "
        "(a conflict, the wrong key, an integrity mismatch), 2 a bad invocation or missing "
        "configuration, 3 an unexpected internal error.",
    )
    parser.add_argument(
        "--log-level",
        choices=const.LOG_LEVEL_CHOICES,
        default=None,
        help="verbosity of diagnostics written to stderr (default: LOG_LEVEL, "
        f"currently {const.DEFAULT_LOG_LEVEL!r})",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "keygen",
        help="generate a new base64-encoded AES-256 master key",
        description="Generate a random 32-byte AES-256 master key and print it, "
        "base64-encoded, to stdout. Pipe the output straight to a file or a Kubernetes "
        "Secret; it is never written anywhere by this command.",
    )

    produce_parser = subparsers.add_parser(
        "produce",
        help="encrypt and publish a model",
        description="Download --source-model from Hugging Face Hub, encrypt it, and publish "
        "the encrypted artifact plus its manifest to --target-repo. Secrets (HF_TOKEN, the "
        "encryption key) are never accepted as CLI arguments, only through environment "
        "variables or a mounted key file, so they cannot leak into shell history or a "
        "process listing.",
    )
    produce_parser.add_argument(
        "--source-model",
        help=f"open Hugging Face model to encrypt (default: SOURCE_MODEL, "
        f"currently {const.DEFAULT_SOURCE_MODEL!r})",
    )
    produce_parser.add_argument(
        "--target-repo",
        help="Hugging Face Hub repo to publish the encrypted artifact to (default: MODEL_REPO_ID)",
    )
    _add_version_argument(produce_parser)
    produce_parser.add_argument(
        "--chunk-size",
        type=int,
        help=f"AES-GCM chunk size in bytes (default: {const.DEFAULT_CHUNK_SIZE})",
    )
    _add_check_only_argument(produce_parser, repo_flag="--target-repo", verb="publish")

    list_parser = subparsers.add_parser(
        "list",
        help="list published artifact versions",
        description="Print every artifact version already published under --repo, one per line.",
    )
    _add_repo_argument(list_parser)

    consume_parser = subparsers.add_parser(
        "consume",
        help="download, verify, decrypt, and unpack a model",
        description="Download, verify, decrypt, and unpack the artifact published under "
        "--repo into --workdir. The encryption key is never accepted as a CLI argument, "
        "only through ENCRYPTION_KEY(_FILE) or --key-file pointing at a mounted "
        "Kubernetes Secret.",
    )
    _add_repo_argument(consume_parser)
    _add_version_argument(consume_parser)
    consume_parser.add_argument(
        "--key-file",
        type=Path,
        help="path to a file holding the base64-encoded master key (default: ENCRYPTION_KEY_FILE)",
    )
    consume_parser.add_argument(
        "--workdir",
        type=Path,
        help="directory to decrypt the model into (default: MODEL_WORKDIR)",
    )
    consume_parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="after decrypting, load the model and run a single fill-mask inference",
    )
    _add_check_only_argument(consume_parser, repo_flag="--repo", verb="download")

    return parser


def _setting_or_arg[T](arg_value: T | None, settings_value: T) -> T:
    """Return arg_value when the CLI argument was given; otherwise settings_value.

    Implements the precedence used throughout the pipeline: an explicit
    --flag always overrides the corresponding environment variable or
    default captured in settings.
    """
    return arg_value if arg_value is not None else settings_value


def _require(values: dict[str, object | None], command: str) -> int | None:
    """Report every value in values that is still None, at once, and return exit code 2.

    Returns None once nothing is missing, so callers can resolve several
    required values up front and report all the gaps in a single message
    instead of making the operator fix them one run at a time.
    """
    missing = [flag for flag, value in values.items() if value is None]
    if not missing:
        return None
    logger.error("%s requires %s (or their env vars)", command, " and ".join(missing))
    return 2


def _resolve_version(
    resolver: Callable[..., str],
    repo: str,
    version: str,
    *,
    check_only: bool,
    command: str,
    error_type: type[Exception],
) -> tuple[str, int | None]:
    """Resolve version against repo via resolver, honoring --check-only and interactive terminals.

    Skipped entirely when neither check_only nor an interactive terminal
    applies, so an unattended run (a Kubernetes Job/Pod, CI) leaves version
    resolution to the producer/consumer flow itself rather than blocking on
    input that will never arrive. Returns (version, exit_code): exit_code is
    None when the caller should proceed with the returned version, and an
    exit code the caller must return immediately otherwise (0 once
    --check-only has printed the resolved version, 1 on a resolution
    failure from error_type).
    """
    if not check_only and not sys.stdin.isatty():
        return version, None
    try:
        resolved = resolver(repo, version, interactive=sys.stdin.isatty())
    except error_type as exc:
        return version, _fail(command, exc)
    if check_only:
        print(resolved)
        return resolved, 0
    return resolved, None


def _fail(command: str, exc: Exception) -> int:
    """Log '<command> failed: <exc>' and return the exit code for that failure."""
    logger.error("%s failed: %s", command, exc)
    return 1


def _resolve_master_key(settings: Settings, *, key_file_override: Path | None = None) -> bytes:
    """Resolve the master key from settings.encryption_key(_file), or from key_file_override.

    key_file_override, when given, takes precedence over
    settings.encryption_key_file, following the CLI argument > environment
    variable precedence used throughout the pipeline.
    """
    key_file = key_file_override if key_file_override is not None else settings.encryption_key_file
    return resolve_key(key_file=key_file, key_value=settings.encryption_key)


def cmd_keygen(_args: argparse.Namespace) -> int:
    """Generate a random 32-byte AES-256 master key and print it, base64-encoded, to stdout."""
    key = secrets.token_bytes(const.KEY_SIZE)
    print(base64.b64encode(key).decode("ascii"))
    return 0


def cmd_produce(args: argparse.Namespace) -> int:
    """Resolve produce configuration and secrets, then run the producer flow."""
    settings = Settings()

    source_model = _setting_or_arg(args.source_model, settings.source_model)
    target_repo = _setting_or_arg(args.target_repo, settings.model_repo_id)
    version = _setting_or_arg(args.version, settings.model_version)
    exit_code = _require({"--target-repo": target_repo, "--version": version}, "produce")
    if exit_code is not None:
        return exit_code
    assert target_repo is not None and version is not None  # noqa: S101 -- _require checked above

    version, exit_code = _resolve_version(
        resolve_produce_version,
        target_repo,
        version,
        check_only=args.check_only,
        command="produce",
        error_type=ProducerError,
    )
    if exit_code is not None:
        return exit_code

    if not settings.hf_token:
        logger.error("HF_TOKEN must be set to publish to Hugging Face Hub")
        return 2

    try:
        master_key = _resolve_master_key(settings)
    except KeyLoadError as exc:
        logger.error("could not load the encryption key: %s", exc)
        return 2

    chunk_size = _setting_or_arg(args.chunk_size, const.DEFAULT_CHUNK_SIZE)

    try:
        artifact_manifest = produce(
            source_model=source_model,
            target_repo=target_repo,
            version=version,
            master_key=master_key,
            hf_token=settings.hf_token,
            chunk_size=chunk_size,
        )
    except ProducerError as exc:
        return _fail("produce", exc)

    sys.stdout.buffer.write(serialize_manifest(artifact_manifest))
    sys.stdout.write("\n")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """Resolve the target repo and print its published artifact versions, one per line."""
    settings = Settings()
    target_repo = _setting_or_arg(args.repo, settings.model_repo_id)
    exit_code = _require({"--repo": target_repo}, "list")
    if exit_code is not None:
        return exit_code
    assert target_repo is not None  # noqa: S101 -- _require checked above

    for version in hub.list_versions(target_repo):
        print(version)
    return 0


def cmd_consume(args: argparse.Namespace) -> int:
    """Resolve consume config and secrets, run the consumer flow, and optionally smoke-test."""
    settings = Settings()

    repo_id = _setting_or_arg(args.repo, settings.model_repo_id)
    version = _setting_or_arg(args.version, settings.model_version)
    exit_code = _require({"--repo": repo_id, "--version": version}, "consume")
    if exit_code is not None:
        return exit_code
    assert repo_id is not None and version is not None  # noqa: S101 -- _require checked above

    version, exit_code = _resolve_version(
        resolve_consume_version,
        repo_id,
        version,
        check_only=args.check_only,
        command="consume",
        error_type=ConsumerError,
    )
    if exit_code is not None:
        return exit_code

    workdir = _setting_or_arg(args.workdir, settings.model_workdir)
    exit_code = _require({"--workdir": workdir}, "consume")
    if exit_code is not None:
        return exit_code
    assert workdir is not None  # noqa: S101 -- _require checked above

    try:
        master_key = _resolve_master_key(settings, key_file_override=args.key_file)
    except KeyLoadError as exc:
        logger.error("could not load the encryption key: %s", exc)
        return 2

    try:
        artifact_manifest = consume(
            repo_id=repo_id, version=version, master_key=master_key, workdir=workdir
        )
    except (ConsumerError, ManifestError, PackagingError) as exc:
        return _fail("consume", exc)

    logger.info(
        "model verified and decrypted from %s version %s into %s", repo_id, version, workdir
    )

    if args.smoke_test:
        try:
            prediction = load_and_predict(workdir, artifact_manifest["model"]["task_hint"])
        except ConsumerError as exc:
            return _fail("smoke test", exc)
        logger.info("smoke test prediction: %s", prediction)

    return 0


_COMMANDS = {
    "keygen": cmd_keygen,
    "produce": cmd_produce,
    "list": cmd_list,
    "consume": cmd_consume,
}


def main(argv: list[str] | None = None) -> int:
    """Parse argv, dispatch to the selected subcommand, and return its exit code.

    An exception the subcommand itself did not already turn into a clean
    error message is logged through the logging channel, instead of
    printing a raw traceback to a Kubernetes Job/Pod log, and reported as
    exit code 3. ``KeyboardInterrupt`` and ``SystemExit`` are not
    ``Exception`` subclasses, so they propagate unchanged.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    log_level_name = _setting_or_arg(args.log_level, Settings().log_level)
    configure_logging(getattr(logging, log_level_name.upper()))
    try:
        return _COMMANDS[args.command](args)
    except Exception:
        logger.exception("%s failed with an unexpected error", args.command)
        return 3
