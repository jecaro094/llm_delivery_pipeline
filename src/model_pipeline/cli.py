"""Command-line interface: ``keygen``, ``produce``, and ``list`` subcommands.

Configuration follows the precedence documented in the project plan:
explicit CLI arguments win over environment variables, which win over
defaults. Environment variables (and an optional local ``.env`` file, see
``.env.example`` at the repository root) are resolved by
:class:`model_pipeline.settings.Settings`; an explicit CLI argument then
overrides the corresponding field. Secrets (the Hugging Face token and the
encryption key) are deliberately only ever accepted through environment
variables or a mounted key file, never as a CLI argument, so they cannot
leak into shell history or a process listing.
"""

from __future__ import annotations

import argparse
import base64
import secrets
import sys

import model_pipeline.constants as const
from model_pipeline import hub
from model_pipeline.keys import KeyLoadError, resolve_key
from model_pipeline.manifest import serialize_manifest
from model_pipeline.producer import ProducerError, produce
from model_pipeline.settings import Settings


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser with its keygen/produce/list subcommands."""
    parser = argparse.ArgumentParser(prog="model_pipeline")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("keygen", help="generate a new base64-encoded AES-256 master key")

    produce_parser = subparsers.add_parser("produce", help="encrypt and publish a model")
    produce_parser.add_argument("--source-model")
    produce_parser.add_argument("--target-repo")
    produce_parser.add_argument("--version")
    produce_parser.add_argument("--chunk-size", type=int)

    list_parser = subparsers.add_parser("list", help="list published artifact versions")
    list_parser.add_argument("--repo")

    return parser


def _resolve_master_key(settings: Settings) -> bytes:
    """Resolve the master key for the producer from settings.encryption_key(_file)."""
    return resolve_key(key_file=settings.encryption_key_file, key_value=settings.encryption_key)


def cmd_keygen(_args: argparse.Namespace) -> int:
    """Generate a random 32-byte AES-256 master key and print it, base64-encoded, to stdout."""
    key = secrets.token_bytes(const.KEY_SIZE)
    print(base64.b64encode(key).decode("ascii"))
    return 0


def cmd_produce(args: argparse.Namespace) -> int:
    """Resolve produce configuration and secrets, then run the producer flow."""
    settings = Settings()

    source_model = args.source_model if args.source_model is not None else settings.source_model
    target_repo = args.target_repo if args.target_repo is not None else settings.model_repo_id
    version = args.version if args.version is not None else settings.model_version
    if target_repo is None or version is None:
        print("produce requires --target-repo and --version (or their env vars)", file=sys.stderr)
        return 2

    if not settings.hf_token:
        print("HF_TOKEN must be set to publish to Hugging Face Hub", file=sys.stderr)
        return 2

    try:
        master_key = _resolve_master_key(settings)
    except KeyLoadError as exc:
        print(f"could not load the encryption key: {exc}", file=sys.stderr)
        return 2

    chunk_size = args.chunk_size if args.chunk_size is not None else const.DEFAULT_CHUNK_SIZE

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
        print(f"produce failed: {exc}", file=sys.stderr)
        return 1

    sys.stdout.buffer.write(serialize_manifest(artifact_manifest))
    sys.stdout.write("\n")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """Resolve the target repo and print its published artifact versions, one per line."""
    settings = Settings()
    target_repo = args.repo if args.repo is not None else settings.model_repo_id
    if target_repo is None:
        print("list requires --repo (or MODEL_REPO_ID)", file=sys.stderr)
        return 2

    for version in hub.list_versions(target_repo):
        print(version)
    return 0


_COMMANDS = {
    "keygen": cmd_keygen,
    "produce": cmd_produce,
    "list": cmd_list,
}


def main(argv: list[str] | None = None) -> int:
    """Parse argv and dispatch to the selected subcommand, returning its exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return _COMMANDS[args.command](args)
