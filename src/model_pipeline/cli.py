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
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import model_pipeline.constants as const
from model_pipeline import hub, signing
from model_pipeline.consumer import (
    ConsumerError,
    consume,
    load_and_predict,
    resolve_consume_version,
    verify_published_version,
)
from model_pipeline.keys import (
    KeyLoadError,
    resolve_key,
    resolve_signing_private_key,
    resolve_signing_public_key,
)
from model_pipeline.manifest import ManifestError, serialize_manifest
from model_pipeline.packaging import PackagingError
from model_pipeline.producer import ProducerError, produce, resolve_produce_version
from model_pipeline.settings import Settings


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser with its keygen/produce/list/consume subcommands."""
    parser = argparse.ArgumentParser(prog="model_pipeline")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("keygen", help="generate a new base64-encoded AES-256 master key")
    subparsers.add_parser("signing-keygen", help="generate a new Ed25519 signing key pair (PEM)")

    produce_parser = subparsers.add_parser("produce", help="encrypt, sign, and publish a model")
    produce_parser.add_argument("--source-model")
    produce_parser.add_argument("--target-repo")
    produce_parser.add_argument("--version")
    produce_parser.add_argument("--chunk-size", type=int)
    produce_parser.add_argument(
        "--check-only",
        action="store_true",
        help="only resolve/validate --version against --target-repo and print it; publish nothing",
    )

    list_parser = subparsers.add_parser("list", help="list published artifact versions")
    list_parser.add_argument("--repo")

    verify_parser = subparsers.add_parser(
        "verify", help="verify a published version's signature, without decrypting anything"
    )
    verify_parser.add_argument("--repo")
    verify_parser.add_argument("--version")
    verify_parser.add_argument("--public-key-file", type=Path)

    consume_parser = subparsers.add_parser(
        "consume", help="verify, download, decrypt, and unpack a model"
    )
    consume_parser.add_argument("--repo")
    consume_parser.add_argument("--version")
    consume_parser.add_argument("--key-file", type=Path)
    consume_parser.add_argument("--public-key-file", type=Path)
    consume_parser.add_argument("--workdir", type=Path)
    consume_parser.add_argument("--smoke-test", action="store_true")
    consume_parser.add_argument(
        "--check-only",
        action="store_true",
        help="only resolve/validate --version against --repo and print it; download nothing",
    )

    return parser


def _resolve_master_key(settings: Settings, *, key_file_override: Path | None = None) -> bytes:
    """Resolve the master key from settings.encryption_key(_file), or from key_file_override.

    key_file_override, when given, takes precedence over
    settings.encryption_key_file, following the CLI argument > environment
    variable precedence used throughout the pipeline.
    """
    key_file = key_file_override if key_file_override is not None else settings.encryption_key_file
    return resolve_key(key_file=key_file, key_value=settings.encryption_key)


def _resolve_signing_public_key(
    settings: Settings, *, key_file_override: Path | None = None
) -> Ed25519PublicKey:
    """Resolve the Ed25519 public verification key from settings or key_file_override.

    key_file_override, when given, takes precedence over
    settings.signing_public_key_file, following the CLI argument >
    environment variable precedence used throughout the pipeline.
    """
    key_file = (
        key_file_override if key_file_override is not None else settings.signing_public_key_file
    )
    return resolve_signing_public_key(key_file=key_file, key_value=settings.signing_public_key)


def cmd_keygen(_args: argparse.Namespace) -> int:
    """Generate a random 32-byte AES-256 master key and print it, base64-encoded, to stdout."""
    key = secrets.token_bytes(const.KEY_SIZE)
    print(base64.b64encode(key).decode("ascii"))
    return 0


def cmd_signing_keygen(_args: argparse.Namespace) -> int:
    """Generate a new Ed25519 signing key pair and print both PEMs, clearly delimited."""
    private_pem, public_pem = signing.generate_keypair()
    print("# private key (keep secret)")
    print(private_pem.decode("ascii"), end="")
    print("# public key")
    print(public_pem.decode("ascii"), end="")
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

    if args.check_only or sys.stdin.isatty():
        try:
            version = resolve_produce_version(target_repo, version, interactive=sys.stdin.isatty())
        except ProducerError as exc:
            print(f"produce failed: {exc}", file=sys.stderr)
            return 1
        if args.check_only:
            print(version)
            return 0

    if not settings.hf_token:
        print("HF_TOKEN must be set to publish to Hugging Face Hub", file=sys.stderr)
        return 2

    try:
        master_key = _resolve_master_key(settings)
    except KeyLoadError as exc:
        print(f"could not load the encryption key: {exc}", file=sys.stderr)
        return 2

    try:
        signing_private_key = resolve_signing_private_key(
            key_file=settings.signing_key_file, key_value=settings.signing_key
        )
    except KeyLoadError as exc:
        print(f"could not load the signing private key: {exc}", file=sys.stderr)
        return 2

    chunk_size = args.chunk_size if args.chunk_size is not None else const.DEFAULT_CHUNK_SIZE

    try:
        artifact_manifest = produce(
            source_model=source_model,
            target_repo=target_repo,
            version=version,
            master_key=master_key,
            signing_private_key=signing_private_key,
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


def cmd_verify(args: argparse.Namespace) -> int:
    """Resolve verify config, verify a published version's signature, and print the result.

    Needs neither the decryption key nor a Hub token: anyone can check that
    a published artifact's manifest was signed by the expected producer.
    """
    settings = Settings()

    repo_id = args.repo if args.repo is not None else settings.model_repo_id
    version = args.version if args.version is not None else settings.model_version
    if repo_id is None or version is None:
        print("verify requires --repo and --version (or their env vars)", file=sys.stderr)
        return 2

    try:
        public_key = _resolve_signing_public_key(settings, key_file_override=args.public_key_file)
    except KeyLoadError as exc:
        print(f"could not load the signing public key: {exc}", file=sys.stderr)
        return 2

    try:
        artifact_manifest = verify_published_version(
            repo_id=repo_id, version=version, public_key=public_key
        )
    except (ConsumerError, ManifestError) as exc:
        print(f"verify failed: {exc}", file=sys.stderr)
        return 1

    fingerprint = artifact_manifest["signature"]["public_key_sha256"]
    print(f"signature OK for {repo_id} version {version} · key fingerprint {fingerprint}")
    return 0


def cmd_consume(args: argparse.Namespace) -> int:
    """Resolve consume config and secrets, run the consumer flow, and optionally smoke-test."""
    settings = Settings()

    repo_id = args.repo if args.repo is not None else settings.model_repo_id
    version = args.version if args.version is not None else settings.model_version
    if repo_id is None or version is None:
        print("consume requires --repo and --version (or their env vars)", file=sys.stderr)
        return 2

    if args.check_only or sys.stdin.isatty():
        try:
            version = resolve_consume_version(repo_id, version, interactive=sys.stdin.isatty())
        except ConsumerError as exc:
            print(f"consume failed: {exc}", file=sys.stderr)
            return 1
        if args.check_only:
            print(version)
            return 0

    workdir = args.workdir if args.workdir is not None else settings.model_workdir
    if workdir is None:
        print("consume requires --workdir (or MODEL_WORKDIR)", file=sys.stderr)
        return 2

    try:
        master_key = _resolve_master_key(settings, key_file_override=args.key_file)
    except KeyLoadError as exc:
        print(f"could not load the encryption key: {exc}", file=sys.stderr)
        return 2

    try:
        public_key = _resolve_signing_public_key(settings, key_file_override=args.public_key_file)
    except KeyLoadError as exc:
        print(f"could not load the signing public key: {exc}", file=sys.stderr)
        return 2

    try:
        artifact_manifest = consume(
            repo_id=repo_id,
            version=version,
            master_key=master_key,
            public_key=public_key,
            workdir=workdir,
        )
    except (ConsumerError, ManifestError, PackagingError) as exc:
        print(f"consume failed: {exc}", file=sys.stderr)
        return 1

    print(f"model verified and decrypted from {repo_id} version {version} into {workdir}")

    if args.smoke_test:
        try:
            prediction = load_and_predict(workdir, artifact_manifest["model"]["task_hint"])
        except ConsumerError as exc:
            print(f"smoke test failed: {exc}", file=sys.stderr)
            return 1
        print(f"smoke test prediction: {prediction}")

    return 0


_COMMANDS = {
    "keygen": cmd_keygen,
    "signing-keygen": cmd_signing_keygen,
    "produce": cmd_produce,
    "list": cmd_list,
    "verify": cmd_verify,
    "consume": cmd_consume,
}


def main(argv: list[str] | None = None) -> int:
    """Parse argv and dispatch to the selected subcommand, returning its exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return _COMMANDS[args.command](args)
