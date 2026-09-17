"""Pipeline configuration loaded from the process environment and an optional ``.env`` file.

Every environment variable the pipeline recognizes is documented in
``.env.example`` at the repository root; this module is the single place
that reads and validates them. Field names map to environment variable
names case-insensitively (``model_repo_id`` reads ``MODEL_REPO_ID``), and an
actual process environment variable always takes precedence over a value
loaded from ``.env``. An explicit CLI argument, when one is given, still
wins over everything resolved here -- that override is applied in
``cli.py``, not in this module, so ``Settings`` only ever reflects the
environment and its defaults.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

import model_pipeline.constants as const


class Settings(BaseSettings):
    """Pipeline configuration resolved from environment variables and ``.env``."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", protected_namespaces=())

    hf_token: str | None = None
    encryption_key: str | None = None
    encryption_key_file: Path | None = None
    signing_key: str | None = None
    signing_key_file: Path | None = None
    signing_public_key: str | None = None
    signing_public_key_file: Path | None = None
    model_repo_id: str | None = None
    model_version: str | None = None
    source_model: str = const.DEFAULT_SOURCE_MODEL
    model_workdir: Path | None = None
