"""Shared test fixtures.

More fixtures (a fake Hugging Face Hub in tmp_path) will be added here as
each module of the pipeline is introduced.
"""

from pathlib import Path

import pytest


@pytest.fixture
def fake_model_dir(tmp_path: Path) -> Path:
    """Create a small directory tree standing in for a downloaded model snapshot."""
    source_dir = tmp_path / "fake-model"
    (source_dir / "tokenizer").mkdir(parents=True)
    (source_dir / "config.json").write_text('{"model_type": "bert"}', encoding="utf-8")
    (source_dir / "pytorch_model.bin").write_bytes(b"\x00\x01binary-weights\x02\x03")
    (source_dir / "tokenizer" / "vocab.txt").write_text("[PAD]\n[CLS]\n", encoding="utf-8")
    return source_dir
