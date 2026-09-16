"""Tests for the ``python -m model_pipeline`` entry point."""

from __future__ import annotations

import runpy
import sys
from unittest.mock import patch

import pytest


def test_main_module_dispatches_to_cli_main_and_exits_with_its_return_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Running the package as __main__ must call cli.main and raise SystemExit with its code."""
    monkeypatch.setattr(sys, "argv", ["model_pipeline"])

    with patch("model_pipeline.cli.main", return_value=42) as mock_main:
        with pytest.raises(SystemExit) as exc_info:
            runpy.run_module("model_pipeline.__main__", run_name="__main__")

    mock_main.assert_called_once_with()
    assert exc_info.value.code == 42
