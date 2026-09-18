"""Tests for the bounded interactive prompt helper."""

from __future__ import annotations

import io
from unittest.mock import patch

import pytest

from model_pipeline.prompt import PromptError, prompt_for_value


def _is_expected(candidate: str) -> bool:
    """Accept only the literal value "expected", the shared validator for these tests."""
    return candidate == "expected"


def _invalid_message(candidate: str) -> str:
    """Report candidate as rejected, the shared message builder for these tests."""
    return f"{candidate!r} is not valid"


def test_prompt_for_value_accepts_first_valid_candidate() -> None:
    """prompt_for_value must return immediately when the first input passes is_valid."""
    with patch("builtins.input", return_value="expected"):
        result = prompt_for_value(
            prompt="value: ",
            default=None,
            is_valid=_is_expected,
            invalid_message=_invalid_message,
        )
    assert result == "expected"


def test_prompt_for_value_retries_after_a_rejected_candidate() -> None:
    """prompt_for_value must reprompt after an invalid candidate and accept a later valid one."""
    with patch("builtins.input", side_effect=["wrong", "expected"]):
        result = prompt_for_value(
            prompt="value: ",
            default=None,
            is_valid=_is_expected,
            invalid_message=_invalid_message,
        )
    assert result == "expected"


def test_prompt_for_value_applies_default_on_empty_input() -> None:
    """prompt_for_value must substitute default when the operator enters an empty line."""
    with patch("builtins.input", return_value=""):
        result = prompt_for_value(
            prompt="value: ",
            default="expected",
            is_valid=_is_expected,
            invalid_message=_invalid_message,
        )
    assert result == "expected"


def test_prompt_for_value_raises_prompt_error_after_max_attempts() -> None:
    """prompt_for_value must raise PromptError once max_attempts candidates are all rejected."""
    with (
        patch("builtins.input", return_value="wrong"),
        pytest.raises(PromptError, match="after 3 attempts"),
    ):
        prompt_for_value(
            prompt="value: ",
            default=None,
            is_valid=_is_expected,
            invalid_message=_invalid_message,
            max_attempts=3,
        )


def test_prompt_for_value_raises_prompt_error_on_eof() -> None:
    """prompt_for_value must raise PromptError, not propagate EOFError, on a closed stdin."""
    with (
        patch("builtins.input", side_effect=EOFError),
        pytest.raises(PromptError, match="stdin is closed"),
    ):
        prompt_for_value(
            prompt="value: ",
            default=None,
            is_valid=_is_expected,
            invalid_message=_invalid_message,
        )


def test_prompt_for_value_never_writes_to_stdout() -> None:
    """prompt_for_value must write prompts and retry messages to stream, never to stdout."""
    stream = io.StringIO()
    with patch("builtins.input", side_effect=["wrong", "expected"]):
        prompt_for_value(
            prompt="value: ",
            default=None,
            is_valid=_is_expected,
            invalid_message=_invalid_message,
            stream=stream,
        )
    output = stream.getvalue()
    assert "value: " in output
    assert "'wrong' is not valid" in output
